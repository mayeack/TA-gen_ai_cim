# encoding=utf-8
"""
ta_gen_ai_cim_duo_input.py - the ta_gen_ai_cim_duo modular input: Cisco Duo
authentication logs, activity logs or a users snapshot, from the Duo Admin
API (bin/ta_gen_ai_cim_duo_api.py), one endpoint per input instance.

Ships OFF: default/inputs.conf holds only the scheme's default stanza, so no
instance exists until an owner adds one in local/ (README/inputs.conf.spec).

Events are one compact JSON object per Duo record, under the sourcetypes
ta_gen_ai_cim:duo:authentication / :activity / :user. _time is Duo's
`timestamp` (authentication), `ts` (activity) or the snapshot time (users).

Log window (authentication, activity) - one Duo call per run, oldest first:
  * every request sends sort=ts:asc (Duo documents no default order);
  * mintime, maxtime and next_offset are checkpointed together after each
    page in the KV collection ta_gen_ai_cim_duo_checkpoint (_key = the input
    stanza name);
  * Duo returns a next_offset on the last page that has records too; only the
    call after it comes back without one. So a saved next_offset is a cursor,
    not a promise of more records: the next run resumes after it with
    mintime = the cursor's timestamp and maxtime = now - lag (Duo's own
    duo_log_sync resumes the same way), and that one call returns whatever is
    new. (This amends the build contract's fixed-maxtime window, which spent a
    whole extra run confirming every window and stalled for good on a Duo that
    echoes the next_offset it was sent.);
  * a page with no records, or with no next_offset, completes the window: the
    next one starts at that call's maxtime + 1 ms (both bounds are inclusive).
    A next_offset equal to the one sent completes it too, with a WARN;
  * a window never moves past records it has not read. When Duo's retention
    floor (180 days, less an hour of margin) overtakes a cursor, the records
    before the floor are gone from Duo and the window resumes at the floor
    with a WARN; nothing after the floor is skipped;
  * a window ends at now - lag_seconds (>= 120: Duo delays logs about two
    minutes) and a run is skipped while mintime >= that end (Duo needs
    mintime < maxtime);
  * throughput: at most 1000 records per run (Duo asks for no more than one
    log request a minute); a tenant that writes more per interval falls
    behind, and anything older than the floor when it is reached is lost;
  * one-page-duplicate window: a run killed after writing a page but before
    its checkpoint resends that page (dedup on txid);
  * at-most-once window: a page is checkpointed once its events are written to
    splunkd, so a splunkd crash that loses events still in its pipeline drops
    them for good;
  * HTTP 429 / code 42901 sets backoff_until (120 s, doubling per consecutive
    429, at most 1 h); runs before it do nothing;
  * interval floor 120 s: validate_input rejects less, and a run that starts
    under 115 s after the last checkpoint write is skipped.

Users snapshot: every page of /admin/v1/users in one run, buffered, then
written as an ALLOWLIST of fields only (no phones, tokens, WebAuthn or
desktop-authenticator records, no notes) plus snapshot_id, snapshot_total and
snapshot_seq. A page that answers 429 / 42901 or fails transiently (Duo
unreachable, HTTP 5xx) is retried in the same run, up to 6 times, waiting 1 s
doubling to 32 s plus jitter (at least Retry-After), at most 120 s in all per
snapshot, as duo_client_python retries; only then is the snapshot abandoned,
and still nothing is written. A snapshot is complete only when its event count
equals snapshot_total; the identity lookup-gen search uses only the newest
complete one.

Search head cluster: best-effort captain-only guard - a member that is not
the captain skips quietly, and a failed lookup skips the run with a WARN.
Untested on a real cluster.

Credentials: the account stanza in ta_gen_ai_cim_account.conf (auth_type =
duo_hmac, url = https://api-<x>.duosecurity.com, client_id = the integration
key); the secret key is read from storage/passwords (realm
ta_gen_ai_cim_account__<account>, name client_secret) with the input's own
session key. No key, signature or Authorization header is ever logged.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import datetime
import json
import logging
import os
import random
import re
import sys
import time

BIN_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_DIR = os.path.join(os.path.dirname(BIN_DIR), 'lib')
for _path in (LIB_DIR, BIN_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from splunklib.modularinput import Argument, Event, Scheme, Script  # noqa: E402

import ta_gen_ai_cim_duo_api as duo_api  # noqa: E402

logger = logging.getLogger('ta_gen_ai_cim_duo_input')

APP = 'TA-gen_ai_cim'
SCHEME = 'ta_gen_ai_cim_duo'
COLLECTION = 'ta_gen_ai_cim_duo_checkpoint'
ACCOUNT_CONF = 'ta_gen_ai_cim_account'
AUTH_TYPE = 'duo_hmac'
REALM_PREFIX = 'ta_gen_ai_cim_account__'
SECRET_NAME = 'client_secret'
ACCOUNT_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$')

ENDPOINTS = {
    'authentication': (duo_api.AUTH_LOGS_PATH, 'ta_gen_ai_cim:duo:authentication'),
    'activity': (duo_api.ACTIVITY_LOGS_PATH, 'ta_gen_ai_cim:duo:activity'),
    'users': (duo_api.USERS_PATH, 'ta_gen_ai_cim:duo:user'),
}

DEFAULT_LAG_SECONDS = 180
MIN_LAG_SECONDS = 120            # Duo delays its logs by about two minutes
MAX_LAG_SECONDS = 86400
DEFAULT_LOOKBACK_HOURS = 24
MAX_LOOKBACK_HOURS = 4320        # Duo keeps 180 days of logs
RETENTION_MS = 180 * 86400 * 1000 - 3600 * 1000   # stay an hour inside it
MIN_INTERVAL_SECONDS = 120
INTERVAL_JITTER_SECONDS = 5      # scheduler slack allowed under the floor
BACKOFF_BASE_SECONDS = 120
BACKOFF_CAP_SECONDS = 3600
LOG_PAGES_PER_RUN = 1            # one Duo log call per endpoint per run
USERS_PAGE_PAUSE_SECONDS = 1.0
MAX_USER_PAGES = 1000
USERS_RETRIES_PER_PAGE = 6       # duo_client_python's schedule: 1, 2, 4 ... 32 s
USERS_RETRY_FIRST_SECONDS = 1.0
USERS_RETRY_MAX_SECONDS = 32.0
USERS_RETRY_BUDGET_SECONDS = 120.0   # all retry waits of one snapshot; the interval floor

USER_SCALAR_FIELDS = ('user_id', 'username', 'realname', 'firstname', 'lastname', 'email',
                      'status', 'is_enrolled', 'created', 'last_login',
                      'alias1', 'alias2', 'alias3', 'alias4')


###############################################################################
# Parameters
###############################################################################

def _int_param(params, key, default, low, high):
    raw = params.get(key)
    if raw is None or str(raw).strip() == '':
        return default
    try:
        value = int(str(raw).strip())
    except ValueError:
        raise ValueError('{} must be an integer'.format(key))
    if not low <= value <= high:
        raise ValueError('{} must be between {} and {}'.format(key, low, high))
    return value


def parse_params(params, check_interval=False):
    """The validated settings of one input stanza as a dict. Raises
    ValueError naming the bad setting (never echoing a secret)."""
    account = str(params.get('account') or '').strip()
    if not ACCOUNT_RE.match(account):
        raise ValueError('account must name a ta_gen_ai_cim_account stanza (letters, digits, _ . -)')
    endpoint = str(params.get('endpoint') or '').strip().lower()
    if endpoint not in ENDPOINTS:
        raise ValueError('endpoint must be one of: {}'.format(', '.join(sorted(ENDPOINTS))))
    if check_interval:
        interval = str(params.get('interval') or '').strip()
        if re.match(r'^\d+$', interval) and int(interval) < MIN_INTERVAL_SECONDS:
            raise ValueError('interval must be at least {} seconds'.format(MIN_INTERVAL_SECONDS))
    index = str(params.get('index') or '').strip()
    index = None if index in ('', 'default') else index   # None: splunkd applies the stanza's index
    if index == 'gen_ai_log':
        raise ValueError('index must not be gen_ai_log: Duo events would contaminate every inference '
                         'metric and detection that reads it')
    return {
        'account': account,
        'endpoint': endpoint,
        'lag_seconds': _int_param(params, 'lag_seconds', DEFAULT_LAG_SECONDS,
                                  MIN_LAG_SECONDS, MAX_LAG_SECONDS),
        'initial_lookback_hours': _int_param(params, 'initial_lookback_hours',
                                             DEFAULT_LOOKBACK_HOURS, 1, MAX_LOOKBACK_HOURS),
        'index': index,
    }


###############################################################################
# Record shaping and event time
###############################################################################

_ISO_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$')


def parse_iso8601(text):
    """Epoch seconds from an ISO 8601 timestamp, or None. Works on Python 3.9,
    whose fromisoformat rejects 'Z' and fractions that are not 3 or 6 digits."""
    m = _ISO_RE.match(str(text or '').strip())
    if not m:
        return None
    base, fraction, zone = m.groups()
    zone = zone or '+00:00'
    if zone == 'Z':
        zone = '+00:00'
    elif ':' not in zone:
        zone = zone[:3] + ':' + zone[3:]
    stamp = base.replace(' ', 'T') + '.' + ((fraction or '0') + '000000')[:6] + zone
    try:
        return datetime.datetime.fromisoformat(stamp).timestamp()
    except ValueError:
        return None


def _epoch(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number / 1000.0 if number > 1e11 else number   # ms -> s


def record_time(endpoint, record, fallback):
    if endpoint == 'authentication':
        value = _epoch(record.get('timestamp'))
        if value is None:
            value = parse_iso8601(record.get('isotimestamp'))
    elif endpoint == 'activity':
        value = parse_iso8601(record.get('ts'))
        if value is None:
            value = _epoch(record.get('ts'))
    else:
        value = None
    return fallback if value is None else value


def user_allowlist(user):
    """Only the fields the identity source needs (contract decision 2)."""
    out = {}
    for key in USER_SCALAR_FIELDS:
        value = user.get(key)
        if value is None or isinstance(value, (str, int, float, bool)):
            if key in user:
                out[key] = value
    aliases = user.get('aliases')
    if isinstance(aliases, dict):
        out['aliases'] = dict((str(k), str(v)) for k, v in aliases.items()
                              if isinstance(v, (str, int)) and str(v))
    elif isinstance(aliases, list):
        out['aliases'] = [str(v) for v in aliases if isinstance(v, str) and v]
    groups = user.get('groups')
    if isinstance(groups, list):
        out['groups'] = [{'name': g['name']} for g in groups
                         if isinstance(g, dict) and isinstance(g.get('name'), str)]
    return out


def compact(record):
    return json.dumps(record, separators=(',', ':'), ensure_ascii=False)


###############################################################################
# Checkpoint, account and cluster access
###############################################################################

class SplunkAccess(object):
    """Everything the input reads from or writes to splunkd, over the input's
    own session key. Tests substitute an object with the same methods."""

    def __init__(self, service):
        self._svc = service

    @classmethod
    def from_metadata(cls, metadata):
        from urllib.parse import urlsplit
        import splunklib.client as client
        uri = urlsplit(metadata['server_uri'])
        return cls(client.Service(scheme=uri.scheme, host=uri.hostname, port=uri.port,
                                  token=metadata['session_key'], owner='nobody', app=APP))

    def _content(self, path):
        body = json.loads(self._svc.get(path, output_mode='json').body.read().decode('utf-8'))
        return (body.get('entry') or [{}])[0].get('content') or {}

    def server_info(self):
        return self._content('server/info')

    def captain_info(self):
        return self._content('shcluster/captain/info')

    def account(self, name):
        try:
            return dict(self._svc.confs[ACCOUNT_CONF][name].content)
        except KeyError:
            raise duo_api.DuoError('account "{}" is not configured in {}.conf'.format(name, ACCOUNT_CONF))

    def secret(self, name):
        try:
            cred = self._svc.storage_passwords['{}{}:{}:'.format(REALM_PREFIX, name, SECRET_NAME)]
        except KeyError:
            cred = None
        value = cred.content.get('clear_password') if cred is not None else None
        if not value:
            raise duo_api.DuoError('no {} is stored for account "{}"'.format(SECRET_NAME, name))
        return value

    def _data(self):
        return self._svc.kvstore[COLLECTION].data

    def load_checkpoint(self, key):
        from splunklib.binding import HTTPError
        try:
            doc = self._data().query_by_id(key)
        except HTTPError as exc:
            if exc.status == 404:
                return {}
            raise
        return doc if isinstance(doc, dict) else {}

    def save_checkpoint(self, key, state):
        from splunklib.binding import HTTPError
        doc = dict(state)
        doc['_key'] = key
        try:
            self._data().update(key, json.dumps(doc))
        except HTTPError as exc:
            if exc.status != 404:
                raise
            self._data().insert(json.dumps(doc))


def shc_poll_decision(access):
    """(poll, reason). Best effort: only the captain of a search head cluster
    polls; on a lookup error nobody polls this run."""
    try:
        info = access.server_info()
        roles = info.get('server_roles') or []
        if isinstance(roles, str):
            roles = [roles]
        if 'shc_member' not in roles:
            return True, 'not a search head cluster member'
        captain = access.captain_info().get('label')
        if captain and captain == info.get('serverName'):
            return True, 'search head cluster captain'
        return False, 'search head cluster member that is not the captain'
    except Exception as exc:
        logger.warning('search head cluster captain check failed (%s); skipping this run',
                       type(exc).__name__)
        return False, 'captain check failed'


###############################################################################
# Collection
###############################################################################

def next_backoff_until(state, now_s, retry_after=None):
    """Exponential: 120 s after a first 429, double the previous delay after
    each consecutive one (the previous delay is backoff_until - updated)."""
    prev_until = float(state.get('backoff_until') or 0)
    prev_updated = float(state.get('updated') or 0)
    prev_delay = prev_until - prev_updated if prev_until > prev_updated > 0 else 0
    delay = BACKOFF_BASE_SECONDS if prev_delay <= 0 else min(BACKOFF_CAP_SECONDS, prev_delay * 2)
    if retry_after:
        delay = max(delay, min(float(retry_after), BACKOFF_CAP_SECONDS))
    return now_s + delay


def _int_or_none(value):
    try:
        return int(value) if value not in (None, '') else None
    except (TypeError, ValueError):
        return None


def offset_ms(next_offset):
    """The millisecond timestamp a v2 next_offset ("<ms>,<txid or id>") starts
    with, or None when it does not start with one."""
    head = str(next_offset or '').split(',', 1)[0].strip()
    return int(head) if head.isdigit() else None


def _open_window(mintime, maxtime, offset):
    return None if mintime >= maxtime else (mintime, maxtime, offset)


def _log_window(name, cfg, state, now_ms):
    """(mintime, maxtime, next_offset) for this run, or None to skip it.

    An unfinished window (a saved next_offset) resumes after its cursor and is
    never abandoned while it still has readable records: mintime becomes the
    cursor's own timestamp, or the retention floor once the floor has passed
    the cursor (the records before the floor are gone from Duo; every record
    after it is still read). Only a cursor that cannot be read starts a new
    window."""
    floor_ms = now_ms - RETENTION_MS
    maxtime = now_ms - cfg['lag_seconds'] * 1000
    offset = state.get('next_offset') or None
    if offset:
        cursor_ms, start_ms = offset_ms(offset), _int_or_none(state.get('mintime_ms'))
        if cursor_ms is None or start_ms is None or cursor_ms < start_ms:
            logger.warning('input %s: checkpointed next_offset is unreadable; starting a new window', name)
        elif cursor_ms < floor_ms:
            logger.warning('input %s: Duo retention passed this window before it was read; records before %d '
                           'are no longer available, resuming the window from there', name, floor_ms)
            return _open_window(floor_ms, maxtime, None)
        else:
            return _open_window(cursor_ms, maxtime, offset)
    last_max = _int_or_none(state.get('maxtime_ms'))
    if last_max is not None:
        mintime = last_max + 1
    else:
        mintime = now_ms - cfg['initial_lookback_hours'] * 3600 * 1000
    if mintime < floor_ms:
        logger.warning('input %s: window start is older than Duo retention; records before %d are not available',
                       name, floor_ms)
        mintime = floor_ms
    return _open_window(mintime, maxtime, None)


def collect_logs(name, cfg, state, client, access, emit, now_s, pages=LOG_PAGES_PER_RUN):
    path, _ = ENDPOINTS[cfg['endpoint']]
    window = _log_window(name, cfg, state, int(round(now_s * 1000)))
    if window is None:
        logger.info('input %s: window empty (mintime >= now - lag); skipping', name)
        return 0
    mintime, maxtime, offset = window
    written, complete = 0, False
    for _ in range(max(1, pages)):
        records, next_offset = client.log_page(path, mintime, maxtime, offset)
        for record in records:
            emit(record, record_time(cfg['endpoint'], record, now_s))
            written += 1
        if not records or not next_offset:
            # Duo's "done": the call after the last page has no records and no
            # next_offset. An empty page that still carries one is done as well.
            complete = True
            if next_offset:
                logger.info('input %s: Duo returned a next_offset with an empty page; window complete', name)
        elif next_offset == offset:
            complete = True
            logger.warning('input %s: Duo returned the next_offset it was sent; closing the window at %d so its '
                           'last page is not read again on every run', name, maxtime)
        access.save_checkpoint(name, {'mintime_ms': mintime, 'maxtime_ms': maxtime,
                                      'next_offset': None if complete else next_offset, 'backoff_until': 0,
                                      'updated': now_s})
        if complete:
            break
        offset = next_offset
    logger.info('input %s: wrote %d %s records (window %d-%d, %s)', name, written, cfg['endpoint'],
                mintime, maxtime, 'complete' if complete else 'resumes after its next_offset')
    return written


def _users_page(name, client, offset, sleep, jitter, budget):
    """client.users_page(offset), retrying a 429 / 42901 or a transient failure
    (DuoUnavailable: Duo unreachable or HTTP 5xx) up to USERS_RETRIES_PER_PAGE
    times: 1 s doubling to 32 s, plus up to 1 s of jitter, and at least the
    server's Retry-After. budget is a one-item list holding the seconds of
    waiting this snapshot has left; a wait that would exceed it re-raises
    instead, and so does any other DuoError."""
    delay = USERS_RETRY_FIRST_SECONDS
    for attempt in range(USERS_RETRIES_PER_PAGE + 1):
        try:
            return client.users_page(offset)
        except (duo_api.DuoRateLimited, duo_api.DuoUnavailable) as exc:
            wait = delay + jitter()
            if isinstance(exc, duo_api.DuoRateLimited) and exc.retry_after:
                wait = max(wait, float(exc.retry_after))
            if attempt == USERS_RETRIES_PER_PAGE or wait > budget[0]:
                raise
            budget[0] -= wait
            logger.info('input %s: users page at offset %d failed (%s, HTTP %s); retry %d in %.1f s',
                        name, offset, type(exc).__name__, exc.http_status, attempt + 1, wait)
            sleep(wait)
            delay = min(delay * 2, USERS_RETRY_MAX_SECONDS)


def collect_users(name, cfg, state, client, access, emit, now_s, sleep=time.sleep, jitter=random.random):
    snapshot_ms = int(round(now_s * 1000))
    users, seen, offset = [], set(), 0
    budget = [USERS_RETRY_BUDGET_SECONDS]
    for page_no in range(MAX_USER_PAGES):
        page, next_offset, _total = _users_page(name, client, offset, sleep, jitter, budget)
        for user in page:
            if not isinstance(user, dict):
                continue
            record = user_allowlist(user)
            ident = record.get('user_id') or record.get('username')
            if ident in seen:
                continue
            seen.add(ident)
            users.append(record)
        if next_offset is None or next_offset <= offset:
            break
        offset = next_offset
        sleep(USERS_PAGE_PAUSE_SECONDS)
    else:  # never a partial snapshot that would look complete
        logger.warning('input %s: more than %d user pages; no snapshot written', name, MAX_USER_PAGES)
        return 0
    if not users:
        logger.info('input %s: Duo returned no users; no snapshot written', name)
        return 0
    snapshot_id = 'duo-users-{}'.format(snapshot_ms)
    for seq, record in enumerate(users, 1):
        record['snapshot_id'] = snapshot_id
        record['snapshot_total'] = len(users)
        record['snapshot_seq'] = seq
        emit(record, snapshot_ms / 1000.0)
    access.save_checkpoint(name, {'mintime_ms': None, 'maxtime_ms': snapshot_ms, 'next_offset': None,
                                  'backoff_until': 0, 'updated': now_s})
    logger.info('input %s: wrote users snapshot %s (%d users)', name, snapshot_id, len(users))
    return len(users)


def make_client(account, secret, transport=None):
    if str(account.get('auth_type') or '').strip() != AUTH_TYPE:
        raise duo_api.DuoError('the account must have auth_type = {}'.format(AUTH_TYPE))
    return duo_api.DuoAdminClient(account.get('url'), account.get('client_id'), secret,
                                  transport=transport)


def run_input(name, params, access, write_event, now=time.time, sleep=time.sleep, transport=None,
              pages=LOG_PAGES_PER_RUN, jitter=random.random):
    """One run of one input stanza. write_event(data, time_s, sourcetype, index)."""
    cfg = parse_params(params)
    poll, reason = shc_poll_decision(access)
    if not poll:
        logger.info('input %s: not polling (%s)', name, reason)
        return 0
    state = access.load_checkpoint(name) or {}
    now_s = float(now())
    backoff_until = float(state.get('backoff_until') or 0)
    if backoff_until > now_s:
        logger.info('input %s: rate limited by Duo; backing off for %d s', name, int(backoff_until - now_s))
        return 0
    since = now_s - float(state.get('updated') or 0)
    if 0 <= since < MIN_INTERVAL_SECONDS - INTERVAL_JITTER_SECONDS:
        # validate_input enforces the floor on UI/REST edits; this also holds it
        # for an interval set below 120 s directly in local/inputs.conf.
        logger.info('input %s: last Duo call %d s ago, under the %d s floor; skipping',
                    name, int(since), MIN_INTERVAL_SECONDS)
        return 0
    sourcetype = ENDPOINTS[cfg['endpoint']][1]

    def emit(record, time_s):
        write_event(compact(record), time_s, sourcetype, cfg['index'])

    try:
        client = make_client(access.account(cfg['account']), access.secret(cfg['account']), transport)
        if cfg['endpoint'] == 'users':
            return collect_users(name, cfg, state, client, access, emit, now_s, sleep, jitter)
        return collect_logs(name, cfg, state, client, access, emit, now_s, pages)
    except duo_api.DuoRateLimited as exc:
        state = dict(state)
        state['backoff_until'] = next_backoff_until(state, now_s, exc.retry_after)
        state['updated'] = now_s
        access.save_checkpoint(name, state)
        logger.warning('input %s: Duo rate limit (HTTP %s); backing off %d s', name, exc.http_status,
                       int(state['backoff_until'] - now_s))
        return 0
    except duo_api.DuoError as exc:
        logger.error('input %s: %s', name, exc)
        return 0


###############################################################################
# Modular input
###############################################################################

class DuoInput(Script):
    """splunklib Script. Holds no state of its own (R-PY-001: never assigns
    self.service or defines _service / _input_definition)."""

    def get_scheme(self):
        scheme = Scheme('Cisco Duo (AI Governance)')
        scheme.description = ('Cisco Duo authentication logs, activity logs or a users snapshot '
                              'from the Duo Admin API, one endpoint per input.')
        scheme.use_external_validation = True
        scheme.use_single_instance = False
        scheme.add_argument(Argument('account', title='Account',
                                     description='ta_gen_ai_cim_account stanza with auth_type = duo_hmac',
                                     required_on_create=True, required_on_edit=False))
        scheme.add_argument(Argument('endpoint', title='Endpoint',
                                     description='authentication, activity or users',
                                     required_on_create=True, required_on_edit=False))
        scheme.add_argument(Argument('lag_seconds', title='Lag (seconds)',
                                     description='window end = now minus this; at least 120 (default 180)',
                                     data_type=Argument.data_type_number))
        scheme.add_argument(Argument('initial_lookback_hours', title='Initial lookback (hours)',
                                     description='first window start = now minus this (default 24, max 4320)',
                                     data_type=Argument.data_type_number))
        return scheme

    def validate_input(self, definition):
        parse_params(definition.parameters, check_interval=True)

    def stream_events(self, inputs, ew):
        access = SplunkAccess.from_metadata(inputs.metadata)
        for name, params in inputs.inputs.items():
            def write_event(data, time_s, sourcetype, index, _name=name):
                ew.write_event(Event(data=data, stanza=_name, time='%.3f' % time_s,
                                     sourcetype=sourcetype, index=index))
            try:
                run_input(name, params, access, write_event)
            except ValueError as exc:  # parse_params: names the setting, never a secret
                logger.error('input %s: %s', name, exc)
            except Exception as exc:  # one bad stanza never stops the others
                logger.error('input %s failed: %s%s', name, type(exc).__name__,
                             ' (HTTP {})'.format(exc.status) if hasattr(exc, 'status') else '')


def _configure_logging():
    level = logging.INFO
    log_dir = os.path.join(os.environ.get('SPLUNK_HOME', '/opt/splunk'), 'var', 'log', 'splunk')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    handlers = [logging.StreamHandler(sys.stderr)]
    handlers[0].setLevel(logging.WARNING)
    try:
        handlers.append(logging.FileHandler(os.path.join(log_dir, 'ta_gen_ai_cim_duo_input.log'),
                                            delay=True))
    except (IOError, OSError):
        pass
    for name in ('ta_gen_ai_cim_duo_input', 'ta_gen_ai_cim_duo_api'):
        target = logging.getLogger(name)
        target.setLevel(level)
        for handler in handlers:
            handler.setFormatter(formatter)
            target.addHandler(handler)


def main(argv=None):
    """Entry point. Splunk runs a modular input scheme from bin/<scheme>.py, so
    bin/ta_gen_ai_cim_duo.py is the thin shim that calls this."""
    _configure_logging()
    return DuoInput().run(list(sys.argv if argv is None else argv))


if __name__ == '__main__':
    sys.exit(main())
