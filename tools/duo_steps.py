# encoding=utf-8
"""
duo_steps.py - the Cisco Duo identity feed steps behind
`tools/show_postdeploy.py --duo` and `--duo-teardown`. One run per stack that
polls Duo. Dev-only (tools/ never ships in the TA package).

--duo, in order:
  D0  TA-gen_ai_cim 1.9.0+, the ta_gen_ai_cim_duo scheme    stops the run before any
      and its input endpoint                                write if one is missing
  D1  index duo (ACS), then WAIT until it exists            a first poll into a missing
                                                            index loses the backfill
  D2  the Duo account (account REST handler)                secret key from a named
                                                            environment variable or a
                                                            hidden prompt, never argv
  D3  the attendee role may search index duo                srchIndexesAllowed only
  D4  note: ES's Authentication data model and index duo    read-only, never blocks: the
                                                            TA's rules read the events
                                                            themselves
  D5  enable the Duo rule and the joined rule, and check    BEFORE the inputs: a rule
      that each judges by index time on a slot one cron     judges an event once, in
      period wide (--duo-with-lookup-gen: also the          the run after it is indexed
      identity lookup search)
  D6  input duo_authentication (--duo-with-users: first     the first poll backfills
      duo_users)                                            --duo-lookback-hours
  D7  verify, read-only                                     inputs, events by sourcetype
  D8  verify, read-only: every burst and chain the rules    "N of N raised", or what
      should have raised from what is indexed has its       was indexed while a rule
      risk event                                            was off

What a stack holds is the operator's choice, made on the command line and
printed by every run: the authentication input reads the WHOLE Duo tenant (the
input has no user filter); the users snapshot and the identity lookup search
are opt-in, because on a stack that polls only a lab tenant they add the tenant
owner's own record to what the attendee role can read.

--duo-teardown reverses all of it: searches off, inputs deleted, the account and
its secret deleted, the role grant removed (for the roles the command line
names; any other role that still lists the index is reported), the generated
identity CSV deleted, and with --duo-purge-data the index and the inputs'
checkpoints (always together: an index without its checkpoints is indexed twice
on the next setup, checkpoints without their index skip the backfill).

Every guard refuses on an answer it cannot read. A delete goes ahead only on a
positive answer that it is safe (the index is confirmed gone, ACS counts no
event, the identity source is confirmed absent), never because a check came
back with an error; and an index delete that ACS has accepted but not yet
carried out leaves a marker beside the checkpoints, so a setup run in between
creates no input into an index that is about to vanish.

Every step reads the stack first and writes only what differs, so a second run
writes nothing. --dry-run makes every read (searches included) and prints the
writes instead of sending them.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import fnmatch
import getpass
import json
import math
import os
import re
import sys
import time
import urllib.parse
import warnings

import genai_es_seed as seed
import lab5_steps as lab5
import ta_gen_ai_cim_duo_api as duo_api
import ta_gen_ai_cim_duo_input as duo_input

APP = seed.APP_NAME
NS = '/servicesNS/nobody/{}'.format(APP)
MIN_TA_VERSION = (1, 9, 0)
SCHEME = duo_input.SCHEME
DUO_INDEX = 'duo'                      # what genai_duo_index assumes
DUO_ACCOUNT = 'duo'
USERS_INPUT = 'duo_users'
AUTH_INPUT = 'duo_authentication'
INPUTS = ((USERS_INPUT, 'users'), (AUTH_INPUT, 'authentication'))   # creation order
AUTH_SOURCETYPE = duo_input.ENDPOINTS['authentication'][1]
SOURCETYPE_PREFIX = 'ta_gen_ai_cim:duo:'
LOOKUP_GEN = 'GenAI - Identity - Duo Identity Lookup Gen'
DUO_DETECTION = 'AI Governance - Duo Authentication Fraud or Denial Burst - Rule'
DUO_CHAIN_DETECTION = 'AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule'
DUO_DETECTIONS = (DUO_DETECTION, DUO_CHAIN_DETECTION)      # must be on the stack
# Detections that read the Duo feed but may not be in the installed TA yet. A
# 404 is a SKIP, not a failure. test_duo_stack.py fails when default/
# savedsearches.conf holds a rule reading the Duo feed that is in neither tuple.
DUO_OPTIONAL_DETECTIONS = ()
# The field that names one finding of each rule (its suppression key). D8
# compares the ids a rule should have raised with the ids on its risk events.
JUDGED_IDS = {DUO_DETECTION: 'burst_id', DUO_CHAIN_DETECTION: 'chain_id'}
JUDGED_NOUNS = {DUO_DETECTION: 'burst', DUO_CHAIN_DETECTION: 'chain'}
RISK_INDEX = 'risk'
NO_ID = '-'                            # a risk event of the rule with no id (an older build raised it)
# A slot is judged by the run of the cron tick after it ends: 2 minutes behind
# the tick, up to 5 of allow_skew, and time for the run itself. D8 looks only at
# what was indexed at least one cron period plus this many minutes ago.
JUDGED_GRACE_MINUTES = 10
# D8 dispatches a rule's own search ad hoc (no alert action runs), as the stack
# has it, with the admin's rights. It never dispatches a text that holds a
# command that writes or acts: Splunk's own (collect and its aliases stash,
# summaryindex and sumindex; dump writes files on the indexers), the commands
# that run something else (map, script, run, runshellscript, sendalert), and
# this TA's custom commands (default/commands.conf: aicase writes KV rows and
# opens ServiceNow cases, genaiseedes writes Mission Control, genaiscore posts
# event content to a model). A deny-list on purpose: neither shipped rule holds
# any of these, and an allow-list would make D8 skip a rule for a harmless
# command it does not know. test_duo_stack.py fails when commands.conf gains a
# command that is missing here.
WRITING_COMMANDS = ('outputlookup', 'outputcsv', 'collect', 'stash', 'summaryindex', 'sumindex',
                    'tscollect', 'mcollect', 'meventcollect', 'dump', 'delete', 'sendalert', 'sendemail', 'map',
                    'script', 'run', 'runshellscript', 'aicase', 'genaiscore', 'genaiseedes')
WRITES = re.compile(r'\|\s*(' + '|'.join(WRITING_COMMANDS) + r')\b', re.I)
LOOKUP_FILE = 'ta_gen_ai_cim_duo_identities.csv'
IDENTITY_SOURCE = 'identity_manager://ta_gen_ai_cim_duo_identities'
CIM_APP = 'Splunk_SA_CIM'
CIM_INDEX_MACRO = 'cim_Authentication_indexes'
ATTENDEE_ROLE = lab5.PARTICIPANT_ROLE
# What the two opt-in pieces put on a stack; printed where a run leaves them out.
USERS_SCOPE = ('the user list of the whole Duo tenant (names, email addresses, status; the tenant owner\'s own '
               'record included), readable by every role that may search index {}'.format(DUO_INDEX))
LOOKUP_SCOPE = ('on a stack that polls only a lab tenant it writes one row, the tenant owner\'s own Duo user '
                'with an email address, into a lookup every role can read')

# The read-only Admin API application ("Grant read log" + "Grant resource -
# Read"). Not the Lab 5 "Identity Ops" keys (DUO_IDENTITY_OPS_*): those can
# write. Environment or prompt only, so nothing that names the tenant or opens
# it reaches argv or the shell history.
ENV_HOST = 'DUO_LOG_FEED_API_HOST'
ENV_IKEY = 'DUO_LOG_FEED_IKEY'
ENV_SKEY = 'DUO_LOG_FEED_SKEY'
ENV_NAME_RE = re.compile(r'^[A-Z_][A-Z0-9_]*$')
# Same rules as bin/ta_gen_ai_cim_account_handler.py (a test pins them).
IKEY_RE = re.compile(r'^[A-Za-z0-9]{16,64}$')
SKEY_RE = re.compile(r'^[\x21-\x7e]{20,128}$')
SECRET_MASK = '********'
HIDDEN = '[hidden]'

DEFAULT_LOOKBACK_HOURS = 720           # 30 days: the lab's scenarios are staged days ahead
DEFAULT_USERS_INTERVAL = 86400
MIN_USERS_INTERVAL = 3600
RETENTION_MARGIN_DAYS = 14
MIN_SEARCHABLE_DAYS = 90
INDEX_WAIT_SECONDS = 600
INDEX_POLL_SECONDS = 10
POLL_SLOT_PERIODS = (2, 3, 4, 5, 6, 10, 12, 15, 20, 30)   # minutes; divisors of 60
PROTECTED_INDEXES = ('main', 'summary', 'history', 'notable', 'risk', 'gen_ai_log',
                     lab5.CII_INDEX)

READY, MISSING, SHORT = 'ready', 'missing', 'short retention'
ACS_INDEX_NOT_FOUND = '404-index-not-found'     # ACS's own error code (Troubleshoot ACS error messages)
# A document beside the checkpoints, written before ACS is asked to delete index
# duo and removed only once ACS confirms the index is gone. While it is there
# --duo creates no input: the index is still listed, but about to vanish.
PURGE_MARKER = 'index_delete_pending'


###############################################################################
# Small helpers
###############################################################################

def q(name):
    return urllib.parse.quote(name, safe='')


def content(data):
    try:
        return data['entry'][0]['content'] or {}
    except (TypeError, KeyError, IndexError):
        return {}


def is_disabled(value):
    return str(value).strip().lower() in ('1', 'true')


def mask_host(host):
    m = re.match(r'^api-([a-z0-9]+)\.(.+)$', host or '')
    return 'api-...{}.{}'.format(m.group(1)[-2:], m.group(2)) if m else '(hidden)'


def mask_ikey(ikey):
    return '...' + ikey[-4:] if ikey and len(ikey) >= 16 else '(hidden)'


def scrub(text, *values):
    """text without the given values, each in the three forms a reply could
    carry it (as sent, percent-encoded, form-encoded). Scrub first, cut after:
    a cut through the middle of a key would leave a piece no pattern matches."""
    text = str(text)
    forms = set()
    for value in values:
        if value and len(value) >= 4:
            forms.update((value, urllib.parse.quote(value, safe=''), urllib.parse.quote_plus(value)))
    for form in sorted(forms, key=len, reverse=True):
        text = text.replace(form, HIDDEN)
    return text


def reply_message(text):
    """splunkd's own error text from a JSON reply, '' when there is none."""
    try:
        messages = json.loads(text).get('messages') or []
        return ' '.join(str(item.get('text', '')) for item in messages if isinstance(item, dict))
    except (ValueError, AttributeError, TypeError):
        return ''


def certificate_refused(code, text):
    """True when a request got no reply because the server's certificate did
    not verify (genai_es_seed.http_request answers (0, the error's text))."""
    return code == 0 and 'certificate verify failed' in str(text).lower().replace('_', ' ')


def saved_path(name):
    return '{}/saved/searches/{}'.format(NS, q(name))


def input_path(name=None):
    base = '{}/data/inputs/{}'.format(NS, SCHEME)
    return '{}/{}'.format(base, q(name)) if name else base


def account_path(name=None):
    base = '{}/ta_gen_ai_cim_account/ta_gen_ai_cim_account'.format(NS)
    return '{}/{}'.format(base, q(name)) if name else base


def checkpoint_key(input_name):
    return '{}://{}'.format(SCHEME, input_name)        # the input stanza name


def checkpoint_path(input_name):
    return '{}/storage/collections/data/{}/{}'.format(NS, duo_input.COLLECTION, q(checkpoint_key(input_name)))


def marker_path(key=PURGE_MARKER):
    base = '{}/storage/collections/data/{}'.format(NS, duo_input.COLLECTION)
    return '{}/{}'.format(base, q(key)) if key else base


def secret_path(account):
    credential = '{}{}:{}:'.format(duo_input.REALM_PREFIX, account, duo_input.SECRET_NAME)
    return '{}/storage/passwords/{}'.format(NS, q(credential))


def role_path(role):
    return '/services/authorization/roles/{}'.format(q(role))


###############################################################################
# Run settings (argv carries these; none is a secret)
###############################################################################

def cron_minutes(field):
    """The minutes of the hour a cron minute field fires on, sorted. Raises
    ValueError (a fixed sentence) for a field this does not read."""
    minutes = set()
    for part in str(field).split(','):
        m = re.match(r'^(\*|\d{1,2}(?:-\d{1,2})?)(?:/(\d{1,2}))?$', part)
        if not m:
            raise ValueError('the minute field of the cron schedule is not one this tool reads')
        span, step = m.group(1), int(m.group(2) or 1)
        if span == '*':
            first, last = 0, 59
        elif '-' in span:
            first, last = (int(x) for x in span.split('-'))
        else:
            first = int(span)
            last = 59 if m.group(2) else first
        if step < 1 or not 0 <= first <= last <= 59:
            raise ValueError('the minute field of the cron schedule is out of range')
        minutes.update(range(first, last + 1, step))
    return sorted(minutes)


def parse_interval(value):
    """'<seconds>' (at least the input's own floor) or a five-field cron
    schedule, as inputs.conf accepts for interval. A cron schedule that fires
    every hour of every day is held to the same floor: the input skips a run
    that starts under two minutes after the last, so a tighter schedule would
    only poll unevenly."""
    text = ' '.join(str(value or '').split())
    if re.match(r'^\d+$', text):
        if int(text) < duo_input.MIN_INTERVAL_SECONDS:
            raise ValueError('the interval must be at least {} seconds'.format(duo_input.MIN_INTERVAL_SECONDS))
        return str(int(text))
    if re.match(r'^[0-9*/,\-]+( [0-9*/,\-]+){4}$', text):
        fields = text.split(' ')
        if fields[1:] == ['*'] * 4:
            minutes = cron_minutes(fields[0])
            gaps = [b - a for a, b in zip(minutes, minutes[1:])] + [60 - minutes[-1] + minutes[0]]
            if min(gaps) * 60 < duo_input.MIN_INTERVAL_SECONDS:
                raise ValueError('the cron schedule polls more often than every {} seconds'.format(
                    duo_input.MIN_INTERVAL_SECONDS))
        return text
    raise ValueError('the interval is seconds (120 or more) or a five-field cron schedule')


def poll_slot(value):
    """'K/N' -> the cron schedule of stack K of the N that poll one Duo tenant:
    every N minutes, K minutes past, so no two stacks share a minute. The
    minutes are written out as a list ('3,23,43 * * * *'), the plainest cron
    form there is, rather than as a stepped range."""
    m = re.match(r'^(\d+)/(\d+)$', str(value or '').strip())
    if not m:
        raise ValueError('--duo-poll-slot is K/N, for example 0/5')
    slot, period = int(m.group(1)), int(m.group(2))
    if period not in POLL_SLOT_PERIODS:
        raise ValueError('N must be one of {} (minutes; it has to divide 60)'.format(
            ', '.join(str(p) for p in POLL_SLOT_PERIODS)))
    if slot >= period:
        raise ValueError('K must be between 0 and N-1')
    return '{} * * * *'.format(','.join(str(minute) for minute in range(slot, 60, period)))


def lookback_days(hours):
    return int(math.ceil(hours / 24.0))


class Settings(object):
    """What one --duo run was asked for. Raises ValueError (never echoing a
    value that could be a mistyped secret)."""

    def __init__(self, auth_interval, users_interval=DEFAULT_USERS_INTERVAL,
                 lookback_hours=DEFAULT_LOOKBACK_HOURS, attendee_roles=(ATTENDEE_ROLE,),
                 users_input=False, lookup_gen=False, rotate_key=False, reset_checkpoint=False,
                 force=False):
        self.auth_interval = parse_interval(auth_interval)
        users = str(users_interval).strip()
        if not re.match(r'^\d+$', users) or int(users) < MIN_USERS_INTERVAL:
            raise ValueError('--duo-users-interval is seconds, {} or more'.format(MIN_USERS_INTERVAL))
        self.users_interval = str(int(users))
        try:
            self.lookback_hours = int(lookback_hours)
        except (TypeError, ValueError):
            raise ValueError('--duo-lookback-hours must be an integer')
        if not 1 <= self.lookback_hours <= duo_input.MAX_LOOKBACK_HOURS:
            raise ValueError('--duo-lookback-hours must be between 1 and {}'.format(duo_input.MAX_LOOKBACK_HOURS))
        self.attendee_roles = tuple(r for r in (str(x).strip() for x in attendee_roles) if r)
        for role in self.attendee_roles:
            if not re.match(r'^[A-Za-z0-9_\-]+$', role):
                raise ValueError('--duo-attendee-role must be a role name')
        # Opt-in, both: on a stack that polls only a lab tenant they put the
        # tenant owner's own record where the attendee role can read it.
        self.users_input = bool(users_input)
        self.lookup_gen = bool(lookup_gen)
        if self.lookup_gen and not self.users_input:
            raise ValueError('--duo-with-lookup-gen needs --duo-with-users: the search reads the users snapshot')
        self.rotate_key = bool(rotate_key)
        self.reset_checkpoint = bool(reset_checkpoint)
        self.force = bool(force)

    @property
    def need_days(self):
        return lookback_days(self.lookback_hours) + RETENTION_MARGIN_DAYS

    @property
    def create_days(self):
        return max(MIN_SEARCHABLE_DAYS, self.need_days)

    def input_fields(self, endpoint):
        """Exactly what is POSTed for one input, checked by the input's own
        validator so the stack cannot refuse what this tool accepted."""
        fields = {'account': DUO_ACCOUNT, 'endpoint': endpoint, 'index': DUO_INDEX,
                  'interval': self.users_interval if endpoint == 'users' else self.auth_interval}
        if endpoint != 'users':
            fields['initial_lookback_hours'] = str(self.lookback_hours)
        duo_input.parse_params(fields, check_interval=True)
        return fields


###############################################################################
# Duo credentials: environment or prompt, never argv, never a file
###############################################################################

def _hidden_prompt(text):
    """getpass on the terminal. Its echoing fallback (no usable terminal) is
    turned into an error, so the key can never be read with echo on."""
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        try:
            return getpass.getpass(text, stream=sys.stderr)
        except (getpass.GetPassWarning, EOFError):
            return ''


def _visible_prompt(text):
    sys.stderr.write(text)
    sys.stderr.flush()
    return sys.stdin.readline()


class Credentials(object):
    """The Duo Admin API application for the feed. host and ikey are read when
    asked for; the secret key only inside secret(), which a step calls at the
    moment it has to send it - a run that changes no account never reads it."""

    def __init__(self, skey_env=ENV_SKEY, env=None, interactive=None, hidden_prompt=None,
                 visible_prompt=None):
        if not ENV_NAME_RE.match(skey_env or ''):
            # Not echoed: a secret pasted where the variable NAME belongs must not come back.
            raise ValueError('--duo-skey-env takes the NAME of an environment variable '
                             '(capitals, digits and underscores), not a value')
        self.skey_env = skey_env
        self.env = os.environ if env is None else env
        if interactive is None:
            interactive = sys.stdin.isatty() and sys.stderr.isatty()
        self.interactive = bool(interactive)
        self._hidden = hidden_prompt or _hidden_prompt
        self._visible = visible_prompt or _visible_prompt
        self._identity = None

    def identity(self, prompt=True):
        """(host, ikey, problem). host is the bare API hostname."""
        if self._identity:
            return self._identity + (None,)
        host, ikey = (self.env.get(ENV_HOST) or '').strip(), (self.env.get(ENV_IKEY) or '').strip()
        missing = [name for name, value in ((ENV_HOST, host), (ENV_IKEY, ikey)) if not value]
        if missing and not (prompt and self.interactive):
            return None, None, 'set {} (or run in a terminal to be prompted)'.format(' and '.join(missing))
        if not host:
            host = (self._visible('Duo API hostname (api-XXXXXXXX.duosecurity.com): ') or '').strip()
        if not ikey:
            ikey = (self._visible('Duo integration key: ') or '').strip()
        try:
            host = duo_api.parse_api_host(host)
        except duo_api.DuoError:
            return None, None, ('the API hostname must be api-XXXXXXXX.duosecurity.com or .duofederal.com '
                                '(https only, no path or port)')
        if not IKEY_RE.match(ikey):
            return None, None, 'the integration key must be 16-64 letters and digits'
        self._identity = (host, ikey)
        return host, ikey, None

    def secret_source(self):
        """Where the key would come from, for a plan line. Never the value."""
        if (self.env.get(self.skey_env) or '').strip():
            return 'from ${}'.format(self.skey_env)
        return 'from a hidden prompt' if self.interactive else None

    def secret(self):
        """(secret key, problem). problem is a fixed sentence."""
        value = (self.env.get(self.skey_env) or '').strip()
        if not value:
            if not self.interactive:
                return None, 'set ${} or run in a terminal to be prompted'.format(self.skey_env)
            value = (self._hidden('Duo secret key (input hidden): ') or '').strip()
        if value == SECRET_MASK or not SKEY_RE.match(value):
            return None, 'the secret key must be 20-128 characters with no spaces'
        return value, None


###############################################################################
# Reads that also run in a dry run
###############################################################################

def oneshot(splunkd, spl, earliest='0', latest='now', app=False, timeout=120):
    """(rows, problem) of a one-shot search, over all time unless told
    otherwise; app=True runs it in the TA's namespace, where the TA's macros
    resolve. A search is a read, so it also runs in a dry run: it goes straight
    to http_request, because Splunkd.call turns every non-GET into a printed
    no-op. No alert action runs for a search dispatched this way."""
    url = '{}{}/search/jobs?output_mode=json'.format(splunkd.mgmt, NS if app else '/services')
    body = {'search': spl, 'exec_mode': 'oneshot', 'earliest_time': earliest, 'latest_time': latest, 'count': '0'}
    code, text = seed.http_request(splunkd.ctx, url, 'POST', data=body, headers=splunkd._headers(),
                                   timeout=timeout)
    if code != 200:
        return None, 'search failed (HTTP {})'.format(code)
    try:
        return json.loads(text).get('results') or [], None
    except (ValueError, AttributeError):
        return None, 'search reply was not JSON'


def index_counts(splunkd):
    """({sourcetype: events} in index duo, problem). No rows when the index is
    empty or does not exist."""
    rows, problem = oneshot(splunkd, '| tstats count where index={} by sourcetype'.format(DUO_INDEX))
    if rows is None:
        return None, problem
    counts = {}
    for row in rows:
        try:
            counts[row.get('sourcetype')] = int(row.get('count') or 0)
        except (TypeError, ValueError):
            pass
    return counts, None


def datamodel_count(splunkd):
    rows, problem = oneshot(
        splunkd, '| tstats summariesonly=false allow_old_summaries=true count from '
                 'datamodel=Authentication.Authentication where index={} sourcetype="{}"'.format(
                     DUO_INDEX, AUTH_SOURCETYPE))
    if rows is None:
        return None, problem
    try:
        return int((rows[0] if rows else {}).get('count') or 0), None
    except (TypeError, ValueError):
        return None, 'unreadable count'


def foreign_sourcetypes(counts):
    return dict((st, n) for st, n in (counts or {}).items() if not str(st).startswith(SOURCETYPE_PREFIX))


###############################################################################
# D0 - D4
###############################################################################

def step_preflight(splunkd, rep, prefix='D0'):
    """Three reads, before anything is written: the TA, its input scheme, and
    the endpoint the inputs are created through. Only a 404 is read as "not
    there"; any other answer is reported as what it is, a read the stack
    refused or failed, so a 403 never sends the operator off to reinstall the
    TA or restart the stack. The third read is the one piece a stack may not
    serve at all (Splunk's page on the Splunk Cloud Platform REST API does not
    list Inputs among the supported resource groups): without it a run would
    find out at D6, after it had created the index, stored the Duo secret key,
    granted the role and enabled both rules."""
    label = '{}. TA-gen_ai_cim 1.9.0+ with the {} input'.format(prefix, SCHEME)
    refused = 'the stack refused or failed the read of {} (HTTP {}); nothing was written. Check the account\'s ' \
              'role and the stack, then run this again'
    path = '/services/apps/local/{}'.format(APP)
    code, data = splunkd.get_json(path)
    if code not in (200, 404):
        rep.fail(label, refused.format(path, code))
        return False
    version = content(data).get('version') if code == 200 else None
    got = lab5.version_tuple(version)
    if not got or got < MIN_TA_VERSION:
        rep.fail(label, 'TA-gen_ai_cim {} - install 1.9.0 or later, then run this again'.format(
            version or 'is not installed'))
        return False
    path = '/services/data/modular-inputs/{}'.format(SCHEME)
    code, _ = splunkd.get_json(path)
    if code == 404:
        rep.fail(label, 'TA {} is installed but its input scheme is not registered; splunkd registers a new '
                        'scheme only when it starts - restart the stack, then run this again'.format(version))
        return False
    if code != 200:
        rep.fail(label, refused.format(path, code))
        return False
    code, _ = splunkd.get_json(input_path() + '?count=0')
    if code != 200:
        rep.fail(label, 'TA {} and its scheme are there, but the stack does not serve the endpoint its inputs are '
                        'created through ({}, HTTP {}); nothing was written. Create the inputs in Splunk Web '
                        '(README, "Turning it on", step 4) or ask for REST access to data/inputs'.format(
                            version, input_path(), code))
        return False
    rep.ok(label, 'TA {}'.format(version))
    return True


def acs_index(acs):
    """(state, searchableDays, detail) of index duo in ACS, by name. Never the
    list endpoint: it returns 30 indexes by default, an ES stack has more."""
    code, text = acs.call('/indexes/{}'.format(DUO_INDEX), 'GET')
    if code is None:
        return None, None, text
    if code == 200:
        try:
            return READY, int(json.loads(text).get('searchableDays')), ''
        except (ValueError, TypeError, AttributeError):
            return READY, None, ''
    if code == 404:
        # ACS answers 404 for a stack it does not know as well (a hostname that is
        # not the stack's name): only its own index-not-found code means the index
        # is not there. (It answers that code while an index is being created too.)
        reason = acs_error_code(text)
        if reason == ACS_INDEX_NOT_FOUND:
            return MISSING, None, ''
        return 'error', None, 'HTTP 404 {}: ACS did not say that index {} is missing (a stack name it does not ' \
                              'know answers 404 too)'.format(reason or '(no error code)', DUO_INDEX)
    return 'error', None, 'HTTP {} {}'.format(code, str(text)[:160])


def acs_error_code(text):
    try:
        return str(json.loads(text).get('code') or '')
    except (ValueError, TypeError, AttributeError):
        return ''


def acs_event_count(acs):
    """ACS's own count of the events in index duo; None when it does not say."""
    code, text = acs.call('/indexes/{}'.format(DUO_INDEX), 'GET')
    if code != 200:
        return None
    try:
        return int(json.loads(text).get('totalEventCount'))
    except (ValueError, TypeError, AttributeError):
        return None


def step_index(acs, splunkd, rep, skip_acs, settings, sleep=time.sleep, clock=time.time,
               wait=INDEX_WAIT_SECONDS, prefix='D1'):
    """READY only when the index is confirmed to exist with enough retention.
    The inputs are created on READY alone: a first poll into a missing index
    loses the backfill for good (the checkpoint moves on, the events do not
    arrive), and an index that keeps fewer days than the backfill reads lets
    the staged events age out before the lab."""
    label = '{}. index {}'.format(prefix, DUO_INDEX)
    need, create = settings.need_days, settings.create_days
    state = None
    if not skip_acs:
        state, days, detail = acs_index(acs)
    if state is None:      # ACS skipped, or no token
        code, _ = splunkd.get_json('/services/data/indexes/{}'.format(DUO_INDEX))
        if code == 200:
            rep.ok(label, 'exists (ACS skipped; make sure it keeps {} days or more)'.format(need))
            return READY
        rep.fail(label, 'not on the stack and ACS is skipped - create it by hand, searchable for {} days '
                        'or more, then run this again'.format(create))
        return MISSING
    if state == 'error':
        rep.fail(label, detail)
        return MISSING
    if state == MISSING:
        code, text = acs.call('/indexes', 'POST', {'name': DUO_INDEX, 'datatype': 'event',
                                                   'searchableDays': create})
        if code not in (200, 201, 202):
            rep.fail(label, 'HTTP {} {}'.format(code, str(text)[:160]))
            return MISSING
        if acs.dry_run:
            rep.ok(label, 'dry-run - would create it, searchable {} days, and wait for it'.format(create))
            return READY
        deadline = clock() + wait
        while True:
            state, days, detail = acs_index(acs)
            if state == READY:
                rep.ok(label, 'created, searchable {} days'.format(create))
                return READY
            if clock() >= deadline:
                rep.fail(label, 'creation accepted but the index is not there after {} s - run this again; '
                                'no input was created'.format(wait))
                return MISSING
            sleep(INDEX_POLL_SECONDS)
    if days is not None and days < need:
        rep.fail(label, 'exists but keeps {} days: the {} h backfill needs {} or more, or the staged '
                        'events age out (ACS: PATCH /indexes/{} searchableDays)'.format(
                            days, settings.lookback_hours, need, DUO_INDEX))
        return SHORT
    rep.ok(label, 'already exists{}'.format(', searchable {} days'.format(days) if days else ''))
    return READY


def _post_account(splunkd, path, fields, secret):
    """POST the account fields plus the secret key; (status, message). The key
    is never echoed: a dry run prints the URL and the other fields masked, and
    of a reply only splunkd's message is kept, with the key, the hostname and
    the integration key scrubbed out of it."""
    url = '{}{}?output_mode=json'.format(splunkd.mgmt, path)
    host = urllib.parse.urlsplit(fields.get('url', '')).hostname
    if splunkd.dry_run:
        if splunkd.echo:
            shown = dict(fields, url=mask_host(host), client_id=mask_ikey(fields.get('client_id')))
            splunkd.echo('       DRY-RUN POST {}\n       DRY-RUN body: {} + client_secret=<hidden>'.format(
                url, json.dumps(shown, sort_keys=True)))
        return 200, ''
    body = dict(fields)
    if secret is not None:
        body['client_secret'] = secret
    try:
        code, text = seed.http_request(splunkd.ctx, url, 'POST', data=body, headers=splunkd._headers(),
                                       timeout=60)
    except Exception as exc:      # never str(exc): it could hold the request
        return 0, type(exc).__name__
    return code, scrub(reply_message(text), secret, host, fields.get('url'), fields.get('client_id'))[:160]


def step_account(splunkd, rep, creds, settings, prefix='D2'):
    """True when account `duo` exists as a Cisco Duo account afterwards (or
    would, in a dry run). The secret key is read only when it must be sent: a
    new account, a changed integration key, or --duo-rotate-key."""
    label = '{}. Duo account {}'.format(prefix, DUO_ACCOUNT)
    code, data = splunkd.get_json(account_path(DUO_ACCOUNT))
    if code not in (200, 404):
        rep.fail(label, 'could not read the account (HTTP {})'.format(code))
        return False
    live = content(data) if code == 200 else None
    if live is not None and (live.get('auth_type') or 'basic') != duo_input.AUTH_TYPE:
        rep.fail(label, 'an account with this name exists and is not a Cisco Duo account '
                        '(auth_type {}); it was left alone'.format(live.get('auth_type') or 'basic'))
        return False
    host, ikey, problem = creds.identity(prompt=live is None or settings.rotate_key)
    if live is not None and not settings.rotate_key:
        if host is None:
            rep.ok(label, 'exists (integration key {}); not compared: {}'.format(
                mask_ikey(live.get('client_id')), problem))
            return True
        if live.get('url') == 'https://' + host and live.get('client_id') == ikey:
            rep.ok(label, 'exists, unchanged ({}, integration key {})'.format(mask_host(host), mask_ikey(ikey)))
            return True
        rep.fail(label, 'exists with another API hostname or integration key ({}); pass --duo-rotate-key '
                        'to replace it together with its secret key'.format(mask_ikey(live.get('client_id'))))
        return False
    if host is None:
        rep.fail(label, problem)
        return False
    # The same arguments the Configuration page's Cisco Duo tab posts.
    fields = {'url': 'https://' + host, 'auth_type': duo_input.AUTH_TYPE, 'client_id': ikey}
    if live is None:
        fields['name'] = DUO_ACCOUNT
    path = account_path() if live is None else account_path(DUO_ACCOUNT)
    verb = 'create' if live is None else 'replace'
    if splunkd.dry_run:
        source = creds.secret_source()
        if source is None:
            rep.fail(label, 'dry-run - would {} it, but no secret key is available: set ${} or run in a '
                            'terminal'.format(verb, creds.skey_env))
            return False
        _post_account(splunkd, path, fields, None)
        rep.ok(label, 'dry-run - would {} it ({}, integration key {}, secret key {})'.format(
            verb, mask_host(host), mask_ikey(ikey), source))
        return True
    secret, problem = creds.secret()
    if secret is None:
        rep.fail(label, problem)
        return False
    code, message = _post_account(splunkd, path, fields, secret)
    secret = None
    if code in (200, 201):
        rep.ok(label, '{} ({}, integration key {}); the secret key is in storage/passwords only'.format(
            'created' if live is None else 'replaced', mask_host(host), mask_ikey(ikey)))
        return True
    if code == 0:
        rep.fail(label, 'no reply from the stack (connection or TLS error); run this again - it reads whether '
                        'the account is there before it sends anything')
    else:
        rep.fail(label, 'HTTP {} {}'.format(code, message).rstrip())
    return False


def step_role(splunkd, rep, role, on=True, prefix='D3'):
    """Search access to index duo for the attendee role: srchIndexesAllowed
    only. Not a default index, so an index-less search never reads Duo data.
    Off removes the literal entry this step adds and nothing else."""
    label = '{}. role {} {} index {}'.format(prefix, role, 'may search' if on else 'loses', DUO_INDEX)
    code, data = splunkd.get_json(role_path(role))
    if code == 404:
        rep.skip(label, 'role not present on this stack')
        return
    if code != 200 or not content(data):
        rep.fail(label, 'HTTP {} - could not read the role'.format(code))
        return
    allowed = lab5._as_list(content(data).get('srchIndexesAllowed'))
    reach = allowed + lab5._as_list(content(data).get('imported_srchIndexesAllowed'))
    if on:
        if any(fnmatch.fnmatchcase(DUO_INDEX, pattern) for pattern in reach):
            rep.ok(label, 'already allowed')
            return
        wanted = allowed + [DUO_INDEX]
    else:
        if DUO_INDEX not in allowed:
            rep.ok(label, 'no entry of its own to remove')
            return
        wanted = [name for name in allowed if name != DUO_INDEX]
    # An empty list would be dropped from the form body and change nothing.
    code, text = splunkd.call(role_path(role), 'POST', {'srchIndexesAllowed': wanted or ''})
    if code in (200, 201):
        rep.ok(label, '{}srchIndexesAllowed {}'.format('dry-run - would set ' if splunkd.dry_run else '',
                                                       '+' + DUO_INDEX if on else '-' + DUO_INDEX))
    else:
        rep.fail(label, 'HTTP {} {}'.format(code, text[:160]))


def step_other_role_grants(splunkd, rep, handled, prefix='DT4'):
    """Report every role, other than the ones this run handled, whose OWN
    srchIndexesAllowed holds the literal entry this tool adds. A setup run with
    --duo-attendee-role X is undone only by a teardown that names X too; this
    says so instead of ending green with the grant still there. It never
    removes such an entry: this run cannot know who added it."""
    label = '{}. other roles that list index {}'.format(prefix, DUO_INDEX)
    code, data = splunkd.get_json('/services/authorization/roles?count=0')
    if code != 200 or not isinstance((data or {}).get('entry'), list):
        rep.fail(label, 'could not list the roles (HTTP {}): check by hand that no role other than {} still lists '
                        'index {} in its searchable indexes'.format(code, ', '.join(handled) or '(none)', DUO_INDEX))
        return
    left = sorted(str(item.get('name')) for item in data['entry']
                  if item.get('name') not in handled
                  and DUO_INDEX in lab5._as_list((item.get('content') or {}).get('srchIndexesAllowed')))
    if not left:
        rep.ok(label, 'none')
        return
    rep.fail(label, 'role {} still lists index {} among its own searchable indexes and was not named on this '
                    'command line: run the teardown again with --duo-attendee-role {} (the role option of the '
                    'setup applies to the teardown too), or remove the entry in Splunk Web'.format(
                        ', '.join(left[:6]) + (' ...' if len(left) > 6 else ''), DUO_INDEX, ','.join(left[:6])))


def macro_index_patterns(definition):
    """Index patterns a cim_*_indexes definition names; [] when it names none."""
    text = str(definition or '')
    found = re.findall(r'index\s*(?:=|::)\s*"?([A-Za-z0-9_.*\-]+)"?', text, flags=re.I)
    for group in re.findall(r'index\s+IN\s*\(([^)]*)\)', text, flags=re.I):
        found.extend(part.strip().strip('"') for part in group.split(',') if part.strip())
    return found


def step_datamodel_scope(splunkd, rep, prefix='D4'):
    """Read-only, and never a gate. The TA's two Duo rules read the Duo events
    themselves, not the Authentication data model, so nothing here decides
    whether the inputs are created. What it tells the operator: whether ES's
    own Authentication content and UEBA, which do read the data model, will see
    index duo. A cim_Authentication_indexes that lists other indexes hides it."""
    label = '{}. ES\'s Authentication data model and index {}'.format(prefix, DUO_INDEX)
    why = 'it matters to ES\'s own Authentication content and UEBA, not to the TA\'s rules'
    code, data = splunkd.get_json('/servicesNS/nobody/{}/configs/conf-macros/{}'.format(CIM_APP, CIM_INDEX_MACRO))
    if code == 404:
        rep.skip(label, '{} not found in {}: nothing to check ({})'.format(CIM_INDEX_MACRO, CIM_APP, why))
        return
    if code != 200:
        rep.skip(label, 'could not read {} (HTTP {}); {}'.format(CIM_INDEX_MACRO, code, why))
        return
    definition = str(content(data).get('definition') or '').strip()
    patterns = macro_index_patterns(definition)
    if not patterns:
        if definition in ('', '()'):
            rep.ok(label, '{} is empty: no index is excluded'.format(CIM_INDEX_MACRO))
        else:
            rep.skip(label, '{} names no index this tool can read; check with: | tstats count from '
                            'datamodel=Authentication.Authentication where index={}'.format(CIM_INDEX_MACRO, DUO_INDEX))
        return
    if any(fnmatch.fnmatchcase(DUO_INDEX, pattern) for pattern in patterns):
        rep.ok(label, '{} includes it'.format(CIM_INDEX_MACRO))
        return
    rep.skip(label, '{} lists {} and not {}: the data model will not hold the Duo events. To change that, add '
                    'index={} in ES under Configure > CIM Setup > Authentication (not changed here); {}'.format(
                        CIM_INDEX_MACRO, ', '.join(patterns[:6]), DUO_INDEX, DUO_INDEX, why))


###############################################################################
# D5 - searches
###############################################################################

_UNIT_SECONDS = {'s': 1, 'sec': 1, 'secs': 1, 'second': 1, 'seconds': 1,
                 'm': 60, 'min': 60, 'mins': 60, 'minute': 60, 'minutes': 60,
                 'h': 3600, 'hr': 3600, 'hrs': 3600, 'hour': 3600, 'hours': 3600,
                 'd': 86400, 'day': 86400, 'days': 86400,
                 'w': 604800, 'week': 604800, 'weeks': 604800,
                 'mon': 2592000, 'month': 2592000, 'months': 2592000,
                 'y': 31536000, 'yr': 31536000, 'yrs': 31536000, 'year': 31536000, 'years': 31536000}
UNBOUNDED, UNKNOWN = 'unbounded', 'unknown'


def reach_hours(earliest):
    """How far back a dispatch.earliest_time reaches by event time, in hours;
    UNBOUNDED for all time, UNKNOWN for a form this does not read. Only for a
    rule whose search has no index-time terms (see slot_minutes): for the
    rules as shipped that key is an index-time slot edge, never a reach."""
    text = str(earliest if earliest is not None else '').strip().lower()
    if text in ('', '0', '1'):
        return UNBOUNDED
    m = re.match(r'^-(\d+)([a-z]+)(@[a-z0-9+\-]*)?$', text)
    if not m or m.group(2) not in _UNIT_SECONDS:
        return UNKNOWN
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2)] / 3600.0


EVENT_TIME = 'event-time'


def _on(value):
    return str(value).strip().lower() in ('1', 'true')


def _minutes_back(value):
    """Minutes before the cron tick for a dispatch time '-N<unit>@m' (the form
    both rules ship with, in minutes; a catch-up range left in is usually days);
    None for any other form."""
    m = re.match(r'^-(\d+)([a-z]+)@m$', str(value or '').strip().lower())
    if not m or m.group(2) not in _UNIT_SECONDS or _UNIT_SECONDS[m.group(2)] % 60:
        return None
    return int(m.group(1)) * (_UNIT_SECONDS[m.group(2)] // 60)


def slot_minutes(live):
    """(period, None) when a detection judges by INDEX time on a slot exactly
    one cron period wide (the Duo rule and the joined rule as shipped): its job
    time range is then the slot of index time one run judges, never how far
    back it reads events, and the runs tile, so whatever is indexed after the
    rule is enabled is judged once, however old the events are.

    Else (None, why). why is EVENT_TIME for a search with no index-time terms
    (a TA build from before the rules judged by index time); any other reason
    is a schedule under which a backfill would be judged twice or not at all."""
    search = str(live.get('search') or '')
    if '_index_earliest=' not in search or '_index_latest=' not in search:
        return None, EVENT_TIME
    cron = re.match(r'^\*/(\d+) \* \* \* \*$', ' '.join(str(live.get('cron_schedule') or '').split()))
    back = [_minutes_back(live.get(key)) for key in ('dispatch.earliest_time', 'dispatch.latest_time')]
    if not cron or None in back or int(cron.group(1)) < 1:
        return None, 'its schedule is not every N minutes over -Xm@m to -Ym@m'
    period, width = int(cron.group(1)), back[0] - back[1]
    if 60 % period:
        return None, 'it runs every {} min, which does not divide the hour: its slots would overlap at each ' \
                     'full hour'.format(period)
    if width != period:
        return None, 'its time range is {} min wide but it runs every {} min: index-time slots would {}'.format(
            width, period, 'overlap' if width > period else 'leave gaps')
    if str(live.get('realtime_schedule')).strip().lower() not in ('0', 'false'):
        return None, 'realtime_schedule is on: a run the scheduler skips is a slot never judged'
    if _on(live.get('allow_data_time_skew')):
        return None, 'allow_data_time_skew is on: the slot moves off the cron tick'
    if any(str(live.get(key) or '').strip() for key in ('dispatch.index_earliest', 'dispatch.index_latest')):
        return None, 'dispatch.index_earliest / dispatch.index_latest is set: the slot is no longer its time range'
    if 'is_scheduled' in live and not _on(live.get('is_scheduled')):
        return None, 'it is not scheduled'
    return period, None


def backfill_problem(name, live, lookback_hours):
    """None when the rule will judge the input's first poll (the backfill)
    exactly once; else the sentence a FAIL row carries."""
    period, why = slot_minutes(live)
    if period is not None:
        return None
    if why != EVENT_TIME:
        return '"{}": {} - restore the shipped schedule (cron and both dispatch times move together)'.format(
            name[:56], why)
    earliest = live.get('dispatch.earliest_time')
    reach = reach_hours(earliest)
    if reach in (UNBOUNDED, UNKNOWN) or reach >= lookback_hours:
        return None
    return ('"{}" on this stack selects by event time, {} ({:g} h), but the input backfills {} h: older staged '
            'events would be indexed and never judged - install the TA build whose rules judge by index '
            'time'.format(name[:56], earliest, reach, lookback_hours))


def _switch(splunkd, rep, label, name, on, optional=False):
    """Set one saved search's disabled flag, only when it differs. Returns
    (the search's content or None when it is not on the stack, whether it is
    now in the wanted state)."""
    code, data = splunkd.get_json(saved_path(name))
    if code == 404:
        if not on:
            rep.ok(label, 'not present')
        elif optional:
            rep.skip(label, 'not in the installed TA')
        else:
            rep.fail(label, 'not found - is TA-gen_ai_cim 1.9.0+ installed?')
        return None, not on or optional
    if code != 200:
        rep.fail(label, 'could not read it (HTTP {})'.format(code))
        return None, False
    live = content(data)
    if is_disabled(live.get('disabled')) != on:
        rep.ok(label, 'already {}'.format('enabled' if on else 'disabled'))
        return live, True
    code, text = splunkd.call(saved_path(name), 'POST', {'disabled': '0' if on else '1'})
    if code in (200, 201):
        rep.ok(label, '{}{}'.format('dry-run - would be ' if splunkd.dry_run else '', 'enabled' if on else 'disabled'))
        return live, True
    rep.fail(label, 'HTTP {} {}'.format(code, text[:160]))
    return live, False


def step_searches(splunkd, rep, settings=None, on=True, prefix='D5'):
    """Enable (or disable) every detection that reads the Duo feed and, when
    asked for, the identity lookup search. On setup this runs BEFORE the inputs
    exist: a rule that selects by index time judges an event once, in the run
    after it is indexed, so a rule turned on after the backfill never sees it.

    Returns False when a detection could not be enabled, or would not judge
    the backfill exactly once (backfill_problem): either way the history would
    be indexed and never judged, or judged twice."""
    verb = 'enable' if on else 'disable'
    label = '{}. {} "{}"'.format(prefix, verb, LOOKUP_GEN)
    if on and settings is not None and not settings.lookup_gen:
        code, data = splunkd.get_json(saved_path(LOOKUP_GEN))
        state = 'left as it is'
        if code == 200:
            state = 'left {}'.format('disabled' if is_disabled(content(data).get('disabled')) else
                                     'enabled, as an earlier run set it')
        rep.skip(label, '{}: no --duo-with-lookup-gen ({})'.format(state, LOOKUP_SCOPE))
    else:
        _switch(splunkd, rep, label, LOOKUP_GEN, on)
    problems, periods, all_set = [], [], True
    for name in DUO_DETECTIONS + DUO_OPTIONAL_DETECTIONS:
        live, done = _switch(splunkd, rep, '{}. {} "{}"'.format(prefix, verb, name[:56]), name, on,
                             optional=name in DUO_OPTIONAL_DETECTIONS)
        all_set = all_set and done
        if on and live is not None and settings is not None:
            problem = backfill_problem(name, live, settings.lookback_hours)
            if problem:
                problems.append(problem)
            else:
                periods.append(slot_minutes(live)[0])
    if not on or settings is None:
        return all_set
    label = '{}. the rules judge the backfill'.format(prefix)
    if problems:
        rep.fail(label, '; '.join(problems))
        return False
    slots = [period for period in periods if period]
    rep.ok(label, 'backfill {} h; {}'.format(
        settings.lookback_hours,
        'judged once, by index time, in slots of {} min'.format(' and '.join(str(p) for p in slots)) if slots
        else 'no rule on the stack to check'))
    return all_set


###############################################################################
# D6 - inputs
###############################################################################

def _stamp(ms):
    try:
        return time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(float(ms) / 1000.0))
    except (TypeError, ValueError):
        return 'an unknown time'


def purge_pending(splunkd):
    """(True, None) while an index delete that --duo-teardown --duo-purge-data
    asked ACS for is not confirmed, (False, None) when none is, (None, why)
    when the marker could not be read."""
    code, _ = splunkd.get_json(marker_path())
    if code == 200:
        return True, None
    if code == 404:
        return False, None
    return None, 'HTTP {}'.format(code)


def _backfill_guard(splunkd, rep, settings, label, acs=None, skip_acs=True):
    """The authentication input is created only when its checkpoint and the
    index agree, so its first poll neither skips the history (a checkpoint
    left behind, an empty index) nor indexes it twice (events already there,
    no checkpoint)."""
    code, saved = splunkd.get_json(checkpoint_path(AUTH_INPUT))
    if code not in (200, 404):
        rep.fail(label, 'could not read its checkpoint (HTTP {}); not created'.format(code))
        return False
    counts, problem = index_counts(splunkd)
    if counts is None:
        rep.fail(label, 'could not count the events already in index {} ({}); not created'.format(
            DUO_INDEX, problem))
        return False
    have = counts.get(AUTH_SOURCETYPE, 0)
    if have == 0 and not skip_acs and acs is not None:
        # No row from the search is not proof of an empty index (a role that cannot
        # search it gets none either). Where ACS counts events the search does not
        # see, a first poll could index the history a second time.
        counted = acs_event_count(acs)
        if counted:
            rep.fail(label, 'a search finds no Duo authentication event in index {} but ACS counts {} event(s) in '
                            'it: what it holds could not be checked; not created'.format(DUO_INDEX, counted))
            return False
    if code == 200 and have == 0:
        if not settings.reset_checkpoint:
            rep.fail(label, 'a checkpoint from an earlier input is still there (read up to {}) but index {} '
                            'holds no Duo authentication event: the input would resume from it and never '
                            'read the history. Pass --duo-reset-checkpoint; not created'.format(
                                _stamp((saved or {}).get('maxtime_ms')), DUO_INDEX))
            return False
        code, text = splunkd.call(checkpoint_path(AUTH_INPUT), 'DELETE')
        if code not in (200, 404):
            rep.fail(label, 'could not delete the old checkpoint (HTTP {}); not created'.format(code))
            return False
    elif code == 404 and have > 0:
        rep.fail(label, 'index {} already holds {} Duo authentication events and this input has no '
                        'checkpoint: its first poll would index the last {} h a second time and every '
                        'count would double. Remove the old data (--duo-teardown --duo-purge-data); '
                        'not created'.format(DUO_INDEX, have, settings.lookback_hours))
        return False
    return True


def step_inputs(splunkd, rep, settings, blockers, prefix='D6', acs=None, skip_acs=True):
    """The users input when it was asked for (--duo-with-users), then the
    authentication input, whose first poll is the backfill. An input that
    exists is never repointed; only its interval and its enabled state follow
    the run's settings. A users input that an earlier run created is left as it
    is by a run that does not ask for it: only the teardown removes an input."""
    for name, endpoint in INPUTS:
        label = '{}. input {}'.format(prefix, name)
        code, data = splunkd.get_json(input_path(name))
        if code not in (200, 404):
            rep.fail(label, 'could not read it (HTTP {})'.format(code))
            continue
        if endpoint == 'users' and not settings.users_input:
            if code == 404:
                rep.skip(label, 'not created: no --duo-with-users (it indexes {})'.format(USERS_SCOPE))
            else:
                rep.ok(label, 'exists, {} (an earlier run created it; left as it is - --duo-teardown removes '
                              'it)'.format('disabled' if is_disabled(content(data).get('disabled')) else 'enabled'))
            continue
        wanted = settings.input_fields(endpoint)
        if code == 200:
            live = content(data)
            other = [key for key in ('account', 'endpoint', 'index') if str(live.get(key) or '') != wanted[key]]
            if other:
                rep.fail(label, 'exists with another {}; left alone (--duo-teardown removes it)'.format(
                    ' and '.join(other)))
                continue
            if blockers:
                rep.skip(label, 'exists; not changed while: {}'.format('; '.join(blockers)))
                continue
            done = []
            if str(live.get('interval') or '') != wanted['interval']:
                # account and endpoint go along unchanged: splunkd validates an edit with the
                # input's own validate_input, which needs both, and may hand it only what is posted.
                code, text = splunkd.call(input_path(name), 'POST', {
                    'account': wanted['account'], 'endpoint': wanted['endpoint'], 'interval': wanted['interval']})
                if code not in (200, 201):
                    rep.fail(label, 'HTTP {} {}'.format(code, text[:160]))
                    continue
                done.append('interval {} -> {}'.format(live.get('interval'), wanted['interval']))
            if is_disabled(live.get('disabled')):
                code, text = splunkd.call(input_path(name) + '/enable', 'POST', {})
                if code not in (200, 201):
                    rep.fail(label, 'HTTP {} {}'.format(code, text[:160]))
                    continue
                done.append('enabled')
            rep.ok(label, ', '.join(done) if done else 'exists, unchanged (interval {})'.format(wanted['interval']))
            continue
        if blockers:
            rep.skip(label, 'not created: {}'.format('; '.join(blockers)))
            continue
        if endpoint == 'authentication' and not _backfill_guard(splunkd, rep, settings, label, acs, skip_acs):
            continue
        code, text = splunkd.call(input_path(), 'POST', dict(wanted, name=name))
        if code not in (200, 201):
            rep.fail(label, 'HTTP {} {}'.format(code, text[:160]))
        elif endpoint == 'authentication':
            rep.ok(label, '{} (interval {}); its first poll reads the last {} h, up to 1000 events a '
                          'run'.format('dry-run - would create it' if splunkd.dry_run else 'created',
                                       wanted['interval'], settings.lookback_hours))
        else:
            rep.ok(label, '{} (interval {})'.format('dry-run - would create it' if splunkd.dry_run else 'created',
                                                    wanted['interval']))


###############################################################################
# D7, D8 - verify (read-only)
###############################################################################

def step_verify(splunkd, rep, settings=None, prefix='D7'):
    """Inputs enabled, events by sourcetype, and a note on the Authentication
    data model. Returns the event counts by sourcetype (None when they could
    not be read), which D8 starts from."""
    for name, endpoint in INPUTS:
        label = '{}. verify input {}'.format(prefix, name)
        code, data = splunkd.get_json(input_path(name))
        if code == 404 and endpoint == 'users' and not (settings is not None and settings.users_input):
            continue                # not asked for, not there: D6 has said so
        if code != 200:
            rep.skip(label, 'not on the stack' if code == 404 else 'HTTP {}'.format(code))
        elif is_disabled(content(data).get('disabled')):
            rep.fail(label, 'disabled')
        else:
            rep.ok(label, 'enabled, interval {}'.format(content(data).get('interval')))
    label = '{}. verify events in index {}'.format(prefix, DUO_INDEX)
    counts, problem = index_counts(splunkd)
    if counts is None:
        rep.skip(label, problem)
        return None
    auth = counts.get(AUTH_SOURCETYPE, 0)
    if not counts:
        rep.skip(label, 'none yet - the first poll runs within one interval of the input being created')
        return counts
    rep.ok(label, ', '.join('{} {}'.format(n, st) for st, n in sorted(counts.items())))
    if auth:
        # A note, never a failure: the TA's rules read the events themselves.
        label = '{}. note: the Authentication data model'.format(prefix)
        seen, problem = datamodel_count(splunkd)
        if seen is None:
            rep.skip(label, '{} - ES\'s own Authentication content and UEBA read it; the TA\'s rules do '
                            'not'.format(problem))
        elif seen == 0:
            rep.skip(label, 'returns none of the {} Duo authentication events: ES\'s own Authentication '
                            'content and UEBA will not see them (check {} and the TA\'s tags). The TA\'s rules '
                            'read the events themselves and are not affected'.format(auth, CIM_INDEX_MACRO))
        else:
            rep.ok(label, '{} of {} events (enrollment events map to Change, not Authentication)'.format(seen, auth))
    return counts


def _ids(rows, field):
    return set(str(row.get(field)) for row in rows or [] if row.get(field) not in (None, ''))


def step_judged(splunkd, rep, counts, prefix='D8'):
    """Read-only: was everything that is indexed judged? The top risk of a
    backfill is history indexed while a rule was off (or in a slot whose run
    failed): the rules never look at an index-time slot twice, so that history
    raises nothing and nothing says so.

    For each rule this dispatches the rule's own search, as the stack has it,
    in one pass over all index time up to the last slot a scheduled run has
    certainly finished (ad hoc: no alert action runs), collects the ids of the
    findings it yields (burst_id, chain_id), and compares them with the ids on
    the rule's risk events. Every expected id must be there."""
    head = '{}. verify the backfill was judged'.format(prefix)
    if counts is None:
        rep.skip(head, 'the events in index {} could not be counted'.format(DUO_INDEX))
        return
    if not counts.get(AUTH_SOURCETYPE, 0):
        rep.skip(head, 'no Duo authentication event is indexed yet: run this again after the first poll')
        return
    code, _ = splunkd.get_json('/services/data/indexes/{}'.format(RISK_INDEX))
    if code == 404:
        rep.skip(head, 'index {} is not on this stack: the rules\' risk and findings need Enterprise '
                       'Security'.format(RISK_INDEX))
        return
    for name in DUO_DETECTIONS:
        field, noun = JUDGED_IDS[name], JUDGED_NOUNS[name]
        label = '{}: "{}"'.format(head, name[:56])
        code, data = splunkd.get_json(saved_path(name))
        if code != 200:
            rep.skip(label, 'not on the stack' if code == 404 else 'could not read the rule (HTTP {})'.format(code))
            continue
        live = content(data)
        if is_disabled(live.get('disabled')):
            rep.skip(label, 'the rule is disabled, so nothing is compared (step D5 enables it)')
            continue
        period, why = slot_minutes(live)
        if period is None:
            rep.skip(label, 'not compared: {}'.format(
                'this build of the rule does not judge by index time' if why == EVENT_TIME else why))
            continue
        spl = str(live.get('search') or '').strip()        # as the stack has it: no character is changed
        if not spl or WRITES.search(spl):
            rep.skip(label, 'not compared: the rule\'s search on this stack is empty or holds a command that '
                            'writes, and is not dispatched from here')
            continue
        if not re.match(r'^(\||search\s)', spl):
            spl = 'search ' + spl
        back = period + JUDGED_GRACE_MINUTES
        expected, problem = oneshot(splunkd, '{} | stats count by {}'.format(spl, field),
                                    latest='-{}m@m'.format(back), app=True, timeout=300)
        if expected is None:
            rep.skip(label, 'not compared: the rule\'s own search did not run ({})'.format(problem))
            continue
        wanted = _ids(expected, field)
        if not wanted:
            rep.skip(label, 'nothing to compare: no {} among the events indexed more than {} minutes '
                            'ago'.format(noun, back))
            continue
        raised, problem = oneshot(
            splunkd, 'search index={} search_name="{}" | eval {}=coalesce({}, "{}") | stats count by {}'.format(
                RISK_INDEX, name, field, field, NO_ID, field), app=True, timeout=300)
        if raised is None:
            rep.skip(label, 'not compared: the risk events could not be read ({})'.format(problem))
            continue
        have = _ids(raised, field)
        missing = sorted(wanted - have)
        if not missing:
            rep.ok(label, '{} of {} {}s raised (of what was indexed more than {} minutes ago)'.format(
                len(wanted), len(wanted), noun, back))
        elif NO_ID in have:
            rep.skip(label, 'not comparable: {} of {} {}s have no risk event under their id, and this rule has '
                            'risk events with no {} at all, raised by a build from before it judged by index '
                            'time. Compare by hand before any catch-up: it would raise them a second '
                            'time'.format(len(missing), len(wanted), noun, field))
        else:
            rep.fail(label, '{} of {} {}s never raised: {}{}. They were indexed while the rule was off, or in '
                            'a slot whose run failed; judge that index time once more (README, "Judging history '
                            'that is already indexed"). If the scheduler is behind, it may still reach '
                            'them'.format(len(missing), len(wanted), noun, ', '.join(missing[:3]),
                                          ' ...' if len(missing) > 3 else ''))


###############################################################################
# Setup
###############################################################################

def scope_lines(settings):
    """What this stack will hold, in the operator's words: printed by every
    setup run before the first step, so the choice is never a silent default."""
    roles = ', '.join(settings.attendee_roles)
    return [
        'Polls   : the Duo authentication log, interval {}; the first poll reads the last {} h'.format(
            settings.auth_interval, settings.lookback_hours),
        'Holds   : every sign-in of the WHOLE Duo tenant, all users, with their source addresses '
        '(the input has no user filter)',
        'Users   : {}'.format('the tenant\'s user list, every {} s (--duo-with-users)'.format(settings.users_interval)
                              if settings.users_input else 'not indexed (--duo-with-users adds the user list)'),
        'Lookup  : {}'.format('the identity lookup search is enabled (--duo-with-lookup-gen)' if settings.lookup_gen
                              else 'the identity lookup search is not enabled (--duo-with-lookup-gen)'),
        'Readers : {}'.format('role {} may search index {}, besides the stack\'s admins'.format(roles, DUO_INDEX)
                              if roles else 'the stack\'s admins only (no --duo-attendee-role)'),
        'Key     : the Duo secret key is stored on this stack (storage/passwords) and opens the whole tenant '
        'for reading to anyone who administers the stack',
    ]


def setup(splunkd, acs, rep, creds, settings, skip_acs, sleep=time.sleep, clock=time.time):
    if not step_preflight(splunkd, rep):
        return
    index_state = step_index(acs, splunkd, rep, skip_acs, settings, sleep=sleep, clock=clock)
    account_ok = step_account(splunkd, rep, creds, settings)
    if settings.attendee_roles:
        for role in settings.attendee_roles:
            step_role(splunkd, rep, role)
    else:
        rep.skip('D3. attendee role', 'no --duo-attendee-role: only the stack\'s admins can search index {}'.format(
            DUO_INDEX))
    step_datamodel_scope(splunkd, rep)                    # a note; never a blocker
    rules_ok = step_searches(splunkd, rep, settings)
    blockers = []
    if index_state == MISSING:
        blockers.append('index {} is not there'.format(DUO_INDEX))
    if not account_ok:
        blockers.append('the Duo account is not set')
    lab = [text for failed, text in ((index_state == SHORT, 'index retention'),
                                     (not rules_ok, 'the rules')) if failed]
    if lab and not settings.force:
        blockers.append('{} failed above (--duo-force creates the inputs anyway)'.format(' and '.join(lab)))
    # Never forced: an input created now would write the backfill into an index
    # that ACS is about to delete.
    pending, why = purge_pending(splunkd)
    if pending:
        blockers.append('an index delete asked for by --duo-teardown --duo-purge-data is not confirmed yet: run '
                        'that teardown again until it reports index {} gone'.format(DUO_INDEX))
    elif pending is None:
        blockers.append('could not read whether an index delete is still under way ({})'.format(why))
    step_inputs(splunkd, rep, settings, blockers, acs=acs, skip_acs=skip_acs)
    counts = step_verify(splunkd, rep, settings)
    step_judged(splunkd, rep, counts)


###############################################################################
# Teardown
###############################################################################

def step_delete_inputs(splunkd, rep, prefix='DT2'):
    """(all gone, the names this run deleted or would delete)."""
    gone, handled = True, set()
    for name, _endpoint in reversed(INPUTS):
        label = '{}. delete input {}'.format(prefix, name)
        code, _ = splunkd.get_json(input_path(name))
        if code == 404:
            rep.ok(label, 'not present')
            continue
        code, text = splunkd.call(input_path(name), 'DELETE')
        if code in (200, 204):
            handled.add(name)
            rep.ok(label, 'dry-run - would delete it' if splunkd.dry_run else 'deleted')
        else:
            gone = False
            rep.fail(label, 'HTTP {} {}'.format(code, text[:160]))
    return gone, handled


def other_writers(splunkd, ignore=()):
    """(names of the scheme's inputs that write to index duo and are not this
    run's own, None), or (None, why) when the inputs could not be listed. A
    hand-made input is not this tool's to delete, and the index is not deleted
    from under it: disabled or not, it would write into nothing once enabled."""
    code, listing = splunkd.get_json(input_path() + '?count=0')
    if code != 200 or not isinstance((listing or {}).get('entry'), list):
        return None, 'HTTP {}'.format(code)
    return sorted(str(item.get('name')) for item in listing['entry']
                  if str((item.get('content') or {}).get('index') or '') == DUO_INDEX
                  and item.get('name') not in ignore), None


def step_delete_account(splunkd, rep, ignore=(), prefix='DT3'):
    """Delete the account, then make sure its secret key is gone. The reply of
    a storage/passwords call is never printed: it can list clear passwords."""
    label = '{}. delete Duo account {} and its secret key'.format(prefix, DUO_ACCOUNT)
    code, data = splunkd.get_json(account_path(DUO_ACCOUNT))
    if code not in (200, 404):
        rep.fail(label, 'could not read the account (HTTP {})'.format(code))
        return
    existed = code == 200
    if existed:
        if (content(data).get('auth_type') or 'basic') != duo_input.AUTH_TYPE:
            rep.fail(label, 'the account with this name is not a Cisco Duo account; left alone')
            return
        code, listing = splunkd.get_json(input_path() + '?count=0')
        if code != 200:
            rep.fail(label, 'kept: could not list the inputs (HTTP {})'.format(code))
            return
        users = sorted(item.get('name') for item in (listing or {}).get('entry') or []
                       if (item.get('content') or {}).get('account') == DUO_ACCOUNT
                       and item.get('name') not in ignore)
        if users:
            rep.fail(label, 'kept, with its secret key: input {} still uses it'.format(', '.join(users)))
            return
        code, text = splunkd.call(account_path(DUO_ACCOUNT), 'DELETE')
        if code not in (200, 204):
            rep.fail(label, 'HTTP {} {}'.format(code, text[:160]))
            return
    code, _reply = splunkd.call(secret_path(DUO_ACCOUNT), 'DELETE')
    if splunkd.dry_run:
        rep.ok(label, 'dry-run - would delete {}'.format('it and its secret key' if existed else
                                                         'a secret key left behind, if there is one'))
    elif code == 404:
        rep.ok(label, 'deleted; no secret key is stored' if existed else 'not present')
    elif code in (200, 204):
        rep.ok(label, '{}; a secret key left behind was removed'.format('deleted' if existed else 'no account'))
    else:
        rep.fail(label, 'the secret key may still be stored (HTTP {}): delete the credential {}{}:{}: of '
                        'the TA by hand, or rotate the key in Duo'.format(
                            code, duo_input.REALM_PREFIX, DUO_ACCOUNT, duo_input.SECRET_NAME))


def step_delete_lookup_file(splunkd, rep, prefix='DT5'):
    label = '{}. delete lookups/{}'.format(prefix, LOOKUP_FILE)
    code, _ = splunkd.get_json('{}/configs/conf-inputs/{}'.format(NS, q(IDENTITY_SOURCE)))
    if code == 200:
        rep.fail(label, 'kept: the ES identity source {} still reads it, and ES logs an ERROR every 5 minutes '
                        'for a source whose file is missing. Remove the source in ES (Assets and identities > '
                        'Identity lookups), then run this again'.format(IDENTITY_SOURCE.split('//')[1]))
        return
    if code != 404:
        # Only "no such stanza" is a go-ahead. A 403, a 500 or no reply says nothing
        # about the source, and deleting the file under an enabled source breaks
        # ES's identity merge for every source.
        rep.fail(label, 'kept: could not check whether an ES identity source still reads it (HTTP {}). Look in '
                        'ES (Assets and identities > Identity lookups) for {}; once it is gone, run this '
                        'again'.format(code, IDENTITY_SOURCE.split('//')[1]))
        return
    path = '{}/data/lookup-table-files/{}'.format(NS, q(LOOKUP_FILE))
    code, _ = splunkd.get_json(path)
    if code == 404:
        rep.ok(label, 'not present')
        return
    code, text = splunkd.call(path, 'DELETE')
    if code in (200, 204):
        rep.ok(label, 'dry-run - would delete it' if splunkd.dry_run else 'deleted')
    else:
        rep.fail(label, 'HTTP {} {}'.format(code, text[:160]))


def _clear_checkpoints(splunkd):
    """Delete the inputs' checkpoints and the pending-delete marker; the names
    that could not be cleared."""
    failed = []
    for name, _endpoint in INPUTS:
        code, _text = splunkd.call(checkpoint_path(name), 'DELETE')
        if code not in (200, 204, 404):
            failed.append('{} (HTTP {})'.format(name, code))
    code, _text = splunkd.call(marker_path(), 'DELETE')
    if code not in (200, 204, 404):
        failed.append('the pending-delete marker (HTTP {})'.format(code))
    return failed


def step_purge_data(acs, splunkd, rep, skip_acs, inputs_gone, writers=(), writers_problem=None,
                    sleep=time.sleep, clock=time.time, wait=120, prefix='DT6'):
    """Delete index duo and the inputs' checkpoints, together or not at all.
    The index goes only when it holds nothing but this feed's sourcetypes and
    nothing else writes to it, and the checkpoints only once the index is
    CONFIRMED gone: every check that comes back unreadable, or that contradicts
    another, keeps both."""
    label = '{}. index {} and the input checkpoints'.format(prefix, DUO_INDEX)
    if DUO_INDEX in PROTECTED_INDEXES or DUO_INDEX.startswith('_'):
        rep.fail(label, 'refusing to delete index {}'.format(DUO_INDEX))
        return
    if not inputs_gone:
        rep.fail(label, 'kept: an input could not be deleted and may still be writing')
        return
    if writers_problem:
        rep.fail(label, 'kept: could not list the inputs to see whether another one writes to the index '
                        '({})'.format(writers_problem))
        return
    if writers:
        rep.fail(label, 'kept: input {} still writes to index {} and is not one this tool made. Delete it '
                        '(Settings > Data inputs > Cisco Duo), then run this again'.format(
                            ', '.join(writers[:4]), DUO_INDEX))
        return
    counts, problem = index_counts(splunkd)
    if counts is None:
        rep.fail(label, 'kept: could not check what the index holds ({})'.format(problem))
        return
    foreign = foreign_sourcetypes(counts)
    if foreign:
        rep.fail(label, 'kept: the index also holds {} event(s) of {} - it is not only this feed\'s'.format(
            sum(foreign.values()), ', '.join(sorted(str(st) for st in foreign)[:3])))
        return
    total = sum(counts.values())
    state, detail = None, ''
    if not skip_acs:
        state, _days, detail = acs_index(acs)
    if state is None:
        code, _ = splunkd.get_json('/services/data/indexes/{}'.format(DUO_INDEX))
        if code != 404:
            rep.fail(label, 'kept: ACS is skipped - delete index {} by hand, then run this again to clear '
                            'the checkpoints (they stay while the index does)'.format(DUO_INDEX))
            return
        state = MISSING
    if state == 'error':
        rep.fail(label, 'kept: {}'.format(detail))
        return
    if state == MISSING and total:
        # "No such index" from the stack, and a search that has just counted events
        # in it: one of the two is wrong, and the checkpoints must not go while the
        # data may still be there (the next --duo would refuse to backfill and send
        # the operator back here).
        rep.fail(label, 'kept: the stack says index {} does not exist, but a search still counts {} event(s) in '
                        'it. Nothing was deleted and the checkpoints stay. Delete the index with ACS or in '
                        'Splunk Web (Settings > Indexes), then run this again'.format(DUO_INDEX, total))
        return
    if state == MISSING:
        failed = _clear_checkpoints(splunkd)
        if failed:
            rep.fail(label, 'the index was already gone; checkpoint not cleared for {} - pass '
                            '--duo-reset-checkpoint on the next --duo'.format(', '.join(failed)))
        else:
            rep.ok(label, 'the index was already gone; checkpoints {}'.format(
                'would be cleared' if splunkd.dry_run else 'cleared'))
        return
    # state == READY: ACS lists the index.
    if total == 0:
        # A search that returns nothing proves nothing about an index this user
        # cannot search: ACS must SAY that it is empty before it is deleted.
        counted = acs_event_count(acs)
        if counted is None:
            rep.fail(label, 'kept: a search finds no event in the index and ACS did not say how many it holds: '
                            'what it holds could not be checked')
            return
        if counted:
            rep.fail(label, 'kept: a search finds no event in the index but ACS counts {}: what it holds '
                            'could not be checked'.format(counted))
            return
    if acs.dry_run:
        rep.ok(label, 'dry-run - would delete the index ({} events, all {}*) and, once ACS confirms it is gone, '
                      'the checkpoints'.format(total, SOURCETYPE_PREFIX))
        return
    # Mark the delete as under way BEFORE asking for it: ACS deletes an index in
    # the background, and until it is gone the index is still listed. A --duo run
    # in between must not create an input into it.
    code, text = splunkd.call(marker_path(None), 'POST', json_body={'_key': PURGE_MARKER, 'updated': int(clock())})
    if code not in (200, 201, 409):
        rep.fail(label, 'kept: could not record that the delete is under way (HTTP {}); nothing was '
                        'deleted'.format(code))
        return
    code, text = acs.call('/indexes/{}'.format(DUO_INDEX), 'DELETE')
    if code not in (200, 202, 204):
        splunkd.call(marker_path(), 'DELETE')
        rep.fail(label, 'kept: HTTP {} {}'.format(code, str(text)[:160]))
        return
    deadline = clock() + wait
    while acs_index(acs)[0] != MISSING:       # an unreadable answer is not a confirmation
        if clock() >= deadline:
            rep.fail(label, 'index delete accepted ({} events, all {}*) but not confirmed after {} s: ACS still '
                            'lists the index, or could not be read. The checkpoints are kept, and --duo creates '
                            'no input until this is finished: run this teardown again until it reports the index '
                            'gone'.format(total, SOURCETYPE_PREFIX, wait))
            return
        sleep(INDEX_POLL_SECONDS)
    failed = _clear_checkpoints(splunkd)
    did = 'index deleted ({} events, all {}*)'.format(total, SOURCETYPE_PREFIX)
    if failed:
        rep.fail(label, '{}; checkpoint not cleared for {} - pass --duo-reset-checkpoint on the next '
                        '--duo'.format(did, ', '.join(failed)))
    else:
        rep.ok(label, '{}; checkpoints cleared. ACS may restart the stack after an index delete'.format(did))


def teardown(splunkd, acs, rep, skip_acs, purge_data, roles=(ATTENDEE_ROLE,), sleep=time.sleep,
             clock=time.time):
    step_searches(splunkd, rep, on=False, prefix='DT1')
    inputs_gone, handled = step_delete_inputs(splunkd, rep)
    step_delete_account(splunkd, rep, ignore=handled)
    for role in roles:
        step_role(splunkd, rep, role, on=False, prefix='DT4')
    if not roles:
        rep.skip('DT4. attendee role', 'no --duo-attendee-role: no role grant is removed')
    step_other_role_grants(splunkd, rep, roles)
    step_delete_lookup_file(splunkd, rep)
    if purge_data:
        writers, problem = other_writers(splunkd, ignore=handled)
        step_purge_data(acs, splunkd, rep, skip_acs, inputs_gone, writers=writers or (), writers_problem=problem,
                        sleep=sleep, clock=clock)
    else:
        rep.skip('DT6. index {} and the input checkpoints'.format(DUO_INDEX),
                 '--duo-keep-data: both kept, so a later --duo resumes where this feed stopped and indexes '
                 'nothing twice')
    rep.skip('DT7. Duo Admin API application',
             'if anyone else could administer this stack, rotate the application\'s secret key in the Duo '
             'Admin Panel: the stack held it. Use one read-only Admin API application per delivery, and delete '
             'it in Duo when the delivery is over')
