#!/usr/bin/env python3
# encoding=utf-8
"""
staged_resend.py - copy the staged PseudoCo Assistant events of a lab persona
to Splunk stacks that were created after the staging. Dev-only tooling
(tools/ never ships in the TA package).

Two steps, so the copy is read once and reviewed once:

    export   read the facilitator's Splunk over splunkd REST, once, into a
             private bundle file (mode 0600, never inside a git work tree)
    review   list what the bundle holds (ids, times, sizes and counts; never a
             body or an address) and approve it by its digest
    send     copy an approved bundle to one stack's HEC, each event at most once
    verify   read the stack again: the copies, the label, the counts the
             dashboards show and the joined rule's finding

A re-sent event is a verbatim copy of a real event. The stored _raw text is
spliced into the HEC line as text (never parsed and written out again), under
the original time text, host, source, sourcetype, index and log_type. A copy
differs from its original only in _indextime and in three HEC indexed fields
that no TA object reads:

    resend=true   resend_bundle=<bundle id>   resend_orig_indextime=<epoch>

    export STAGED_RESEND_SOURCE_PASSWORD=...       # or STAGED_RESEND_SOURCE_TOKEN
    python3 tools/staged_resend.py export --source https://127.0.0.1:8089 \\
        --host <HEC host label> --persona nina.osei \\
        --from 2026-11-16T21:05:00-08:00 --to 2026-11-16T21:37:00-08:00 \\
        --bundle ~/staged/nina.bundle.json
    python3 tools/staged_resend.py review --bundle ~/staged/nina.bundle.json
    python3 tools/staged_resend.py review --bundle ~/staged/nina.bundle.json --approve <digest12>
    export SPLUNK_ADMIN_PASSWORD=...               # or SPLUNK_ADMIN_TOKEN
    python3 tools/staged_resend.py send --bundle ~/staged/nina.bundle.json \\
        --stack https://<stack>.splunkcloud.com --hec-file stack.json
    python3 tools/staged_resend.py verify --bundle ~/staged/nina.bundle.json \\
        --stack https://<stack>.splunkcloud.com --wait 900

No option takes a secret: passwords and tokens come from the environment or
from the 0600 file `show_postdeploy.py --out` writes, and none is printed.
Output shows ids, hashes, times and counts only.

Exit codes: 0 ok, 1 a check failed, 2 usage or refused input, 3 delivery
unknown (an event may or may not have been indexed: nothing is sent again).

This tool cannot delete from an index. A copy stays in a stack until the
stack's retention removes it, so read the review listing before you approve.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import argparse
import collections
import csv
import datetime
import decimal
import fcntl
import fnmatch
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
APP_ROOT = os.path.dirname(HERE)
for _path in (os.path.join(APP_ROOT, 'bin'), HERE):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import genai_es_seed as seed  # noqa: E402  (Splunkd REST client, Reporter, TLS context)
import lab5_steps as lab5  # noqa: E402  (PERSONA_RE, last4, version_tuple)

TOOL = 'ta_gen_ai_cim.staged_resend'
FORMAT = 'ta-gen-ai-cim/staged-resend/1'          # the bundle format; also the first line of the digest
APP = seed.APP_NAME
TA_FLOOR = (1, 9, 0)
JOINED_RULE = 'AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule'
PERSONA_LOOKUP = os.path.join(APP_ROOT, 'lookups', 'pseudoco_identity_personas.csv')

DEFAULT_INDEX = 'gen_ai_log'
DEFAULT_SOURCE = 'demobot:hec'                    # the assistant's HEC source
LOG_TYPES = ('governance', 'audit', 'escalation', 'error')
ID_KEYS = ('audit_id', 'escalation_id', 'event_id')    # an assistant event opens with exactly one
ID_KEY_OF = {'governance': 'event_id', 'error': 'event_id', 'audit': 'audit_id', 'escalation': 'escalation_id'}

# The label: three HEC indexed fields beside log_type. Nothing in default/,
# bin/ or lookups/ reads these names, and no fields.conf stanza declares them
# (tools/tests/test_staged_resend.py keeps both true).
LABEL_FLAG, LABEL_BUNDLE, LABEL_ORIGIN = 'resend', 'resend_bundle', 'resend_orig_indextime'
LABEL_FIELDS = (LABEL_FLAG, LABEL_BUNDLE, LABEL_ORIGIN)
NO_LABEL = 'none'                                 # what the searches print for an event without one

# The macro exclude_scoring_sourcetypes, as fnmatch patterns: what the TA
# itself writes back into gen_ai_log and an export never copies.
SCORING_SOURCETYPES = ('ai_cim:*:ml_scoring', 'gen_ai:*:scoring', 'ai_cim:*:gen_ai_scoring', 'genai_scoring',
                       'ai_cim:response:*')

# The HEC request: POST <hec_url>, which must be https and end in HEC_PATH.
# Authorization ("Splunk <token>") is added by the sender and by nothing else.
# No indexer acknowledgement: Splunk Cloud supports it for Firehose only.
HEC_PATH = '/services/collector/event'
HEC_HEADERS = (('Content-Type', 'application/json; charset=utf-8'), ('Connection', 'close'))
MAX_REQUEST_EVENTS = 50
MAX_REQUEST_BYTES = 512 * 1024      # Splunk Cloud documents a 1 MB HEC content length
MAX_EVENT_BYTES = 900000            # one HEC line; a larger event is refused at export
MIN_AGE_SECONDS = 900               # nothing a rule with a 5-minute recency test could read as live
MAX_AGE_DAYS = 180                  # the joined rule reads back 181 days
MAX_WINDOW_SECONDS = 7 * 86400
EDGE_GUARD_SECONDS = 300            # a persona's event this close outside the window stops the export
CENSUS_PAD_SECONDS = 3600
RETRY_WAITS = (5, 15, 45)           # seconds, only after an answer that proves nothing was indexed
IDS_PER_SEARCH = 40                 # keeps every presence search under 5,000 characters
SETTLE_SECONDS = 180
MAX_WAIT_SECONDS = 7200             # the most `verify --wait` and `send --wait-finding` take
RESEND_UNCONFIRMED_AFTER = 3600

EXIT_OK, EXIT_FAILED, EXIT_REFUSED, EXIT_UNKNOWN = 0, 1, 2, 3

# Where a secret may come from. No command line option takes one.
ENV_HEC_TOKEN = 'STAGED_RESEND_HEC_TOKEN'
ENV_SOURCE_PASSWORD, ENV_SOURCE_TOKEN = 'STAGED_RESEND_SOURCE_PASSWORD', 'STAGED_RESEND_SOURCE_TOKEN'
ENV_STACK_PASSWORD, ENV_STACK_TOKEN = 'SPLUNK_ADMIN_PASSWORD', 'SPLUNK_ADMIN_TOKEN'

# Every pattern is used with fullmatch(): "$" alone would accept a trailing newline.
UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
TIME_RE = re.compile(r'[1-9]\d{8,10}(\.\d{1,6})?')           # tostring(_time): epoch seconds, 0 to 6 decimals
SHA_RE = re.compile(r'[0-9a-f]{64}')
META_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}')  # host, source, sourcetype
INDEX_RE = re.compile(r'[a-z0-9][a-z0-9_-]{0,79}')
BUNDLE_ID_RE = re.compile(r'rs-\d{8}-[0-9a-f]{12}')
TXID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{0,63}')
WORD_RE = re.compile(r'[A-Za-z0-9_.:-]{1,40}')               # a body value that may be shown in a listing
# The shapes datetime.isoformat() writes, so Python 3.9 and 3.13 read a timestamp alike.
STAMP_RE = re.compile(r'\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(\.\d{3}|\.\d{6})?(Z|[+-]\d\d:\d\d)?')
WHEN_RE = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d(:\d\d)?(Z|[+-]\d\d:\d\d)')

# Body keys that hold a client address or message text. They are counted for
# the review listing and never printed.
ADDRESS_KEYS = ('client_address', 'ip_address', 'src')
TEXT_KEYS = ('input_messages', 'output_messages', 'response_text', 'conversation_history')
SIGNIN_ACTION = 'identity_signin_success'
# Top-level body keys that decide what is copied and under which id. An event
# that writes one of them twice is refused: Python and Splunk would disagree.
READ_KEYS = ID_KEYS + ('timestamp', 'enduser_id', 'user', 'session_id') + LABEL_FIELDS


class Refused(Exception):
    """An input the tool will not act on (exit 2). The message is safe to
    print: it never holds a body, an address, a secret or a value that failed
    its check."""


# --- small helpers -----------------------------------------------------------

def sha256_text(text):
    """sha256 of a text's UTF-8 bytes: what SPL's sha256(_raw) returns."""
    try:
        return hashlib.sha256(text.encode('utf-8')).hexdigest()
    except UnicodeEncodeError:
        raise Refused('an event text is not valid Unicode (a lone surrogate): it cannot be hashed or sent')


def as_list(value):
    """A search result value as a list of strings. splunkd returns a bare
    string for one value, a list for several and no key at all for none."""
    if value is None or value == '':
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def one(value):
    """The single value of a result field; None when absent or multivalued."""
    values = as_list(value)
    return values[0] if len(values) == 1 else None


def as_int(value, default=None):
    """A result field as an int (every result value is a string); default when it is not one."""
    text = one(value)
    if text is None or not re.fullmatch(r'-?\d{1,18}', text):
        return default
    return int(text)


def join_key(value):
    """The identity join key, as the macro genai_identity_join_key writes it:
    lower(replace(trim(mvindex(x, 0)), "@.*", "")). '' when there is none."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None or isinstance(value, (dict, list, tuple)):
        return ''
    return re.sub(r'@.*', '', str(value).strip(' \t')).lower()


def actor_of(body):
    """Whose event this is: the body's enduser_id, else its user, as a join
    key ('' for none). The census search S1 reads the same two keys."""
    for key in ('enduser_id', 'user'):
        if body.get(key) is not None:
            return join_key(body[key])
    return ''


def time_3f(time_text):
    """A time text as SPL's printf("%.3f", _time) prints it. The same instant
    is 1794890405.273 on a HEC event and 1794890405.273000 on a collect-written
    one, so times are compared in this form and never as tostring() text."""
    return '%.3f' % float(time_text)


def is_loopback(host):
    """True for localhost and loopback addresses: the only hosts that may be
    reached over plain http or without certificate verification by default."""
    name = str(host or '').strip('[]').lower()
    if name == 'localhost':
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def is_public_address(text):
    """True when a body's address value is a globally routable IP address."""
    try:
        return ipaddress.ip_address(str(text).strip()).is_global
    except ValueError:
        return False


def whole_number(text, flag, low, high):
    """An option value as an int in [low, high]. No option uses argparse's
    type=: argparse repeats a bad value, and a value is never repeated here."""
    raw = str(text if text is not None else '').strip()
    if not re.fullmatch(r'\d{1,9}', raw) or not low <= int(raw) <= high:
        raise Refused('{}: expected a whole number from {} to {}'.format(flag, low, high))
    return int(raw)


def split_url(text, flag, default_port):
    """(scheme, host, port, path) of a splunkd or HEC URL. https only; plain
    http is accepted for a loopback host, which is what the offline tests use.
    A URL with a user name, a query or a fragment is refused, not trimmed."""
    try:
        parts = urllib.parse.urlsplit(str(text or '').strip())
        host, port = parts.hostname or '', parts.port
    except ValueError:
        parts, host, port = None, '', None
    if parts is None or not host or parts.username or parts.password or parts.query or parts.fragment:
        raise Refused('{}: expected https://<host>[:port] with no user name, query or fragment '
                      '(the value is not repeated here)'.format(flag))
    if parts.scheme != 'https' and not (parts.scheme == 'http' and is_loopback(host)):
        raise Refused('{}: the URL must be https (plain http is accepted for a loopback host only)'.format(flag))
    return parts.scheme, host, port or default_port, parts.path


# --- what the operator names: window, hosts, personas ------------------------

def parse_when(text, flag):
    """ISO-8601 with an explicit offset -> whole epoch seconds. A time with no
    offset is refused, never guessed. So is a fraction: tstats cuts a time
    bound to the whole second and search does not, so the census and the
    export would disagree at the edges of a fractional window."""
    raw = str(text or '').strip()
    if not WHEN_RE.fullmatch(raw):
        raise Refused('{}: expected ISO-8601 with whole seconds and an explicit offset, for example '
                      '2026-11-16T21:05:00-08:00 or 2026-11-17T05:05:00Z'.format(flag))
    try:
        when = datetime.datetime.fromisoformat(raw.replace('Z', '+00:00'))
    except ValueError:
        raise Refused('{}: not a real date and time'.format(flag))
    return int(when.timestamp())


def check_window(t_from, t_to, now):
    """--from is inclusive and --to exclusive, both in the past, at most 7 days apart."""
    if not t_from < t_to:
        raise Refused('--from must be before --to (--to is exclusive)')
    if t_to > now:
        raise Refused('--to is in the future: stage first, export afterwards')
    if t_to - t_from > MAX_WINDOW_SECONDS:
        raise Refused('the window is longer than {} days'.format(MAX_WINDOW_SECONDS // 86400))
    return t_from, t_to


def check_names(values, flag, pattern):
    """Hosts, an index or a source the operator named: plain values only, since
    each one is quoted into a search. Returns them sorted, without repeats."""
    names = sorted({str(value).strip() for value in values or ()})
    if not names or not all(pattern.fullmatch(name) for name in names):
        raise Refused('{}: expected a plain name (letters, digits and . _ : / @ -); the value is not '
                      'repeated here'.format(flag))
    return names


def known_personas(path=None):
    """The persona names of the Lab 5 identity lookup. Its `identity` column is
    name|email, so the name is the part before the pipe."""
    try:
        with open(path or PERSONA_LOOKUP, newline='', encoding='utf-8') as handle:
            rows = list(csv.DictReader(handle))
    except (OSError, ValueError):
        raise Refused('cannot read lookups/pseudoco_identity_personas.csv to check --persona against')
    names = {str(row.get('identity') or '').split('|')[0].strip().lower() for row in rows}
    names.discard('')
    if not names:
        raise Refused('lookups/pseudoco_identity_personas.csv names no persona in its identity column')
    return names


def check_personas(values, allow_unlisted=False, known=None):
    """The personas to copy, as identity join keys. A persona is a lab persona
    username (lab5.PERSONA_RE), never a participant account (l5-...), and is in
    the lookup unless --allow-unlisted-persona."""
    names = sorted({str(value).strip().lower() for value in values or ()})
    if not names:
        raise Refused('--persona: name at least one persona, for example nina.osei')
    for name in names:
        if name.startswith('l5-') or not lab5.PERSONA_RE.fullmatch(name):
            raise Refused('--persona: expected a lab persona username such as nina.osei, never a participant '
                          'account (the value is not repeated here)')
    if not allow_unlisted:
        listed = known_personas() if known is None else known
        missing = [name for name in names if name not in listed]
        if missing:
            raise Refused('--persona {}: not in lookups/pseudoco_identity_personas.csv '
                          '(--allow-unlisted-persona copies it anyway)'.format(', '.join(missing)))
    return names


# --- one event: its body, its id, its time ------------------------------------

def _no_constant(name):
    raise ValueError('NaN and Infinity are not JSON')


def parse_body(raw):
    """(body, keys): the JSON object an assistant event is, and its top-level
    keys in the order they were written. Refused: text that is not one JSON
    object from "{" to "}", NaN or Infinity (HEC would refuse them), and a
    second occurrence of a top-level key this tool reads (Python would read
    the last value and Splunk both). Any other text is taken as it is: odd
    spacing, a line break between two keys, an unread key written twice."""
    if not isinstance(raw, str) or not (raw.startswith('{') and raw.endswith('}')):
        raise Refused('an event text is not one JSON object from "{" to "}"')
    seen = []

    def remember(pairs):
        seen.append(pairs)
        return dict(pairs)

    try:
        body = json.loads(raw, object_pairs_hook=remember, parse_constant=_no_constant)
    except (ValueError, RecursionError):
        raise Refused('an event text is not valid JSON')
    keys = [key for key, _ in seen[-1]]          # the outermost object is decoded last
    if any(keys.count(key) > 1 for key in READ_KEYS):
        raise Refused('an event text names twice a top-level key that decides what is copied')
    return body, keys


def own_id(body, keys, log_type=None):
    """(id key, id) of an assistant event: exactly one of audit_id,
    escalation_id and event_id, as the FIRST key, holding a UUID. The id is the
    idempotency key, and "first key" is what tells an assistant event from a
    record that only quotes one (a scoring or response-action write-back)."""
    present = [key for key in keys if key in ID_KEYS]
    if len(present) != 1 or keys[0] != present[0]:
        raise Refused('an event does not open with exactly one of audit_id, escalation_id, event_id')
    key, value = present[0], body[present[0]]
    if not isinstance(value, str) or not UUID_RE.fullmatch(value):
        raise Refused('an event id is not a UUID as the assistant writes it')
    if log_type is not None and ID_KEY_OF.get(log_type) != key:
        raise Refused('event {}: log_type {} is not identified by {}'.format(value, log_type, key))
    return key, value


def forwarder_time(body):
    """The HEC time the assistant's forwarder gives an event (backend/hec/
    forwarder.py): the body's ISO timestamp, a naive one read as UTC, rounded
    to the millisecond. None when the body has no timestamp of that shape (the
    forwarder then stamps the send time, which no copy can reproduce)."""
    stamp = body.get('timestamp')
    if not isinstance(stamp, str) or not STAMP_RE.fullmatch(stamp):
        return None
    try:
        when = datetime.datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return round(when.timestamp(), 3)


def is_scoring_sourcetype(sourcetype):
    return any(fnmatch.fnmatchcase(sourcetype, pattern) for pattern in SCORING_SOURCETYPES)


def describe(event):
    """What a listing may say about an event: log_type, action or operation,
    and two flags. Words only; a value that is not a plain word shows as '-'."""
    body, _ = parse_body(event['raw'])
    what = body.get('action') if event['log_type'] == 'audit' else body.get('operation_name')
    what = what if isinstance(what, str) and WORD_RE.fullmatch(what) else '-'
    flags = [name for name, key in (('blocked', 'policy_blocked'), ('verified', 'identity_verified'))
             if body.get(key) is True]
    return ' '.join([event['log_type'], what] + flags)


# --- the HEC line --------------------------------------------------------------

PLACEHOLDER_BUNDLE_ID = 'rs-00000000-000000000000'    # as long as any bundle id: for size checks before one exists


def check_event(event):
    """The checks every use of a bundle event starts with: the stored text
    still has its sha256, and the time and metadata are plain values that can
    be written into a HEC line and quoted into a search."""
    if not isinstance(event, dict):
        raise Refused('a bundle event is not an object')
    ident = event.get('id')
    if not isinstance(ident, str) or not UUID_RE.fullmatch(ident):
        raise Refused('a bundle event has no UUID id')
    raw = event.get('raw')
    if not isinstance(raw, str) or sha256_text(raw) != event.get('sha256'):
        raise Refused('event {} no longer matches its sha256'.format(ident))
    if not (raw.startswith('{') and raw.endswith('}')):
        raise Refused('event {} is not one JSON object from "{{" to "}}"'.format(ident))
    if not isinstance(event.get('time'), str) or not TIME_RE.fullmatch(event['time']):
        raise Refused('event {} has a malformed time'.format(ident))
    for name, pattern in (('host', META_RE), ('source', META_RE), ('sourcetype', META_RE), ('index', INDEX_RE)):
        if not isinstance(event.get(name), str) or not pattern.fullmatch(event[name]):
            raise Refused('event {}: {} is missing or not a plain value'.format(ident, name))
    if event.get('log_type') not in LOG_TYPES or event.get('id_key') != ID_KEY_OF[event['log_type']]:
        raise Refused('event {} has no known log_type with its id key'.format(ident))
    indexed = event.get('origin_indextime')
    if not isinstance(indexed, int) or isinstance(indexed, bool) or indexed <= 0:
        raise Refused('event {} has no original index time'.format(ident))
    return event


def _envelope(event, fields):
    """The assistant's own envelope, key for key (backend/hec/forwarder.py
    _build_event, written compact by backend/hec/client.py). The time is the
    bare text of tostring(_time) and the event is the stored _raw text itself:
    neither is parsed and written out again, so the bytes sent are the bytes
    that were hashed."""
    line = ''.join(('{"time":', event['time'],
                    ',"host":', json.dumps(event['host']),
                    ',"source":', json.dumps(event['source']),
                    ',"sourcetype":', json.dumps(event['sourcetype']),
                    ',"index":', json.dumps(event['index']),
                    ',"event":', event['raw'],
                    ',"fields":', fields, '}'))
    try:
        json.loads(line, parse_constant=_no_constant)       # the line as a whole must be valid JSON
    except (ValueError, RecursionError):
        raise Refused('event {} does not make a valid HEC line'.format(event['id']))
    return line


def event_line(event, bundle_id):
    """One line of a HEC /services/collector/event request for a re-sent
    event: the assistant's envelope plus the three label fields."""
    check_event(event)
    if not isinstance(bundle_id, str) or not BUNDLE_ID_RE.fullmatch(bundle_id):
        raise Refused('not a bundle id: an event is never sent without its label')
    fields = '{{"log_type":{},"{}":"true","{}":{},"{}":"{}"}}'.format(
        json.dumps(event['log_type']), LABEL_FLAG, LABEL_BUNDLE, json.dumps(bundle_id), LABEL_ORIGIN,
        event['origin_indextime'])
    return _envelope(event, fields)


def assistant_line(event):
    """The line the assistant itself sent for this event: the same envelope
    with log_type as its only field. This tool never sends it. It exists for
    the golden-line contract test, which compares it with what the assistant's
    own forwarder builds."""
    check_event(event)
    return _envelope(event, '{{"log_type":{}}}'.format(json.dumps(event['log_type'])))


# body: the request's bytes, one line per event, joined by "\n". An event text
# may itself hold a line break (JSON allows one between two keys), so a body is
# never split on line breaks again: a reader decodes one JSON object after another.
Batch = collections.namedtuple('Batch', 'events body')


def ordered(events):
    """Events in time order, the id breaking ties, whatever order they came in."""
    try:
        return sorted(events, key=lambda event: (decimal.Decimal(event['time']), event['id']))
    except (decimal.InvalidOperation, KeyError, TypeError, ValueError):
        raise Refused('an event has no plain time and id to be put in order by')


def make_batch(events, bundle_id):
    events = list(events)
    return Batch(events, '\n'.join(event_line(event, bundle_id) for event in events).encode('utf-8'))


def batches(events, bundle_id, max_events=MAX_REQUEST_EVENTS, max_bytes=MAX_REQUEST_BYTES):
    """The requests for these events, in time order: at most max_events lines
    and max_bytes each. An event whose own line is larger than max_bytes (and
    under MAX_EVENT_BYTES, which export enforces) travels alone."""
    out, current, size = [], [], 0
    for event in ordered(events):
        length = len(event_line(event, bundle_id).encode('utf-8'))
        if current and (len(current) >= max_events or size + 1 + length > max_bytes):
            out.append(make_batch(current, bundle_id))
            current, size = [], 0
        size += length + (1 if current else 0)
        current.append(event)
    if current:
        out.append(make_batch(current, bundle_id))
    return out


def halve(batch, bundle_id):
    """The two requests that replace one HEC answered 413 to. One event alone
    cannot be made smaller: that is a refusal, and nothing of it was indexed."""
    if len(batch.events) < 2:
        raise Refused('event {} alone is larger than this HEC accepts in one request'.format(batch.events[0]['id']))
    middle = len(batch.events) // 2
    return make_batch(batch.events[:middle], bundle_id), make_batch(batch.events[middle:], bundle_id)


# --- eligibility: one row of the export search --------------------------------

# What the export search (S3) tables for each event.
ROW_FIELDS = ('rs_time', 'rs_indextime', 'rs_sha256', 'rs_len', 'index', 'host', 'source', 'sourcetype',
              'rs_log_type', 'rs_bundle', '_raw')


def read_row(row):
    """(raw, body, keys, time text) of one export row, after the checks every
    row gets, selected or not: a time the window can be cut on, and a _raw that
    arrived as Splunk holds it. Splunk computes sha256(_raw) and len(_raw) in
    the same search (len counts characters, as Python's does)."""
    time_text = row.get('rs_time')
    if not isinstance(time_text, str) or not TIME_RE.fullmatch(time_text):
        raise Refused('the export search returned an event without a plain _time')
    raw = row.get('_raw')
    if not isinstance(raw, str) or not raw:
        raise Refused('the export search returned no _raw for the event at {}'.format(time_text))
    if sha256_text(raw) != row.get('rs_sha256') or as_int(row.get('rs_len')) != len(raw):
        raise Refused('_raw of the event at {} arrived altered: its sha256 or its length differs from what '
                      'Splunk computed'.format(time_text))
    try:
        body, keys = parse_body(raw)
    except Refused as exc:
        raise Refused('the event at {}: {}'.format(time_text, exc))
    return raw, body, keys, time_text


def event_from_row(row, source, now, parsed=None):
    """One bundle event from one row of the export search, or Refused. Every
    rule of an eligible event is checked here, so that nothing is dropped
    silently later: one indexed log_type of the assistant; the assistant's
    source; not a scoring sourcetype; not itself a re-sent copy and no label
    key in its body; exactly one id, as the first key, of the kind its log_type
    has; _time equal to the body's timestamp by the forwarder's rule; older
    than 15 minutes; a HEC line of at most MAX_EVENT_BYTES."""
    raw, body, keys, time_text = parsed or read_row(row)
    where = 'the event at {}'.format(time_text)
    log_type = one(row.get('rs_log_type'))
    if log_type not in LOG_TYPES:
        raise Refused('{} has no single indexed log_type of the assistant'.format(where))
    event = {'time': time_text, 'log_type': log_type, 'sha256': row['rs_sha256'], 'chars': len(raw),
             'bytes': len(raw.encode('utf-8')), 'raw': raw}
    for name, pattern in (('host', META_RE), ('source', META_RE), ('sourcetype', META_RE), ('index', INDEX_RE)):
        value = row.get(name)
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise Refused('{}: {} is missing or not a plain value'.format(where, name))
        event[name] = value
    if event['source'] != source:
        raise Refused('{} does not come from the source named with --event-source'.format(where))
    if is_scoring_sourcetype(event['sourcetype']):
        raise Refused('{} is a scoring or response write-back, not an assistant event'.format(where))
    if row.get('rs_bundle') != NO_LABEL:
        raise Refused('{} is itself a re-sent copy (it carries resend_bundle): export from the Splunk that got '
                      'it live'.format(where))
    try:
        event['id_key'], event['id'] = own_id(body, keys, log_type)
    except Refused as exc:
        raise Refused('{}: {}'.format(where, exc))
    ident = event['id']
    if any(name in body for name in LABEL_FIELDS):
        raise Refused('event {}: its body has a key named like the re-send label'.format(ident))
    stamp = forwarder_time(body)
    if stamp is None or decimal.Decimal(repr(stamp)) != decimal.Decimal(time_text):
        raise Refused('event {}: _time is not the timestamp in its body by the forwarder\'s rule'.format(ident))
    event['origin_indextime'] = as_int(row.get('rs_indextime'), 0)
    if event['origin_indextime'] <= 0:
        raise Refused('event {}: the export search returned no index time'.format(ident))
    if now - float(time_text) < MIN_AGE_SECONDS:
        raise Refused('event {} is younger than {} minutes: wait, a rule with a recency test would read its '
                      'copy as live'.format(ident, MIN_AGE_SECONDS // 60))
    if len(event_line(event, PLACEHOLDER_BUNDLE_ID).encode('utf-8')) > MAX_EVENT_BYTES:
        raise Refused('event {} makes a HEC line of more than {} bytes'.format(ident, MAX_EVENT_BYTES))
    return event


# --- selection: the staged set -------------------------------------------------

Selection = collections.namedtuple('Selection', 'events left_out notes')
# The census search S1 labels the selection with these four values, in this order:
# rs_where, rs_host, rs_who, rs_kind.
CENSUS_SELECTED = ('in the window', 'selected host', 'selected persona', 'eligible')


def select_events(rows, personas, t_from, t_to, source, now, exact_window=False, allow_partial_session=False):
    """The staged set: the eligible events of the named personas in
    [t_from, t_to), out of the rows of the export search. The rows may reach
    past either end of the window (at least EDGE_GUARD_SECONDS, so the two
    guards have something to look at).

    The persona is read here, from the parsed body, never in SPL: spath stops
    at extraction_cutoff characters and would drop an event silently.

    Refused, and the whole export with it: an event of a persona that is not
    eligible; one id twice; an event of a persona within EDGE_GUARD_SECONDS
    outside the window, unless exact_window (a pass is not cut in two by
    accident); an event that is not selected but shares its session_id with
    one that is, unless allow_partial_session. Events of other identities are
    counted and never named."""
    wanted = set(personas)
    selected, sessions, other_sessions, edge = [], set(), [], 0
    left_out = collections.OrderedDict((('other identities', 0), ('no user', 0), ('outside the window', 0)))
    for row in rows:
        parsed = read_row(row)
        body, when = parsed[1], decimal.Decimal(parsed[3])
        actor, session = actor_of(body), body.get('session_id')
        session = session if isinstance(session, str) and session else None
        inside = t_from <= when < t_to
        if inside and actor in wanted:
            selected.append(event_from_row(row, source, now, parsed))
            sessions.add(session)
            continue
        other_sessions.append(session)
        if actor in wanted:
            left_out['outside the window'] += 1
            edge += 1 if t_from - EDGE_GUARD_SECONDS <= when <= t_to + EDGE_GUARD_SECONDS else 0
        elif inside:
            left_out['other identities' if actor else 'no user'] += 1
    if not selected:
        raise Refused('no event of {} in the window: nothing to export'.format(', '.join(sorted(wanted))))
    if len({event['id'] for event in selected}) != len(selected):
        raise Refused('an event id occurs twice in the selection: it cannot serve as the idempotency key')
    notes = []
    if edge and not exact_window:
        raise Refused('{} event(s) of the persona lie within {} s outside the window: widen it so that no pass '
                      'is cut in two, or pass --exact-window'.format(edge, EDGE_GUARD_SECONDS))
    if edge:
        notes.append('--exact-window: {} event(s) of the persona within {} s outside the window are not '
                     'copied'.format(edge, EDGE_GUARD_SECONDS))
    sessions.discard(None)
    shared = sum(1 for session in other_sessions if session in sessions)
    if shared and not allow_partial_session:
        raise Refused('{} event(s) that are not selected share a session with selected ones (another identity, '
                      'no user, or outside the window): pass --allow-partial-session to copy the persona\'s '
                      'part of those sessions only'.format(shared))
    if shared:
        notes.append('--allow-partial-session: {} event(s) of the selected sessions are not copied'.format(shared))
    return Selection(ordered(selected), left_out, notes)


def census_eligible(census_rows):
    """How many events the census search S1 counted as the selection. The
    export refuses when this is not the number select_events() selected."""
    total = 0
    for row in census_rows:
        if tuple(one(row.get(name)) for name in ('rs_where', 'rs_host', 'rs_who', 'rs_kind')) == CENSUS_SELECTED:
            total += as_int(row.get('events'), 0)
    return total


# --- the bundle ------------------------------------------------------------------

EVENT_FIELDS = ('id', 'id_key', 'time', 'host', 'source', 'sourcetype', 'index', 'log_type', 'sha256', 'chars',
                'bytes', 'origin_indextime', 'raw')
BUNDLE_FIELDS = ('format', 'bundle_id', 'digest', 'origin', 'selection', 'census', 'events', 'expect', 'privacy',
                 'review')


def digest(events):
    """sha256 over what a stack will hold of these events, in time order. It
    is the same for every export of the same selection, whatever order the
    rows came in, and differs after a change to any byte of a body, a time, a
    piece of metadata or an original index time."""
    lines = [FORMAT]
    for event in ordered(events):
        check_event(event)
        lines.append('\t'.join((event['id_key'], event['id'], event['time'], event['host'], event['source'],
                                event['sourcetype'], event['index'], event['log_type'], event['sha256'],
                                str(event['origin_indextime']))))
    return sha256_text('\n'.join(lines))


def bundle_id_of(events, dig):
    """rs-<UTC date of the first event>-<first 12 hex digits of the digest>:
    the value of resend_bundle, so a stack's label names the exact bytes."""
    first = ordered(events)[0]
    day = time.strftime('%Y%m%d', time.gmtime(int(decimal.Decimal(first['time']))))
    return 'rs-{}-{}'.format(day, dig[:12])


def privacy_counts(events, is_public=is_public_address):
    """Counts for the review listing, never the values: events that carry a
    client address or message text, distinct addresses, and how many of those
    are public."""
    addresses, with_address, with_text = set(), 0, 0
    for event in events:
        body, _ = parse_body(event['raw'])
        details = body.get('details') if isinstance(body.get('details'), dict) else {}
        found = {value for value in [body.get(key) for key in ADDRESS_KEYS] + [details.get('client_address')]
                 if isinstance(value, str) and value}
        addresses |= found
        with_address += 1 if found else 0
        with_text += 1 if any(body.get(key) for key in TEXT_KEYS) else 0
    return {'events': len(events), 'events_with_client_address': with_address,
            'distinct_client_addresses': len(addresses),
            'public_client_addresses': sum(1 for address in addresses if is_public(address)),
            'events_with_message_text': with_text}


def signin_txids(events):
    """The Duo transaction ids of the application sign-ins in the set
    (details.duo_txid of each identity_signin_success record), sorted. Search
    D1 pairs each with its Duo authentication; they are never printed."""
    found = set()
    for event in events:
        body, _ = parse_body(event['raw'])
        if event['log_type'] != 'audit' or body.get('action') != SIGNIN_ACTION:
            continue
        details = body.get('details') if isinstance(body.get('details'), dict) else {}
        txid = details.get('duo_txid')
        if txid is None:
            continue
        if not isinstance(txid, str) or not TXID_RE.fullmatch(txid):
            raise Refused('event {}: its Duo transaction id is not a plain id'.format(event['id']))
        found.add(txid)
    return sorted(found)


def content_sha256(bundle):
    """sha256 of everything in a bundle but its review stamp. The stamp holds
    it, so an approval covers the census and the expectations too, not only
    the events the digest covers."""
    rest = dict((key, value) for key, value in bundle.items() if key != 'review')
    return sha256_text(json.dumps(rest, sort_keys=True, separators=(',', ':'), ensure_ascii=True))


def bundle_text(bundle):
    """The bundle file's text: ASCII JSON, keys sorted, one event after another in time order."""
    return json.dumps(bundle, indent=1, sort_keys=True, ensure_ascii=True) + '\n'


def check_bundle(bundle):
    """R1's content rules. The format and its exact keys; every event (its
    sha256, its length, the id that opens its text, plain metadata, a HEC line
    that fits); one index; time order; no id twice; the digest and the bundle
    id made from it; the privacy counts; and the four objects export adds, each
    in the exact shape PARTS names and in agreement with the events
    (check_parts). Returns the bundle."""
    if not isinstance(bundle, dict) or bundle.get('format') != FORMAT:
        raise Refused('not a staged-resend bundle of format {}'.format(FORMAT))
    if sorted(bundle) != sorted(BUNDLE_FIELDS):
        raise Refused('the bundle does not hold exactly the keys of its format')
    events = bundle['events']
    if not isinstance(events, list) or not events:
        raise Refused('the bundle holds no event')
    for event in events:
        check_event(event)
        raw, ident = event['raw'], event['id']
        if sorted(event) != sorted(EVENT_FIELDS):
            raise Refused('event {} does not hold exactly the keys of its format'.format(ident))
        if event['chars'] != len(raw) or event['bytes'] != len(raw.encode('utf-8')):
            raise Refused('event {}: its recorded length is not the length of its text'.format(ident))
        body, keys = parse_body(raw)
        if own_id(body, keys, event['log_type']) != (event['id_key'], ident):
            raise Refused('event {}: the id that opens its text is another one'.format(ident))
        if any(name in body for name in LABEL_FIELDS):
            raise Refused('event {}: its body has a key named like the re-send label'.format(ident))
        if len(event_line(event, PLACEHOLDER_BUNDLE_ID).encode('utf-8')) > MAX_EVENT_BYTES:
            raise Refused('event {} makes a HEC line of more than {} bytes'.format(ident, MAX_EVENT_BYTES))
    if events != ordered(events) or len({event['id'] for event in events}) != len(events):
        raise Refused('the bundle\'s events are not in time order, or one id occurs twice')
    if len({event['index'] for event in events}) != 1:
        raise Refused('the bundle\'s events are in more than one index')
    if bundle['digest'] != digest(events) or bundle['bundle_id'] != bundle_id_of(events, bundle['digest']):
        raise Refused('the bundle was edited: its digest or its id no longer matches its events')
    if not all(isinstance(bundle[name], dict) for name in ('origin', 'selection', 'census', 'expect', 'privacy')):
        raise Refused('the bundle\'s origin, selection, census, expect and privacy must be objects')
    check_parts(bundle)
    # public_client_addresses is left out: Python releases differ on a few special address ranges.
    counted = privacy_counts(events)
    if any(bundle['privacy'].get(name) != count for name, count in counted.items()
           if name != 'public_client_addresses'):
        raise Refused('the bundle was edited: its privacy counts are not those of its events')
    review = bundle['review']
    if review is not None and not (isinstance(review, dict) and sorted(review) == ['approved', 'at', 'content']):
        raise Refused('the bundle\'s review stamp is not one this tool wrote')
    try:
        bundle_text(bundle)
    except (TypeError, ValueError):
        raise Refused('the bundle holds a value that is not JSON')
    return bundle


def build_bundle(events, origin, selection, census, expect):
    """The bundle: all that `send` and `verify` need, so that neither reads the
    source again. events are bundle events (event_from_row). The other four
    are what the export read beside them, in the shapes PARTS names:
      origin     the source's server GUID and versions, and when it was read
      selection  what the operator named: hosts, personas, window, index,
                 source and the overrides used
      census     the rows of the census search, and what Python left out
      expect     the E1 row, the chain ids and the Duo counts read on the source
    A new bundle is not approved (review is null)."""
    events = ordered(events)
    if not events:
        raise Refused('a bundle needs at least one event')
    dig = digest(events)
    return check_bundle({'format': FORMAT, 'bundle_id': bundle_id_of(events, dig), 'digest': dig,
                         'origin': origin, 'selection': selection, 'census': census, 'events': events,
                         'expect': expect, 'privacy': privacy_counts(events), 'review': None})


def is_approved(bundle):
    """True when the review stamp is for the bundle exactly as it now is."""
    review = bundle.get('review')
    return (isinstance(review, dict) and review.get('approved') == bundle['digest']
            and review.get('content') == content_sha256(bundle))


def approve(bundle, digest12, now):
    """The bundle with a review stamp. digest12 must be the first 12 hex
    digits of its digest, which the review listing prints."""
    if not isinstance(digest12, str) or digest12 != bundle['digest'][:12]:
        raise Refused('--approve: that is not this bundle\'s digest; read the listing and use the 12 digits it '
                      'prints')
    stamped = dict(bundle)
    stamped['review'] = {'approved': bundle['digest'], 'content': content_sha256(bundle), 'at': int(now)}
    return check_bundle(stamped)


# --- private files: the bundle and the ledger -----------------------------------
# lab5_steps.write_out is not used for them: it writes through a symlink and
# into a file that already exists with a wider mode. A bundle holds whole
# bodies (prompt text, a client address), so it is created exclusively.

_NEW_PRIVATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW


def inside_git_tree(path):
    """True when the folder that holds path, or one above it, is a git work
    tree (it has a .git folder, or a worktree's .git file)."""
    folder = os.path.realpath(os.path.dirname(os.path.abspath(path)))
    while True:
        if os.path.lexists(os.path.join(folder, '.git')):
            return True
        parent = os.path.dirname(folder)
        if parent == folder:
            return False
        folder = parent


def check_new_path(path, what):
    """What export checks before it reads a single body: the file it will
    write lies outside any git work tree and does not exist yet (nothing is
    ever overwritten, and a symlink counts as existing)."""
    if inside_git_tree(path):
        raise Refused('{} would lie inside a git work tree: keep it outside any repository'.format(what))
    if os.path.lexists(path):
        raise Refused('{} already exists: nothing is overwritten, name a new path'.format(what))
    if not os.path.isdir(os.path.dirname(os.path.abspath(path))):
        raise Refused('{}: its folder does not exist'.format(what))


def _check_private(info, what):
    if not stat.S_ISREG(info.st_mode):
        raise Refused('{} is not a regular file'.format(what))
    if info.st_uid != os.getuid():
        raise Refused('{} belongs to another user'.format(what))
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise Refused('{} is readable or writable by others (mode {:o}): chmod 600 it'.format(
            what, stat.S_IMODE(info.st_mode)))


def write_new_private(path, text, what):
    """Create path with mode 0600 and write text into it. O_EXCL and
    O_NOFOLLOW: never through a symlink and never into an existing file."""
    check_new_path(path, what)
    try:
        fd = os.open(path, _NEW_PRIVATE, 0o600)
    except OSError:
        raise Refused('{} cannot be created (it exists, is a symlink, or its folder is not writable)'.format(what))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        os.unlink(path)
        raise


def read_private(path, what):
    """The text of a private file: a regular file of this user with no group
    or other bit, opened with O_NOFOLLOW and checked on the open descriptor
    (O_NONBLOCK so that a FIFO at the path is refused instead of waited on)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise Refused('{} cannot be read (missing, or a symlink)'.format(what))
    try:
        _check_private(os.fstat(fd), what)
    except Refused:
        os.close(fd)
        raise
    with os.fdopen(fd, 'r', encoding='utf-8') as handle:
        try:
            return handle.read()
        except ValueError:
            raise Refused('{} is not UTF-8 text'.format(what))


def replace_private(path, text, what):
    """Rewrite an existing private file in one step (review --approve): a new
    file created exclusively beside it, then os.replace. Replacing never writes
    through a symlink, and a reader sees the old text or the new, never half."""
    try:
        _check_private(os.lstat(path), what)
    except OSError:
        raise Refused('{} cannot be read (missing)'.format(what))
    temp = os.path.join(os.path.dirname(os.path.abspath(path)),
                        '.{}.{}.tmp'.format(os.path.basename(path), os.getpid()))
    try:
        fd = os.open(temp, _NEW_PRIVATE, 0o600)
    except OSError:
        raise Refused('{} cannot be rewritten: its folder is not writable'.format(what))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        if os.path.lexists(temp):
            os.unlink(temp)
        raise


def open_private_append(path, what):
    """An append-only private file, for the ledger: created 0600 when missing,
    never opened through a symlink (O_NOFOLLOW), and refused when an existing
    one is wider than 0600, another user's or not a regular file. Returns a
    text file open for reading and appending; the caller locks it before it
    reads a line."""
    if inside_git_tree(path):
        raise Refused('{} would lie inside a git work tree: keep it outside any repository'.format(what))
    try:
        fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise Refused('{} cannot be opened (a symlink, or its folder is not writable)'.format(what))
    try:
        _check_private(os.fstat(fd), what)
    except Refused:
        os.close(fd)
        raise
    return os.fdopen(fd, 'a+', encoding='utf-8')


def ledger_path(bundle_path):
    """<bundle>.ledger.jsonl, beside the bundle: what was handed to which stack."""
    return os.path.abspath(bundle_path) + '.ledger.jsonl'


def write_bundle(path, bundle):
    """Write a new bundle file (0600, exclusive). An existing path is refused."""
    write_new_private(path, bundle_text(check_bundle(bundle)), '--bundle')


def load_bundle(path, need_approval=False):
    """R1. The bundle is a private regular file outside any git work tree (not
    a symlink, mode 0600), its digest and every sha256 hold, and, for send and
    verify, it is approved exactly as it now is."""
    if inside_git_tree(path):
        raise Refused('--bundle lies inside a git work tree: move it out of the repository')
    try:
        bundle = json.loads(read_private(path, '--bundle'))
    except (ValueError, RecursionError):
        raise Refused('--bundle is not a JSON file')
    check_bundle(bundle)
    if need_approval and not is_approved(bundle):
        raise Refused('--bundle is not approved as it now is: read `review --bundle ...`, then approve it with '
                      '--approve {}'.format(bundle['digest'][:12]))
    return bundle


# --- the decision table: what a stack already holds ------------------------------

SEND, LIVE, THIS_BUNDLE, OTHER_BUNDLE, CONFLICT, DUPLICATE = (
    'send', 'live', 'this-bundle', 'other-bundle', 'conflict', 'duplicate')
SKIP_VERDICTS = (LIVE, THIS_BUNDLE, OTHER_BUNDLE)       # the event is there, identical: never sent again
STOP_VERDICTS = (CONFLICT, DUPLICATE)                   # the whole run stops and nothing is sent
Decision = collections.namedtuple('Decision', 'verdict differs')
_COMPARED = ('sha256', 'host', 'source', 'sourcetype', 'index', 'log_type')


def decide(event, row, bundle_id):
    """What to do with one event, from the stack's row of the presence search
    (P1) for its id, or None when the search returned no row for it.

        nothing                              send
        one copy, identical, no label        live           skip: delivered live
        one copy, identical, with a label    this-bundle    skip: re-sent before
                                             other-bundle   (by another bundle)
        one copy that differs                conflict       stop, nothing is sent
        more than one copy                   duplicate      stop

    Identical: equal sha256 of _raw, time to the millisecond (printf "%.3f",
    never tostring's text), host, source, sourcetype, index and log_type. So a
    copy under another sourcetype (a stack whose HEC destination wrote one
    sourcetype for everything) is a conflict, not a skip. Every value arrives
    as a string or a list of strings and a column may be missing: a row that
    lacks a column or holds two values in one differs, so a malformed answer
    never reads as "send" or as "skip"."""
    if row is None:
        return Decision(SEND, ())
    copies = as_int(row.get('copies'))
    if copies is None or copies < 1:
        return Decision(CONFLICT, ('copies',))
    if copies > 1:
        return Decision(DUPLICATE, ())
    differs = [name for name in _COMPARED if as_list(row.get(name)) != [event[name]]]
    when = one(row.get('time'))
    if when is None or not TIME_RE.fullmatch(when) or time_3f(when) != time_3f(event['time']):
        differs.append('time')
    label = one(row.get(LABEL_BUNDLE))
    if label is None:
        differs.append(LABEL_BUNDLE)
    if differs:
        return Decision(CONFLICT, tuple(differs))
    if label == NO_LABEL:
        return Decision(LIVE, ())
    return Decision(THIS_BUNDLE if label == bundle_id else OTHER_BUNDLE, ())


def rows_by_id(rows):
    """{id: row} of the presence search's rows. One id in two rows (it should
    never happen) adds its copies up, which decide() reads as a duplicate."""
    found = {}
    for row in rows:
        ident = one(row.get('rs_id'))
        if ident is None or not UUID_RE.fullmatch(ident):
            raise Refused('the presence search returned a row without one event id')
        if ident in found:
            row = dict(row, copies=str(max(2, as_int(found[ident].get('copies'), 1) + as_int(row.get('copies'), 1))))
        found[ident] = row
    return found


def plan(events, rows, bundle_id):
    """{id: Decision} for a set of events, in time order, from the rows of the
    presence search over all of them."""
    found = rows_by_id(rows)
    return collections.OrderedDict((event['id'], decide(event, found.get(event['id']), bundle_id))
                                   for event in ordered(events))


def plan_counts(decisions):
    """{verdict: how many}, for the one line a run prints about its plan."""
    counts = collections.OrderedDict((verdict, 0) for verdict in (SEND,) + SKIP_VERDICTS + STOP_VERDICTS)
    for decision in decisions.values():
        counts[decision.verdict] += 1
    return counts


# --- the HEC answer ----------------------------------------------------------------

ACCEPTED, NOT_SENT, REFUSED, TOO_LARGE, UNKNOWN = 'accepted', 'not sent', 'refused', 'too large', 'unknown'
Outcome = collections.namedtuple('Outcome', 'state http code detail')

# Splunk's HEC code table (Troubleshoot HTTP Event Collector). The text shown
# for an answer comes from here, never from the answer, which is not printed.
HEC_TEXT = {
    0: 'Success', 1: 'Token disabled', 2: 'Token is required', 3: 'Invalid authorization', 4: 'Invalid token',
    5: 'No data', 6: 'Invalid data format', 7: 'Incorrect index', 8: 'Internal server error', 9: 'Server is busy',
    10: 'Data channel is missing', 11: 'Invalid data channel', 12: 'Event field is required',
    13: 'Event field cannot be blank', 14: 'ACK is disabled', 15: 'Error in handling indexed fields',
    16: 'Query string authorization is not enabled', 17: 'HEC is healthy', 18: 'HEC is unhealthy, queues are full',
    19: 'HEC is unhealthy, ack service unavailable',
    20: 'HEC is unhealthy, queues are full, ack service unavailable', 21: 'Invalid token', 22: 'Token disabled',
    23: 'Server is shutting down', 24: 'Queue is approaching capacity', 25: 'ACK is approaching capacity',
    26: 'Queue is at capacity', 27: 'ACK channel is at capacity'}
ACCEPTED_CODES = (0, 24, 25)                                  # with HTTP 200; 24 and 25 are accepted too
NOT_SENT_PAIRS = ((503, 9), (503, 23), (429, 26), (429, 27))  # HEC's own "nothing was taken", by exact pair
REQUEST_REFUSED_CODES = (5, 10, 11, 14, 16, 21, 22)           # with HTTP 400: the whole request
EVENT_REFUSED_CODES = (6, 7, 12, 13, 15)                      # with HTTP 400: from one event on


def classify_answer(status, text):
    """One HEC answer -> Outcome.

        accepted    200 with code 0, 24 or 25               never sent again
        not sent    503 with code 9 or 23,                  retry after RETRY_WAITS
                    429 with code 26 or 27
        refused     401, 403; 400 with code 5, 10, 11,      stop: nothing was indexed
                    14, 16, 21, 22; 400 with code 6, 7,
                    12, 13, 15 at event 0
        too large   413                                     halve the request
        unknown     everything else                         never sent again in any run
                                                            until the stack shows it absent
                                                            and the operator overrides

    "Everything else" is the point. A 503 or 429 without one of HEC's four
    codes (an HTML page from a gateway, an empty body), any other 5xx, a 3xx,
    404, 408, a 400 past event 0 and a 200 without code 0, 24 or 25 are not
    answers HEC gives for a request it did not take, so the request may have
    been indexed. Retrying on the status alone is how one event becomes five."""
    code, number = None, None
    try:
        answer = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        answer = None
    if isinstance(answer, dict):
        code, number = answer.get('code'), answer.get('invalid-event-number')
    code = code if isinstance(code, int) and not isinstance(code, bool) else None
    number = number if isinstance(number, int) and not isinstance(number, bool) else None
    if status == 200 and code in ACCEPTED_CODES:
        state = ACCEPTED
    elif status in (401, 403):
        state = REFUSED
    elif status == 413:
        state = TOO_LARGE
    elif (status, code) in NOT_SENT_PAIRS:
        state = NOT_SENT
    elif status == 400 and (code in REQUEST_REFUSED_CODES or (code in EVENT_REFUSED_CODES and number == 0)):
        state = REFUSED
    else:
        state = UNKNOWN
    named = 'no HEC code' if code is None else 'HEC code {} ({})'.format(code, HEC_TEXT.get(code, 'not in the table'))
    detail = 'HTTP {}, {}{}'.format(status, named, '' if number is None else ', at event {}'.format(number))
    return Outcome(state, status, code, detail)


def not_sent(reason):
    """No request left this machine: connect, DNS or TLS failed first."""
    return Outcome(NOT_SENT, None, None, 'no request left this machine ({})'.format(reason))


def unknown(reason):
    """The request left and no answer was read: a timeout or a reset."""
    return Outcome(UNKNOWN, None, None, 'the request left and no answer came back ({})'.format(reason))


def as_search(text):
    """A search text as splunkd's search/jobs wants it. Text that opens with a
    generating command ("| tstats ...") goes as it is; anything else needs a
    leading `search `. A saved rule's text can be either: 47 of the 115 shipped
    searches open with a pipe, and `search | tstats` is a FATAL error."""
    body = str(text or '').strip()
    if not body:
        raise Refused('an empty search text')
    return body if body.startswith('|') else 'search ' + body


# --- splunkd: the credential, the certificate and the one REST client -------------

USER_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._@-]{0,63}')
SPL_VALUE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/@ -]{0,255}')   # what may stand between two quotes in a search
SEARCH_PATH = '/servicesNS/nobody/{}/search/jobs'.format(APP)       # the TA's namespace: its macros resolve there
SEARCH_TIMEOUT = 300
WARN_RETRIES = 2                    # a search that answers with a WARN is run again, at most this often
WARN_PAUSE = 3                      # seconds between those runs
MAX_SEARCH_ROWS = 20000             # splunkd cuts an answer at maxresultrows (50,000) without saying so


def safe_text(text, hidden=()):
    """A server's message as it may be printed: printable ASCII, at most 240
    characters, and without any value in hidden (a Duo transaction id that the
    search text carried and an error message could quote back)."""
    shown = str(text if text is not None else '')
    for value in sorted({str(item) for item in hidden if item}, key=len, reverse=True):
        shown = shown.replace(value, '<hidden>')
    shown = ''.join(ch if ' ' <= ch <= '~' else ' ' for ch in shown)
    shown = ' '.join(shown.split())
    return shown[:240] + ('...' if len(shown) > 240 else '')


def credential(env, password_name, token_name):
    """('password' | 'token', value) from the environment, the only place a
    Splunk credential comes from. Exactly one of the two variables must be
    set: with both, the tool does not guess which one is meant. The value is
    never printed and never part of a refusal."""
    password, token = env.get(password_name) or '', env.get(token_name) or ''
    if bool(password) == bool(token):
        raise Refused('set exactly one of ${} and ${} in the environment ({}); no option takes a secret'.format(
            password_name, token_name, 'both are set' if password else 'neither is set'))
    kind, value = ('password', password) if password else ('token', token)
    if value != value.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise Refused('${}: the value starts or ends with a space, or holds a line break; set it again '
                      '(`read -rs` keeps it off the screen)'.format(password_name if password else token_name))
    return kind, value


def tls_policy(scheme, host, ca_file, no_verify, override):
    """(verify, what the run says about it) for a splunkd address. The
    certificate is verified against the system trust store, and against
    --ca-file too when one is given. It is not verified on the named override,
    and by default not for a loopback address (a CA file turns it on there)."""
    if scheme != 'https':
        return False, 'plain http to a loopback address, no certificate'
    if no_verify:
        return False, 'NOT VERIFIED ({}): the credential goes to a server nobody authenticated'.format(override)
    if ca_file:
        return True, 'verified against the system trust store and --ca-file'
    if is_loopback(host):
        return False, 'not verified (a loopback address; {} is not needed)'.format(override)
    return True, 'verified against the system trust store'


def failure_text(exc):
    """What may be said about a call that got no answer: the kind of failure.
    An exception's own text is never used, except OpenSSL's reason for a
    certificate: http.client quotes a bad header value in its ValueError, and
    the header holds the credential."""
    reason = getattr(exc, 'reason', exc)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return 'the certificate did not verify ({})'.format(safe_text(getattr(reason, 'verify_message', '')))
    if isinstance(reason, ssl.SSLError):
        return 'TLS failed ({})'.format(type(reason).__name__)
    if isinstance(reason, socket.timeout):
        return 'no answer in time'
    if isinstance(reason, OSError):
        return 'no connection ({})'.format(type(reason).__name__)
    return 'the request failed ({})'.format(type(exc).__name__)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx is an answer, never a new request: urllib would follow it and
    carry the Authorization header to whatever server the Location names."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Splunkd(seed.Splunkd):
    """seed.Splunkd as this tool needs it. The certificate is verified unless
    tls_policy() says otherwise, --ca-file is trusted in addition to the system
    store, a token travels as Bearer, a redirect is never followed, plain http
    is accepted for a loopback address only (split_url), and there is no dry
    run (seed's prints POST bodies). A call that got no answer returns
    (0, text), and that text is safe to print."""

    def __init__(self, url, flag, kind, secret, username, verify, ca_file=None, override=None):
        scheme, host, port, path = split_url(url, flag, 8089)
        if path not in ('', '/'):
            raise Refused('{}: expected the management address alone, https://<host>[:port], with no path'.format(flag))
        if kind == 'password' and not USER_RE.fullmatch(str(username or '')):
            raise Refused('the user name that goes with {} is not a plain account name (the value is not '
                          'repeated here)'.format(flag))
        address = '{}://{}:{}'.format(scheme, '[{}]'.format(host) if ':' in host else host, port)
        seed.Splunkd.__init__(self, address, session_key=secret if kind == 'token' else None,
                              username=username if kind == 'password' else None,
                              password=secret if kind == 'password' else None, verify=bool(verify), dry_run=False)
        self.flag, self.override, self.host = flag, override, host
        if ca_file and scheme == 'https':
            try:
                self.ctx.load_verify_locations(ca_file)
            except (OSError, ValueError, ssl.SSLError):
                raise Refused('--ca-file cannot be read as a CA bundle (PEM certificates)')
        handlers = [_NoRedirect(), urllib.request.HTTPSHandler(context=self.ctx)]
        if is_loopback(host):
            handlers.append(urllib.request.ProxyHandler({}))       # a loopback address is never reached through a proxy
        self.opener = urllib.request.build_opener(*handlers)

    def __repr__(self):
        return 'Splunkd({})'.format(self.flag)                     # never the credential

    def _headers(self, json_body=False):
        if self.session_key:
            return {'Authorization': 'Bearer {}'.format(self.session_key)}
        return seed.Splunkd._headers(self)

    def call(self, path, method='GET', data=None, json_body=None, timeout=60):
        """(HTTP status, text). Form data only; output_mode=json on every URL."""
        if json_body is not None or not (data is None or isinstance(data, dict)):
            raise Refused('a bug in this tool: its splunkd client sends form data only')
        url = '{}{}{}output_mode=json'.format(self.mgmt, path, '&' if '?' in path else '?')
        headers, body = self._headers(), None
        if data is not None:
            body = urllib.parse.urlencode(data, doseq=True).encode('utf-8')
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        try:
            request = urllib.request.Request(url, data=body, method=method, headers=headers)
            with self.opener.open(request, timeout=timeout) as answer:
                return answer.getcode(), answer.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read().decode('utf-8', 'replace')
            except Exception:                                      # the answer's body could not be read
                return exc.code, ''
            finally:
                exc.close()
        except Exception as exc:                                   # network, TLS, a malformed header
            return 0, failure_text(exc)

    def failure(self, what, code, text, hidden=()):
        """The refusal for a call that did not answer 200. Never the answer's
        body as a whole: its first message, cleaned, and nothing else."""
        if code == 0:
            hint = ''
            if 'certificate' in text:
                hint = ': pass the CA that signed it with --ca-file' + (
                    ', or name the risk with {}'.format(self.override) if self.override else '')
            return Refused('{}: no answer from {} ({}){}'.format(what, self.flag, text, hint))
        if 300 <= code < 400:
            return Refused('{}: {} answered HTTP {}, a redirect. It is never followed (the credential would go '
                           'with it): give the management port itself'.format(what, self.flag, code))
        if code == 401:
            return Refused('{}: {} did not accept the credential (HTTP 401). With a password, check the user '
                           'name option'.format(what, self.flag))
        return Refused('{}: {} answered HTTP {}{}'.format(what, self.flag, code, first_message(text, hidden)))

    def content(self, path, what):
        """The content object of a one-entry answer; None when splunkd answers 404."""
        code, text = self.call(path)
        if code == 404:
            return None
        if code != 200:
            raise self.failure(what, code, text)
        try:
            found = json.loads(text)['entry'][0]['content']
        except (ValueError, KeyError, IndexError, TypeError, RecursionError):
            found = None
        if not isinstance(found, dict):
            raise Refused('{}: the answer of {} is not what splunkd writes'.format(what, self.flag))
        return found


def job_messages(answer):
    """[(TYPE, text)] of a search answer: what splunkd puts in "messages"."""
    found = answer.get('messages') if isinstance(answer, dict) else None
    out = []
    for item in found if isinstance(found, list) else []:
        if isinstance(item, dict):
            out.append((str(item.get('type') or '').upper(), str(item.get('text') or '')))
    return out


def first_message(text, hidden=()):
    """': <the first message of an answer>', cleaned, or '' when there is none."""
    try:
        messages = job_messages(json.loads(text))
    except (ValueError, RecursionError):
        messages = []
    return ': {}'.format(safe_text(messages[0][1], hidden)) if messages and messages[0][1] else ''


def run_search(splunkd, spl, earliest, latest, what, hidden=(), sleep=time.sleep):
    """The rows of one one-shot search: a list of objects whose values are
    strings, lists of strings, or absent (as_list, one and as_int read them).
    Time bounds travel as REST arguments, never inside the text.

    Refused: a text that opens with neither "search " nor "|" (splunkd reads
    `((a) OR b)` as an unknown command; the conditional prefix is as_search);
    any answer that is not HTTP 200 with a JSON list of results (a parse error
    is HTTP 400 with a FATAL message); a FATAL or ERROR message; MAX_SEARCH_ROWS
    rows or more; and a WARN that is still there after WARN_RETRIES more runs.
    splunkd attaches a warning about its own start-up time to correct answers
    when the machine is busy, so one WARN means "ask again", but an answer is
    only ever taken from a run without one. hidden: values the text carries
    that no message may quote back."""
    if not isinstance(spl, str) or not (spl.startswith('search ') or spl.startswith('|')):
        raise Refused('{}: a bug in this tool, its search text opens with neither "search " nor "|": nothing '
                      'was dispatched'.format(what))
    form = {'search': spl, 'exec_mode': 'oneshot', 'earliest_time': str(earliest), 'latest_time': str(latest),
            'count': '0'}
    warning = ''
    for attempt in range(WARN_RETRIES + 1):
        if attempt:
            sleep(WARN_PAUSE)
        code, text = splunkd.call(SEARCH_PATH, 'POST', data=form, timeout=SEARCH_TIMEOUT)
        if code != 200:
            raise splunkd.failure(what, code, text, hidden)
        try:
            answer = json.loads(text)
        except (ValueError, RecursionError):
            answer = None
        rows = answer.get('results') if isinstance(answer, dict) else None
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise Refused('{}: the search answer of {} is not what splunkd writes'.format(what, splunkd.flag))
        messages = job_messages(answer)
        failed = [body for kind, body in messages if kind in ('FATAL', 'ERROR')]
        if failed:
            raise Refused('{}: the search failed on {}: {}'.format(what, splunkd.flag, safe_text(failed[0], hidden)))
        if len(rows) >= MAX_SEARCH_ROWS:
            raise Refused('{}: the search returned {} rows or more, and splunkd may have cut the answer: narrow '
                          'what is read'.format(what, MAX_SEARCH_ROWS))
        warnings = [body for kind, body in messages if kind == 'WARN']
        if not warnings:
            return rows
        warning = safe_text(warnings[0], hidden)
    raise Refused('{}: the search on {} still answers with a warning after {} runs, so its answer is not used: '
                  '{}'.format(what, splunkd.flag, WARN_RETRIES + 1, warning))


# --- the searches: every text this tool dispatches ---------------------------------
# All of them read. Each opens with "search " or "|", holds no command that
# writes, and gets its time range as REST arguments. A value enters a text only
# through quoted(), after its own pattern accepted it. The tests pin every text.

ALL_TIME = ('0', '+1d')             # earliest_time, latest_time: everything a Splunk holds, a skewed clock included
RULE_ALL_INDEX_TIME = ('0', 'now')  # for a rule that judges by index time: every slot there ever was
ID_EVAL = 'eval rs_id=coalesce(spath(_raw, "audit_id"), spath(_raw, "escalation_id"), spath(_raw, "event_id"))'
RULE_TABLE = ('chain_id, user, _time, burst_time, signin_time, blocked_time, blocked_turns, duo_failures_10m, '
              'duo_app, signin_duo, guardrails')
DUO_REACH_SECONDS = 6000            # the joined rule's event-time context either side of its events


def quoted(values, joiner):
    """Plain values as quoted SPL strings: "a" OR "b" with joiner ' OR ',
    "a", "b" with ', '. A value that is not plain is refused, never escaped:
    no quote, backslash, wildcard, bracket or pipe can get into a text."""
    values = list(values)
    if not values or not all(isinstance(value, str) and SPL_VALUE_RE.fullmatch(value) for value in values):
        raise Refused('a value that is not a plain name cannot be put into a search (a bug in this tool, or an '
                      'unusual id: nothing was dispatched)')
    return joiner.join('"{}"'.format(value) for value in values)


def host_terms(hosts):
    return ' OR '.join('host={}'.format(quoted([host], '')) for host in hosts)


def chunks(values, size=IDS_PER_SEARCH):
    """Lists of at most size values: 40 ids keep a search under 5,000 characters."""
    values = list(values)
    return [values[start:start + size] for start in range(0, len(values), size)]


def spl_index_exists(index):
    """One row per indexer for an index this account can search, no row for
    one that is missing or hidden from it. A search on a hidden index answers
    "no events" with no error, which every other check would read as "the
    Splunk holds nothing"."""
    return '| eventcount summarize=false index={}'.format(quoted([index], ''))


def spl_census(index, hosts, personas, source, t_from, t_to):
    """S1. Splunk's own count of everything near the window (the range is the
    window padded by CENSUS_PAD_SECONDS): where, which host, whose, what kind.
    Nobody but the selected personas is named. spath reads only the first
    extraction_cutoff characters of an event, so a user who sits deeper shows
    as "no user" here: the export then stops, because Python counted more."""
    if not all(isinstance(bound, int) and not isinstance(bound, bool) for bound in (t_from, t_to)):
        raise Refused('a window bound that is not a whole second cannot be put into a search')
    return ('search index={index} '
            '| eval rs_ids=mvappend(spath(_raw, "audit_id"), spath(_raw, "escalation_id"), spath(_raw, "event_id")), '
            'rs_user=lower(replace(trim(coalesce(spath(_raw, "enduser_id"), spath(_raw, "user"))), "@.*", "")) '
            '| eval rs_where=case(_time<{t_from:d}, "before the window", _time>={t_to:d}, "after the window", '
            'true(), "in the window"), '
            'rs_host=if(in(host, {hosts}), "selected host", "other host"), '
            'rs_who=case(in(rs_user, {personas}), "selected persona", isnull(rs_user) OR rs_user=="", "no user", '
            'true(), "other identity"), '
            'rs_kind=case(isnull(log_type), "no log_type", source!={source}, "another source", isnull(rs_ids), '
            '"no id", mvcount(rs_ids)>1, "several ids", true(), "eligible"), '
            'rs_log_type=coalesce(mvjoin(log_type, ","), "none") '
            '| stats count as events by rs_where, rs_host, rs_who, rs_kind, sourcetype, rs_log_type '
            '| sort 0 rs_where, rs_host, rs_who, rs_kind, sourcetype').format(
                index=quoted([index], ''), hosts=quoted(hosts, ', '), personas=quoted(personas, ', '),
                source=quoted([source], ''), t_from=t_from, t_to=t_to)


def spl_legacy(index, hosts):
    """S2. Events whose body keys were also indexed as fields: what the
    assistant's forwarder wrote before 31 July 2026. A copy cannot carry them."""
    return ('| tstats count as legacy_indexed_body_keys where index={} ({}) '
            '(session_id=* OR request_id=* OR trace_id=* OR enduser_id=* OR user=*)').format(
                quoted([index], ''), host_terms(hosts))


def spl_export(index, hosts, source):
    """S3. The one read of event text. No persona filter: the persona is
    matched in Python on the parsed body (select_events). Splunk's own sha256
    and length of _raw travel with it, so a text altered on the way is seen."""
    return ('search index={} ({}) source={} '
            '(log_type::governance OR log_type::audit OR log_type::escalation OR log_type::error) '
            '| eval rs_time=tostring(_time), rs_indextime=_indextime, rs_sha256=sha256(_raw), rs_len=len(_raw), '
            'rs_log_type=mvjoin(log_type, ","), rs_bundle=coalesce(mvjoin(resend_bundle, ","), "none") '
            '| sort 0 _time '
            '| table rs_time, rs_indextime, rs_sha256, rs_len, index, host, source, sourcetype, rs_log_type, '
            'rs_bundle, _raw').format(quoted([index], ''), host_terms(hosts), quoted([source], ''))


def spl_present(index, ids):
    """P1. What a Splunk holds of these ids, one row per id it holds, over all
    time (ALL_TIME), at most IDS_PER_SEARCH ids a search. The id is read from
    the event's own text, so an event that only quotes an id (a scoring
    write-back) owns none and is not counted. The TA's response-action record
    does carry the event_id of the turn it acted on as a key of its own: its
    sourcetype is left out, or one analyst action would make a turn look
    indexed twice. decide() reads the rows."""
    return ('search index={index} sourcetype!="ai_cim:response:*" ({terms}) '
            '| {id_eval} '
            '| search rs_id IN ({listed}) '
            '| eval rs_sha256=sha256(_raw), rs_time=printf("%.3f", _time), rs_time_text=tostring(_time), '
            'rs_log_type=coalesce(mvjoin(log_type, ","), "none"), '
            'rs_bundle=coalesce(mvjoin(resend_bundle, ","), "none") '
            '| stats count as copies, values(rs_sha256) as sha256, values(rs_time) as time, '
            'values(rs_time_text) as time_text, values(host) as host, values(source) as source, '
            'values(sourcetype) as sourcetype, values(index) as index, values(rs_log_type) as log_type, '
            'values(rs_bundle) as resend_bundle, min(_indextime) as first_indexed, '
            'max(_indextime) as last_indexed by rs_id').format(
                index=quoted([index], ''), terms=quoted(ids, ' OR '), id_eval=ID_EVAL, listed=quoted(ids, ', '))


def spl_expect(ids, index=None):
    """E1. What the TA's identity views count for these ids, per identity:
    the row a stack must show again after the copy. With index=None the events
    are read through the macro genai_identity_ai_events, which is what
    Identity Activity and the joined rule read (it fixes the index). With an
    index they are read from that index with the same scoring exclusion: for
    gen_ai_log that is the macro's own definition, and for a scratch index it
    is the only text that reads the copies and not the originals."""
    base = '`genai_identity_ai_events`' if index is None else (
        'index={} `exclude_scoring_sourcetypes`'.format(quoted([index], '')))
    return ('search {base} ({terms}) '
            '| {id_eval} '
            '| search rs_id IN ({listed}) '
            '| eval identity_key=`genai_identity_join_key(user)`, turn=if(`genai_identity_verified_turn`, 1, 0), '
            'blocked=if(turn==1 AND \'gen_ai.policy.blocked\'=="true", 1, 0), '
            'signin=if(\'gen_ai.audit.action\'=="identity_signin_success", 1, 0), '
            'identity_event=if(\'gen_ai.identity.verified\'=="true" OR like(\'gen_ai.audit.action\', "identity_%"), '
            '1, 0) '
            '| stats dc(rs_id) as events, count as copies, sum(identity_event) as identity_events, '
            'sum(turn) as ai_turns, sum(blocked) as ai_blocked, sum(signin) as app_signins by identity_key').format(
                base=base, terms=quoted(ids, ' OR '), id_eval=ID_EVAL, listed=quoted(ids, ', '))


def duo_bounds(events):
    """(earliest, latest) for D1 and D2: the joined rule's event-time reach
    around the set, 6,000 s before its first event to 6,001 s after its last."""
    events = ordered(events)
    return (int(decimal.Decimal(events[0]['time'])) - DUO_REACH_SECONDS,
            int(decimal.Decimal(events[-1]['time'])) + DUO_REACH_SECONDS + 1)


def spl_duo_half(txids):
    """D1. The Duo authentications behind the set's application sign-ins,
    matched on the transaction id. The last stats keeps the ids out of the
    answer; with none found it returns one row that holds txids_found only."""
    return ('search `genai_duo_auth_events` ({terms}) '
            '| eval rs_txid=mvindex(txid, 0), identity_user=`genai_identity_join_key(user)` '
            '| search rs_txid IN ({listed}) '
            '| stats count as copies, values(action) as action, values(identity_user) as identity_user, '
            'min(_time) as duo_time, min(_indextime) as first_indexed by rs_txid '
            '| stats count as txids_found, sum(eval(if(copies==1, 1, 0))) as found_once, values(action) as action, '
            'values(identity_user) as identity_user, min(duo_time) as first_duo_time, '
            'max(duo_time) as last_duo_time').format(terms=quoted(txids, ' OR '), listed=quoted(txids, ', '))


def spl_duo_context(personas):
    """D2. The personas' Duo authentications around the set, by outcome: the
    failures a stack needs before the joined rule can see a burst."""
    return ('search `genai_duo_auth_events` '
            '| eval identity_user=`genai_identity_join_key(user)`, duo_class=`genai_identity_duo_class` '
            '| search identity_user IN ({}) '
            '| stats count as duo_events, dc(txid) as txids by identity_user, action, duo_class').format(
                quoted(personas, ', '))


def spl_rule_dry_run(rule_text):
    """V5. A Splunk's own text of the joined rule, dispatched ad hoc (no alert
    action runs for a search dispatched this way) over RULE_ALL_INDEX_TIME, so
    that every chain it can see is "new". The table keeps the rule's src (a
    client address) out of the answer."""
    return '{} | table {}'.format(as_search(rule_text), RULE_TABLE)


# --- what export adds to a bundle: origin, selection, census, expect ----------------
# Four objects beside the events. check_bundle() holds them to PARTS exactly,
# so `review` can print their values and `send` and `verify` can read them
# without a second look: a value that is not a count, a flag or a plain name of
# the kind its key takes makes the bundle one this tool did not write.

GUID_RE = re.compile(r'[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}')
VERSION_RE = re.compile(r'\d{1,4}(\.\d{1,6}){1,3}')
CHAIN_RE = re.compile(r'[a-z][a-z0-9]*(\.[a-z0-9]+)+:takeover:[1-9]\d{8,10}')
NOTE_RE = re.compile(r'--[a-z-]{3,30}: \d{1,6} event\(s\) [a-z0-9 ]{1,120}')      # what select_events notes
LOG_TYPES_RE = re.compile(r'[a-z_]{1,20}(,[a-z_]{1,20}){0,5}')                   # "none", or indexed values joined
CENSUS_WORDS = collections.OrderedDict((
    ('where', ('before the window', 'in the window', 'after the window')),
    ('host', ('selected host', 'other host')),
    ('who', ('selected persona', 'no user', 'other identity')),
    ('kind', ('eligible', 'no log_type', 'another source', 'no id', 'several ids'))))
EXPECT_COUNTS = ('events', 'copies', 'identity_events', 'ai_turns', 'ai_blocked', 'app_signins')
OTHER_NAME = 'other'                # stands for a sourcetype or log_type name that is not a plain one


class _Maybe(object):
    """A part that may be null."""

    def __init__(self, spec):
        self.spec = spec


PARTS = collections.OrderedDict((
    ('origin', {'guid': GUID_RE, 'splunk_version': VERSION_RE, 'ta_version': VERSION_RE, 'read_at': int}),
    ('selection', {'index': INDEX_RE, 'source': META_RE, 'hosts': [META_RE], 'personas': [lab5.PERSONA_RE],
                   'from': int, 'to': int, 'exact_window': bool, 'allow_partial_session': bool,
                   'allow_unlisted_persona': bool, 'notes': [NOTE_RE]}),
    ('census', {'pad_seconds': int, 'eligible': int, 'legacy_indexed_body_keys': int,
                'rows': [dict([(name, words) for name, words in CENSUS_WORDS.items()]
                              + [('sourcetype', META_RE), ('log_type', LOG_TYPES_RE), ('events', int)])],
                'left_out': {'other identities': int, 'no user': int, 'outside the window': int},
                'log_check': _Maybe({'equal': int, 'of': int})}),
    ('expect', {'identity': [dict([('identity_key', lab5.PERSONA_RE)] + [(name, int) for name in EXPECT_COUNTS])],
                'duo': {'signins': int, 'txids': int, 'txids_found': int, 'found_once': int,
                        'context': [{'identity_user': lab5.PERSONA_RE, 'action': WORD_RE, 'duo_class': WORD_RE,
                                     'duo_events': int, 'txids': int}]},
                'rule': {'name': (JOINED_RULE,), 'found': bool, 'sha256': _Maybe(SHA_RE), 'rows': int},
                'chains': [CHAIN_RE]})))


def _shape(value, spec, where):
    """Refused unless value has exactly the shape spec names: an object with
    exactly these keys, a list of one shape, one of a tuple of words, a count
    (int), a flag (bool), or a string its pattern accepts in full."""
    if isinstance(spec, _Maybe):
        fits = value is None or _shape(value, spec.spec, where)
    elif isinstance(spec, dict):
        fits = isinstance(value, dict) and sorted(value) == sorted(spec) and all(
            _shape(value[key], spec[key], '{}.{}'.format(where, key)) for key in sorted(spec))
    elif isinstance(spec, list):
        fits = isinstance(value, list) and all(_shape(item, spec[0], where) for item in value)
    elif isinstance(spec, tuple):
        fits = isinstance(value, str) and value in spec
    elif spec is bool:
        fits = isinstance(value, bool)
    elif spec is int:
        fits = isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 10 ** 12
    else:
        fits = isinstance(value, str) and spec.fullmatch(value) is not None
    if not fits:
        raise Refused('the bundle\'s {} is not what `export` writes: the file was edited, or something else '
                      'made it'.format(where))
    return True


def signin_events(events):
    """[(event, body)] of the application sign-ins in a set."""
    found = []
    for event in events:
        body, _ = parse_body(event['raw'])
        if event['log_type'] == 'audit' and body.get('action') == SIGNIN_ACTION:
            found.append((event, body))
    return found


def chain_candidates(events):
    """The chain ids the joined rule can raise for this set: one per sign-in,
    <identity>:takeover:<the sign-in's whole second>, as the rule writes them."""
    return sorted({'{}:takeover:{}'.format(actor_of(body), int(decimal.Decimal(event['time'])))
                   for event, body in signin_events(events)})


def check_parts(bundle):
    """The four objects have the shape PARTS names and agree with the events:
    one index and source, every event of a selected host and persona and
    inside the window, the census count equal to the number of events, and
    no expectation about anyone or anything that is not in the set."""
    for name, spec in PARTS.items():
        _shape(bundle[name], spec, name)
    events, chosen, expect = bundle['events'], bundle['selection'], bundle['expect']
    edited = Refused('the bundle was edited: its selection, census or expected results do not fit its events')
    if not chosen['hosts'] or not chosen['personas'] or not chosen['from'] < chosen['to']:
        raise edited
    for event in events:
        body, _ = parse_body(event['raw'])
        inside = chosen['from'] <= decimal.Decimal(event['time']) < chosen['to']
        if not (inside and event['index'] == chosen['index'] and event['source'] == chosen['source']
                and event['host'] in chosen['hosts'] and actor_of(body) in chosen['personas']):
            raise edited
    signins = signin_events(events)
    if (bundle['census']['eligible'] != len(events)
            or expect['duo']['signins'] != len(signins) or expect['duo']['txids'] != len(signin_txids(events))
            or not set(expect['chains']) <= set(chain_candidates(events))
            or not {row['identity_key'] for row in expect['identity']} <= set(chosen['personas'])
            or not {row['identity_user'] for row in expect['duo']['context']} <= set(chosen['personas'])
            or (expect['chains'] and not expect['rule']['found'])):
        raise edited
    return bundle


def census_part(rows, left_out, legacy, log_check):
    """The bundle's census from the rows of S1: the six columns as words and
    a count. A row outside the search's own vocabulary is refused; a
    sourcetype or log_type that is not a plain name is filed under "other"."""
    listed, eligible = [], census_eligible(rows)
    for row in rows:
        item = collections.OrderedDict()
        for name, words in CENSUS_WORDS.items():
            item[name] = one(row.get('rs_' + name))
            if item[name] not in words:
                raise Refused('the census search answered with a row that is not in its own words')
        sourcetype, log_type = one(row.get('sourcetype')), one(row.get('rs_log_type'))
        item['sourcetype'] = sourcetype if sourcetype and META_RE.fullmatch(sourcetype) else OTHER_NAME
        item['log_type'] = log_type if log_type and LOG_TYPES_RE.fullmatch(log_type) else OTHER_NAME
        item['events'] = as_int(row.get('events'), -1)
        if item['events'] < 0:
            raise Refused('the census search answered with a row that has no count')
        listed.append(dict(item))
    return {'pad_seconds': CENSUS_PAD_SECONDS, 'eligible': eligible, 'legacy_indexed_body_keys': int(legacy),
            'rows': listed, 'left_out': dict(left_out), 'log_check': log_check}


def census_holes(census):
    """Census rows that say the copy would have a hole: an event of a selected
    persona, in the window, on a selected host, that is not eligible and is
    not one of the TA's own write-backs. The export search never returns such
    an event (it has no log_type, or another source), so only the census sees it."""
    return [row for row in census['rows']
            if (row['where'], row['host'], row['who']) == CENSUS_SELECTED[:3] and row['kind'] != CENSUS_SELECTED[3]
            and not is_scoring_sourcetype(row['sourcetype'])]


def identity_part(row_lists, personas):
    """expect.identity from the rows of E1, one search per chunk of ids: per
    identity, the counts added up. An identity that is not a selected persona
    is refused: the TA would show those events under another name."""
    totals = collections.OrderedDict()
    for rows in row_lists:
        for row in rows:
            key = one(row.get('identity_key'))
            if key not in personas:
                raise Refused('the TA reads some of the selected events as another identity than the selected '
                              'persona (its user field differs from enduser_id): Identity Activity would show '
                              'them under another name')
            total = totals.setdefault(key, collections.OrderedDict((name, 0) for name in EXPECT_COUNTS))
            for name in EXPECT_COUNTS:
                total[name] += as_int(row.get(name), 0)
    return [dict(counts, identity_key=key) for key, counts in sorted(totals.items())]


def duo_part(events, half_rows, context_rows, personas):
    """expect.duo from the rows of D1 (one row a search; with nothing matched
    it holds txids_found alone, so an absent column counts as 0) and of D2 (a
    row per persona, action and class)."""
    context = []
    for row in context_rows:
        user, action, duo_class = (one(row.get(name)) for name in ('identity_user', 'action', 'duo_class'))
        if user not in personas or not all(word and WORD_RE.fullmatch(word) for word in (action, duo_class)):
            raise Refused('the Duo context search answered with a row that is not in its own shape')
        context.append({'identity_user': user, 'action': action, 'duo_class': duo_class,
                        'duo_events': as_int(row.get('duo_events'), 0), 'txids': as_int(row.get('txids'), 0)})
    return {'signins': len(signin_events(events)), 'txids': len(signin_txids(events)),
            'txids_found': sum(as_int(row.get('txids_found'), 0) for row in half_rows),
            'found_once': sum(as_int(row.get('found_once'), 0) for row in half_rows),
            'context': sorted(context, key=lambda row: (row['identity_user'], row['action'], row['duo_class']))}


# --- the assistant's own log (--check-logs) -----------------------------------------

# log_type -> the stem of the JSONL file the assistant appends that kind of
# record to (its backend/logging/log_handlers.py). The current file is
# <stem>.json; a rotated one is <stem>_<stamp>.json and is deleted after 90 days.
LOG_STEMS = {'governance': 'ai_governance', 'audit': 'audit_trail', 'escalation': 'escalations', 'error': 'errors'}


def log_hashes(folder, events):
    """{event id: the sha256 values of the assistant's own log lines for it}.

    The assistant writes a body to its log with json.dumps(body) and to HEC
    with json.dumps(body, separators=(",", ":")), so the compact form of a log
    line is the text Splunk must hold for that id. This is the only place
    where this tool writes JSON out again, and what it writes is hashed and
    dropped: nothing of it reaches a bundle or a HEC line."""
    found = dict((event['id'], set()) for event in events)
    for log_type in sorted({event['log_type'] for event in events}):
        wanted = dict((event['id'].encode('ascii'), event) for event in events if event['log_type'] == log_type)
        stem = LOG_STEMS[log_type]
        try:
            names = sorted(name for name in os.listdir(folder)
                           if name == stem + '.json' or (name.startswith(stem + '_') and name.endswith('.json')))
        except OSError:
            raise Refused('--check-logs: that folder cannot be read')
        for name in names:
            try:
                with open(os.path.join(folder, name), 'rb') as handle:
                    for line in handle:
                        for needle, event in wanted.items():
                            if needle not in line:
                                continue
                            try:
                                body = json.loads(line.decode('utf-8'))
                            except (ValueError, RecursionError):
                                continue                      # a torn line: it proves nothing either way
                            if isinstance(body, dict) and body.get(event['id_key']) == event['id']:
                                found[event['id']].add(sha256_text(json.dumps(body, separators=(',', ':'))))
            except OSError:
                raise Refused('--check-logs: {} in that folder cannot be read'.format(name))
    return found


def check_logs(folder, events):
    """--check-logs DIR: every event of the set is in the assistant's own
    log, with the text Splunk holds. Returns the counts for the census; Refused
    when an id is missing from the log or its text differs (ids and the first
    12 digits of each hash are named, never a text)."""
    if not os.path.isdir(folder):
        raise Refused('--check-logs: expected the folder that holds the assistant\'s JSONL logs '
                      '(ai_governance.json, audit_trail.json, escalations.json, errors.json)')
    found = log_hashes(folder, events)
    missing = [event['id'] for event in events if not found[event['id']]]
    if missing:
        raise Refused('--check-logs: {} of {} event id(s) are not in the assistant\'s log in that folder (is it '
                      'the checkout that staged them, and is the rotated file still there?): {}{}'.format(
                          len(missing), len(events), ', '.join(missing[:5]), ' ...' if len(missing) > 5 else ''))
    differ = ['{} (log {}, Splunk {})'.format(event['id'], sorted(found[event['id']] - {event['sha256']})[0][:12],
                                              event['sha256'][:12])
              for event in events if found[event['id']] != {event['sha256']}]
    if differ:
        raise Refused('--check-logs: for {} of {} event(s) the assistant\'s log holds another text than Splunk: '
                      '{}{}'.format(len(differ), len(events), ', '.join(differ[:5]), ' ...' if len(differ) > 5 else ''))
    return {'equal': len(events), 'of': len(events)}


# --- command line ------------------------------------------------------------------

class Parser(argparse.ArgumentParser):
    """argparse repeats what it does not understand. A value typed after a
    mistaken option could be a secret, so only what is shaped like an option
    name is repeated (cut at any "="), never a value. For the same reason no
    option here has a type= or choices=: argparse repeats a bad value."""

    def error(self, message):
        if message.startswith('unrecognized arguments'):
            names = sorted({token.split('=', 1)[0] for token in message.split(': ', 1)[-1].split()
                            if re.fullmatch(r'--[a-z][a-z0-9-]*(=.*)?', token)})
            message = ('unrecognized arguments{} (values are not repeated here: a secret never belongs on the '
                       'command line). See --help'.format(': ' + ' '.join(names) if names else ''))
        elif 'invalid choice' in message:
            message = 'expected one of the commands export, review, send, verify. See --help'
        super(Parser, self).error(message)


def _stack_options(parser, with_hec):
    """The options send and verify share: where the stack is and how its
    certificates are checked. --ca-file is trusted IN ADDITION to the system
    store, for the stack's port 8089 and for its HEC endpoint alike."""
    parser.add_argument('--bundle', required=True, metavar='PATH', help='the approved bundle file')
    parser.add_argument('--stack', required=True, metavar='URL',
                        help='the stack, for example https://<stack>.splunkcloud.com (splunkd on port 8089 '
                             'unless the URL names one; ${} or ${})'.format(ENV_STACK_PASSWORD, ENV_STACK_TOKEN))
    parser.add_argument('--username', default='admin', metavar='NAME',
                        help='the user ${} belongs to (default %(default)s; not used with a token)'.format(
                            ENV_STACK_PASSWORD))
    parser.add_argument('--ca-file', metavar='PATH',
                        help='a CA bundle trusted in addition to the system store, for the stack\'s splunkd'
                             + (' and its HEC endpoint' if with_hec else ''))
    parser.add_argument('--no-verify-splunkd', action='store_true',
                        help='do not verify the certificate of the stack\'s port 8089 (the run says so)')


def build_parser():
    parser = Parser(prog='staged_resend.py', allow_abbrev=False,
                    description='Copy the staged PseudoCo Assistant events of a lab persona to stacks created '
                                'after the staging: export once, review, then send and verify per stack.',
                    epilog='No option takes a secret. Exit codes: 0 ok, 1 a check failed, 2 usage or refused '
                           'input, 3 delivery unknown.')
    commands = parser.add_subparsers(dest='command', metavar='{export,review,send,verify}')
    commands.required = True

    export = commands.add_parser('export', allow_abbrev=False,
                                 help='read the staged events from the facilitator\'s Splunk into a bundle')
    export.add_argument('--source', required=True, metavar='URL',
                        help='splunkd of the Splunk that got the events live, for example '
                             'https://127.0.0.1:8089 (${} or ${})'.format(ENV_SOURCE_PASSWORD, ENV_SOURCE_TOKEN))
    export.add_argument('--source-username', default='admin', metavar='NAME',
                        help='the user ${} belongs to (default %(default)s; not used with a token)'.format(
                            ENV_SOURCE_PASSWORD))
    export.add_argument('--host', action='append', required=True, metavar='H',
                        help='host label the assistant stamped on the staged events (repeatable)')
    export.add_argument('--persona', action='append', required=True, metavar='P',
                        help='lab persona whose events are copied, for example nina.osei (repeatable)')
    export.add_argument('--from', dest='start', required=True, metavar='ISO',
                        help='start of the window, ISO-8601 with an offset and whole seconds')
    export.add_argument('--to', dest='end', required=True, metavar='ISO',
                        help='end of the window, exclusive; at most 7 days after --from')
    export.add_argument('--bundle', metavar='PATH',
                        help='the bundle file to create (0600, outside any git work tree; never overwritten)')
    export.add_argument('--index', default=DEFAULT_INDEX, metavar='NAME', help='default %(default)s')
    export.add_argument('--event-source', default=DEFAULT_SOURCE, metavar='NAME',
                        help='the assistant\'s HEC source (default %(default)s)')
    export.add_argument('--exact-window', action='store_true',
                        help='copy the window as named although the persona has events within {} s outside '
                             'it'.format(EDGE_GUARD_SECONDS))
    export.add_argument('--allow-partial-session', action='store_true',
                        help='copy although events that are not selected share a session with selected ones')
    export.add_argument('--allow-unlisted-persona', action='store_true',
                        help='accept a persona that is not in lookups/pseudoco_identity_personas.csv')
    export.add_argument('--check-logs', metavar='DIR',
                        help='also compare every event with the assistant\'s own JSONL logs in DIR')
    export.add_argument('--list-only', action='store_true', help='print the selection and write no bundle')
    tls = export.add_mutually_exclusive_group()
    tls.add_argument('--no-verify-source', action='store_true',
                     help='do not verify the source\'s certificate (the run says so)')
    tls.add_argument('--ca-file', metavar='PATH',
                     help='a CA bundle trusted for the source, in addition to the system store')

    review = commands.add_parser('review', allow_abbrev=False,
                                 help='list what a bundle holds (never a body or an address) and approve it')
    review.add_argument('--bundle', required=True, metavar='PATH')
    review.add_argument('--approve', metavar='DIGEST12',
                        help='approve the bundle: the 12 hex digits the listing prints')

    send = commands.add_parser('send', allow_abbrev=False,
                               help='copy an approved bundle to one stack, each event at most once')
    _stack_options(send, with_hec=True)
    hec = send.add_mutually_exclusive_group(required=True)
    hec.add_argument('--hec-file', metavar='PATH',
                     help='the 0600 JSON file `show_postdeploy.py --out` wrote (hec_url, hec_token, index)')
    hec.add_argument('--hec-url', metavar='URL',
                     help='the HEC event endpoint, with the token in ${}'.format(ENV_HEC_TOKEN))
    send.add_argument('--dry-run', action='store_true', help='run every check, print the plan, send nothing')
    send.add_argument('--allow-rule-off', action='store_true',
                      help='send although the joined rule is off or not running: no finding will be raised')
    send.add_argument('--without-duo', action='store_true',
                      help='send although the Duo half of the sign-ins is not in the stack yet')
    send.add_argument('--no-canary', action='store_true',
                      help='do not send one event first and read it back before the rest')
    send.add_argument('--resend-unconfirmed', action='store_true',
                      help='send ids again that were handed to HEC over {} s ago and never became '
                           'searchable'.format(RESEND_UNCONFIRMED_AFTER))
    send.add_argument('--retention-days', metavar='N',
                      help='the index\'s searchable days, for a stack that does not report them (the run '
                           'says the number was stated, not read)')
    send.add_argument('--settle', default=str(SETTLE_SECONDS), metavar='SECONDS',
                      help='how long to wait for the copies to be searchable (default %(default)s)')
    send.add_argument('--wait-finding', default='0', metavar='SECONDS',
                      help='then wait this long for the joined rule\'s finding (default: do not wait)')

    verify = commands.add_parser('verify', allow_abbrev=False,
                                 help='read the stack again: copies, label, counts and the finding')
    _stack_options(verify, with_hec=False)
    verify.add_argument('--wait', default='0', metavar='SECONDS',
                        help='wait this long for the scheduled run and its finding, for example 900 '
                             '(default: check once)')
    return parser


# --- review ------------------------------------------------------------------------

def utc_text(time_text):
    """A time text as UTC to the millisecond, for a listing."""
    seconds, _, millis = time_3f(time_text).partition('.')
    return '{}.{}Z'.format(time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(int(seconds))), millis)


def show_events(events, echo):
    """One line per event and the counts of what is sensitive: ids, times,
    sizes, hashes and counts. Never a body, an address or a Duo transaction
    id. Every count is taken from the events, not from a summary."""
    counts = privacy_counts(events)
    for event in events:
        echo('  {}  {:<18} {:<44} {:>7} B  {}  {}'.format(
            utc_text(event['time']), event['sourcetype'], describe(event), event['bytes'], event['sha256'][:12],
            event['id']))
    echo('')
    echo('  The bodies are copied whole and none is shown here: {} of {} event(s) carry message text, {} carry '
         'a client address ({} distinct, {} public).'.format(
             counts['events_with_message_text'], len(events), counts['events_with_client_address'],
             counts['distinct_client_addresses'], counts['public_client_addresses']))
    echo('  {} application sign-in(s), {} with a Duo transaction id.'.format(
        len(signin_events(events)), len(signin_txids(events))))


def utc_second(epoch):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(int(epoch)))


def show_selection(chosen, echo):
    """What the operator named: every value here passed its own pattern."""
    echo('  Selection: index {}, source {}, host(s) {}, persona(s) {}'.format(
        chosen['index'], chosen['source'], ', '.join(chosen['hosts']), ', '.join(chosen['personas'])))
    echo('    window {} to {} (the end is exclusive; {} s)'.format(
        utc_second(chosen['from']), utc_second(chosen['to']), chosen['to'] - chosen['from']))
    used = [flag for flag, name in (('--exact-window', 'exact_window'),
                                    ('--allow-partial-session', 'allow_partial_session'),
                                    ('--allow-unlisted-persona', 'allow_unlisted_persona')) if chosen[name]]
    echo('    overrides used: {}'.format(', '.join(used) or 'none'))
    for note in chosen['notes']:
        echo('    {}'.format(note))


def show_census(census, echo, rows_only=False):
    """Splunk's own count around the window. It names nobody but the selected
    personas. rows_only: the rows alone, before a selection has been made."""
    echo('  Census: what Splunk counted within {} s of the window (nobody else is named)'.format(
        census['pad_seconds']))
    for row in census['rows']:
        echo('    {:<18} {:<14} {:<17} {:<15} {:<24} {:<12} {:>6}'.format(
            row['where'], row['host'], row['who'], row['kind'], row['sourcetype'], row['log_type'], row['events']))
    if not census['rows']:
        echo('    (no event at all)')
    if rows_only:
        return
    left = census['left_out']
    echo('    counted as the selection: {}. Not copied: {} of other identities and {} with no user in the '
         'window, {} of the persona outside it.'.format(census['eligible'], left['other identities'],
                                                        left['no user'], left['outside the window']))
    check = census['log_check']
    echo('    the assistant\'s own log: {}'.format(
        'not compared (no --check-logs)' if check is None else '{} of {} equal'.format(check['equal'], check['of'])))


def show_expect(expect, echo, selected=None):
    """What the source showed for the set: the rows `send` and `verify` hold a
    stack to. selected: how many events the set has, to say when the TA's
    identity views count fewer of them."""
    echo('  Expected results, as read on the source:')
    for row in expect['identity']:
        echo('    {}: events {}, copies {}, identity_events {}, ai_turns {}, ai_blocked {}, app_signins {}'.format(
            row['identity_key'], *[row[name] for name in EXPECT_COUNTS]))
    if not expect['identity']:
        echo('    no identity row: the TA\'s identity views count none of these events')
    counted = sum(row['events'] for row in expect['identity'])
    if selected is not None and expect['identity'] and counted != selected:
        echo('    note: the TA reads an identity for {} of the {} event(s); the others are in none of these '
             'counts'.format(counted, selected))
    duo = expect['duo']
    echo('    Duo: {} of {} sign-in transaction(s) found, {} exactly once'.format(
        duo['txids_found'], duo['txids'], duo['found_once']))
    for row in duo['context']:
        echo('    Duo context: {} {}/{}: {} event(s), {} transaction(s)'.format(
            row['identity_user'], row['action'], row['duo_class'], row['duo_events'], row['txids']))
    rule = expect['rule']
    if not rule['found']:
        echo('    joined rule: not on the source, so no chain id is expected')
    else:
        echo('    joined rule (text {}): {} chain(s) for this set\'s sign-ins{}'.format(
            rule['sha256'][:12], len(expect['chains']), ': ' + ', '.join(expect['chains']) if expect['chains'] else ''))


def show_bundle(bundle, echo):
    """The review listing: the events, then what export recorded beside them.
    check_bundle() held every value printed here to a count, a flag or a plain
    name of the kind its key takes."""
    events, origin = bundle['events'], bundle['origin']
    echo('Bundle {}'.format(bundle['bundle_id']))
    echo('  {} event(s) for index {}, {} to {}'.format(
        len(events), events[0]['index'], utc_text(events[0]['time']), utc_text(events[-1]['time'])))
    echo('  hosts: {}   sourcetypes: {}'.format(', '.join(sorted({event['host'] for event in events})),
                                              ', '.join(sorted({event['sourcetype'] for event in events}))))
    echo('')
    show_events(events, echo)
    echo('')
    show_selection(bundle['selection'], echo)
    show_census(bundle['census'], echo)
    show_expect(bundle['expect'], echo, len(events))
    echo('  Origin: server {}, Splunk {}, {} {}, read {}'.format(
        origin['guid'], origin['splunk_version'], APP, origin['ta_version'], utc_second(origin['read_at'])))
    echo('  Digest {} - {}'.format(bundle['digest'][:12],
                                 'approved as it is' if is_approved(bundle) else 'NOT approved'))


def cmd_review(opts, env, clock, sleep, echo):
    """review: R1 on the bundle file, the listing, and with --approve the
    review stamp (written beside the old file and moved over it in one step)."""
    bundle = load_bundle(opts.bundle)
    show_bundle(bundle, echo)
    echo('')
    if opts.approve is None:
        if not is_approved(bundle):
            echo('To approve it: staged_resend.py review --bundle <path> --approve {}'.format(bundle['digest'][:12]))
        return EXIT_OK
    stamped = approve(bundle, opts.approve, clock())
    replace_private(opts.bundle, bundle_text(stamped), '--bundle')
    echo('Approved: digest {}. An edit after this makes `send` refuse the bundle.'.format(bundle['digest'][:12]))
    return EXIT_OK


# --- export ---------------------------------------------------------------------------

def connect_source(opts, env):
    """(the source's splunkd client, what the run says about its certificate).
    The credential comes from the environment; nothing is contacted yet."""
    kind, secret = credential(env, ENV_SOURCE_PASSWORD, ENV_SOURCE_TOKEN)
    scheme, host, _, _ = split_url(opts.source, '--source', 8089)
    verify, words = tls_policy(scheme, host, opts.ca_file, opts.no_verify_source, '--no-verify-source')
    client = Splunkd(opts.source, '--source', kind, secret, opts.source_username, verify, opts.ca_file,
                     '--no-verify-source')
    return client, words


def numeric_version(text):
    """'1.9.0' of '1.9.0' or '1.9.0-rc1'; None when the text opens with no version."""
    found = re.match(r'\d{1,4}(\.\d{1,6}){1,3}', text) if isinstance(text, str) else None
    return found.group(0) if found else None


def read_origin(splunkd, now, what='reading the source'):
    """Who a Splunk is: its server GUID (a bundle is never sent back to the
    Splunk it came from) and its versions, read at `now`. Refused without the
    TA at TA_FLOOR or later: the searches that read the expected results use
    its macros. `send` asks a stack the same two questions."""
    info = splunkd.content('/services/server/info', what)
    if info is None:
        raise Refused('{}: {} has no /services/server/info (is it the management port?)'.format(what, splunkd.flag))
    app = splunkd.content('/services/apps/local/{}'.format(APP), what)
    guid, version = info.get('guid'), numeric_version(info.get('version'))
    if not isinstance(guid, str) or not GUID_RE.fullmatch(guid) or version is None:
        raise Refused('{}: {} did not name its server GUID and its version'.format(what, splunkd.flag))
    ta_version = numeric_version((app or {}).get('version'))
    if ta_version is None or lab5.version_tuple(ta_version) < TA_FLOOR:
        raise Refused('{} has no {} {} or later: the searches that read the expected results use its '
                      'macros'.format(splunkd.flag, APP, '.'.join(str(part) for part in TA_FLOOR)))
    return {'guid': guid, 'splunk_version': version, 'ta_version': ta_version, 'read_at': int(now)}


def presence_rows(splunkd, index, events, what, sleep=time.sleep):
    """The rows of the presence search P1 for these events on one Splunk,
    IDS_PER_SEARCH ids a search, over all time (plan() and rows_by_id() read
    them)."""
    rows = []
    for ids in chunks([event['id'] for event in ordered(events)]):
        rows.extend(run_search(splunkd, spl_present(index, ids), ALL_TIME[0], ALL_TIME[1], what, (), sleep))
    return rows


def presence(splunkd, index, events, bundle_id, what, sleep=time.sleep):
    """{id: Decision} for these events from the presence search P1 on one Splunk."""
    return plan(events, presence_rows(splunkd, index, events, what, sleep), bundle_id)


def check_source_presence(decisions):
    """The export's self-check: the search that will later say what a stack
    holds must find every exported event on the source exactly once, identical
    and unlabelled. If it cannot see an event here, it could not see its copy
    there, and "nothing there" means "send"."""
    counts = plan_counts(decisions)
    if counts[DUPLICATE]:
        twice = [ident for ident, decision in decisions.items() if decision.verdict == DUPLICATE]
        raise Refused('{} of the selected id(s) are held more than once on the source: {}{}. An id is the '
                      'idempotency key, so such a set cannot be exported (many events of 27 to 30 July 2026 are '
                      'held twice: a HEC copy beside a file-monitor copy)'.format(
                          len(twice), ', '.join(twice[:5]), ' ...' if len(twice) > 5 else ''))
    if counts[SEND]:
        unseen = [ident for ident, decision in decisions.items() if decision.verdict == SEND]
        raise Refused('the presence search does not find {} of the event(s) the export search returned: {}{}. It '
                      'would not find their copies on a stack either, so nothing is exported'.format(
                          len(unseen), ', '.join(unseen[:5]), ' ...' if len(unseen) > 5 else ''))
    if counts[LIVE] != len(decisions):
        odd = ['{} ({})'.format(ident, ', '.join(decision.differs) or decision.verdict)
               for ident, decision in decisions.items() if decision.verdict != LIVE]
        raise Refused('the presence search reads {} event(s) differently from the export search: {}{}'.format(
            len(odd), ', '.join(odd[:5]), ' ...' if len(odd) > 5 else ''))


def read_rule(splunkd, what='reading the joined rule'):
    """The joined rule's search text as a Splunk holds it, or None when it has
    no such saved search."""
    path = '/servicesNS/nobody/{}/saved/searches/{}'.format(APP, urllib.parse.quote(JOINED_RULE, safe=''))
    found = splunkd.content(path, what)
    text = found.get('search') if found else None
    return text if isinstance(text, str) and text.strip() else None


def read_expect(source, index, events, personas, sleep):
    """The bundle's `expect`, read on the source once: the identity counts
    (E1), the Duo half of the sign-ins and the Duo context (D1, D2), and the
    chain ids the source's own text of the joined rule raises for the set's
    sign-ins when every index-time slot is judged at once (V5)."""
    def search(spl, bounds, what, hidden=()):
        return run_search(source, spl, bounds[0], bounds[1], what, hidden, sleep)

    ids = [event['id'] for event in events]
    identity = identity_part([search(spl_expect(part, index), ALL_TIME, 'E1, the expected counts')
                              for part in chunks(ids)], personas)
    txids, bounds, half = signin_txids(events), duo_bounds(events), []
    for part in chunks(txids):
        half.extend(search(spl_duo_half(part), bounds, 'D1, the Duo half of the sign-ins', txids))
    duo = duo_part(events, half, search(spl_duo_context(personas), bounds, 'D2, the Duo context'), personas)
    text, candidates = read_rule(source), chain_candidates(events)
    rule = {'name': JOINED_RULE, 'found': text is not None, 'sha256': sha256_text(text) if text else None, 'rows': 0}
    chains = []
    if text is not None and candidates:
        rows = search(spl_rule_dry_run(text), RULE_ALL_INDEX_TIME, 'V5, the joined rule on the source')
        rule['rows'] = len(rows)
        chains = sorted({one(row.get('chain_id')) for row in rows} & set(candidates))
    return {'identity': identity, 'duo': duo, 'rule': rule, 'chains': chains}


def read_selection(source, opts, names, now, sleep, echo):
    """(events, census, selection notes): the census S1, the legacy detector
    S2, the one read of event text S3, and the selection made from it in
    Python. The census is printed before anything can refuse the selection,
    so a refused run still shows where the persona's events lie."""
    index, hosts, personas, event_source, t_from, t_to = names

    def search(spl, bounds, what):
        return run_search(source, spl, bounds[0], bounds[1], what, (), sleep)

    if not search(spl_index_exists(index), ('0', 'now'), 'looking for the index'):
        raise Refused('--source has no index {} that this account can search: nothing was read'.format(index))
    padded = (t_from - CENSUS_PAD_SECONDS, t_to + CENSUS_PAD_SECONDS)
    census_rows = search(spl_census(index, hosts, personas, event_source, t_from, t_to), padded, 'S1, the census')
    census = census_part(census_rows, {'other identities': 0, 'no user': 0, 'outside the window': 0}, 0, None)
    show_census(census, echo, rows_only=True)
    echo('')
    legacy_rows = search(spl_legacy(index, hosts), (t_from, t_to), 'S2, the legacy detector')
    legacy = as_int(legacy_rows[0].get('legacy_indexed_body_keys'), 0) if legacy_rows else 0
    if legacy:
        raise Refused('{} event(s) of the selected host(s) in the window carry body keys as indexed fields: the '
                      'assistant\'s forwarder of before 31 July 2026 wrote them, and a copy cannot carry those '
                      'fields. Such a window cannot be exported'.format(legacy))
    rows = search(spl_export(index, hosts, event_source), padded, 'S3, the export search')
    chosen = select_events(rows, personas, t_from, t_to, event_source, now, opts.exact_window,
                           opts.allow_partial_session)
    census = census_part(census_rows, chosen.left_out, legacy, None)
    if census['eligible'] != len(chosen.events):
        raise Refused('Splunk\'s census counts {} eligible event(s) of the persona in the window and this tool '
                      'selected {}: an event would be left out or added unseen (a user name that sits deeper '
                      'in an event than spath reads shows as "no user" in the census)'.format(
                          census['eligible'], len(chosen.events)))
    holes = census_holes(census)
    if holes:
        raise Refused('{} event(s) of the persona in the window, on a selected host, are not eligible ({}): the '
                      'scenario would be copied with a hole in it'.format(
                          sum(row['events'] for row in holes),
                          ', '.join(sorted({'{} {}'.format(row['kind'], row['sourcetype']) for row in holes}))))
    echo('Selected {} event(s) with {} distinct id(s), {} to {}, {} characters of event text.'.format(
        len(chosen.events), len({event['id'] for event in chosen.events}), chosen.events[0]['time'],
        chosen.events[-1]['time'], sum(event['chars'] for event in chosen.events)))
    echo('  Splunk\'s sha256 and length of each of the {} event text(s) it returned equal the ones computed '
         'here.'.format(len(rows)))
    echo('  Not copied: {} of other identities and {} with no user in the window, {} of the persona outside '
         'it.'.format(chosen.left_out['other identities'], chosen.left_out['no user'],
                      chosen.left_out['outside the window']))
    for note in chosen.notes:
        echo('  {}'.format(note))
    return chosen.events, census, list(chosen.notes)


def cmd_export(opts, env, clock, sleep, echo):
    """export: read the staged set from the source, once, into a new private
    bundle. Order: everything the operator named and the bundle path are
    checked before any connection; the census is printed before the selection
    can be refused; the event text is read once (S3) and matched to personas
    in Python; then the cross-checks (the census count, --check-logs, the
    presence search on the source itself) and the expected results. Nothing is
    written unless all of it held. --list-only stops after the selection."""
    now = clock()
    hosts = check_names(opts.host, '--host', META_RE)
    personas = check_personas(opts.persona, opts.allow_unlisted_persona)
    index = check_names([opts.index], '--index', INDEX_RE)[0]
    event_source = check_names([opts.event_source], '--event-source', META_RE)[0]
    t_from, t_to = check_window(parse_when(opts.start, '--from'), parse_when(opts.end, '--to'), now)
    if not opts.list_only:
        if not opts.bundle:
            raise Refused('--bundle: name the file to create, or pass --list-only to write none')
        check_new_path(opts.bundle, '--bundle')              # before a single event text is read
    if opts.check_logs is not None and not os.path.isdir(opts.check_logs):
        raise Refused('--check-logs: expected the folder that holds the assistant\'s JSONL logs')
    source, tls_words = connect_source(opts, env)
    echo('Export from --source')
    echo('  certificate: {}'.format(tls_words))              # said before the first request is made
    origin = read_origin(source, now)
    echo('  Splunk {}, {} {}'.format(origin['splunk_version'], APP, origin['ta_version']))
    chosen = {'index': index, 'source': event_source, 'hosts': hosts, 'personas': personas, 'from': t_from,
              'to': t_to, 'exact_window': bool(opts.exact_window),
              'allow_partial_session': bool(opts.allow_partial_session),
              'allow_unlisted_persona': bool(opts.allow_unlisted_persona), 'notes': []}
    show_selection(chosen, echo)
    events, census, chosen['notes'] = read_selection(
        source, opts, (index, hosts, personas, event_source, t_from, t_to), now, sleep, echo)
    echo('')
    show_events(events, echo)
    if opts.check_logs is not None:
        census['log_check'] = check_logs(opts.check_logs, events)
        echo('  --check-logs: {} of {} event(s) equal to the assistant\'s own log.'.format(
            census['log_check']['equal'], census['log_check']['of']))
    dig = digest(events)
    bundle_id = bundle_id_of(events, dig)
    if opts.list_only:
        echo('')
        echo('--list-only: nothing was written. The same selection gives bundle {} (digest {}). The presence '
             'check on the source and the expected results are read by a run without it.'.format(bundle_id, dig[:12]))
        return EXIT_OK
    check_source_presence(presence(source, index, events, bundle_id, 'P1, the presence search on the source', sleep))
    echo('  On the source the presence search finds each of the {} id(s) once, identical.'.format(len(events)))
    expect = read_expect(source, index, events, personas, sleep)
    bundle = build_bundle(events, origin, chosen, census, expect)
    echo('')
    show_expect(expect, echo, len(events))
    if index != DEFAULT_INDEX:
        echo('  note: index {} is not {}, the index the TA\'s identity macro reads. `send` refuses such a bundle '
             'on a stack whose macro reads another index; it is for a scratch rehearsal.'.format(index, DEFAULT_INDEX))
    write_bundle(opts.bundle, bundle)
    if load_bundle(opts.bundle) != bundle:                   # R1 on the file itself, as `send` will read it
        raise Refused('--bundle does not read back as it was written: delete that file and export again')
    echo('')
    echo('Wrote bundle {} (mode 0600): {} event(s), digest {}, NOT approved.'.format(
        bundle['bundle_id'], len(events), bundle['digest'][:12]))
    echo('Read it, then approve it: staged_resend.py review --bundle <path> [--approve {}]'.format(
        bundle['digest'][:12]))
    return EXIT_OK


# --- send: the HEC endpoint and its token (R2) ----------------------------------------

HEC_HEALTH_PATH = '/services/collector/health'
HEC_TIMEOUT = 30                    # seconds for the connection and for each read of the answer
POLL_SECONDS = 10                   # between two looks at what the stack holds
HEC_FILE_KEYS = ('hec_url', 'hec_token', 'index')     # what `show_postdeploy.py --out` writes that is read here
HEC_PREFIXES = ('http-inputs-', 'http-inputs.', 'inputs.', 'input-')   # Splunk Cloud's HEC names for a stack
TOKEN_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._~+/=-]{7,511}')         # a HEC token: one header value, no space
HecTarget = collections.namedtuple('HecTarget', 'scheme host port token origin')


def hec_belongs(stack_host, hec_host):
    """True when a HEC host name is the stack's: the same host, or the
    stack's name behind one of Splunk Cloud's HEC prefixes
    (http-inputs-<stack>.splunkcloud.com). A loopback stack takes a loopback
    HEC only, and the other way round. It catches the token file of another
    stack; it is not a security boundary (the certificate is)."""
    if is_loopback(stack_host) or is_loopback(hec_host):
        return is_loopback(stack_host) and is_loopback(hec_host)
    stack, hec = stack_host.lower().rstrip('.'), hec_host.lower().rstrip('.')
    name = stack.split('.')[0]
    return hec == stack or any(hec == prefix + stack or hec.startswith(prefix + name + '.')
                               for prefix in HEC_PREFIXES)


def read_hec_file(path):
    """(url, token, index) from the 0600 JSON file `show_postdeploy.py --out`
    wrote. The file `--lab5 --out` writes holds the token of the Identity
    Intelligence index and is named as such. No value of the file is repeated."""
    try:
        data = json.loads(read_private(path, '--hec-file'))
    except (ValueError, RecursionError):
        raise Refused('--hec-file is not a JSON file')
    if not isinstance(data, dict):
        raise Refused('--hec-file is not the JSON object `show_postdeploy.py --out` writes')
    if not data.get('hec_url') or not data.get('hec_token'):
        if data.get('cii_hec_token') or data.get('cii_hec_url'):
            raise Refused('--hec-file is the file `show_postdeploy.py --lab5 --out` wrote: its token writes the '
                          'Identity Intelligence index only. Pass the file the first `show_postdeploy.py --out` '
                          'run wrote')
        raise Refused('--hec-file has no hec_url and hec_token: pass the file `show_postdeploy.py --out` wrote')
    return data['hec_url'], data['hec_token'], data.get('index')


def hec_target(opts, env, bundle, stack_host):
    """R2. Where the events go and with which token: from --hec-file, or
    from --hec-url with the token in $STAGED_RESEND_HEC_TOKEN. Refused: a file
    that is not private, a URL that is not https://<host>[:port]/services/
    collector/event (never /raw: the time would be lost), an index that is not
    the bundle's, a HEC host that is not the stack's, a token that is not one
    plain header value. Nothing is contacted here and the token is never
    printed, not even in part."""
    index = None
    if opts.hec_file:
        url, token, index = read_hec_file(opts.hec_file)
        flag, origin = '--hec-file', '--hec-file'
    else:
        url, token = opts.hec_url, env.get(ENV_HEC_TOKEN) or ''
        flag, origin = '--hec-url', '--hec-url and ${}'.format(ENV_HEC_TOKEN)
        if not token:
            raise Refused('--hec-url: set the HEC token in ${} (no option takes a secret)'.format(ENV_HEC_TOKEN))
    scheme, host, port, path = split_url(url, flag, 443)
    if path != HEC_PATH:
        raise Refused('{}: the HEC URL must end in {} (never /raw: the event time would be lost)'.format(
            flag, HEC_PATH))
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        raise Refused('{}: the HEC token is not one plain value (it has a space or a line break, or is too '
                      'short); it is not repeated here'.format(flag))
    wanted = bundle['events'][0]['index']
    if index is not None and index != wanted:
        raise Refused('--hec-file is for another index than the bundle\'s ({}): this token may not write '
                      'there'.format(wanted))
    if not hec_belongs(stack_host, host):
        raise Refused('{}: the HEC host is not the one of the stack named with --stack: this token belongs to '
                      'another stack'.format(flag))
    return HecTarget(scheme, host, port, token, origin)


def hec_tls_policy(scheme, host, ca_file):
    """(verify, what the run says about it) for the HEC endpoint. There is no
    override: the token goes over unverified TLS to a loopback address only,
    and --ca-file turns verification on there too."""
    if scheme != 'https':
        return False, 'plain http to a loopback address, no certificate'
    if ca_file:
        return True, 'verified against the system trust store and --ca-file'
    if is_loopback(host):
        return False, 'not verified (a loopback address)'
    return True, 'verified against the system trust store'


def call_failure(exc):
    """failure_text() for an exception http.client raised itself (urllib
    wraps one in a URLError, whose `reason` failure_text reads)."""
    return failure_text(urllib.error.URLError(exc)).replace('(URLError)', '({})'.format(type(exc).__name__))


class Hec(object):
    """The HEC event endpoint of one stack, over http.client: one connection
    per request, opened with an explicit connect(), so that "nothing left this
    machine" (connect, DNS and TLS failures) can be told from "the request
    left and the answer is not known". The token travels in the Authorization
    header of a POST to HEC_PATH and nowhere else. Nothing is followed and
    nothing goes through a proxy."""

    def __init__(self, target, ca_file=None, timeout=HEC_TIMEOUT):
        self.scheme, self.host, self.port, self.timeout = target.scheme, target.host, target.port, timeout
        self._token = target.token
        self.verify, self.tls_words = hec_tls_policy(target.scheme, target.host, ca_file)
        self.ctx = None
        if self.scheme == 'https':
            self.ctx = seed._ssl_context(self.verify)
            if ca_file:
                try:
                    self.ctx.load_verify_locations(ca_file)
                except (OSError, ValueError, ssl.SSLError):
                    raise Refused('--ca-file cannot be read as a CA bundle (PEM certificates)')

    def __repr__(self):
        return 'Hec({}://{}:{})'.format(self.scheme, self.host, self.port)      # never the token

    def _connection(self):
        if self.scheme == 'https':
            return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.ctx)
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def post(self, body):
        """One POST of one request body -> Outcome. A failure of connect()
        is `not sent`. After that the request may have left: when request()
        itself fails (a server that answers 413 from the headers closes while
        the body is still being written), the answer is read all the same,
        once, and classified; with no answer the outcome is `unknown`."""
        conn = self._connection()
        try:
            conn.connect()
        except Exception as exc:                                  # DNS, refused, timeout, TLS: before any request
            conn.close()
            return not_sent(call_failure(exc))
        headers = dict(HEC_HEADERS, Authorization='Splunk {}'.format(self._token))
        try:
            try:
                conn.request('POST', HEC_PATH, body=body, headers=headers)
            except Exception:                                     # part of it may have left: look for an answer
                pass
            answer = conn.getresponse()
            status, text = answer.status, answer.read(65536)
        except Exception as exc:
            return unknown(call_failure(exc))
        finally:
            conn.close()
        return classify_answer(status, text.decode('utf-8', 'replace'))

    def health(self):
        """(HTTP status, text) of GET /services/collector/health, which takes
        no token; (0, the kind of failure) when there was no answer."""
        conn = self._connection()
        try:
            conn.request('GET', HEC_HEALTH_PATH, headers={'Connection': 'close'})
            answer = conn.getresponse()
            return answer.status, answer.read(65536).decode('utf-8', 'replace')
        except Exception as exc:
            return 0, call_failure(exc)
        finally:
            conn.close()


# --- send: the ledger --------------------------------------------------------------------
# <bundle>.ledger.jsonl: one JSON line per step, appended and forced to disk,
# under an exclusive lock for the whole run. It holds ids, counts, times and
# HEC's status and code: never a token, a body or an address.

LEDGER_VERSION = 1
LEDGER_KINDS = ('run', 'intent', 'outcome', 'confirmed', 'released', 'torn')
PROVES_NOTHING_INDEXED = (NOT_SENT, REFUSED, TOO_LARGE)     # the answers that end an id's "unconfirmed"


def ledger_line(text):
    """One ledger line as an object, or None for text this tool did not write."""
    try:
        line = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not (isinstance(line, dict) and line.get('v') == LEDGER_VERSION and line.get('kind') in LEDGER_KINDS
            and isinstance(line.get('stack'), str) and GUID_RE.fullmatch(line['stack'])
            and isinstance(line.get('at'), int) and not isinstance(line.get('at'), bool)):
        return None
    ids = line.get('ids', [])
    if not isinstance(ids, list) or not all(isinstance(item, str) and UUID_RE.fullmatch(item) for item in ids):
        return None
    if line['kind'] == 'outcome' and line.get('state') not in (ACCEPTED, NOT_SENT, REFUSED, TOO_LARGE, UNKNOWN):
        return None
    return line


def read_ledger(text, guid):
    """({id: when it was last handed to HEC} for the ids that are unconfirmed
    on the stack `guid`, whether the text ends in a torn line).

    An id is unconfirmed from its intent line on, until a `confirmed` line (the
    stack showed it) or an outcome that proves nothing of the request was
    indexed. An accepted or unknown outcome, a missing outcome (the run died)
    and a `released` line all leave it unconfirmed. A line this tool did not
    write is refused, with one exception: a last line that was cut off (no
    line end), which a full disk or a power cut leaves behind. It says nothing:
    an intent line is complete on disk before its request is sent."""
    pending, lines = {}, text.split('\n')
    torn = lines[-1] != ''
    for number, raw in enumerate(lines[:-1] if not torn else lines):
        line = ledger_line(raw)
        if line is None:
            follower = ledger_line(lines[number + 1]) if number + 1 < len(lines) else None
            if (torn and number == len(lines) - 1) or (follower is not None and follower['kind'] == 'torn'):
                continue
            raise Refused('the ledger beside the bundle has a line (number {}) that this tool did not write: '
                          'nothing is sent, because what was handed to which stack is no longer known'.format(
                              number + 1))
        if line['stack'].upper() != guid.upper():
            continue
        if line['kind'] == 'intent':
            pending.update((ident, line['at']) for ident in line['ids'])
        elif line['kind'] == 'confirmed' or (line['kind'] == 'outcome' and line['state'] in PROVES_NOTHING_INDEXED):
            for ident in line['ids']:
                pending.pop(ident, None)
    return pending, torn


def ledger_handed(text, guid, bundle_id):
    """The ids that runs of one bundle handed to the stack `guid` and that
    may therefore be on it, sorted: every intent line of that bundle, less
    the requests whose answer proved that nothing was indexed. It is what
    `verify` holds the stack's labelled events against."""
    counts = collections.Counter()
    for raw in text.split('\n'):
        line = ledger_line(raw)
        if line is None or line['stack'].upper() != guid.upper() or line.get('bundle') != bundle_id:
            continue
        if line['kind'] == 'intent':
            counts.update(line['ids'])
        elif line['kind'] == 'outcome' and line['state'] in PROVES_NOTHING_INDEXED:
            counts.subtract(line['ids'])
    return sorted(ident for ident, count in counts.items() if count > 0)


class Ledger(object):
    """The ledger of one bundle, open and locked for one run against the
    stack `guid`. A real run opens it for appending (created 0600 when
    missing) under an exclusive lock; a dry run reads an existing one under a
    shared lock and writes nothing. The lock is taken before a line is read
    and is held until close(), so two runs never decide from the same state."""

    def __init__(self, path, guid, bundle_id, clock, write=True):
        self.path, self.guid, self.bundle_id, self.clock, self.write = path, guid, bundle_id, clock, write
        self.handle, self.pending, self.torn = None, {}, False
        self.handed = 0                                       # events this run put on record as handed to HEC

    def open(self):
        busy = Refused('another `send` holds the ledger of this bundle: one send per bundle at a time (wait for '
                       'it to end; nothing was read or sent here)')
        if self.write:
            self.handle = open_private_append(self.path, 'the ledger beside the bundle')
        elif not os.path.lexists(self.path):
            return self                                       # a dry run creates nothing
        else:
            try:
                fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except OSError:
                raise Refused('the ledger beside the bundle cannot be read (a symlink?)')
            self.handle = os.fdopen(fd, 'r', encoding='utf-8')
        try:
            _check_private(os.fstat(self.handle.fileno()), 'the ledger beside the bundle')
            fcntl.flock(self.handle.fileno(), (fcntl.LOCK_EX if self.write else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except OSError:
            self.close()
            raise busy
        except Refused:
            self.close()
            raise
        try:
            self.handle.seek(0)
            self.pending, self.torn = read_ledger(self.handle.read(), self.guid)
        except ValueError:
            self.close()
            raise Refused('the ledger beside the bundle is not UTF-8 text: nothing is sent')
        except Refused:
            self.close()
            raise
        return self

    def close(self):
        if self.handle is not None:
            self.handle.close()                               # closing the file gives the lock back
            self.handle = None

    def _append(self, kind, ids=(), **more):
        """One line, complete on disk before this returns."""
        if not self.write or self.handle is None:
            raise Refused('a bug in this tool: a dry run tried to write the ledger')
        line = dict(more, v=LEDGER_VERSION, kind=kind, stack=self.guid, bundle=self.bundle_id, at=int(self.clock()))
        if ids:
            line['ids'] = list(ids)
        text = json.dumps(line, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n'
        if self.torn:                                         # end the cut-off line and say that it was one
            self.torn = False
            self.handle.write('\n')
            self._append('torn')
        self.handle.write(text)
        self.handle.flush()
        os.fsync(self.handle.fileno())
        return line

    def run(self, **counts):
        self._append('run', tool=TOOL, **counts)

    def intent(self, ids, size, canary):
        """BEFORE the request: these ids are about to be handed to HEC."""
        line = self._append('intent', ids, bytes=int(size), canary=bool(canary))
        self.handed += len(ids)
        self.pending.update((ident, line['at']) for ident in ids)

    def outcome(self, ids, outcome):
        self._append('outcome', ids, state=outcome.state, http=outcome.http, code=outcome.code)
        if outcome.state in PROVES_NOTHING_INDEXED:
            for ident in ids:
                self.pending.pop(ident, None)

    def confirmed(self, ids):
        """The stack showed these ids: they are no longer unconfirmed."""
        ids = [ident for ident in ids if ident in self.pending]
        if ids and self.write:
            self._append('confirmed', ids)
        for ident in ids:
            self.pending.pop(ident, None)

    def released(self, ids):
        """--resend-unconfirmed let these through. It changes nothing by
        itself: an id stays unconfirmed until its new request is on record."""
        self._append('released', ids)


# --- send: the joined rule on the stack (R5) ---------------------------------------------

RULE_PARSE_TIME = ('1', '2')        # a time range that holds nothing: the text is parsed and expanded, no event read
Slot = collections.namedtuple('Slot', 'period lag')        # minutes: the cron period, and how far back a slot ends
_UNIT_MINUTES = dict([(unit, 1) for unit in ('m', 'min', 'mins', 'minute', 'minutes')]
                     + [(unit, 60) for unit in ('h', 'hr', 'hrs', 'hour', 'hours')]
                     + [(unit, 1440) for unit in ('d', 'day', 'days')])


def spl_rule_parses(rule_text):
    """A stack's own text of the joined rule over RULE_PARSE_TIME: splunkd
    parses it and expands its macros, and answers one row."""
    return '{} | stats count as rows'.format(as_search(rule_text))


def spl_rule_ticks(rule):
    """The scheduler's status lines of one saved search, per tick, newest
    first. A tick the scheduler deferred logs `continued` and later `success`
    for the same scheduled_time, so runs are judged per tick, never per line."""
    return ('search index=_internal sourcetype=scheduler savedsearch_name={} '
            '| stats count(eval(status=="success")) as ok, count(eval(status=="continued")) as deferred, '
            'count(eval(status=="skipped")) as skipped by scheduled_time '
            '| sort 0 - scheduled_time').format(quoted([rule], ''))


def spl_rule_errors(rule):
    """A run that fails writes no status line at all: it writes an ERROR line
    that names the search only as savedsearch_id="<owner>;<app>;<name>"."""
    return ('search index=_internal sourcetype=scheduler log_level=ERROR savedsearch_id="*;{};{}" '
            '| stats count as errors, latest(message) as message, max(_time) as last_error').format(
                APP, quoted([rule], '')[1:-1])


def _on(value):
    return str(value).strip().lower() in ('1', 'true')


def _minutes_back(value):
    """Minutes before the cron tick for a dispatch time '-N<unit>@m'; None for any other form."""
    found = re.fullmatch(r'-(\d{1,6})([a-z]+)@m', str(value or '').strip().lower())
    if not found or found.group(2) not in _UNIT_MINUTES:
        return None
    return int(found.group(1)) * _UNIT_MINUTES[found.group(2)]


def rule_slot(rule):
    """(Slot, None) when a saved search judges by INDEX time on a slot exactly
    one cron period wide, as the joined rule ships (tools/duo_steps.py
    slot_minutes holds the Duo rules to the same contract): its runs then tile
    index time, and whatever is indexed after the rule is enabled is judged
    exactly once, however old the events are. Else (None, why)."""
    search = str(rule.get('search') or '')
    if '_index_earliest=' not in search or '_index_latest=' not in search:
        return None, 'it does not judge by index time (a TA build from before the rule did)'
    cron = re.fullmatch(r'\*/(\d{1,2}) \* \* \* \*', ' '.join(str(rule.get('cron_schedule') or '').split()))
    back = [_minutes_back(rule.get(key)) for key in ('dispatch.earliest_time', 'dispatch.latest_time')]
    if not cron or None in back or int(cron.group(1)) < 1:
        return None, 'its schedule is not every N minutes over -Xm@m to -Ym@m'
    period, width = int(cron.group(1)), back[0] - back[1]
    if 60 % period:
        return None, 'it runs every {} min, which does not divide the hour: its slots would overlap'.format(period)
    if width != period:
        return None, 'its time range is {} min wide but it runs every {} min: index-time slots would {}'.format(
            width, period, 'overlap' if width > period else 'leave gaps')
    if str(rule.get('realtime_schedule')).strip().lower() not in ('0', 'false'):
        return None, 'realtime_schedule is on: a run the scheduler skips is a slot never judged'
    if _on(rule.get('allow_data_time_skew')):
        return None, 'allow_data_time_skew is on: the slot moves off the cron tick'
    if any(str(rule.get(key) or '').strip() for key in ('dispatch.index_earliest', 'dispatch.index_latest')):
        return None, 'dispatch.index_earliest / dispatch.index_latest is set: the slot is no longer its time range'
    if 'is_scheduled' in rule and not _on(rule.get('is_scheduled')):
        return None, 'it is not scheduled'
    return Slot(period, back[1]), None


# --- send: the stack and its index (R3, R4) ----------------------------------------------

IDENTITY_MACRO = 'genai_identity_ai_events'     # what Identity Activity and the joined rule read events through
RETENTION_MARGIN_DAYS = 7


def check_stack(stack, bundle, now):
    """R3. splunkd answers and takes the credential, the TA is 1.9.0 or
    later, and the stack is not the Splunk the bundle was exported from (a
    copy beside its original is a duplicate nothing can remove)."""
    found = read_origin(stack, now, 'R3, reading the stack')
    if found['guid'].upper() == bundle['origin']['guid'].upper():
        raise Refused('--stack is the Splunk this bundle was exported from: its events are already there, and '
                      'a copy beside its original cannot be removed')
    return found


def read_macro_index(stack):
    """(the one index the stack's identity macro reads, None), or (None, why
    it could not be told). Unproven on a Splunk Cloud stack, so "could not be
    told" is an answer the caller handles, never a failure by itself."""
    code, text = stack.call('/servicesNS/nobody/{}/configs/conf-macros/{}'.format(APP, IDENTITY_MACRO))
    if code != 200:
        return None, 'the stack did not show the macro (HTTP {})'.format(code) if code else 'no answer'
    try:
        definition = json.loads(text)['entry'][0]['content']['definition']
    except (ValueError, KeyError, IndexError, TypeError, RecursionError):
        definition = None
    found = re.fullmatch(r'index\s*=\s*"?([a-z0-9][a-z0-9_-]{0,79})"?(\s.*)?', str(definition or '').strip(), re.S)
    if not found:
        return None, 'its definition names no single index this tool can read'
    return found.group(1), None


def read_retention(stack, index):
    """('read', seconds, disabled) from the stack's data/indexes, or
    ('unread', HTTP status, None) when the stack does not serve that endpoint
    or reports no number (a Splunk Cloud search head may not)."""
    code, text = stack.call('/services/data/indexes/{}'.format(urllib.parse.quote(index, safe='')))
    if code != 200:
        return 'unread', code, None
    try:
        content = json.loads(text)['entry'][0]['content']
        seconds = int(str(content.get('frozenTimePeriodInSecs')))
    except (ValueError, KeyError, IndexError, TypeError, AttributeError, RecursionError):
        return 'unread', code, None
    return ('read', seconds, _on(content.get('disabled'))) if seconds > 0 else ('unread', code, None)


def retention_problem(stack, opts, index, age_days):
    """(None, what was learned) when the index keeps the oldest event at
    least RETENTION_MARGIN_DAYS more days, else (the problem, None). The
    number is read from the stack; where the stack reports none, it is the
    operator's (--retention-days), and the output says so."""
    stated = None if opts.retention_days is None else whole_number(opts.retention_days, '--retention-days', 1, 36500)
    how, value, disabled = read_retention(stack, index)
    if how == 'read':
        if disabled:
            return 'the index is disabled on the stack', None
        days, source = value / 86400.0, 'read from the stack'
        if stated is not None:
            source += '; --retention-days was not needed and is not used'
    elif stated is None:
        return ('the stack does not report the index\'s retention (data/indexes answered HTTP {}): state its '
                'searchable days with --retention-days N (90 for an index show_postdeploy.py created)'.format(
                    value)), None
    else:
        days, source = float(stated), 'STATED with --retention-days, not read (data/indexes answered HTTP {})'.format(
            value)
    if days < age_days + RETENTION_MARGIN_DAYS:
        return ('it keeps {:.0f} days ({}) and the oldest event is {:.1f} days old: the copy would be frozen '
                'within {} days of arriving'.format(days, source, age_days, RETENTION_MARGIN_DAYS)), None
    return None, 'keeps {:.0f} days ({})'.format(days, source)


def check_index(stack, rep, opts, bundle, now, sleep):
    """R4. No override. The index is proven from the search tier (an index
    the account cannot search answers every later search with "nothing
    there", which would read as "send"); it is the index the stack's identity
    macro reads; it keeps the copy; and the events are old enough to be inert
    and young enough for the joined rule to read."""
    events = bundle['events']
    index, label = events[0]['index'], 'R4. index {}'.format(events[0]['index'])
    oldest, newest = float(events[0]['time']), float(events[-1]['time'])
    if not run_search(stack, spl_index_exists(index), '0', 'now', 'R4, looking for the index', (), sleep):
        rep.fail(label, 'this account can search no index of that name on the stack (it is missing, or '
                               'hidden from the account\'s role): every later check would read that as "the '
                               'stack holds nothing", which means "send"')
        return False
    reads, why = read_macro_index(stack)
    if reads is not None and reads != index:
        return rep.fail(label, 'the stack\'s macro {} reads index {}: Identity Activity and the joined rule would '
                               'never read a copy in {} (a bundle of another index is for a scratch rehearsal '
                               'on a dev Splunk)'.format(IDENTITY_MACRO, reads, index))
    if reads is None and index != DEFAULT_INDEX:
        return rep.fail(label, 'which index the stack\'s macro {} reads could not be told ({}), and the bundle\'s '
                               'index is not {}'.format(IDENTITY_MACRO, why, DEFAULT_INDEX))
    macro = ('the stack\'s {} reads it'.format(IDENTITY_MACRO) if reads is not None else
             'NOT CHECKED: which index {} reads ({}); the shipped definition reads {}, and `verify` reads the '
             'copies through it'.format(IDENTITY_MACRO, why, DEFAULT_INDEX))
    if now - newest < MIN_AGE_SECONDS:
        return rep.fail(label, 'the newest event is under {} minutes old: a rule with a recency test would read '
                               'its copy as live. Wait'.format(MIN_AGE_SECONDS // 60))
    if now - oldest > MAX_AGE_DAYS * 86400:
        return rep.fail(label, 'the oldest event is over {} days old: the joined rule reads back 181 days and '
                               'would never judge its copy'.format(MAX_AGE_DAYS))
    problem, learned = retention_problem(stack, opts, index, (now - oldest) / 86400.0)
    if problem:
        return rep.fail(label, problem)
    rep.ok(label, 'this account can search it; {}; {}; oldest event {:.1f} days old'.format(
        macro, learned, (now - oldest) / 86400.0))


def rule_problem(stack, rule, sleep):
    """(None, Slot, what was learned) when the joined rule will judge what
    is indexed from now on, else (the problem, None, None)."""
    if rule is None:
        return 'it is not on this stack (a TA build from before the rule: no such saved search)', None, None
    if _on(rule.get('disabled')):
        return 'it is disabled: enable it first (show_postdeploy.py --duo); what is indexed before that is ' \
               'never judged', None, None
    slot, why = rule_slot(rule)
    if slot is None:
        return why, None, None
    try:
        run_search(stack, spl_rule_parses(rule.get('search')), RULE_PARSE_TIME[0], RULE_PARSE_TIME[1],
                   'R5, parsing the rule', (), sleep)
    except Refused as exc:
        return 'its text does not run on this stack ({})'.format(exc), None, None
    reach = 2 * slot.period + 5
    ticks = run_search(stack, spl_rule_ticks(JOINED_RULE), '-{}m'.format(reach), 'now', 'R5, the rule\'s runs',
                       (), sleep)
    ran = [row for row in ticks if as_int(row.get('ok'), 0) > 0]
    late = sum(1 for row in ticks if as_int(row.get('deferred'), 0) > 0)
    if ran:
        tick = as_int(ran[0].get('scheduled_time'), 0)
        return None, slot, 'enabled, every {} min on a slot of index time that ends {} min back; last successful ' \
                           'tick {}{}'.format(slot.period, slot.lag, utc_second(tick) if tick else 'unknown',
                                              '; {} tick(s) were deferred first (lag, not failure)'.format(late)
                                              if late else '')
    errors = run_search(stack, spl_rule_errors(JOINED_RULE), '-{}m'.format(reach), 'now', 'R5, the rule\'s errors',
                        (), sleep)
    failed = as_int(errors[0].get('errors'), 0) if errors else 0
    if failed:
        return 'its scheduled runs FAIL ({} error line(s) in the last {} min): {}'.format(
            failed, reach, safe_text(one(errors[0].get('message')) or 'no message')), None, None
    return ('no successful scheduled run in the last {} min{}: wait for the next tick plus about two minutes and '
            'run `send` again'.format(reach, ' ({} tick(s) deferred and not run yet)'.format(late) if late else '')
            ), None, None


def check_rule(stack, rep, opts, sleep):
    """R5. The joined rule judges by INDEX time, so it must be on and running
    before the copy arrives: a copy indexed earlier is never judged. Returns
    the rule's Slot, or None when no finding is to be expected.
    --allow-rule-off sends all the same, for the dashboards alone."""
    label = 'R5. the joined rule'
    path = '/servicesNS/nobody/{}/saved/searches/{}'.format(APP, urllib.parse.quote(JOINED_RULE, safe=''))
    problem, slot, learned = rule_problem(stack, stack.content(path, 'R5, reading the joined rule'), sleep)
    if problem is None:
        rep.ok(label, learned + ('; --allow-rule-off was not needed' if opts.allow_rule_off else ''))
    elif opts.allow_rule_off:
        rep.skip(label, '{}. Sent all the same (--allow-rule-off): NO FINDING will be raised for this '
                        'copy'.format(problem))
    else:
        rep.fail(label, '{}. A sent event cannot be taken back (--allow-rule-off sends for the dashboards '
                        'alone)'.format(problem))
    return slot


def check_duo(stack, rep, opts, bundle, sleep):
    """R6. The other half of the chain: the Duo authentication behind every
    sign-in of the bundle is in the stack's Duo events exactly once, and the
    personas' Duo failures there are at least the ones read at export. No
    transaction id is printed. --without-duo sends all the same."""
    label, events = 'R6. the Duo half', bundle['events']
    txids, personas = signin_txids(events), bundle['selection']['personas']
    needed = collections.OrderedDict()
    for row in bundle['expect']['duo']['context']:
        if row['action'] == 'failure':
            needed[row['identity_user']] = needed.get(row['identity_user'], 0) + row['duo_events']
    if not txids and not needed:
        return rep.skip(label, 'the bundle has no sign-in with a Duo transaction id and its export read no Duo '
                               'failure: nothing to pair')
    bounds, once, found = duo_bounds(events), 0, 0
    for part in chunks(txids):
        for row in run_search(stack, spl_duo_half(part), bounds[0], bounds[1], 'R6, the Duo half', txids, sleep):
            once, found = once + as_int(row.get('found_once'), 0), found + as_int(row.get('txids_found'), 0)
    have = collections.Counter()
    for row in run_search(stack, spl_duo_context(personas), bounds[0], bounds[1], 'R6, the Duo context', (), sleep):
        if one(row.get('action')) == 'failure' and one(row.get('identity_user')) in personas:
            have[one(row.get('identity_user'))] += as_int(row.get('duo_events'), 0)
    problems = []
    if once != len(txids):
        problems.append('the Duo authentication of {} of {} sign-in(s) is on the stack exactly once ({} found at '
                        'all)'.format(once, len(txids), found))
    problems.extend('{} has {} Duo failure(s) on the stack and had {} where the bundle was exported'.format(
        user, have[user], count) for user, count in needed.items() if have[user] < count)
    if not problems:
        rep.ok(label, '{} of {} sign-in(s) paired exactly once; Duo failures: {}{}'.format(
            once, len(txids), ', '.join('{} {}'.format(user, have[user]) for user in needed) or 'none expected',
            '; --without-duo was not needed' if opts.without_duo else ''))
    elif opts.without_duo:
        rep.skip(label, '{}. Sent all the same (--without-duo): no chain can form until Duo\'s events '
                        'arrive'.format('; '.join(problems)))
    else:
        rep.fail(label, '{}. Run `show_postdeploy.py --duo` and let its first poll finish, then `send` again '
                        '(--without-duo sends without it)'.format('; '.join(problems)))


def check_health(hec, rep):
    """R8. HEC says it is healthy (GET /services/collector/health, no token)."""
    label = 'R8. HEC health'
    status, text = hec.health()
    if status == 0:
        return rep.fail(label, 'no answer from the HEC endpoint ({})'.format(text))
    answer = classify_answer(status, text)
    if status == 200 and answer.code == 17:
        return rep.ok(label, 'HEC is healthy; certificate: {}'.format(hec.tls_words))
    rep.fail(label, 'the HEC endpoint did not say it is healthy ({})'.format(answer.detail))


# --- send: what goes, what waits, what stops (R7) ------------------------------------------

class Halt(Exception):
    """A run that ends here, with its exit code. Unlike Refused it can come
    after something was sent, so it always says what was and what was not."""

    def __init__(self, code, text):
        Exception.__init__(self, text)
        self.code = code


def canary_of(events):
    """The one event that goes first, alone: the earliest audit record that
    is not a sign-in (a session start raises nothing and enters no data model),
    else the earliest event."""
    plain = [event for event in ordered(events)
             if event['log_type'] == 'audit' and parse_body(event['raw'])[0].get('action') != SIGNIN_ACTION]
    return (plain or ordered(events))[0]


def poll_presence(stack, index, events, bundle_id, seconds, clock, sleep, what):
    """{id: Decision} from the presence search, asked again every
    POLL_SECONDS until the stack holds every one of these events (no `send`
    verdict is left) or `seconds` have passed. With 0 seconds it looks once."""
    deadline = clock() + seconds
    while True:
        decisions = presence(stack, index, events, bundle_id, what, sleep)
        left = deadline - clock()
        if left <= 0 or all(decision.verdict != SEND for decision in decisions.values()):
            return decisions
        sleep(min(POLL_SECONDS, max(1, left)))


Plan = collections.namedtuple('Plan', 'decisions send held released later stop')


def make_plan(events, decisions, pending, now, resend_unconfirmed, no_canary=False):
    """What a run does with each event, from what the stack holds (P1) and
    what the ledger says was handed to this stack before:

        send       the stack does not hold it and it was never handed to HEC
        held       it was handed to HEC and the stack does not show it: never
                   sent again, whatever the answer was and also when the run
                   died before one came ...
        released   ... unless --resend-unconfirmed, RESEND_UNCONFIRMED_AFTER
                   seconds or more after it was handed over
        later      it would be sent, but ids are held and no copy of this
                   bundle is on the stack yet: the only events ever handed to
                   this stack are unaccounted for, so nothing proves that it
                   keeps an event as sent. Nothing new goes before that
                   (--no-canary waives the proof here as everywhere)
        stop       a conflict or a duplicate: nothing at all is sent
    Everything else is on the stack, identical, and is skipped."""
    send, held, released, later, stop = [], [], [], [], []
    for event in ordered(events):
        ident, verdict = event['id'], decisions[event['id']].verdict
        if verdict in STOP_VERDICTS:
            stop.append(event)
        elif verdict == SEND and ident not in pending:
            send.append(event)
        elif verdict == SEND and resend_unconfirmed and now - pending[ident] >= RESEND_UNCONFIRMED_AFTER:
            released.append(event)
        elif verdict == SEND:
            held.append(event)
    proven = any(decision.verdict == THIS_BUNDLE for decision in decisions.values())
    if held and not proven and not no_canary:
        send, later = [], send
    return Plan(decisions, send, held, released, later, stop)


def show_plan(events, plan, pending, now, first, echo):
    """One line per event: its id and what this run does with it. Never a body."""
    names = {}
    names.update((event['id'], 'send') for event in plan.send)
    names.update((event['id'], 'SEND AGAIN (--resend-unconfirmed: handed to HEC {} s ago, not on the stack)'.format(
        int(now - pending[event['id']]))) for event in plan.released)
    names.update((event['id'], 'HOLD (handed to HEC {} s ago and not on the stack: not sent again)'.format(
        int(now - pending[event['id']]))) for event in plan.held)
    names.update((event['id'], 'WAIT (not sent before the event(s) handed over earlier are on the stack)')
                 for event in plan.later)
    for event in ordered(events):
        decision = plan.decisions[event['id']]
        action = names.get(event['id'])
        if action is None and decision.verdict in STOP_VERDICTS:
            action = 'STOP ({}{})'.format(decision.verdict,
                                          ': ' + ', '.join(decision.differs) if decision.differs else '')
        elif action is None:
            action = 'skip (on the stack, identical: {})'.format(decision.verdict)
        if first is not None and event['id'] == first['id']:
            action += ', first and alone (the canary)'
        echo('    {}  {:<10} {:<20} {}'.format(event['id'], event['log_type'], event['sourcetype'], action))


# --- send: the requests ---------------------------------------------------------------------

class Sender(object):
    """Hands events to HEC, each at most once. Every request is on record in
    the ledger before it is made. Only an answer that proves nothing was
    indexed is followed by a second request for the same events."""

    def __init__(self, stack, hec, ledger, bundle, settle, clock, sleep, echo):
        self.stack, self.hec, self.ledger, self.bundle, self.settle = stack, hec, ledger, bundle, settle
        self.clock, self.sleep, self.echo = clock, sleep, echo
        self.bundle_id, self.index = bundle['bundle_id'], bundle['events'][0]['index']
        self.sent = []                                        # ids of this run that HEC took or the stack showed

    def request(self, batch, canary):
        """One request -> Outcome. The intent line is complete on disk
        first. `not sent` (and nothing else) is tried again after RETRY_WAITS."""
        ids = [event['id'] for event in batch.events]
        self.ledger.intent(ids, len(batch.body), canary)
        outcome = self.hec.post(batch.body)
        for wait in RETRY_WAITS:
            if outcome.state != NOT_SENT:
                break
            self.echo('    not sent, nothing was indexed ({}): again in {} s'.format(outcome.detail, wait))
            self.sleep(wait)
            outcome = self.hec.post(batch.body)
        self.ledger.outcome(ids, outcome)
        return outcome

    def judge(self, events, decisions, what):
        """Events this run handed over, as the stack now shows them. Each must
        be there once, identical and labelled with this bundle; anything else
        ends the run."""
        absent = [event['id'] for event in events if decisions[event['id']].verdict == SEND]
        wrong = ['{} ({})'.format(event['id'], ', '.join(decisions[event['id']].differs) or
                                  decisions[event['id']].verdict)
                 for event in events if decisions[event['id']].verdict not in (SEND, THIS_BUNDLE)]
        if wrong:
            raise Halt(EXIT_FAILED, '{}: the stack does not hold {} of {} event(s) as they were sent: {}. A stack '
                                    'that changes an event is not one to copy into; nothing more was sent, and '
                                    'what is there cannot be removed'.format(what, len(wrong), len(events),
                                                                             ', '.join(wrong[:5])))
        if absent:
            raise Halt(EXIT_UNKNOWN, '{}: {} of {} event(s) handed to HEC are not searchable after {} s: {}. '
                                     'They are NOT sent again and nothing more was sent. Wait, run `verify`, '
                                     'then `send` again'.format(what, len(absent), len(events), self.settle,
                                                                ', '.join(absent[:5])))
        self.ledger.confirmed([event['id'] for event in events])

    def look(self, events, what):
        return poll_presence(self.stack, self.index, events, self.bundle_id, self.settle, self.clock, self.sleep, what)

    def deliver(self, batch, canary=False):
        """Hand one request over and account for every event of it."""
        count, ids = len(batch.events), [event['id'] for event in batch.events]
        outcome = self.request(batch, canary)
        if outcome.state == TOO_LARGE and count > 1:
            self.echo('  {} event(s) are too large for one request ({}): sending them in two'.format(
                count, outcome.detail))
            for half in halve(batch, self.bundle_id):
                self.deliver(half)
            return
        if outcome.state in PROVES_NOTHING_INDEXED:
            raise Halt(EXIT_FAILED, 'HEC did not take a request of {} event(s) ({}; {}). Nothing of it was indexed '
                                    'and nothing after it was sent'.format(count, outcome.state, outcome.detail))
        if outcome.state == UNKNOWN:
            self.echo('  the answer for {} event(s) does not say whether they were indexed ({}). They are NOT '
                      'sent again; asking the stack for up to {} s'.format(count, outcome.detail, self.settle))
            self.judge(batch.events, self.look(batch.events, 'P1, after an answer that says nothing'),
                       'after an answer that says nothing')
        else:
            self.echo('  {} event(s) accepted by HEC ({})'.format(count, outcome.detail))
            if canary:
                self.judge(batch.events, self.look(batch.events, 'P1, the canary'), 'the canary')
                self.echo('  the canary is on the stack once, identical and labelled {}'.format(self.bundle_id))
        self.sent.extend(ids)


def check_presence(stack, rep, opts, bundle, ledger, settle, quiet, clock, sleep, echo):
    """R7. What the stack holds of every id (P1) and what the ledger says was
    handed to this stack before -> Plan. Ids that were handed over and are not
    there are waited for (up to --settle, in a run that may still send) and
    are never sent again, unless --resend-unconfirmed and an hour has passed.
    A conflict or a duplicate fails the step, and nothing overrides that."""
    label, events, bundle_id = 'R7. what the stack holds', bundle['events'], bundle['bundle_id']
    index = events[0]['index']
    decisions = presence(stack, index, events, bundle_id, 'R7, the presence search', sleep)
    ledger.confirmed([ident for ident, decision in decisions.items() if decision.verdict in SKIP_VERDICTS])
    plan = make_plan(events, decisions, ledger.pending, clock(), opts.resend_unconfirmed, opts.no_canary)
    if plan.held and not plan.stop and not quiet:
        echo('  {} id(s) were handed to HEC before and are not on the stack: waiting up to {} s for them (they '
             'are not sent again)'.format(len(plan.held), settle))
        decisions.update(poll_presence(stack, index, plan.held, bundle_id, settle, clock, sleep,
                                       'R7, waiting for unconfirmed ids'))
        ledger.confirmed([ident for ident, decision in decisions.items() if decision.verdict in SKIP_VERDICTS])
        plan = make_plan(events, decisions, ledger.pending, clock(), opts.resend_unconfirmed, opts.no_canary)
    counts = plan_counts(decisions)
    if plan.stop:
        rep.fail(label, '{} conflict(s) and {} duplicate(s): {}. Nothing is sent and no option overrides this: '
                        'the tool can repair neither'.format(counts[CONFLICT], counts[DUPLICATE], ', '.join(
                            '{} ({})'.format(event['id'], ', '.join(decisions[event['id']].differs) or 'copies')
                            for event in plan.stop[:5])))
        return plan
    words = 'to send {}; on the stack, identical: {} (live {}, this bundle {}, another bundle {})'.format(
        len(plan.send), counts[LIVE] + counts[THIS_BUNDLE] + counts[OTHER_BUNDLE], counts[LIVE],
        counts[THIS_BUNDLE], counts[OTHER_BUNDLE])
    if plan.held:
        words += '; HELD {}: handed to HEC before, not on the stack, NOT sent again (--resend-unconfirmed lets ' \
                 'one through {} s after it was handed over)'.format(len(plan.held), RESEND_UNCONFIRMED_AFTER)
    if plan.later:
        words += '; WAITING {}: nothing new is sent before the event(s) handed over earlier are on the ' \
                 'stack'.format(len(plan.later))
    if plan.released:
        words += '; {} sent AGAIN (--resend-unconfirmed): if the stack did take one, it becomes a duplicate for ' \
                 'good'.format(len(plan.released))
    elif opts.resend_unconfirmed:
        words += '; --resend-unconfirmed let nothing through'
    rep.ok(label, words)
    return plan


def send_plan(sender, plan, opts, echo):
    """Hand over what the plan sends: the canary first and alone, the rest
    only after the stack returned it once, identical and labelled."""
    ledger, bundle_id = sender.ledger, sender.bundle_id
    going = ordered(plan.send + plan.released)
    if not going:
        return echo('  nothing to send')
    if plan.released:
        ledger.released([event['id'] for event in plan.released])
    ledger.run(send=len(going), held=len(plan.held))
    first = first_of(plan, opts)
    if opts.no_canary:
        echo('  --no-canary: no event goes first and alone. A stack that changes what it indexes gets every event '
             'wrong, not one')
    if first is not None:
        echo('  the canary: one event first, alone ({})'.format(first['id']))
        sender.deliver(make_batch([first], bundle_id), canary=True)
        going = [event for event in going if event['id'] != first['id']]
    for batch in batches(going, bundle_id):
        sender.deliver(batch)


def first_of(plan, opts):
    """The canary of this run, or None: with --no-canary, with nothing to
    send, or when a copy of this bundle is on the stack already (an earlier
    run's canary proved that this stack keeps an event as it is sent)."""
    going = plan.send + plan.released
    proven = any(decision.verdict == THIS_BUNDLE for decision in plan.decisions.values())
    return None if (opts.no_canary or proven or not going) else canary_of(going)


def finish_send(sender, plan, opts, echo):
    """After the last request: wait until the stack shows every id once and
    identical (--settle), then say how the run ended. Exit 0 only when the
    whole set is on the stack; 3 while an id that was handed to HEC is not."""
    events, ledger = sender.bundle['events'], sender.ledger
    waited = sender.settle if sender.sent else 0          # held ids were waited for before anything was sent
    decisions = poll_presence(sender.stack, sender.index, events, sender.bundle_id, waited, sender.clock,
                              sender.sleep, 'P1, after sending')
    stopped = [event['id'] for event in events if decisions[event['id']].verdict in STOP_VERDICTS]
    if stopped:
        raise Halt(EXIT_FAILED, 'after sending, the stack holds {} id(s) twice or in another form: {}. That cannot '
                                'be removed'.format(len(stopped), ', '.join(stopped[:5])))
    sender.judge([event for event in events if event['id'] in sender.sent], decisions, 'after the last request')
    ledger.confirmed([ident for ident, decision in decisions.items() if decision.verdict in SKIP_VERDICTS])
    absent = [event['id'] for event in events if decisions[event['id']].verdict == SEND]
    if absent:
        waiting = [ident for ident in absent if ident not in ledger.pending]
        raise Halt(EXIT_UNKNOWN, '{} id(s) that were handed to HEC before are still not on the stack and were NOT '
                                 'sent again: {}.{} Run `verify` later, then `send` again; --resend-unconfirmed '
                                 'lets one through {} s after it was handed over'.format(
                                     len(absent) - len(waiting),
                                     ', '.join([ident for ident in absent if ident in ledger.pending][:5]),
                                     ' {} more id(s) were not sent in this run.'.format(len(waiting)) if waiting
                                     else '', RESEND_UNCONFIRMED_AFTER))
    echo('')
    echo('SENT: the stack holds each of the {} id(s) once, identical. This run sent {}; {} were there '
         'already.'.format(len(events), len(sender.sent), len(events) - len(sender.sent)))
    echo('Next: staged_resend.py verify --bundle <path> --stack <url> --wait 900')
    return EXIT_OK


def run_send(opts, stack, hec, ledger, bundle, settle, clock, sleep, echo):
    """R4 to R8, the plan, and (unless --dry-run or a failed step) the requests."""
    rep, now = seed.Reporter(echo), clock()
    searchable = check_index(stack, rep, opts, bundle, now, sleep) is not False
    check_rule(stack, rep, opts, sleep)
    check_duo(stack, rep, opts, bundle, sleep)
    plan = None
    if searchable:
        quiet = bool(opts.dry_run or rep.failures())          # a run that will send nothing does not wait
        plan = check_presence(stack, rep, opts, bundle, ledger, settle, quiet, clock, sleep, echo)
    else:
        rep.skip('R7. what the stack holds', 'not read: without a searchable index "nothing there" proves nothing')
    check_health(hec, rep)
    if plan is not None:
        echo('')
        echo('  Per id ({} event(s)):'.format(len(bundle['events'])))
        show_plan(bundle['events'], plan, ledger.pending, clock(), first_of(plan, opts), echo)
    echo('')
    if rep.failures():
        echo('NOT SENT: {} step(s) failed. Nothing was sent to HEC.'.format(rep.failures()))
        return EXIT_FAILED
    if opts.dry_run:
        echo('DRY RUN: every step passed. Nothing was sent to HEC and the ledger was not written. A run without '
             '--dry-run would send {} event(s).'.format(len(plan.send) + len(plan.released)))
        return EXIT_OK
    sender = Sender(stack, hec, ledger, bundle, settle, clock, sleep, echo)
    echo('Sending to HEC ({}; at most {} events and {} KiB a request)'.format(
        hec.tls_words, MAX_REQUEST_EVENTS, MAX_REQUEST_BYTES // 1024))
    send_plan(sender, plan, opts, echo)
    return finish_send(sender, plan, opts, echo)


def cmd_send(opts, env, clock, sleep, echo):
    """send: copy an approved bundle to one stack, each event at most once.
    Order: everything that needs no network first (R1 the bundle, the options,
    the credential, R2 the HEC endpoint); then R3; then the ledger's lock,
    taken before a ledger line or the stack's holdings are read; then R4 to
    R8, each a row, and the plan; then the requests. Nothing reaches HEC
    unless every step passed or its named override was given, and --dry-run
    reaches HEC only for its health. With --wait-finding N a complete send is
    followed by what `verify --wait N` does, after the ledger's lock has been
    given back; the exit code is then the verification's."""
    settle = whole_number(opts.settle, '--settle', 0, 3600)
    wait_finding = whole_number(opts.wait_finding, '--wait-finding', 0, MAX_WAIT_SECONDS)
    if opts.retention_days is not None:
        whole_number(opts.retention_days, '--retention-days', 1, 36500)
    bundle = load_bundle(opts.bundle, need_approval=True)                     # R1
    kind, secret = credential(env, ENV_STACK_PASSWORD, ENV_STACK_TOKEN)
    scheme, host, _, _ = split_url(opts.stack, '--stack', 8089)
    verify, tls_words = tls_policy(scheme, host, opts.ca_file, opts.no_verify_splunkd, '--no-verify-splunkd')
    stack = Splunkd(opts.stack, '--stack', kind, secret, opts.username, verify, opts.ca_file, '--no-verify-splunkd')
    target = hec_target(opts, env, bundle, host)                              # R2
    hec = Hec(target, opts.ca_file)
    events = bundle['events']
    echo('Send bundle {} to --stack{}'.format(bundle['bundle_id'], ' (DRY RUN)' if opts.dry_run else ''))
    echo('  [  OK] R1. bundle - private, approved as it is: {} event(s), digest {}'.format(
        len(events), bundle['digest'][:12]))
    echo('  [  OK] R2. HEC - token from {}; the endpoint is the stack\'s; index {}'.format(
        target.origin, events[0]['index']))
    echo('  certificate of port 8089: {}'.format(tls_words))      # said before the first request is made
    echo('  certificate of HEC: {}'.format(hec.tls_words))
    found = check_stack(stack, bundle, clock())                                # R3
    echo('  [  OK] R3. stack - Splunk {}, {} {}, not the Splunk the bundle came from'.format(
        found['splunk_version'], APP, found['ta_version']))
    ledger = Ledger(ledger_path(opts.bundle), found['guid'], bundle['bundle_id'], clock,
                    write=not opts.dry_run).open()
    try:
        code = run_send(opts, stack, hec, ledger, bundle, settle, clock, sleep, echo)
    except Halt as halt:
        echo('')
        echo('{}: {}'.format('DELIVERY UNKNOWN' if halt.code == EXIT_UNKNOWN else 'STOPPED', halt))
        return halt.code
    except Refused as exc:
        if not ledger.handed:
            raise                                             # nothing was handed to HEC: a plain refusal
        echo('')
        echo('DELIVERY UNKNOWN: {} event(s) were handed to HEC in this run, and then the stack could not be read '
             '({}). Nothing is sent again: run `verify`, then `send` again'.format(ledger.handed, exc))
        return EXIT_UNKNOWN
    finally:
        ledger.close()                                        # before any wait: a send to another stack may start
    if code != EXIT_OK or not wait_finding:
        return code
    echo('')
    if opts.dry_run:
        echo('--wait-finding is not used in a dry run: nothing was sent, so there is nothing to wait for.')
        return code
    echo('--wait-finding {}: reading the stack again, as `verify --wait {}` does'.format(wait_finding, wait_finding))
    try:
        return run_verify(stack, bundle, found['guid'], opts.bundle, wait_finding, clock, sleep, echo)
    except Refused as exc:
        echo('')
        echo('NOT VERIFIED: the send is complete, and then the stack could not be read ({}). Nothing is to be '
             'sent again; run `verify`.'.format(exc))
        return EXIT_FAILED


# --- verify: the three texts it adds (P2, V6, V6b) -------------------------------------------

FINDING_GRACE_SECONDS = 420         # after the tick: the scheduler's start, its skew (5 min), the run, the actions
FINDING_POLL_SECONDS = 30           # between two looks for the finding
FINDING_REACH_SECONDS = 86400       # V6 reads from a day before the first event: a risk event is dated at the event


def spl_label(index, bundle_id):
    """P2. The events a stack holds under this bundle's label, counted from
    the index's own fields (tstats: the label is three indexed fields and no
    fields.conf stanza declares them). No row when there is none."""
    if not isinstance(bundle_id, str) or not BUNDLE_ID_RE.fullmatch(bundle_id):
        raise Refused('a bug in this tool: a label that is not a bundle id cannot be searched for')
    return ('| tstats count as events, min(_indextime) as first_indexed, max(_indextime) as last_indexed '
            'where index={} resend_bundle={} by sourcetype, log_type, host').format(
                quoted([index], ''), quoted([bundle_id], ''))


def spl_findings(rule, chains):
    """V6. What the scheduled rule raised for these chains: its findings
    (index notable, dated when they were raised, the event's time in
    orig_time) and its risk events (index risk, dated at the event). The
    answer holds counts, times and the chain ids that were asked for."""
    chains = list(chains)
    if not chains or not all(isinstance(chain, str) and CHAIN_RE.fullmatch(chain) for chain in chains):
        raise Refused('a bug in this tool: a finding is looked for by chain id, and this is not a list of them')
    return ('search (index=notable OR index=risk) search_name={} ({}) '
            '| eval rs_event_time=coalesce(orig_time, _time) '
            '| stats count as rows, min(_indextime) as first_raised, values(rs_event_time) as event_time '
            'by index, chain_id').format(
                quoted([rule], ''), ' OR '.join('chain_id={}'.format(quoted([chain], '')) for chain in chains))


def spl_rule_runs(rule, tick):
    """V6b. The scheduler's own record of a saved search's runs from one cron
    tick on: what is printed when a finding is late. A deferred or skipped
    tick has a line without dispatch_time, so its row has no lag."""
    if not isinstance(tick, int) or isinstance(tick, bool) or tick < 0:
        raise Refused('a bug in this tool: a cron tick is a whole second')
    return ('search index=_internal sourcetype=scheduler savedsearch_name={} scheduled_time>={:d} '
            '| eval lag=dispatch_time-scheduled_time '
            '| table scheduled_time, dispatch_time, lag, status, result_count, suppressed, alert_actions').format(
                quoted([rule], ''), tick)


def judging_tick(indexed, slot):
    """The cron tick (epoch seconds) of the scheduled run that judges what
    was indexed at second `indexed`. A run at tick T reads the index-time
    slot [T - lag - period, T - lag), so it is the first tick after
    indexed + lag: for the shipped rule (every 5 min, ending 2 min back)
    (floor((indexed + 120) / 300) + 1) * 300."""
    step, lag = slot.period * 60, slot.lag * 60
    return ((int(indexed) + lag) // step + 1) * step


# --- verify: the copies and the label (V1, V2) -----------------------------------------------

def ledger_text(bundle_path):
    """The ledger beside a bundle as `verify` reads it: its whole text, or ''
    when there is none. Read-only, never through a symlink, and under a shared
    lock that is given back at once (a `verify --wait` must not keep a `send`
    to another stack out). A `send` that is running holds the ledger
    exclusively and is refused here: its requests are still under way."""
    path, what = ledger_path(bundle_path), 'the ledger beside the bundle'
    if not os.path.lexists(path):
        return ''
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise Refused('{} cannot be read (a symlink?)'.format(what))
    with os.fdopen(fd, 'r', encoding='utf-8') as handle:
        _check_private(os.fstat(handle.fileno()), what)
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError:
            raise Refused('a `send` of this bundle is running (it holds the ledger): run `verify` when it has '
                          'ended. Nothing was read')
        try:
            return handle.read()
        except ValueError:
            raise Refused('{} is not UTF-8 text'.format(what))


Copies = collections.namedtuple('Copies', 'rows decisions unknown failed')


def verify_copies(stack, rep, bundle, handed, clock, sleep, echo):
    """V1. Every id of the bundle is on the stack exactly once and identical
    (decide()), under a label or delivered live. An id the ledger says was
    handed to HEC and that is not searchable yet is asked for again every
    POLL_SECONDS, for up to SETTLE_SECONDS; an id nobody handed over is not
    waited for. Returns Copies: the rows by id, the decisions, `unknown`
    (handed-over ids are still missing and nothing else is wrong: exit 3)
    and `failed`."""
    label, events, bundle_id = 'V1. the copies', bundle['events'], bundle['bundle_id']
    index, handed = events[0]['index'], set(handed)

    def look():
        rows = presence_rows(stack, index, events, 'V1, the presence search', sleep)
        decisions = plan(events, rows, bundle_id)
        return rows, decisions, [ident for ident, decision in decisions.items() if decision.verdict == SEND]

    rows, decisions, absent = look()
    deadline = clock() + SETTLE_SECONDS
    if handed.intersection(absent):
        echo('  {} id(s) that were handed to HEC are not searchable yet: asking again every {} s, for up to '
             '{} s'.format(len(handed.intersection(absent)), POLL_SECONDS, SETTLE_SECONDS))
    while handed.intersection(absent) and clock() < deadline:
        sleep(min(POLL_SECONDS, max(1, deadline - clock())))
        rows, decisions, absent = look()
    counts = plan_counts(decisions)
    wrong = ['{} ({})'.format(ident, ', '.join(decision.differs) or 'more than one copy')
             for ident, decision in decisions.items() if decision.verdict in STOP_VERDICTS]
    waiting = [ident for ident in absent if ident in handed]
    unsent = [ident for ident in absent if ident not in handed]
    problems = []
    if wrong:
        problems.append('{} id(s) are there in another form and {} more than once: {}{}. Neither can be removed '
                        'from the stack'.format(counts[CONFLICT], counts[DUPLICATE], ', '.join(wrong[:5]),
                                                ' ...' if len(wrong) > 5 else ''))
    if waiting:
        problems.append('{} id(s) were handed to HEC and are not searchable after {} s: {}{}. DELIVERY UNKNOWN: '
                        'they are not to be sent again; run `verify` again later'.format(
                            len(waiting), SETTLE_SECONDS, ', '.join(waiting[:5]), ' ...' if len(waiting) > 5 else ''))
    if unsent:
        problems.append('{} id(s) are not on the stack and the ledger records no send of them to it: {}{}. Run '
                        '`send`'.format(len(unsent), ', '.join(unsent[:5]), ' ...' if len(unsent) > 5 else ''))
    if problems:
        rep.fail(label, '; '.join(problems))
    else:
        rep.ok(label, 'each of the {} id(s) is on the stack once, identical: {} under this bundle\'s label, {} '
                      'delivered live, {} under another bundle\'s label'.format(
                          len(events), counts[THIS_BUNDLE], counts[LIVE], counts[OTHER_BUNDLE]))
    return Copies(rows_by_id(rows), decisions, bool(waiting) and not wrong, bool(problems))


def verify_label(stack, rep, bundle, handed, sleep):
    """V2. The events that carry this bundle's label on the stack (P2) are
    the ones the ledger says were handed to it, kind for kind (sourcetype,
    log_type, host): none that nobody recorded, none recorded that is not
    there. Only counts are printed."""
    label, events, handed = 'V2. the label', bundle['events'], set(handed)
    rows = run_search(stack, spl_label(events[0]['index'], bundle['bundle_id']), ALL_TIME[0], ALL_TIME[1],
                      'V2, the labelled events', (), sleep)
    held = collections.Counter()
    for row in rows:
        held[tuple(one(row.get(name)) for name in ('sourcetype', 'log_type', 'host'))] += as_int(row.get('events'), 0)
    recorded = collections.Counter((event['sourcetype'], event['log_type'], event['host'])
                                   for event in events if event['id'] in handed)
    have, want = sum(held.values()), sum(recorded.values())
    if +held == recorded:
        return rep.ok(label, '{} event(s) carry this bundle\'s label, the {} the ledger records as handed to this '
                             'stack'.format(have, want))
    if have > want:
        why = ('events were sent that this ledger does not record: it is not the ledger of every send (keep the '
               'ledger with the bundle and send from one machine), or an id is there twice')
    elif have < want:
        why = 'events that were handed to HEC are not there, or not there under the label: see V1'
    else:
        why = 'a copy is under another sourcetype, log_type or host than its original'
    rep.fail(label, '{} event(s) carry this bundle\'s label and the ledger records {} handed to this stack: '
                    '{}'.format(have, want, why))


def macro_problem(stack, index):
    """(why the stack's own macros cannot prove anything about the copies,
    None), or (None, what was learned about the macro). V3 and V5 read
    through the identity macro, which fixes the index: where it reads another
    index than the bundle's they would count other events (on a dev Splunk,
    the originals) and pass without reading one copy."""
    reads, why = read_macro_index(stack)
    if reads is not None and reads != index:
        return ('the stack\'s macro {} reads index {} and the copies are in {}: read through it, nothing would '
                'be said about them'.format(IDENTITY_MACRO, reads, index)), None
    if reads is None and index != DEFAULT_INDEX:
        return ('which index the stack\'s macro {} reads could not be told ({}), and the bundle\'s index is not '
                '{}'.format(IDENTITY_MACRO, why, DEFAULT_INDEX)), None
    if reads is None:
        return None, '; NOT CHECKED: which index {} reads ({}); the shipped definition reads {}'.format(
            IDENTITY_MACRO, why, DEFAULT_INDEX)
    return None, ''


def identity_text(rows):
    return '; '.join('{}: events {}, copies {}, identity_events {}, ai_turns {}, ai_blocked {}, app_signins {}'.format(
        row['identity_key'], *[row[name] for name in EXPECT_COUNTS]) for row in rows) or 'no identity row'


def verify_counts(stack, rep, bundle, macro, sleep):
    """V3. Read through the stack's own identity macro (what Identity
    Activity reads), the bundle's ids give the row the source gave at export
    (E1). macro: what macro_problem() said."""
    label, events, expected = 'V3. the counts the dashboards read', bundle['events'], bundle['expect']['identity']
    if macro[0]:
        return rep.fail(label, macro[0])
    try:
        row_lists = [run_search(stack, spl_expect(part), ALL_TIME[0], ALL_TIME[1], 'V3, the expected counts', (),
                                sleep) for part in chunks([event['id'] for event in events])]
        found = identity_part(row_lists, bundle['selection']['personas'])
    except Refused as exc:
        return rep.fail(label, 'not read: {}'.format(exc))
    if found == expected:
        return rep.ok(label, '{}, as on the source{}'.format(identity_text(found), macro[1]))
    rep.fail(label, 'the stack gives [{}] and the source gave [{}]: the events are read differently here (compare '
                    'the TA versions and look for a local override of its macros or props), or V1 failed'.format(
                        identity_text(found), identity_text(expected)))


# --- verify: the Duo half, the rule and its finding (V4, V5, V6) ------------------------------

def verify_duo(stack, rep, bundle, sleep):
    """V4. The Duo authentication behind every sign-in of the bundle is in
    the stack's Duo events exactly once (D1). No transaction id is printed."""
    label, events = 'V4. the Duo half', bundle['events']
    txids, bounds, once, found = signin_txids(events), duo_bounds(events), 0, 0
    if not txids:
        return rep.skip(label, 'the bundle has no sign-in with a Duo transaction id: nothing to pair')
    for part in chunks(txids):
        for row in run_search(stack, spl_duo_half(part), bounds[0], bounds[1], 'V4, the Duo half', txids, sleep):
            once, found = once + as_int(row.get('found_once'), 0), found + as_int(row.get('txids_found'), 0)
    if once == len(txids):
        return rep.ok(label, 'the Duo authentication of each of the {} sign-in(s) is on the stack exactly '
                             'once'.format(len(txids)))
    rep.fail(label, 'the Duo authentication of {} of {} sign-in(s) is on the stack exactly once ({} found at all): '
                    'the Duo half is missing or from another tenant (`show_postdeploy.py --duo`, then its steps D7 '
                    'and D8)'.format(once, len(txids), found))


def verify_rule(stack, rep, bundle, rule, macro, sleep):
    """V5. The stack's own text of the joined rule, dispatched ad hoc over
    all index time (no alert action runs for such a search), returns the
    chain ids the source's rule returned for this set's sign-ins. rule: the
    stack's saved search (None when it has none)."""
    label, events = 'V5. the rule, run by hand', bundle['events']
    expected, candidates = bundle['expect']['chains'], chain_candidates(events)
    text = rule.get('search') if rule else None
    if not candidates:
        return rep.skip(label, 'the set has no application sign-in: no chain can form')
    if not isinstance(text, str) or not text.strip():
        if expected:
            return rep.fail(label, 'the joined rule is not on this stack, and the bundle expects {} chain(s)'.format(
                len(expected)))
        return rep.skip(label, 'the joined rule is not on this stack, and the bundle expects no chain')
    if macro[0]:
        return rep.fail(label, macro[0])
    try:
        rows = run_search(stack, spl_rule_dry_run(text), RULE_ALL_INDEX_TIME[0], RULE_ALL_INDEX_TIME[1],
                          'V5, the joined rule on the stack', (), sleep)
    except Refused as exc:
        return rep.fail(label, 'its text does not run on this stack ({})'.format(exc))
    found = sorted({one(row.get('chain_id')) for row in rows} & set(candidates))
    missing = sorted(set(expected) - set(found))
    if missing:
        return rep.fail(label, 'the stack\'s rule returns {} of the {} chain(s) the source\'s returned; not {}: a '
                               'Duo denial burst, a sign-in or a blocked turn of that chain is not on the stack '
                               '(V1, V4)'.format(len(expected) - len(missing), len(expected), ', '.join(missing)))
    rep.ok(label, '{} chain(s) for this set\'s sign-ins{}{}'.format(
        len(found), ': ' + ', '.join(found) if found else ' (the source showed none either)',
        '; {} more than the source showed'.format(len(found) - len(expected)) if len(found) > len(expected) else ''))


def judging_slot(rule):
    """(Slot, None) when a stack's joined rule judges what gets indexed, on a
    schedule this tool can time; else (None, why no run can be waited for)."""
    if rule is None:
        return None, 'the joined rule is not on this stack: no scheduled run judges the copy'
    if _on(rule.get('disabled')):
        return None, 'the joined rule is disabled on this stack: no scheduled run judges the copy'
    slot, why = rule_slot(rule)
    return slot, None if slot else 'the joined rule\'s runs cannot be timed ({})'.format(why)


def findings_seen(stack, chains, events, sleep):
    """{chain id: {'notable': rows, 'risk': rows, 'first': epoch or None}}
    from V6's search. Its range starts a day before the set's first event (a
    risk event is dated at the event that raised it) and ends a day ahead. A
    row for anything that was not asked for is ignored; a missing column
    counts as nothing."""
    earliest = int(decimal.Decimal(ordered(events)[0]['time'])) - FINDING_REACH_SECONDS
    seen = collections.OrderedDict((chain, {'notable': 0, 'risk': 0, 'first': None}) for chain in chains)
    rows = []
    for part in chunks(chains):
        rows.extend(run_search(stack, spl_findings(JOINED_RULE, part), str(earliest), ALL_TIME[1],
                               'V6, the findings', (), sleep))
    for row in rows:
        chain, index, raised = one(row.get('chain_id')), one(row.get('index')), as_int(row.get('first_raised'))
        if chain not in seen or index not in ('notable', 'risk'):
            continue
        seen[chain][index] += max(0, as_int(row.get('rows'), 0))
        if raised is not None and (seen[chain]['first'] is None or raised < seen[chain]['first']):
            seen[chain]['first'] = raised
    return seen


def shown_time(epoch):
    """A second a stack named, as UTC text; a value that is no plausible
    epoch is not turned into a date (time.gmtime raises on a hostile one)."""
    if isinstance(epoch, bool) or not isinstance(epoch, (int, float)) or not 0 <= epoch < 10 ** 11:
        return 'unknown'
    return utc_second(epoch)


def shown_word(value, pattern=WORD_RE):
    """A value of a stack's answer as it may be printed: itself when it is
    one plain word (or fits the given pattern), else a stand-in."""
    text = one(value)
    if text is None:
        return 'none'
    return text if pattern.fullmatch(text) else 'other'


ACTIONS_RE = re.compile(r'[A-Za-z0-9_]{1,40}(, ?[A-Za-z0-9_]{1,40}){0,9}')     # alert_actions="notable,risk"


MAX_RUN_LINES = 12


def show_runs(stack, tick, now, hidden, sleep, echo):
    """V6b. When a finding is late: the scheduler's own record of the joined
    rule's runs from the cron tick `tick` on, any error line it wrote for the
    rule (a failing run writes no status line at all), what that says, and
    whether this account can search the two indexes a finding lands in.
    Lines are printed; nothing is judged here. A status line of a deferred or
    skipped tick has no dispatch time, no count and no actions. The record is
    read for a day from the tick at most, and its first MAX_RUN_LINES lines
    are printed."""
    since, until = str(tick - 60), 'now' if now - tick < 86400 else str(tick + 86400)
    runs = run_search(stack, spl_rule_runs(JOINED_RULE, tick), since, until, 'V6b, the rule\'s runs', (), sleep)
    errors = run_search(stack, spl_rule_errors(JOINED_RULE), since, until, 'V6b, the rule\'s errors', (), sleep)
    echo('    The scheduler\'s record of the rule from the tick {} on:'.format(shown_time(tick)))
    runs = sorted(runs, key=lambda item: as_int(item.get('scheduled_time'), 0))
    for row in runs[:MAX_RUN_LINES]:
        scheduled, lag = as_int(row.get('scheduled_time')), as_int(row.get('lag'))
        echo('      tick {}: {}{}, {} result(s), suppressed {}, actions {}'.format(
            shown_time(scheduled), shown_word(row.get('status')),
            ', started {} s after the tick'.format(lag) if lag is not None else '',
            as_int(row.get('result_count'), 0), as_int(row.get('suppressed'), 0),
            shown_word(row.get('alert_actions'), ACTIONS_RE)))
    if len(runs) > MAX_RUN_LINES:
        echo('      ... and {} later line(s)'.format(len(runs) - MAX_RUN_LINES))
    failed = as_int(errors[0].get('errors'), 0) if errors else 0
    done = [row for row in runs if one(row.get('status')) == 'success']
    if failed:
        echo('      {} error line(s); the last: {}'.format(
            failed, safe_text(one(errors[0].get('message')) or 'no message', hidden)))
        echo('      -> a run FAILED, and a failed run loses its slot: the schedule never reads that index time '
             'again. Fix what the message names, then judge that index time by hand (README, "Judging history '
             'that is already indexed").')
    elif not runs:
        echo('      (no line) -> the scheduler recorded no run of the rule for that tick: the rule is not running, '
             'or this account cannot read index _internal.')
    elif not done:
        echo('      -> deferred or skipped and not run yet: the scheduler is behind. This rule never gives up a '
             'period; wait and run `verify` again.')
    elif any(as_int(row.get('suppressed'), 0) > 0 for row in done):
        echo('      -> suppressed: the chain was already raised in the last 24 hours. Look for the earlier finding.')
    elif all(as_int(row.get('result_count'), 0) == 0 for row in done):
        echo('      -> success with 0 results: the copy was not the last missing step in its slot. Check V4: the '
             'Duo half was probably indexed while the rule was off.')
    else:
        echo('      -> a run returned results, but no finding is searchable: its alert actions did not run, or '
             'the finding is not indexed yet.')
    for name in ('notable', 'risk'):
        if not run_search(stack, spl_index_exists(name), '0', 'now', 'V6b, looking for index ' + name, (), sleep):
            echo('      This account can search no index {} on the stack: without Enterprise Security, or without '
                 'the role to read it, no finding can be shown.'.format(name))


def verify_finding(stack, rep, bundle, rule, copies, wait, clock, sleep, echo):
    """V6. The scheduled rule raised each expected chain: exactly one row in
    index notable and one in index risk. The run that judges the copy is the
    tick judging_tick() names for the second the last copy was indexed, and
    its finding is due FINDING_GRACE_SECONDS after that tick. It is looked for
    every FINDING_POLL_SECONDS until it is there, it is overdue, or `wait`
    seconds have passed; never when V1 failed or no run can be timed. A
    finding that is overdue is followed by the scheduler's record (V6b); one
    whose run is still to come is not, whatever else failed."""
    label, events, chains = 'V6. the finding', bundle['events'], bundle['expect']['chains']
    if not chains:
        return rep.skip(label, 'the bundle expects no chain, so there is no finding to look for')
    slot, why = judging_slot(rule)
    held = [row for ident, row in copies.rows.items()
            if ident in copies.decisions and copies.decisions[ident].verdict in SKIP_VERDICTS]
    last = [value for value in (as_int(row.get('last_indexed')) for row in held) if 0 < (value or 0) < 10 ** 11]
    first = [value for value in (as_int(row.get('first_indexed')) for row in held) if 0 < (value or 0) < 10 ** 11]
    tick = judging_tick(max(last), slot) if slot and last else None
    due = None if tick is None or copies.failed else tick + FINDING_GRACE_SECONDS
    started = clock()
    while True:
        seen, now = findings_seen(stack, chains, events, sleep), clock()
        short = [chain for chain in chains if seen[chain]['notable'] < 1 or seen[chain]['risk'] < 1]
        if not short or due is None or now >= due or now - started >= wait:
            break
        sleep(max(1, min(FINDING_POLL_SECONDS, started + wait - now, due - now)))
    counts = '; '.join('{}: {} finding(s), {} risk event(s)'.format(chain, seen[chain]['notable'], seen[chain]['risk'])
                       for chain in chains)
    if not short and all(seen[chain]['notable'] == 1 and seen[chain]['risk'] == 1 for chain in chains):
        raised = [seen[chain]['first'] for chain in chains if seen[chain]['first'] is not None]
        return rep.ok(label, 'one finding and one risk event for each of the {} chain(s){}'.format(
            len(chains), ', first raised {}'.format(shown_time(min(raised))) if raised else ''))
    if not short:
        return rep.fail(label, 'a chain was raised more than once ({}): one finding and one risk event are '
                               'expected for each'.format(counts))
    if due is not None and now < due:
        return rep.fail(label, 'NOT RAISED YET ({}). The scheduled run that judges the copy is the tick {}, and '
                               'its finding is due by {}: run `verify --wait {}`, or run it again after that '
                               'time'.format(counts, utc_second(tick), utc_second(due), int(due - now) + 60))
    if copies.failed:
        reason = 'the copies are not all on the stack as they were sent (V1), so no run was waited for'
    elif tick is None:
        reason = why or 'the stack does not say when the copies were indexed'
    else:
        reason = 'the tick {} judged the copy and its finding was due by {}'.format(utc_second(tick), utc_second(due))
    rep.fail(label, 'NOT RAISED ({}): {}'.format(counts, reason))
    if slot and first and tick is not None and now >= tick + FINDING_GRACE_SECONDS:    # overdue: what the runs did
        try:
            show_runs(stack, judging_tick(min(first), slot), now, signin_txids(events), sleep, echo)
        except Refused as exc:
            echo('    The scheduler\'s record of the rule could not be read: {}'.format(exc))


def run_verify(stack, bundle, guid, bundle_path, wait, clock, sleep, echo):
    """V1 to V6 on the stack `guid` -> the exit code: 0 when every step held
    (a step with nothing to check is skipped and says so), 3 when ids that
    were handed to HEC are still not searchable and nothing else is wrong
    with the copies, else 1. It only reads: the ledger (what was handed to
    this stack) and the stack. The ledger is read once, before the stack."""
    rep, index = seed.Reporter(echo), bundle['events'][0]['index']
    text = ledger_text(bundle_path)
    read_ledger(text, guid)                      # a line this tool did not write is refused, as `send` refuses it
    handed = ledger_handed(text, guid, bundle['bundle_id'])
    if not run_search(stack, spl_index_exists(index), '0', 'now', 'V1, looking for the index', (), sleep):
        rep.fail('V1. the copies', 'this account can search no index {} on the stack (it is missing, or hidden '
                                   'from the account\'s role): every search would answer "nothing there", so '
                                   'nothing was verified'.format(index))
        echo('')
        echo('NOT VERIFIED: the index cannot be searched.')
        return EXIT_FAILED
    copies = verify_copies(stack, rep, bundle, handed, clock, sleep, echo)
    verify_label(stack, rep, bundle, handed, sleep)
    macro = macro_problem(stack, index)
    verify_counts(stack, rep, bundle, macro, sleep)
    verify_duo(stack, rep, bundle, sleep)
    saved = '/servicesNS/nobody/{}/saved/searches/{}'.format(APP, urllib.parse.quote(JOINED_RULE, safe=''))
    rule = stack.content(saved, 'V5, reading the joined rule')
    verify_rule(stack, rep, bundle, rule, macro, sleep)
    verify_finding(stack, rep, bundle, rule, copies, wait, clock, sleep, echo)
    echo('')
    if not rep.failures():
        echo('VERIFIED: the stack holds the {} event(s) of bundle {} once and identical, and every step that had '
             'something to check passed.'.format(len(bundle['events']), bundle['bundle_id']))
        return EXIT_OK
    if copies.unknown:
        echo('DELIVERY UNKNOWN: event(s) that were handed to HEC are not searchable. Nothing is to be sent again; '
             'run `verify` again later. {} step(s) failed.'.format(rep.failures()))
        return EXIT_UNKNOWN
    echo('NOT VERIFIED: {} step(s) failed.'.format(rep.failures()))
    return EXIT_FAILED


def connect_stack(opts, env):
    """(the stack's splunkd client, what the run says about its certificate).
    The credential comes from the environment; nothing is contacted yet."""
    kind, secret = credential(env, ENV_STACK_PASSWORD, ENV_STACK_TOKEN)
    scheme, host, _, _ = split_url(opts.stack, '--stack', 8089)
    verify, words = tls_policy(scheme, host, opts.ca_file, opts.no_verify_splunkd, '--no-verify-splunkd')
    return Splunkd(opts.stack, '--stack', kind, secret, opts.username, verify, opts.ca_file,
                   '--no-verify-splunkd'), words


def cmd_verify(opts, env, clock, sleep, echo):
    """verify: read one stack again after a send. Order: the option, the
    bundle (R1, approved as it is) and the credential before any connection;
    how the certificate is treated is said before the first request; then the
    stack says who it is (R3: never the Splunk the bundle came from); then V1
    to V6. Nothing is sent and nothing is written, the ledger included."""
    wait = whole_number(opts.wait, '--wait', 0, MAX_WAIT_SECONDS)
    bundle = load_bundle(opts.bundle, need_approval=True)
    stack, tls_words = connect_stack(opts, env)
    echo('Verify bundle {} on --stack ({} event(s), digest {})'.format(
        bundle['bundle_id'], len(bundle['events']), bundle['digest'][:12]))
    echo('  certificate of port 8089: {}'.format(tls_words))
    found = check_stack(stack, bundle, clock())
    echo('  stack: Splunk {}, {} {}, not the Splunk the bundle came from'.format(
        found['splunk_version'], APP, found['ta_version']))
    return run_verify(stack, bundle, found['guid'], opts.bundle, wait, clock, sleep, echo)


def crashed(command, exc, echo):
    """The last line of a run that hit a bug in this tool -> its exit code.
    Only the kind of error and the line of this file are named: an
    exception's own text can quote a header (the credential) or an event.
    After a `send` the answer is "delivery unknown": whatever was handed to
    HEC is on record in the ledger, and the next run reads it."""
    line, trace = 0, exc.__traceback__
    while trace is not None:
        if os.path.abspath(trace.tb_frame.f_code.co_filename) == os.path.abspath(__file__):
            line = trace.tb_lineno
        trace = trace.tb_next
    echo('FAILED: an unexpected error in this tool ({} at line {} of staged_resend.py); its text is not shown. '
         '{}'.format(type(exc).__name__, line,
                     'If a request had left, it is on record in the ledger: run `verify`, then `send` again.'
                     if command == 'send' else 'Nothing was sent.'))
    return EXIT_UNKNOWN if command == 'send' else EXIT_FAILED


def main(argv=None, env=None, clock=time.time, sleep=time.sleep, echo=print):
    """Run one command; returns the exit code. env, clock, sleep and echo are
    injected by the tests."""
    try:
        opts = build_parser().parse_args(argv)
    except SystemExit as exc:                    # argparse: 0 after --help, 2 after a usage error
        return exc.code if isinstance(exc.code, int) else EXIT_REFUSED
    command = globals()['cmd_' + opts.command]   # looked up at call time, so that a test can replace one
    try:
        return command(opts, os.environ if env is None else env, clock, sleep, echo)
    except Refused as exc:
        echo('REFUSED: {}'.format(exc))
        return EXIT_REFUSED
    except Exception as exc:                     # a bug. Its message is never printed: it can quote a value
        return crashed(opts.command, exc, echo)


if __name__ == '__main__':
    sys.exit(main())
