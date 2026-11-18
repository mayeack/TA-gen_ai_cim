#!/usr/bin/env python3
# encoding=utf-8
"""
fake_resend_stack.py - a loopback stand-in for one Splunk, for
test_staged_resend.py: splunkd REST over an in-memory event store. It plays
the facilitator's Splunk that `export` reads and, for `send`, a stack: its
HEC on a second loopback port, its index and macro endpoints, the
scheduler's log, and for `verify` the scheduler itself and what the joined
rule's alert actions write into the notable and risk indexes. Dev only.

It is strict on purpose, so that a wrong tool fails a test:
  * a search is answered only when its WHOLE text is one of the texts written
    out below, independently of the tool. Any other text is HTTP 400 with a
    FATAL message, which is what splunkd answers to a text it cannot parse.
    So is a text that opens with neither "search " nor "|" (splunkd reads
    `((a) OR b)` as an unknown command) and one that puts a generating command
    after "search " (`search | tstats ...`);
  * the joined rule's text is the SHIPPED stanza of default/savedsearches.conf,
    read when the fake is made. A checkout without the stanza raises here: the
    suite fails, it never skips;
  * answers have splunkd's shapes, each seen live on 10.4.3: every value is a
    string, several values are a list, an absent value is no key at all;
    `stats` without BY over nothing is one row that holds the count alone and
    with BY it is no row; tstats cuts a time bound to the whole second and
    search does not; spath reads only the first `spath_cutoff` characters of
    an event and returns the text "null" for a JSON null;
  * every request is recorded, with its headers, and nothing is answered
    without the credential;
  * it can fail in the ways that matter here: a WARN on a search (once or
    always), an index the account cannot search (no row, no message), a
    redirect to another server, an event text altered on the way out;
  * HEC keeps the TEXT of "event" and of "time" exactly as it was sent and
    decodes a body as one JSON object after another (never split on line
    breaks). An accepted event is searchable `index_lag` seconds later. A
    POST can be scripted (`hec_script`): any status and body, with or without
    indexing first; indexed and then no answer at all; a 400 at event n with
    the events before it indexed; a 413 from the headers with the body
    unread, or after reading it (`hec_max_bytes`); a stack that rewrites what
    it indexes (`hec_rewrite`); HEC unhealthy; HEC not listening; https;
  * the stack's side of splunkd: data/indexes and the identity macro (each
    can answer 403 or 404, as a search head that does not serve it), and the
    scheduler's log with `continued` lines and the ERROR line of a failing
    run, which carries no savedsearch_name, status or scheduled_time;
  * with `auto_schedule` the joined rule runs on its own schedule, read from
    the shipped stanza: the run of a cron tick judges one slot of INDEX time
    and raises a chain once, as one finding (index notable, dated when it was
    raised, the event's time in orig_time) and one risk event (index risk,
    dated at the event). A run can be late (`dispatch_delay`, with a
    `continued` line first), fail (`run_fails`) or raise nothing
    (`actions_run`); a stack without Enterprise Security has neither index.

All data comes from the tests: invented personas, RFC 5737 addresses, made-up ids.
"""

import base64
import collections
import decimal
import hashlib
import http.server
import json
import os
import re
import ssl
import sys
import threading
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from test_lab5_conf import read_conf  # noqa: E402

APP = 'TA-gen_ai_cim'
JOINED_RULE = 'AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule'
DUO_SOURCETYPE = 'ta_gen_ai_cim:duo:authentication'
LEGACY_KEYS = ('session_id', 'request_id', 'trace_id', 'enduser_id', 'user')
ID_KEYS = ('audit_id', 'escalation_id', 'event_id')
SCORING = re.compile(r'ai_cim:.*:ml_scoring|gen_ai:.*:scoring|ai_cim:.*:gen_ai_scoring|genai_scoring|'
                     r'ai_cim:response:.*')
SLOW_START = ('Configuration initialization for /opt/splunk/etc took longer than expected (4547ms) when '
              'dispatching a search with search ID 1794900000.1.')

Q = r'"[^"\\*]*"'                                      # one quoted plain value
ANY_OF, LISTED = Q + r'(?: OR ' + Q + r')*', Q + r'(?:, ' + Q + r')*'
HOSTS = r'host=' + Q + r'(?: OR host=' + Q + r')*'
INT = r'-?\d+'
ID_EVAL = '| eval rs_id=coalesce(spath(_raw, "audit_id"), spath(_raw, "escalation_id"), spath(_raw, "event_id")) '


def text_pattern(template, **values):
    """A pattern for one whole search text. The text is written out literally;
    {name} marks a value, whose own pattern is given by keyword."""
    out = ''
    for number, part in enumerate(re.split(r'\{(\w+)\}', template)):
        out += '(?P<{}>{})'.format(part, values[part]) if number % 2 else re.escape(part)
    return re.compile(out)


def shipped_rule():
    """The joined rule's stanza as splunkd would answer for a freshly
    installed TA. A KeyError here means the checkout has no such rule."""
    stanza = read_conf('savedsearches.conf')[JOINED_RULE]
    return {'search': stanza['search'], 'cron_schedule': stanza['cron_schedule'],
            'dispatch.earliest_time': stanza['dispatch.earliest_time'],
            'dispatch.latest_time': stanza['dispatch.latest_time'],
            'realtime_schedule': stanza.get('realtime_schedule', '1') == '1',
            'disabled': stanza.get('disabled') == '1', 'is_scheduled': stanza.get('enableSched') == '1'}


# The search texts the tool is meant to send (spec 3.9, with the two changes
# the review asked for: the presence search leaves the TA's response-action
# records out, and the expectation search can name its index).
RULE_TABLE = (' | table chain_id, user, _time, burst_time, signin_time, blocked_time, blocked_turns, '
              'duo_failures_10m, duo_app, signin_duo, guardrails')
TEXTS = collections.OrderedDict((
    ('eventcount', text_pattern('| eventcount summarize=false index={index}', index=Q)),
    ('census', text_pattern(
        'search index={index} '
        '| eval rs_ids=mvappend(spath(_raw, "audit_id"), spath(_raw, "escalation_id"), spath(_raw, "event_id")), '
        'rs_user=lower(replace(trim(coalesce(spath(_raw, "enduser_id"), spath(_raw, "user"))), "@.*", "")) '
        '| eval rs_where=case(_time<{t_from}, "before the window", _time>={t_to}, "after the window", true(), '
        '"in the window"), rs_host=if(in(host, {hosts}), "selected host", "other host"), '
        'rs_who=case(in(rs_user, {personas}), "selected persona", isnull(rs_user) OR rs_user=="", "no user", '
        'true(), "other identity"), rs_kind=case(isnull(log_type), "no log_type", source!={source}, '
        '"another source", isnull(rs_ids), "no id", mvcount(rs_ids)>1, "several ids", true(), "eligible"), '
        'rs_log_type=coalesce(mvjoin(log_type, ","), "none") '
        '| stats count as events by rs_where, rs_host, rs_who, rs_kind, sourcetype, rs_log_type '
        '| sort 0 rs_where, rs_host, rs_who, rs_kind, sourcetype',
        index=Q, t_from=INT, t_to=INT, hosts=LISTED, personas=LISTED, source=Q)),
    ('legacy', text_pattern(
        '| tstats count as legacy_indexed_body_keys where index={index} ({hosts}) '
        '(session_id=* OR request_id=* OR trace_id=* OR enduser_id=* OR user=*)', index=Q, hosts=HOSTS)),
    ('export', text_pattern(
        'search index={index} ({hosts}) source={source} '
        '(log_type::governance OR log_type::audit OR log_type::escalation OR log_type::error) '
        '| eval rs_time=tostring(_time), rs_indextime=_indextime, rs_sha256=sha256(_raw), rs_len=len(_raw), '
        'rs_log_type=mvjoin(log_type, ","), rs_bundle=coalesce(mvjoin(resend_bundle, ","), "none") '
        '| sort 0 _time '
        '| table rs_time, rs_indextime, rs_sha256, rs_len, index, host, source, sourcetype, rs_log_type, '
        'rs_bundle, _raw', index=Q, hosts=HOSTS, source=Q)),
    ('present', text_pattern(
        'search index={index} sourcetype!="ai_cim:response:*" ({terms}) ' + ID_EVAL
        + '| search rs_id IN ({listed}) '
        '| eval rs_sha256=sha256(_raw), rs_time=printf("%.3f", _time), rs_time_text=tostring(_time), '
        'rs_log_type=coalesce(mvjoin(log_type, ","), "none"), rs_bundle=coalesce(mvjoin(resend_bundle, ","), "none") '
        '| stats count as copies, values(rs_sha256) as sha256, values(rs_time) as time, '
        'values(rs_time_text) as time_text, values(host) as host, values(source) as source, '
        'values(sourcetype) as sourcetype, values(index) as index, values(rs_log_type) as log_type, '
        'values(rs_bundle) as resend_bundle, min(_indextime) as first_indexed, max(_indextime) as last_indexed '
        'by rs_id', index=Q, terms=ANY_OF, listed=LISTED)),
    ('expect', text_pattern(
        'search {base} ({terms}) ' + ID_EVAL + '| search rs_id IN ({listed}) '
        '| eval identity_key=`genai_identity_join_key(user)`, turn=if(`genai_identity_verified_turn`, 1, 0), '
        'blocked=if(turn==1 AND \'gen_ai.policy.blocked\'=="true", 1, 0), '
        'signin=if(\'gen_ai.audit.action\'=="identity_signin_success", 1, 0), '
        'identity_event=if(\'gen_ai.identity.verified\'=="true" OR like(\'gen_ai.audit.action\', "identity_%"), 1, 0) '
        '| stats dc(rs_id) as events, count as copies, sum(identity_event) as identity_events, sum(turn) as ai_turns, '
        'sum(blocked) as ai_blocked, sum(signin) as app_signins by identity_key',
        base=r'`genai_identity_ai_events`|index=' + Q + r' `exclude_scoring_sourcetypes`', terms=ANY_OF,
        listed=LISTED)),
    ('duo_half', text_pattern(
        'search `genai_duo_auth_events` ({terms}) '
        '| eval rs_txid=mvindex(txid, 0), identity_user=`genai_identity_join_key(user)` '
        '| search rs_txid IN ({listed}) '
        '| stats count as copies, values(action) as action, values(identity_user) as identity_user, '
        'min(_time) as duo_time, min(_indextime) as first_indexed by rs_txid '
        '| stats count as txids_found, sum(eval(if(copies==1, 1, 0))) as found_once, values(action) as action, '
        'values(identity_user) as identity_user, min(duo_time) as first_duo_time, max(duo_time) as last_duo_time',
        terms=ANY_OF, listed=LISTED)),
    ('duo_context', text_pattern(
        'search `genai_duo_auth_events` '
        '| eval identity_user=`genai_identity_join_key(user)`, duo_class=`genai_identity_duo_class` '
        '| search identity_user IN ({personas}) '
        '| stats count as duo_events, dc(txid) as txids by identity_user, action, duo_class', personas=LISTED)),
    ('rule_ticks', text_pattern(
        'search index=_internal sourcetype=scheduler savedsearch_name={rule} '
        '| stats count(eval(status=="success")) as ok, count(eval(status=="continued")) as deferred, '
        'count(eval(status=="skipped")) as skipped by scheduled_time '
        '| sort 0 - scheduled_time', rule=Q)),
    ('rule_errors', text_pattern(
        'search index=_internal sourcetype=scheduler log_level=ERROR savedsearch_id="*;TA-gen_ai_cim;{rule}" '
        '| stats count as errors, latest(message) as message, max(_time) as last_error', rule=r'[^"\\*;]+')),
    ('label', text_pattern(
        '| tstats count as events, min(_indextime) as first_indexed, max(_indextime) as last_indexed '
        'where index={index} resend_bundle={bundle} by sourcetype, log_type, host', index=Q, bundle=Q)),
    ('findings', text_pattern(
        'search (index=notable OR index=risk) search_name={rule} ({chains}) '
        '| eval rs_event_time=coalesce(orig_time, _time) '
        '| stats count as rows, min(_indextime) as first_raised, values(rs_event_time) as event_time '
        'by index, chain_id', rule=Q, chains=r'chain_id=' + Q + r'(?: OR chain_id=' + Q + r')*')),
    ('rule_runs', text_pattern(
        'search index=_internal sourcetype=scheduler savedsearch_name={rule} scheduled_time>={tick} '
        '| eval lag=dispatch_time-scheduled_time '
        '| table scheduled_time, dispatch_time, lag, status, result_count, suppressed, alert_actions',
        rule=Q, tick=r'\d+')),
))
PARSE_TAIL = ' | stats count as rows'                  # the tail of the tool's "does the rule's text run here" search


class Reply(Exception):
    """An HTTP answer that is not a 200."""

    def __init__(self, status, body):
        Exception.__init__(self, status)
        self.status, self.body = status, body


def fatal(text):
    return Reply(400, {'messages': [{'type': 'FATAL', 'text': text}]})


def members(raw):
    """[(key, value, where the value ends)] of a JSON object's top-level
    members, in the order they are written; [] for text that is not one."""
    decoder, out = json.JSONDecoder(), []

    def skip(pos):
        while pos < len(raw) and raw[pos] in ' \t\r\n':
            pos += 1
        return pos

    try:
        pos = skip(0)
        if raw[pos] != '{':
            return []
        pos = skip(pos + 1)
        while raw[pos] != '}':
            key, pos = decoder.raw_decode(raw, pos)
            pos = skip(pos)
            if raw[pos] != ':':
                return []
            value, pos = decoder.raw_decode(raw, skip(pos + 1))
            out.append((key, value, pos))
            pos = skip(pos)
            if raw[pos] == ',':
                pos = skip(pos + 1)
    except (ValueError, IndexError):
        return []
    return out


def quoted_values(text):
    return re.findall(r'"([^"]*)"', text or '')


def shaped(values):
    """Distinct values as splunkd writes them into a result: None for none
    (the key is then left out), a string for one, a sorted list for several."""
    found = sorted({str(value) for value in values if value is not None})
    return None if not found else found[0] if len(found) == 1 else found


def row(**columns):
    return dict((name, value) for name, value in columns.items() if value is not None)


def join_key(value):
    """The macro genai_identity_join_key on one value."""
    return None if value is None else re.sub(r'@.*', '', str(value).strip()).lower()


def member_spans(text, pos=0):
    """[(key, where its value starts, where it ends)] of the JSON object that
    starts at text[pos]: what lets the fake keep a value's TEXT exactly, as
    HEC keeps the text of "event" and of "time"."""
    decoder, out = json.JSONDecoder(), []

    def skip(at):
        while at < len(text) and text[at] in ' \t\r\n':
            at += 1
        return at

    pos = skip(pos + 1)
    while text[pos] != '}':
        key, pos = decoder.raw_decode(text, pos)
        start = skip(skip(pos) + 1)                           # past the colon
        _, pos = decoder.raw_decode(text, start)
        out.append((key, start, pos))
        pos = skip(pos)
        if text[pos] == ',':
            pos = skip(pos + 1)
    return out


def envelopes(text):
    """[(the decoded object, {key: the value's own text})] of a HEC request
    body: one JSON object after another, whatever stands between them. A body
    is never split on line breaks, because an event text may hold one."""
    decoder, out, pos = json.JSONDecoder(), [], 0
    while True:
        while pos < len(text) and text[pos] in ' \t\r\n':
            pos += 1
        if pos >= len(text):
            return out
        whole, end = decoder.raw_decode(text, pos)
        texts = dict((key, text[start:stop]) for key, start, stop in member_spans(text, pos)) \
            if isinstance(whole, dict) else {}
        out.append((whole, texts))
        pos = end


class FakeSplunk(object):
    def __init__(self, guid='5CA1AB1E-0000-4000-8000-00000000F001', clock=None):
        self.guid, self.clock = guid, clock or (lambda: 1794900000.0)
        self.version, self.ta_version = '10.4.3', '1.9.0'
        self.user = 'admin'
        self.password, self.token = 'fixture-rest-password-' + guid[-4:], 'fixture-rest-token-' + guid[-4:]
        self.indexes, self.hidden = {'gen_ai_log', 'duo'}, set()      # hidden: there, but not for this account
        self.macro_index = {'genai_identity_ai_events': 'gen_ai_log', 'genai_duo_index': 'duo'}
        self.saved = {JOINED_RULE: shipped_rule()}
        self.events = []
        self.spath_cutoff = 5000
        self.warn_runs, self.warn_text = 0, SLOW_START   # the next N search answers carry a WARN; -1: every one
        self.fail_search = {}                            # {kind: message}: that search answers with an ERROR
        self.odd_answer = {}                             # {kind: text}: that search answers 200 with this body
        self.alter_raw = None                            # f(raw) applied to _raw on the way out of the export search
        self.rewrite_present = None                      # f(row) -> row or None, on each row of the presence search
        self.redirect_to = None                          # every request answers 302 to this address
        self.requests, self.searches, self.server = [], [], None
        # -- the stack's side (send, verify) --
        self.retention_seconds, self.index_disabled = 90 * 86400, False
        self.index_status, self.macro_status = 200, 200        # what data/indexes and conf-macros answer
        self.macro_text = None                                 # the identity macro's definition, if not the shipped one
        self.ticks, self.rule_errors = [], []                  # the scheduler's log: status lines, (time, message)
        self.hec_token = 'fixture-hec-token-' + guid[-4:]
        self.hec_script, self.hec_requests, self.hec_server = [], [], None
        self.hec_healthy, self.hec_max_bytes, self.early_413 = True, None, False
        self.index_lag, self.hec_rewrite = 0, None             # seconds until an accepted event is searchable; f(event)
        # -- the scheduler and Enterprise Security (verify) --
        self.indexes |= {'notable', 'risk'}                    # where a finding and its risk event land
        self.findings = []                                     # what the rule's alert actions wrote
        self.auto_schedule = None      # an epoch: from then on the joined rule runs on its own schedule
        self.dispatch_delay = 80       # seconds after the cron tick at which a scheduled run starts
        self.run_fails = None          # a message: every scheduled run fails with it (an ERROR line, no status line)
        self.actions_run = True        # False: a run returns its rows and its alert actions write nothing
        self.ran, self.deferred, self.raised = set(), set(), set()

    # -- the store ---------------------------------------------------------------
    def add(self, raw, time_text, sourcetype, log_type=None, host='stage-host', source='demobot:hec',
            index='gen_ai_log', indexed=None, fields=None):
        """One indexed event. fields are its INDEXED fields (what HEC "fields"
        carried); a value may be a list. The text is kept exactly."""
        held = dict(fields or {})
        if log_type is not None:
            held.setdefault('log_type', log_type)
        self.indexes.add(index)
        self.events.append({'raw': raw, 'time_text': str(time_text), 'time': decimal.Decimal(str(time_text)),
                            'host': host, 'source': source, 'sourcetype': sourcetype, 'index': index,
                            'fields': held, 'duo': None, 'visible': 0,
                            'indexed': int(indexed if indexed is not None else int(float(time_text)) + 2)})
        return self.events[-1]

    def add_duo(self, user, when, action='failure', txid=None, index='duo'):
        """One Duo authentication as the TA's input writes it (reduced to what the searches read)."""
        txid = txid or 'd0000000-0000-4000-8000-{:012d}'.format(len(self.events))
        result = 'success' if action == 'success' else 'denied'
        raw = json.dumps({'txid': txid, 'user': {'name': user}, 'result': result}, separators=(',', ':'))
        event = self.add(raw, str(int(when)), DUO_SOURCETYPE, host='duo-input', source='duo', index=index)
        event['duo'] = {'user': user, 'action': action, 'txid': txid, 'result': result}
        return event

    # -- searching -----------------------------------------------------------------
    def bound(self, text):
        """A REST time argument: epoch seconds, "now" or "+1d"."""
        text = str(text if text is not None else '')
        if re.fullmatch(r'\d+(\.\d+)?', text):
            return decimal.Decimal(text)
        if text in ('now', '+1d'):
            return decimal.Decimal(repr(float(self.clock()))) + (86400 if text == '+1d' else 0)
        if re.fullmatch(r'-\d+m', text):
            return decimal.Decimal(repr(float(self.clock()))) - 60 * int(text[1:-1])
        raise Reply(400, {'messages': [{'type': 'FATAL', 'text': 'Invalid earliest_time.'}]})

    def seen(self, index, earliest, latest, whole_seconds=False):
        """The events of one index in a time range, oldest first. An index that
        does not exist, or that this account may not search, holds nothing and
        says nothing. tstats cuts both bounds and the time to the whole second."""
        if index not in self.indexes or index in self.hidden:
            return []
        now = self.clock()
        if whole_seconds:
            earliest, latest = int(earliest), int(latest)
            inside = [event for event in self.events if earliest <= int(event['time']) < latest]
        else:
            inside = [event for event in self.events if earliest <= event['time'] < latest]
        return sorted((event for event in inside if event['index'] == index and event['visible'] <= now),
                      key=lambda event: event['time'])

    def spath(self, found, key):
        """spath(_raw, "<key>") on a top-level key: its text, the text "null"
        for a JSON null, and nothing for a key that is absent or whose value
        ends beyond the extraction cutoff."""
        for name, value, end in found:
            if name == key:
                if end > self.spath_cutoff:
                    return None
                return 'null' if value is None else value if isinstance(value, str) else json.dumps(value)
        return None

    def own_id(self, event):
        found = members(event['raw'])
        for key in ID_KEYS:
            value = self.spath(found, key)
            if value is not None:
                return value
        return None

    def rule_named(self, spl, tail=RULE_TABLE):
        """The saved search whose own text, dispatched as splunkd wants it and
        followed by the dry-run table (or another tail), is exactly this text;
        else None."""
        for name, content in self.saved.items():
            text = content['search'].strip()
            if spl == (text if text.startswith('|') else 'search ' + text) + tail:
                return name
        return None

    def search(self, form):
        spl = form.get('search', '')
        record = {'search': spl, 'earliest': form.get('earliest_time'), 'latest': form.get('latest_time'), 'kind': None}
        self.searches.append(record)
        if form.get('exec_mode') != 'oneshot' or form.get('count') != '0':
            raise Reply(400, {'messages': [{'type': 'ERROR', 'text': 'the fake runs one-shot searches with count=0'}]})
        if not (spl.startswith('search ') or spl.startswith('|')):
            raise fatal("Error in 'SearchParser': Missing a search command before '{}'.".format(spl[:1]))
        if re.match(r'search\s*\|', spl):
            raise fatal("Error in '{}' command: This command must be the first command of a search.".format(
                (re.findall(r'\|\s*(\w+)', spl) or ['?'])[0]))
        earliest, latest = self.bound(form.get('earliest_time')), self.bound(form.get('latest_time'))
        self.schedule()                                   # the scheduled runs that are due by now have happened
        kind, found = self.rule_named(spl), None
        if kind is None and self.rule_named(spl, PARSE_TAIL):
            rows, kind = [{'rows': '0'}], 'rule_parses'       # parsed and expanded; the time range held nothing
        elif kind is None:
            for name, pattern in TEXTS.items():
                found = pattern.fullmatch(spl)
                if found:
                    kind = name
                    break
            else:
                raise fatal("Error in 'SearchParser': this is not a search text the fake knows.")
            rows = getattr(self, 'q_' + kind)(earliest, latest, **found.groupdict())
        else:
            rows = self.rule_rows(kind)
            kind = 'rule'
        record['kind'] = kind
        if kind in self.odd_answer:
            return self.odd_answer[kind]
        messages = []
        if kind in self.fail_search:
            rows, messages = [], [{'type': 'ERROR', 'text': self.fail_search[kind]}]
        elif self.warn_runs:
            self.warn_runs -= 1 if self.warn_runs > 0 else 0
            messages = [{'type': 'WARN', 'text': self.warn_text}]
        return {'preview': False, 'init_offset': 0, 'messages': messages, 'fields': [], 'results': rows}

    def q_eventcount(self, earliest, latest, index):
        name = quoted_values(index)[0]
        if name not in self.indexes or name in self.hidden:
            return []
        return [{'count': str(sum(1 for event in self.events if event['index'] == name)), 'index': name,
                 'server': 'fake-indexer'}]

    @staticmethod
    def listed(value):
        """An indexed field's values as a list: none, one or several."""
        if isinstance(value, (list, tuple)):
            return [str(item) for item in value]
        return [] if value is None else [str(value)]

    def q_census(self, earliest, latest, index, t_from, t_to, hosts, personas, source):
        counts = collections.Counter()
        chosen_hosts, chosen, wanted = quoted_values(hosts), quoted_values(personas), quoted_values(source)[0]
        for event in self.seen(quoted_values(index)[0], earliest, latest):
            found = members(event['raw'])
            ids = [value for value in (self.spath(found, key) for key in ID_KEYS) if value is not None]
            user = self.spath(found, 'enduser_id')
            user = join_key(user if user is not None else self.spath(found, 'user'))
            log_type = self.listed(event['fields'].get('log_type'))
            where = ('before the window' if event['time'] < int(t_from) else
                     'after the window' if event['time'] >= int(t_to) else 'in the window')
            who = 'selected persona' if user in chosen else 'no user' if user in (None, '') else 'other identity'
            kind = ('no log_type' if not log_type else 'another source' if event['source'] != wanted else
                    'no id' if not ids else 'several ids' if len(ids) > 1 else 'eligible')
            counts[(where, 'selected host' if event['host'] in chosen_hosts else 'other host', who, kind,
                    event['sourcetype'], ','.join(log_type) or 'none')] += 1
        names = ('rs_where', 'rs_host', 'rs_who', 'rs_kind', 'sourcetype', 'rs_log_type')
        return [dict(zip(names, key), events=str(count)) for key, count in sorted(counts.items())]

    def q_legacy(self, earliest, latest, index, hosts):
        chosen = quoted_values(hosts)
        count = sum(1 for event in self.seen(quoted_values(index)[0], earliest, latest, whole_seconds=True)
                    if event['host'] in chosen and any(key in event['fields'] for key in LEGACY_KEYS))
        return [{'legacy_indexed_body_keys': str(count)}]            # tstats count: one row, also for 0

    def q_export(self, earliest, latest, index, hosts, source):
        chosen, wanted, rows = quoted_values(hosts), quoted_values(source)[0], []
        for event in self.seen(quoted_values(index)[0], earliest, latest):
            log_type = self.listed(event['fields'].get('log_type'))
            if (event['host'] not in chosen or event['source'] != wanted
                    or not set(log_type) & {'governance', 'audit', 'escalation', 'error'}):
                continue
            raw = event['raw']
            rows.append(row(rs_time=event['time_text'], rs_indextime=str(event['indexed']),
                            rs_sha256=hashlib.sha256(raw.encode('utf-8')).hexdigest(), rs_len=str(len(raw)),
                            index=event['index'], host=event['host'], source=event['source'],
                            sourcetype=event['sourcetype'], rs_log_type=','.join(log_type),
                            rs_bundle=','.join(self.listed(event['fields'].get('resend_bundle'))) or 'none',
                            _raw=self.alter_raw(raw) if self.alter_raw else raw))
        return rows

    def q_present(self, earliest, latest, index, terms, listed):
        ids, groups = quoted_values(listed), collections.OrderedDict()
        for event in self.seen(quoted_values(index)[0], earliest, latest):
            if re.fullmatch(r'ai_cim:response:.*', event['sourcetype']):
                continue
            if not any(ident in event['raw'] for ident in quoted_values(terms)):
                continue
            ident = self.own_id(event)
            if ident in ids:
                groups.setdefault(ident, []).append(event)
        rows = []
        for ident, held in sorted(groups.items()):
            rows.append(row(
                rs_id=ident, copies=str(len(held)),
                sha256=shaped(hashlib.sha256(event['raw'].encode('utf-8')).hexdigest() for event in held),
                time=shaped('%.3f' % float(event['time']) for event in held),
                time_text=shaped(event['time_text'] for event in held), host=shaped(event['host'] for event in held),
                source=shaped(event['source'] for event in held),
                sourcetype=shaped(event['sourcetype'] for event in held),
                index=shaped(event['index'] for event in held),
                log_type=shaped(','.join(self.listed(event['fields'].get('log_type'))) or 'none' for event in held),
                resend_bundle=shaped(','.join(self.listed(event['fields'].get('resend_bundle'))) or 'none'
                                     for event in held),
                first_indexed=str(min(event['indexed'] for event in held)),
                last_indexed=str(max(event['indexed'] for event in held))))
        if self.rewrite_present:
            rows = [kept for kept in (self.rewrite_present(dict(found)) for found in rows) if kept is not None]
        return rows

    @staticmethod
    def read_as_ta(event):
        """What the TA's search-time fields say about an assistant event:
        (identity key, verified AI turn, blocked, application sign-in, identity event)."""
        body = dict((key, value) for key, value, _ in members(event['raw']))
        audit = body.get('action') if 'audit_id' in body else None
        verified = body.get('identity_verified') is True
        turn = (audit is None and verified and body.get('provider_name') is not None
                and body.get('operation_name') == 'chat')
        user = body.get('user')
        return (join_key(user) if isinstance(user, str) else None, turn, turn and body.get('policy_blocked') is True,
                audit == 'identity_signin_success', verified or str(audit or '').startswith('identity_'))

    def q_expect(self, earliest, latest, base, terms, listed):
        index = self.macro_index['genai_identity_ai_events'] if base.startswith('`') else quoted_values(base)[0]
        ids, totals = quoted_values(listed), collections.OrderedDict()
        for event in self.seen(index, earliest, latest):
            if (SCORING.fullmatch(event['sourcetype'])
                    or not any(ident in event['raw'] for ident in quoted_values(terms))):
                continue
            ident = self.own_id(event)
            key, turn, blocked, signin, identity_event = self.read_as_ta(event)
            if ident not in ids or key is None:
                continue                                              # stats ... by identity_key drops a null key
            total = totals.setdefault(key, {'ids': set(), 'copies': 0, 'identity_events': 0, 'ai_turns': 0,
                                            'ai_blocked': 0, 'app_signins': 0})
            total['ids'].add(ident)
            for name, flag in (('copies', True), ('identity_events', identity_event), ('ai_turns', turn),
                               ('ai_blocked', blocked), ('app_signins', signin)):
                total[name] += 1 if flag else 0
        return [dict(((name, str(value)) for name, value in total.items() if name != 'ids'), identity_key=key,
                     events=str(len(total['ids']))) for key, total in sorted(totals.items())]

    def duo_events(self, earliest, latest):
        return [event for event in self.seen(self.macro_index['genai_duo_index'], earliest, latest)
                if event['sourcetype'] == DUO_SOURCETYPE and event['duo']]

    def q_duo_half(self, earliest, latest, terms, listed):
        wanted, groups = quoted_values(listed), collections.OrderedDict()
        for event in self.duo_events(earliest, latest):
            if event['duo']['txid'] in wanted:
                groups.setdefault(event['duo']['txid'], []).append(event)
        if not groups:
            return [{'txids_found': '0'}]                 # stats without BY over nothing: the count alone
        held = [event for group in groups.values() for event in group]
        return [row(txids_found=str(len(groups)),
                    found_once=str(sum(1 for group in groups.values() if len(group) == 1)),
                    action=shaped(event['duo']['action'] for event in held),
                    identity_user=shaped(join_key(event['duo']['user']) for event in held),
                    first_duo_time=str(min(event['time'] for event in held)),
                    last_duo_time=str(max(event['time'] for event in held)))]

    def q_duo_context(self, earliest, latest, personas):
        counts, wanted = collections.OrderedDict(), quoted_values(personas)
        for event in self.duo_events(earliest, latest):
            user, duo = join_key(event['duo']['user']), event['duo']
            if user in wanted:
                key = (user, duo['action'], 'success' if duo['result'] == 'success' else 'denied')
                counts.setdefault(key, []).append(duo['txid'])
        return [{'identity_user': key[0], 'action': key[1], 'duo_class': key[2], 'duo_events': str(len(txids)),
                 'txids': str(len(set(txids)))} for key, txids in sorted(counts.items())]

    def chains(self):
        """[(row, judged)]: a stand-in for the joined rule judged over all
        index time. Per identity, 5 Duo failures within 10 minutes, then an
        application sign-in under 30 minutes after the fifth, then a blocked
        verified turn within 60 minutes of that sign-in; one row per such
        sign-in. judged: the index second at which the last piece the chain
        needs was indexed, which is what decides the scheduled run that
        raises it."""
        everything = (decimal.Decimal(0), decimal.Decimal(10) ** 11)
        failures, found = collections.defaultdict(list), []
        for event in self.duo_events(*everything):
            if event['duo']['action'] == 'failure':
                failures[join_key(event['duo']['user'])].append(event)
        app = [(event, self.read_as_ta(event))
               for event in self.seen(self.macro_index['genai_identity_ai_events'], *everything)
               if not SCORING.fullmatch(event['sourcetype'])]
        for event, (key, _, _, signin, _) in app:
            when, mine = float(event['time']), failures.get(key, ())
            bursts = [fail for fail in mine if 0 < when - float(fail['time']) < 1800
                      and sum(1 for other in mine if 0 <= float(fail['time']) - float(other['time']) <= 600) >= 5]
            blocked = [turn for turn, read in app
                       if read[0] == key and read[2] and 0 <= float(turn['time']) - when <= 3600]
            if not (signin and key and bursts and blocked):
                continue
            last = max(bursts, key=lambda fail: fail['time'])
            counted = [other for other in mine if 0 <= float(last['time']) - float(other['time']) <= 600]
            first_turn = min(blocked, key=lambda turn: turn['time'])
            judged = max([event['indexed'], first_turn['indexed']] + [fail['indexed'] for fail in counted])
            found.append(({'chain_id': '{}:takeover:{}'.format(key, int(when)), 'user': key,
                           '_time': '%.3f' % float(first_turn['time']), 'blocked_turns': str(len(blocked)),
                           'duo_failures_10m': str(len(counted)), 'duo_app': 'PseudoCo VPN',
                           'signin_duo': 'none indexed', 'guardrails': 'cisco_ai_defense'}, judged))
        return found

    def rule_rows(self, name):
        return [row for row, _ in self.chains()]

    # -- the scheduler's log (index=_internal sourcetype=scheduler) ----------------------
    def tick(self, scheduled, status='success', logged=None, results=0, suppressed=0, actions=''):
        """One status line of the joined rule: a run of the tick `scheduled`
        that the scheduler logged at `logged` (80 s after the tick unless
        given). `continued` is a deferral; the same tick logs `success` later.
        Only a `success` line carries a dispatch time, a result count, a
        suppressed count and the alert actions that ran."""
        logged = int(logged if logged is not None else scheduled + 80)
        line = {'scheduled_time': int(scheduled), 'status': status, 'time': decimal.Decimal(logged)}
        if status == 'success':
            line.update(dispatch_time=logged - 2, result_count=int(results), suppressed=int(suppressed),
                        alert_actions=actions)
        self.ticks.append(line)

    def slot_seconds(self):
        """(period, how far back a slot starts, how far back it ends), in
        seconds, read from the joined rule's own schedule as the fake holds it."""
        rule = self.saved[JOINED_RULE]
        period = int(re.fullmatch(r'\*/(\d+) \* \* \* \*', rule['cron_schedule']).group(1)) * 60
        back = [int(re.fullmatch(r'-(\d+)m@m', rule[key]).group(1)) * 60
                for key in ('dispatch.earliest_time', 'dispatch.latest_time')]
        return period, back[0], back[1]

    def q_rule_ticks(self, earliest, latest, rule):
        counts = collections.OrderedDict()
        if quoted_values(rule)[0] != JOINED_RULE:
            return []
        for line in self.ticks:
            if earliest <= line['time'] < latest:
                count = counts.setdefault(line['scheduled_time'], {'ok': 0, 'deferred': 0, 'skipped': 0})
                name = {'success': 'ok', 'continued': 'deferred', 'skipped': 'skipped'}.get(line['status'])
                if name:
                    count[name] += 1
        return [dict(((name, str(value)) for name, value in count.items()), scheduled_time=str(tick))
                for tick, count in sorted(counts.items(), reverse=True)]         # stats ... by: no row for nothing

    def q_rule_errors(self, earliest, latest, rule):
        """The ERROR lines of a failing run: no savedsearch_name, no status,
        no scheduled_time, only savedsearch_id and a message."""
        found = [(when, message) for when, message in self.rule_errors
                 if rule == JOINED_RULE and earliest <= decimal.Decimal(int(when)) < latest]
        if not found:
            return [{'errors': '0'}]                          # stats without BY over nothing: the count alone
        return [{'errors': str(len(found)), 'message': max(found)[1], 'last_error': str(max(found)[0])}]

    def q_rule_runs(self, earliest, latest, rule, tick):
        """The status lines from one tick on, newest first, as `table` shows
        them (seen live on 10.4.3): a column a line does not have is absent,
        so a deferred or skipped tick has only scheduled_time and status; a
        run that ran no alert action logs alert_actions="" and shows it as an
        empty string."""
        rows = []
        for line in sorted(self.ticks, key=lambda item: item['time'], reverse=True):
            if (quoted_values(rule)[0] != JOINED_RULE or line['scheduled_time'] < int(tick)
                    or not earliest <= line['time'] < latest):
                continue
            found = {'scheduled_time': str(line['scheduled_time']), 'status': line['status']}
            if 'dispatch_time' in line:
                found.update(dispatch_time=str(line['dispatch_time']), result_count=str(line['result_count']),
                             lag=str(line['dispatch_time'] - line['scheduled_time']),
                             suppressed=str(line['suppressed']), alert_actions=line['alert_actions'])
            rows.append(found)
        return rows

    def q_label(self, earliest, latest, index, bundle):
        """tstats over the label: whole-second bounds, and BY drops an event
        that lacks one of the three fields. No row for nothing."""
        groups = collections.OrderedDict()
        for event in self.seen(quoted_values(index)[0], earliest, latest, whole_seconds=True):
            log_type = self.listed(event['fields'].get('log_type'))
            if quoted_values(bundle)[0] in self.listed(event['fields'].get('resend_bundle')) and log_type:
                groups.setdefault((event['sourcetype'], log_type[0], event['host']), []).append(event)
        return [{'sourcetype': key[0], 'log_type': key[1], 'host': key[2], 'events': str(len(held)),
                 'first_indexed': str(min(event['indexed'] for event in held)),
                 'last_indexed': str(max(event['indexed'] for event in held))}
                for key, held in sorted(groups.items())]

    def q_findings(self, earliest, latest, rule, chains):
        """Findings and risk events of one rule for the chain ids asked for,
        by index and chain. An index this account cannot search, or a stack
        without Enterprise Security (no such index), holds nothing."""
        wanted, name, groups = set(quoted_values(chains)), quoted_values(rule)[0], collections.OrderedDict()
        for item in self.findings:
            if (item['index'] in self.indexes and item['index'] not in self.hidden and item['search_name'] == name
                    and item['chain_id'] in wanted and earliest <= item['time'] < latest
                    and item['indexed'] <= self.clock()):
                groups.setdefault((item['index'], item['chain_id']), []).append(item)
        return [row(index=key[0], chain_id=key[1], rows=str(len(held)),
                    first_raised=str(min(item['indexed'] for item in held)),
                    event_time=shaped(item['orig_time'] or str(item['time']) for item in held))
                for key, held in sorted(groups.items())]

    def schedule(self):
        """With auto_schedule set: every scheduled run of the joined rule
        that has started by now and was not made yet. The run of the cron
        tick T starts dispatch_delay seconds after T and judges the events
        indexed in [T - back, T - lag). A chain is raised by the run whose
        slot holds the second its last piece was indexed, once (the rule's
        own "already judged" test and its suppression). A run that is over 80
        s late logs `continued` at T + 80 first. A failing run logs an ERROR
        line and nothing else, and its slot is never judged again."""
        rule = self.saved.get(JOINED_RULE)
        if self.auto_schedule is None or not rule or rule['disabled']:
            return
        period, back, lag = self.slot_seconds()
        now, tick = self.clock(), (int(self.auto_schedule) // period + 1) * period
        while tick + 80 <= now:
            starts = tick + self.dispatch_delay
            if starts > now and tick not in self.deferred:
                self.deferred.add(tick)
                self.tick(tick, 'continued', tick + 80)
            if starts <= now and tick not in self.ran:
                self.ran.add(tick)
                self.run_rule(tick, starts, tick - back, tick - lag)
            tick += period

    def run_rule(self, tick, starts, slot_from, slot_to):
        if self.run_fails:
            self.rule_errors.append((starts + 1, self.run_fails))
            return
        rows = [row for row, judged in self.chains()
                if slot_from <= judged < slot_to and row['chain_id'] not in self.raised]
        for row in rows if self.actions_run else []:
            self.raised.add(row['chain_id'])
            self.raise_finding(row['chain_id'], starts + 3, row['_time'])
        self.tick(tick, 'success', starts + 2, results=len(rows),
                  actions='notable,risk' if rows and self.actions_run else '')

    def raise_finding(self, chain_id, raised, event_time, notable=1, risk=1, rule=JOINED_RULE):
        """What the rule's alert actions write for one result: a finding in
        index notable, dated when it was raised, with the result's own time
        in orig_time; and a risk event in index risk, dated at the result."""
        for index, count in (('notable', notable), ('risk', risk)):
            for _ in range(count):
                self.findings.append({
                    'index': index, 'search_name': rule, 'chain_id': chain_id, 'indexed': int(raised) + 2,
                    'time': decimal.Decimal(str(raised if index == 'notable' else event_time)),
                    'orig_time': str(event_time) if index == 'notable' else None})

    # -- HEC ---------------------------------------------------------------------------------
    def hec_take(self, text, upto=None):
        """Index the events of one request body, in order, stopping before
        event number `upto`. The event text and the time text are kept exactly
        as they were sent. Returns (how many were indexed, None), or the 400
        answer of HEC for the first event it cannot take: everything before
        that event IS indexed, which is why such an answer proves nothing."""
        try:
            found = envelopes(text)
        except (ValueError, IndexError):
            return 0, (400, {'text': 'Invalid data format', 'code': 6, 'invalid-event-number': 0})
        for number, (whole, texts) in enumerate(found):
            if upto is not None and number >= upto:
                return number, None
            if not isinstance(whole, dict) or 'event' not in whole:
                return number, (400, {'text': 'Event field is required', 'code': 12, 'invalid-event-number': number})
            if whole.get('index') not in self.indexes:
                return number, (400, {'text': 'Incorrect index', 'code': 7, 'invalid-event-number': number})
            event = self.add(texts['event'], texts['time'], whole.get('sourcetype'), host=whole.get('host'),
                             source=whole.get('source'), index=whole['index'], indexed=int(self.clock()),
                             fields=whole.get('fields'))
            event['visible'] = self.clock() + self.index_lag
            if self.hec_rewrite:
                self.hec_rewrite(event)
        return len(found), None

    def hec_answer(self, step, length, text):
        """(status, body) for one POST that was read, or None for no answer at
        all (the connection just closes). step: 'ok'; 'lost' (indexed, then
        no answer); ('answer', status, body, take) for any answer, with or
        without indexing first; ('partial', n) for a 400 at event n."""
        if self.hec_max_bytes and length > self.hec_max_bytes:
            return 413, {'text': 'Content-Length of {} too large'.format(length), 'code': 413}
        if step == 'lost':
            self.hec_take(text)
            return None
        if isinstance(step, tuple) and step[0] == 'answer':
            if step[3]:
                self.hec_take(text)
            return step[1], step[2]
        if isinstance(step, tuple) and step[0] == 'partial':
            self.hec_take(text, upto=step[1])
            return 400, {'text': 'Invalid data format', 'code': 6, 'invalid-event-number': step[1]}
        taken, refused = self.hec_take(text)
        return refused or (200, {'text': 'Success', 'code': 0})

    # -- REST ----------------------------------------------------------------------
    def rest(self, method, path, form):
        def entry(name, content):
            return {'entry': [{'name': name, 'content': content}]}

        saved = '/servicesNS/nobody/{}/saved/searches/'.format(APP)
        if method == 'GET' and path == '/services/server/info':
            return entry('server-info', {'guid': self.guid, 'version': self.version, 'serverName': 'fake-splunk'})
        if method == 'GET' and path == '/services/apps/local/' + APP and self.ta_version is not None:
            return entry(APP, {'version': self.ta_version})
        if method == 'GET' and path.startswith(saved) and urllib.parse.unquote(path[len(saved):]) in self.saved:
            name = urllib.parse.unquote(path[len(saved):])
            return entry(name, self.saved[name])
        if method == 'POST' and path == '/servicesNS/nobody/{}/search/jobs'.format(APP):
            return self.search(form)
        indexes, macro = '/services/data/indexes/', '/servicesNS/nobody/{}/configs/conf-macros/'.format(APP)
        for status, prefix in ((self.index_status, indexes), (self.macro_status, macro)):
            if method == 'GET' and path.startswith(prefix) and status != 200:
                raise Reply(status, {'messages': [{'type': 'ERROR', 'text': 'this stack does not serve that'}]})
        name = urllib.parse.unquote(path[len(indexes):]) if path.startswith(indexes) else None
        if method == 'GET' and name in self.indexes and name not in self.hidden:
            return entry(name, {'frozenTimePeriodInSecs': self.retention_seconds, 'disabled': self.index_disabled,
                                'datatype': 'event'})
        if method == 'GET' and path == macro + 'genai_identity_ai_events':
            shipped = 'index={} `exclude_scoring_sourcetypes`'.format(self.macro_index['genai_identity_ai_events'])
            return entry('genai_identity_ai_events', {'definition': self.macro_text or shipped, 'iseval': '0'})
        raise Reply(404, {'messages': [{'type': 'ERROR', 'text': 'Not Found'}]})

    def authorized(self, header):
        basic = base64.b64encode('{}:{}'.format(self.user, self.password).encode('utf-8')).decode('ascii')
        return header in ('Basic ' + basic, 'Bearer ' + self.token)

    # -- HTTP ----------------------------------------------------------------------
    def start(self):
        """Serve on a free loopback port; returns the address (plain http)."""
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def answer(self, status, body, location=None):
                data = (body if isinstance(body, str) else json.dumps(body)).encode('utf-8')
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                if location:
                    self.send_header('Location', location)
                self.end_headers()
                self.wfile.write(data)

            def run(self, method):
                parts = urllib.parse.urlsplit(self.path)
                raw = self.rfile.read(int(self.headers.get('Content-Length') or 0)).decode('utf-8')
                form = dict((key, values[0]) for key, values
                            in urllib.parse.parse_qs(raw, keep_blank_values=True).items())
                fake.requests.append({'method': method, 'path': parts.path, 'query': parts.query,
                                      'headers': dict(self.headers.items()), 'form': form})
                if fake.redirect_to:
                    return self.answer(302, '', location=fake.redirect_to + self.path)
                if not fake.authorized(self.headers.get('Authorization')):
                    return self.answer(401, {'messages': [{'type': 'WARN', 'text': 'call not properly authenticated'}]})
                if 'output_mode=json' not in parts.query.split('&'):
                    return self.answer(400, {'messages': [{'type': 'ERROR', 'text': 'output_mode=json expected'}]})
                try:
                    return self.answer(200, fake.rest(method, parts.path, form))
                except Reply as reply:
                    return self.answer(reply.status, reply.body)

            def do_GET(self):
                self.run('GET')

            def do_POST(self):
                self.run('POST')

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True).start()
        return 'http://127.0.0.1:{}'.format(self.server.server_address[1])

    def start_hec(self, port=0, tls=None):
        """Serve HEC on a loopback port of its own (a stack's HEC is another
        address than its port 8089); returns the event endpoint's URL. tls:
        (certificate file, key file) to serve https."""
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def answer(self, status, body):
                data = (body if isinstance(body, str) else json.dumps(body)).encode('utf-8')
                self.send_response(status)
                self.send_header('Content-Type', 'application/json; charset=UTF-8')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                fake.hec_requests.append({'method': 'GET', 'path': self.path, 'headers': dict(self.headers.items()),
                                          'length': 0, 'body': None, 'step': 'health'})
                if self.path != '/services/collector/health':
                    return self.answer(404, {'text': 'The requested URL was not found on this server.', 'code': 404})
                if fake.hec_healthy:
                    return self.answer(200, {'text': 'HEC is healthy', 'code': 17})
                self.answer(503, {'text': 'HEC is unhealthy, queues are full', 'code': 18})

            def do_POST(self):
                length = int(self.headers.get('Content-Length') or 0)
                step = fake.hec_script.pop(0) if fake.hec_script else 'ok'
                record = {'method': 'POST', 'path': self.path, 'headers': dict(self.headers.items()),
                          'length': length, 'body': None, 'step': step if isinstance(step, str) else step[0]}
                fake.hec_requests.append(record)
                if step == 'early413' or (fake.early_413 and fake.hec_max_bytes and length > fake.hec_max_bytes):
                    # splunkd checks the declared length: it answers from the headers and closes, body unread
                    self.close_connection = True
                    return self.answer(413, {'text': 'Content-Length of {} too large'.format(length), 'code': 413})
                record['body'] = self.rfile.read(length)
                given = self.headers.get('Authorization')
                if self.path != '/services/collector/event':
                    return self.answer(404, {'text': 'The requested URL was not found on this server.', 'code': 404})
                if given is None:
                    return self.answer(401, {'text': 'Token is required', 'code': 2})
                if given != 'Splunk ' + fake.hec_token:
                    return self.answer(403, {'text': 'Invalid token', 'code': 4})
                reply = fake.hec_answer(step, length, record['body'].decode('utf-8'))
                if reply is None:
                    self.close_connection = True              # the reply is lost: the client reads nothing
                    return None
                return self.answer(*reply)

        server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
        if tls:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(*tls)
                server.socket = context.wrap_socket(server.socket, server_side=True)
            except Exception:                                 # a Python that cannot serve TLS: nothing is left behind
                server.server_close()
                raise
        self.hec_server = server
        threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True).start()
        return '{}://127.0.0.1:{}/services/collector/event'.format('https' if tls else 'http',
                                                                  self.hec_server.server_address[1])

    def stop_hec(self):
        if self.hec_server:
            self.hec_server.shutdown()
            self.hec_server.server_close()
            self.hec_server = None

    def hec_posts(self):
        """The POSTs HEC received, in order."""
        return [request for request in self.hec_requests if request['method'] == 'POST']

    def stop(self):
        self.stop_hec()
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
