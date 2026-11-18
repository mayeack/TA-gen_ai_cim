#!/usr/bin/env python3
# encoding=utf-8
"""
Offline tests for tools/staged_resend.py, the tool that copies the staged
PseudoCo Assistant events of a lab persona to stacks created after the staging.
Nothing here reaches a Splunk, a HEC or the network.

What is pinned:
  * the HEC line: the assistant's envelope, key for key, the three label
    fields, the time text as stored, and the event text SPLICED in. The texts
    are literals of this file and of fixtures/staged_resend_golden.json, never
    json.dumps output: a compact round trip leaves most "odd" JSON alone, so a
    test built with json.dumps cannot tell a splice from a re-serialization;
  * what makes an event eligible, one refusal per rule, and that the persona
    is matched in Python on the parsed body;
  * the selection: the window's edges, the two guards and their overrides;
  * the bundle: digest, id, exact keys, every way an edit is caught, the
    approval, and the files (0600, never through a symlink, never over an
    existing file, never inside a git work tree);
  * the decision table, on rows shaped as splunkd returns them (strings,
    lists, missing columns);
  * the HEC answer classes: "not sent" only on HEC's four exact pairs, and
    every answer the table does not name is "unknown";
  * the command line: four commands, no option that takes a secret or has an
    argparse type, no value repeated in an error;
  * the shipped confs: nothing reads the label, and the rule and macros the
    tool names exist;
  * export, against fake_resend_stack.py (a loopback splunkd): every search
    text, written out here; the order and the time range of each read; the
    refusals, each before any event text is read or before anything is
    written; the bundle (0600, a deterministic id) and what it records beside
    the events, held to an exact shape; --list-only; and --check-logs on the
    assistant's own log lines of the golden fixture;
  * the splunkd client: the credential from exactly one environment variable,
    the certificate verified unless the run names why not, no redirect
    followed, a WARN answered by asking again, and no rows ever read out of
    an answer that is not splunkd's clean JSON;
  * review of an exported bundle: ids, 12 digits of a hash, times and counts;
  * send, against a second fake that plays a stack with its own HEC: the
    request byte for byte, the canary, every class of HEC answer (a request
    is repeated only after an answer that proves nothing was indexed), the
    write-ahead ledger and its lock, an unknown answer never followed by a
    second request in the same run or a later one, 413 halving, --dry-run,
    and the preconditions R1 to R8, each failing alone and each override
    named in the output;
  * verify, against the same stack with its scheduler running: V1 to V6,
    each failing alone; what is waited for and for how long (ids that were
    handed to HEC, for 180 s; the finding, until it is there, overdue, or
    --wait is used up); the tick that judges a copy, by hand and against a
    scheduler that reads the slot from the shipped stanza; a late finding
    with the scheduler's own record; a missing chain; exit 3 only while
    handed-over ids are not searchable; and that verify sends nothing, writes
    nothing and prints nothing a stack answers but counts, times and plain
    words.

Every value is invented: persona short names, @corp.test, RFC 5737 addresses
and made-up UUIDs. The suite needs the joined rule's stanza in
default/savedsearches.conf underneath it and FAILS without it (it never skips).

    python3 -B -m unittest discover -s tools/tests -p 'test_staged_resend.py' -v
"""

import base64
import collections
import contextlib
import hashlib
import http.client
import http.server
import importlib.util
import io
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
for _path in (os.path.join(REPO, 'bin'), os.path.join(REPO, 'tools'), HERE):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import fake_resend_stack as fake_stack  # noqa: E402
import staged_resend as tool  # noqa: E402
from test_lab5_conf import read_conf  # noqa: E402

GOLDEN = os.path.join(HERE, 'fixtures', 'staged_resend_golden.json')
BUNDLE_ID = 'rs-20261117-0123456789ab'
HOST = 'stage-host'
ADDRESS = '192.0.2.10'                                     # RFC 5737
TXID = '5ca1ab1e-0006-4000-8000-0000000000d1'
PROMPT = 'What is a normal resting heart rate'
T_FROM, T_TO = 1794890400, 1794890700                      # 2026-11-17 04:40:00Z to 04:45:00Z
NOW = 1794900000.0                                         # hours after every fixture event


def sha(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


# A backslash and a "u", put together here so that this source holds no escape
# a tool could decode on the way in: the fixtures need the six characters.
U = chr(92) + 'u'


# Bodies as the assistant writes them: compact, the id first. They are literal
# text on purpose (see the module docstring).
SIGNIN = ('{"audit_id":"5ca1ab1e-0001-4000-8000-0000000000a1","session_id":"identity-a1","request_id":"r-a1",'
          '"timestamp":"2026-11-17T04:40:19.555851","action":"identity_signin_success","actor":"user",'
          '"details":{"duo_txid":"' + TXID + '"},"ip_address":"' + ADDRESS + '",'
          '"enduser_id":"nina.osei","user":"nina.osei","src":"' + ADDRESS + '"}')
STARTED = ('{"audit_id":"5ca1ab1e-0001-4000-8000-0000000000a2","session_id":"sess-1","request_id":"r-a2",'
           '"timestamp":"2026-11-17T04:40:51.147000","action":"session_started","actor":"user","details":{},'
           '"ip_address":"' + ADDRESS + '","enduser_id":"nina.osei","user":"nina.osei","src":"' + ADDRESS + '"}')
TURN = (r'{"event_id":"5ca1ab1e-0002-4000-8000-0000000000b1","operation_name":"chat","provider_name":"ollama",'
        r'"session_id":"sess-1","timestamp":"2026-11-17T04:41:05.273000",'
        r'"input_messages":[{"role":"user","content":"' + PROMPT + r'?"}],'
        r'"response_text":"caf' + U + '00e9 ' + U + '2019quoted' + U + r'2019 a/b","risk_score":60.0,'
        r'"estimated_cost":1e-05,'
        r'"big":12345678901234567890,"identity_verified":true,"policy_blocked":false,'
        r'"client_address":"' + ADDRESS + r'","enduser_id":"nina.osei","user":"nina.osei"}')
BLOCKED = ('{"event_id":"5ca1ab1e-0002-4000-8000-0000000000b2","operation_name":"chat","provider_name":"ollama",'
           '"session_id":"sess-1","timestamp":"2026-11-17T04:41:41","input_messages":[{"role":"user",'
           '"content":"' + PROMPT + ' again?"}],"identity_verified":true,"policy_blocked":true,'
           '"enduser_id":"nina.osei","user":"nina.osei"}')
ERROR = ('{"event_id":"5ca1ab1e-0002-4000-8000-0000000000b3","session_id":"sess-1",'
         '"timestamp":"2026-11-17T04:41:50.500000","error_type":"timeout","enduser_id":"nina.osei",'
         '"user":"nina.osei"}')
ESCALATION = ('{"escalation_id":"5ca1ab1e-0003-4000-8000-0000000000c1","session_id":"sess-1","request_id":"r-c1",'
              '"timestamp":"2026-11-17T04:42:00.010000","reason":"policy","severity":"HIGH",'
              '"conversation_history":[],"symptoms":[],"review_status":"pending","enduser_id":"nina.osei",'
              '"user":"nina.osei"}')
OTHER = ('{"event_id":"5ca1ab1e-0002-4000-8000-0000000000e1","operation_name":"chat","session_id":"sess-9",'
         '"timestamp":"2026-11-17T04:42:10.100000","enduser_id":"grace.lin","user":"grace.lin"}')
ANONYMOUS = ('{"event_id":"5ca1ab1e-0002-4000-8000-0000000000e2","operation_name":"chat","session_id":"sess-8",'
             '"timestamp":"2026-11-17T04:42:20.200000","enduser_id":null}')

# (text, tostring(_time), sourcetype, log_type): six events of the persona, two of nobody we copy.
STAGED = ((SIGNIN, '1794890419.556', 'demobot:audit', 'audit'),
          (STARTED, '1794890451.147', 'demobot:audit', 'audit'),
          (TURN, '1794890465.273', 'gen_ai:json', 'governance'),
          (BLOCKED, '1794890501.0', 'gen_ai:json', 'governance'),
          (ERROR, '1794890510.5', 'demobot:error', 'error'),
          (ESCALATION, '1794890520.01', 'demobot:escalation', 'escalation'))
OTHERS = ((OTHER, '1794890530.1', 'gen_ai:json', 'governance'),
          (ANONYMOUS, '1794890540.2', 'gen_ai:json', 'governance'))
NEVER_SHOWN = (ADDRESS, TXID, PROMPT, 'caf', 'quoted')    # body values no output may hold


def row_of(raw, time_text, sourcetype, log_type, **change):
    """One row of the export search (S3), as splunkd returns it: every value a string."""
    row = {'_raw': raw, 'rs_time': time_text, 'rs_indextime': str(int(float(time_text)) + 2),
           'rs_sha256': sha(raw), 'rs_len': str(len(raw)), 'index': 'gen_ai_log', 'host': HOST,
           'source': 'demobot:hec', 'sourcetype': sourcetype, 'rs_log_type': log_type, 'rs_bundle': 'none'}
    row.update(change)
    return row


def rows():
    return [row_of(*item) for item in STAGED + OTHERS]


def select(found=None, **options):
    return tool.select_events(rows() if found is None else found, ['nina.osei'], T_FROM, T_TO, 'demobot:hec',
                              NOW, **options)


def staged_events():
    return select().events


def plain_event(raw, time_text='1794890419.556', sourcetype='gen_ai:json', log_type='governance'):
    """A bundle event around any literal text, built by hand: no eligibility check runs."""
    key, ident = re.match(r'\{\s*"(\w+)"\s*:\s*"([0-9a-f-]{36})"', raw).groups()
    return {'id': ident, 'id_key': key, 'time': time_text, 'host': HOST, 'source': 'demobot:hec',
            'sourcetype': sourcetype, 'index': 'gen_ai_log', 'log_type': log_type, 'sha256': sha(raw),
            'chars': len(raw), 'bytes': len(raw.encode('utf-8')), 'origin_indextime': 1794890421, 'raw': raw}


GUID = '5CA1AB1E-0000-4000-8000-00000000F001'


def parts_of(events):
    """origin, selection, census and expect in the shapes `export` writes, for
    a set of bundle events: the smallest window around them, nothing left out,
    nothing read about Duo or the rule."""
    times = sorted(float(event['time']) for event in events)
    return {
        'origin': {'guid': GUID, 'splunk_version': '10.4.3', 'ta_version': '1.9.0', 'read_at': int(NOW)},
        'selection': {'index': events[0]['index'], 'source': events[0]['source'],
                      'hosts': sorted({event['host'] for event in events}),
                      'personas': sorted({tool.actor_of(tool.parse_body(event['raw'])[0]) for event in events}),
                      'from': int(times[0]), 'to': int(times[-1]) + 1, 'exact_window': False,
                      'allow_partial_session': False, 'allow_unlisted_persona': False, 'notes': []},
        'census': {'pad_seconds': 3600, 'eligible': len(events), 'legacy_indexed_body_keys': 0, 'rows': [],
                   'left_out': {'other identities': 0, 'no user': 0, 'outside the window': 0}, 'log_check': None},
        'expect': {'identity': [], 'chains': [],
                   'duo': {'signins': len(tool.signin_events(events)), 'txids': len(tool.signin_txids(events)),
                           'txids_found': 0, 'found_once': 0, 'context': []},
                   'rule': {'name': tool.JOINED_RULE, 'found': False, 'sha256': None, 'rows': 0}}}


def bundle_of(found=None):
    events = staged_events() if found is None else found
    parts = parts_of(events)
    return tool.build_bundle(events, parts['origin'], parts['selection'], parts['census'], parts['expect'])


class ToolCase(unittest.TestCase):
    """Collects what a run printed and every refusal's text, and checks at the
    end of each test that none of it holds a body value."""

    def setUp(self):
        self.out = []
        self.folder = tempfile.mkdtemp(prefix='staged-resend-test-')
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.state_dir = tempfile.mkdtemp(prefix='staged-resend-state-')     # never the real ~/.staged-resend
        self.addCleanup(shutil.rmtree, self.state_dir, True)
        self.addCleanup(setattr, tool, 'DEFAULT_STATE_DIR', tool.DEFAULT_STATE_DIR)
        tool.DEFAULT_STATE_DIR = self.state_dir

    def tearDown(self):
        text = '\n'.join(self.out)
        for needle in NEVER_SHOWN:
            self.assertNotIn(needle, text, 'the output or a refusal shows a body value')

    def echo(self, line=''):
        self.out.append(str(line))

    def refused(self, call, *args, **kwargs):
        """The text of the Refused a call must raise."""
        with self.assertRaises(tool.Refused) as caught:
            call(*args, **kwargs)
        self.out.append(str(caught.exception))
        return str(caught.exception)

    def path(self, *names):
        return os.path.join(self.folder, *names)


BS, E_ACUTE, DASH, GRIN = chr(92), chr(0xe9), chr(0x2014), chr(0x1F600)
# Event texts that a parse-and-write-again changes. The first seven come back
# different from json.dumps(json.loads(text)) in its compact AND its default
# form. The last is what a compact round trip leaves alone (lowercase escapes,
# 1e-05, a 20-digit integer, 60.0): on its own it proves nothing.
SPLICE = (
    ('odd spacing', '{ "event_id" : "5ca1ab1e-0002-4000-8000-000000000101",  "a":1 ,"b" : [ 1,2 ] }'),
    ('a line break and a tab between keys', '{"event_id":"5ca1ab1e-0002-4000-8000-000000000102",\n\t"a":1}'),
    ('unescaped UTF-8', '{"event_id":"5ca1ab1e-0002-4000-8000-000000000103","note":"caf' + E_ACUTE + ' ' + DASH
     + ' ' + GRIN + '"}'),
    ('an uppercase hex escape', '{"event_id":"5ca1ab1e-0002-4000-8000-000000000104","note":"caf' + U + '00E9"}'),
    ('an escaped solidus', '{"event_id":"5ca1ab1e-0002-4000-8000-000000000105","note":"<' + BS + '/script> a'
     + BS + '/b"}'),
    ('numbers written another way', '{"event_id":"5ca1ab1e-0002-4000-8000-000000000106","small":1E-5,'
     '"price":2.50,"kilo":1.0e3}'),
    ('an unread key twice', '{"event_id":"5ca1ab1e-0002-4000-8000-000000000107","k":1,"k":2}'),
    ('what a compact round trip keeps', '{"event_id":"5ca1ab1e-0002-4000-8000-000000000108","note":"caf' + U
     + '00e9","tiny":1e-05,"big":12345678901234567890,"sixty":60.0}'),
)
HEAD = ('{"time":1794890419.556,"host":"stage-host","source":"demobot:hec","sourcetype":"gen_ai:json",'
        '"index":"gen_ai_log","event":')
TAIL = (',"fields":{"log_type":"governance","resend":"true","resend_bundle":"rs-20261117-0123456789ab",'
        '"resend_orig_indextime":"1794890421"}}')


class LineTests(ToolCase):
    def test_the_line_is_the_assistants_envelope_plus_the_three_label_fields(self):
        event = staged_events()[0]
        envelope = ('{"time":1794890419.556,"host":"stage-host","source":"demobot:hec",'
                    '"sourcetype":"demobot:audit","index":"gen_ai_log","event":' + SIGNIN)
        self.assertEqual(tool.event_line(event, BUNDLE_ID), envelope + (
            ',"fields":{"log_type":"audit","resend":"true","resend_bundle":"rs-20261117-0123456789ab",'
            '"resend_orig_indextime":"1794890421"}}'))
        self.assertEqual(tool.assistant_line(event), envelope + ',"fields":{"log_type":"audit"}}')

    def test_the_fixture_texts_are_ones_a_round_trip_changes(self):
        for name, text in SPLICE[:-1]:
            with self.subTest(name):
                self.assertNotEqual(json.dumps(json.loads(text), separators=(',', ':')), text)
                self.assertNotEqual(json.dumps(json.loads(text)), text)
        last = SPLICE[-1][1]
        self.assertEqual(json.dumps(json.loads(last), separators=(',', ':')), last)

    def test_the_event_text_is_spliced_in_and_never_written_again(self):
        for name, text in SPLICE:
            with self.subTest(name):
                line = tool.event_line(plain_event(text), BUNDLE_ID)
                self.assertEqual(line, HEAD + text + TAIL)
                body = tool.make_batch([plain_event(text)], BUNDLE_ID).body
                self.assertEqual(body, (HEAD + text + TAIL).encode('utf-8'))
                self.assertEqual(tool.assistant_line(plain_event(text)),
                                 HEAD + text + ',"fields":{"log_type":"governance"}}')

    def test_the_time_text_is_sent_as_stored(self):
        for text in ('1794890419.556', '1794890465.5', '1794890501.0', '1794890501', '1794890520.01',
                     '1794890465.273000'):
            with self.subTest(text):
                line = tool.event_line(plain_event(SPLICE[0][1], time_text=text), BUNDLE_ID)
                self.assertTrue(line.startswith('{"time":' + text + ',"host":'), line[:40])
        for bad in ('1.7e9', '1794890419.5560000', ' 1794890419', '1794890419.556\n', '1794890419.', 'NaN',
                    '-1794890419', '0794890419', '', None, 1794890419.556):
            with self.subTest(bad=bad):
                self.refused(tool.event_line, plain_event(SPLICE[0][1], time_text=bad), BUNDLE_ID)

    def test_the_golden_lines_of_the_assistants_own_forwarder(self):
        with io.open(GOLDEN, encoding='utf-8') as handle:      # a missing fixture is an error, never a skip
            golden = json.load(handle)
        where, bundle_id = golden['destination'], golden['resend']['bundle_id']
        self.assertEqual(golden['resend']['label_keys'], ['log_type'] + list(tool.LABEL_FIELDS))
        self.assertGreaterEqual(len(golden['cases']), 8)
        self.assertGreaterEqual(len(golden['splice']), 7)
        for case in golden['cases'] + golden['splice']:
            with self.subTest(case['name']):
                event = plain_event(case['raw'], case['time'], case['sourcetype'], case['log_type'])
                event.update(host=where['host'], source=where['source'], index=where['index'],
                             origin_indextime=int(case['resend_orig_indextime']))
                self.assertEqual((event['id_key'], event['id'], event['sha256']),
                                 (case['id_key'], case['id'], case['sha256']))
                self.assertEqual(tool.event_line(event, bundle_id), case['resend_line'])
                if 'hec_line' in case:                         # what the assistant itself sent
                    self.assertEqual(tool.assistant_line(event), case['hec_line'])
                body, keys = tool.parse_body(case['raw'])
                self.assertEqual(tool.own_id(body, keys, case['log_type']), (case['id_key'], case['id']))
                self.assertEqual(repr(tool.forwarder_time(body)), case['time'])

    def test_an_event_is_never_sent_without_its_label(self):
        event = staged_events()[2]
        for bad in (None, '', 'none', 'rs-2026-0123456789ab', BUNDLE_ID + '\n', BUNDLE_ID.upper(), 7):
            with self.subTest(bundle_id=bad):
                self.refused(tool.event_line, event, bad)
        for batch in tool.batches(staged_events(), BUNDLE_ID, max_events=4):
            for line in batch.body.decode('utf-8').split('\n'):
                fields = json.loads(line)['fields']
                self.assertEqual(sorted(fields), ['log_type', 'resend', 'resend_bundle', 'resend_orig_indextime'])
                self.assertEqual((fields['resend'], fields['resend_bundle']), ('true', BUNDLE_ID))
                self.assertRegex(fields['resend_orig_indextime'], r'^\d{10}$')
        self.assertEqual(json.loads(tool.assistant_line(event))['fields'], {'log_type': 'governance'})

    def test_a_changed_or_malformed_event_makes_no_line(self):
        good = staged_events()[2]
        changes = {
            'one byte of the text': {'raw': good['raw'].replace('nina.osei', 'grace.lin')},
            'a quote in the host': {'host': 'stage"host'}, 'a space in the source': {'source': 'demobot hec'},
            'an index with a capital': {'index': 'Gen_ai_log'}, 'an internal index': {'index': '_internal'},
            'a sourcetype with a line break': {'sourcetype': 'gen_ai:json\n'},
            'an unknown log_type': {'log_type': 'scoring'}, 'the id key of another log_type': {'id_key': 'audit_id'},
            'an id that is not a UUID': {'id': 'abc" OR index=* "'}, 'no index time': {'origin_indextime': 0},
            'an index time as text': {'origin_indextime': '1794890467'},
            'a true index time': {'origin_indextime': True},
            'a sha256 that is not one': {'sha256': 'x' * 64}}
        for name, change in changes.items():
            with self.subTest(name):
                self.refused(tool.event_line, dict(good, **change), BUNDLE_ID)
                self.refused(tool.assistant_line, dict(good, **change))
        for name, text in (('NaN', '{"event_id":"5ca1ab1e-0002-4000-8000-000000000109","x":NaN}'),
                           ('Infinity', '{"event_id":"5ca1ab1e-0002-4000-8000-000000000109","x":-Infinity}'),
                           ('two objects', '{"event_id":"5ca1ab1e-0002-4000-8000-000000000109"} {"a":1}'),
                           ('an open object', '{"event_id":"5ca1ab1e-0002-4000-8000-000000000109","a":{}')):
            with self.subTest(name):
                self.refused(tool.event_line, plain_event(text), BUNDLE_ID)

    def test_batches_keep_time_order_and_both_limits(self):
        events = staged_events()
        shuffled = [events[i] for i in (3, 0, 5, 1, 4, 2)]
        whole = tool.batches(shuffled, BUNDLE_ID)
        self.assertEqual([[e['id'] for e in batch.events] for batch in whole], [[e['id'] for e in events]])
        self.assertEqual(whole[0].body, '\n'.join(tool.event_line(e, BUNDLE_ID) for e in events).encode('utf-8'))
        self.assertEqual([len(b.events) for b in tool.batches(events, BUNDLE_ID, max_events=4)], [4, 2])
        sizes = [len(tool.event_line(e, BUNDLE_ID).encode('utf-8')) for e in events]
        limit = sizes[0] + 1 + sizes[1]                       # exactly two lines and the "\n" between them
        split = tool.batches(events, BUNDLE_ID, max_bytes=limit)
        self.assertEqual([e['id'] for b in split for e in b.events], [e['id'] for e in events])
        self.assertEqual(len(split[0].events), 2)
        self.assertEqual(len(tool.batches(events, BUNDLE_ID, max_bytes=limit - 1)[0].events), 1)
        for batch in split:
            self.assertTrue(len(batch.body) <= limit or len(batch.events) == 1)
        self.assertEqual(tool.batches([], BUNDLE_ID), [])
        for broken in (dict(events[0], time='soon'), dict(events[0], time=None), {'id': 'x'}, 'not an event'):
            with self.subTest(broken=str(broken)[:12]):                    # a refusal, never a traceback
                self.refused(tool.batches, events[1:] + [broken], BUNDLE_ID)
                self.refused(tool.digest, events[1:] + [broken])
                self.refused(tool.plan, events[1:] + [broken], [], BUNDLE_ID)
        self.assertEqual((tool.MAX_REQUEST_EVENTS, tool.MAX_REQUEST_BYTES, tool.MAX_EVENT_BYTES),
                         (50, 512 * 1024, 900000))
        self.assertEqual(tool.HEC_PATH, '/services/collector/event')
        self.assertEqual(dict(tool.HEC_HEADERS), {'Content-Type': 'application/json; charset=utf-8',
                                                  'Connection': 'close'})      # the token is not a constant

    def test_an_event_over_the_request_budget_travels_alone(self):
        events = staged_events()
        alone = tool.batches(events, BUNDLE_ID, max_bytes=10)     # every line is larger than this
        self.assertEqual([len(b.events) for b in alone], [1] * len(events))

    def test_a_413_halves_the_request_and_one_event_cannot_be_halved(self):
        events = staged_events()
        batch = tool.batches(events, BUNDLE_ID)[0]
        first, second = tool.halve(batch, BUNDLE_ID)
        self.assertEqual([e['id'] for e in first.events + second.events], [e['id'] for e in events])
        self.assertEqual(first.body + b'\n' + second.body, batch.body)
        self.assertEqual((len(first.events), len(second.events)), (3, 3))
        single = tool.make_batch(events[:1], BUNDLE_ID)
        self.assertIn(events[0]['id'], self.refused(tool.halve, single, BUNDLE_ID))


def changed(raw, old, new, count=1):
    """A fixture text with one piece replaced; fails loudly when the piece is not there."""
    assert raw.count(old) >= 1, old
    return raw.replace(old, new, count)


class EligibilityTests(ToolCase):
    def eligible(self, item, **change):
        row = row_of(*item)
        row.update(change)
        return tool.event_from_row(row, 'demobot:hec', NOW)

    def test_an_assistant_event_becomes_a_bundle_event(self):
        event = self.eligible(STAGED[0])
        self.assertEqual(event, {
            'id': '5ca1ab1e-0001-4000-8000-0000000000a1', 'id_key': 'audit_id', 'time': '1794890419.556',
            'host': HOST, 'source': 'demobot:hec', 'sourcetype': 'demobot:audit', 'index': 'gen_ai_log',
            'log_type': 'audit', 'sha256': sha(SIGNIN), 'chars': len(SIGNIN), 'bytes': len(SIGNIN.encode('utf-8')),
            'origin_indextime': 1794890421, 'raw': SIGNIN})
        self.assertEqual(sorted(event), sorted(tool.EVENT_FIELDS))
        self.assertEqual([self.eligible(item)['id_key'] for item in STAGED],
                         ['audit_id', 'audit_id', 'event_id', 'event_id', 'event_id', 'escalation_id'])

    def test_an_error_record_has_an_id_and_is_copied_like_the_rest(self):
        event = self.eligible(STAGED[4])
        self.assertEqual((event['log_type'], event['id_key'], event['sourcetype']),
                         ('error', 'event_id', 'demobot:error'))

    def test_the_time_is_the_bodys_timestamp_by_the_forwarders_rule(self):
        for stamp, expected in (('2026-11-17T04:40:19.555851', '1794890419.556'),
                                ('2026-11-17T04:41:41', '1794890501.0'),
                                ('2026-11-17T04:41:41.000400', '1794890501.0'),
                                ('2026-11-17T04:41:40.999600', '1794890501.0'),
                                ('2026-11-17T04:41:50.500000', '1794890510.5'),
                                ('2026-11-17T04:41:50.5Z', None),
                                ('2026-11-17T04:41:50.500Z', '1794890510.5'),
                                ('2026-11-16T20:41:50.500000-08:00', '1794890510.5'),
                                ('2026-11-17 04:41:50.500000', '1794890510.5'),
                                ('2026-11-17T04:41:60', None), ('yesterday', None), (1794890510.5, None)):
            with self.subTest(stamp=stamp):
                got = tool.forwarder_time({'timestamp': stamp})
                self.assertEqual(None if got is None else repr(got), expected)
        self.assertIsNone(tool.forwarder_time({}))
        # Splunk prints the digits HEC was sent: a whole second is "N.0", and the same value may carry zeros.
        for raw, text in ((BLOCKED, '1794890501.0'), (BLOCKED, '1794890501'), (TURN, '1794890465.273000')):
            self.assertEqual(self.eligible((raw, text, 'gen_ai:json', 'governance'))['time'], text)
        for off in ('1794890465.272', '1794890465.2731', '1794890466.273', '1794890465'):
            with self.subTest(time_text=off):
                self.assertIn('forwarder', self.refused(self.eligible, (TURN, off, 'gen_ai:json', 'governance')))

    def test_every_rule_of_an_eligible_event_refuses(self):
        turn = STAGED[2]
        cases = {
            'no indexed log_type': dict(rs_log_type=None),
            'two log_types': dict(rs_log_type='governance,governance'),
            'a log_type the assistant does not write': dict(rs_log_type='scoring'),
            'another source': dict(source='ai_defense_response'),
            'a re-sent copy': dict(rs_bundle='rs-20261101-aaaaaaaaaaaa'),
            'no label column at all': dict(rs_bundle=None),
            'a host that is not a plain value': dict(host='stage host'),
            'an index that is not a plain value': dict(index='gen_ai_log"'),
            'no index time': dict(rs_indextime=None),
            'a sha256 Splunk computed differently': dict(rs_sha256=sha(TURN + ' ')),
            'a length Splunk computed differently': dict(rs_len=str(len(TURN) + 1)),
            'no length': dict(rs_len=None),
            'a time that is not a number': dict(rs_time='2026-11-17 04:41:05'),
            'no _raw': dict(_raw=None)}
        for pattern in tool.SCORING_SOURCETYPES:
            cases['scoring sourcetype ' + pattern] = dict(sourcetype=pattern.replace('*', 'pii'))
        for name, change in cases.items():
            with self.subTest(name):
                self.refused(self.eligible, turn, **change)
        self.assertIn('younger than 15 minutes', self.refused(
            tool.event_from_row, row_of(*turn), 'demobot:hec', float(turn[1]) + 899))
        self.assertEqual(tool.event_from_row(row_of(*turn), 'demobot:hec', float(turn[1]) + 900)['time'], turn[1])
        self.assertEqual(tool.MIN_AGE_SECONDS, 900)

    def test_the_body_rules_refuse(self):
        ident = '"event_id":"5ca1ab1e-0002-4000-8000-0000000000b1",'
        other = '"audit_id":"5ca1ab1e-0001-4000-8000-0000000000ff",'
        texts = {
            'two ids': changed(TURN, ident, ident + other),
            'an id that is not the first key': changed(TURN, '{' + ident, '{"operation_name":"chat",' + ident),
            'no id': changed(TURN, ident, ''),
            'an id that is not a UUID': changed(TURN, '5ca1ab1e-0002-4000-8000-0000000000b1', 'turn-1'),
            'an uppercase id': changed(TURN, '5ca1ab1e-0002-4000-8000-0000000000b1',
                                       '5CA1AB1E-0002-4000-8000-0000000000B1'),
            'the id key of another log_type': changed(TURN, '{"event_id"', '{"audit_id"'),
            'a body key named like the label': changed(TURN, '"risk_score":60.0', '"resend_bundle":"x"'),
            'a body key named resend': changed(TURN, '"risk_score":60.0', '"resend":"true"'),
            'the id twice': changed(TURN, '"risk_score":60.0', ident.rstrip(',')),
            'the user twice': changed(TURN, '"risk_score":60.0', '"enduser_id":"grace.lin"'),
            'the timestamp twice': changed(TURN, '"risk_score":60.0', '"timestamp":"2026-11-17T04:41:05.273000"'),
            'no timestamp': changed(TURN, '"timestamp":"2026-11-17T04:41:05.273000",', ''),
            'NaN': changed(TURN, '"risk_score":60.0', '"risk_score":NaN'),
            'text around the object': ' ' + TURN,
            'an array': '[' + TURN + ']',
            'half an object': TURN[:-1]}
        for name, text in texts.items():
            with self.subTest(name):
                self.refused(self.eligible, (text, '1794890465.273', 'gen_ai:json', 'governance'))
        # The two readers refuse by themselves too, not only through the line that is built afterwards.
        body, keys = tool.parse_body(TURN)
        self.assertEqual(keys[:2], ['event_id', 'operation_name'])
        self.assertEqual(tool.own_id(body, keys), ('event_id', '5ca1ab1e-0002-4000-8000-0000000000b1'))
        self.assertEqual(tool.own_id(body, keys, 'error')[0], 'event_id')
        for log_type in ('audit', 'escalation', 'scoring'):
            self.refused(tool.own_id, body, keys, log_type)
        for text in (texts['NaN'], changed(TURN, '"risk_score":60.0', '"risk_score":-Infinity'), '{}x', 'x{}',
                     '', None, b'{}'):
            self.refused(tool.parse_body, text)
        self.assertEqual(tool.parse_body('{}'), ({}, []))
        # What is NOT refused: text the assistant would never write but a verbatim copy can carry.
        kept = changed(TURN, '"risk_score":60.0', '"k":1, "k":2,\n\t"risk_score" : 6.0E1')
        self.assertEqual(self.eligible((kept, '1794890465.273', 'gen_ai:json', 'governance'))['raw'], kept)

    def test_an_event_over_900000_bytes_is_refused_at_export(self):
        pad = 'x' * 900000
        big = changed(TURN, '"risk_score":60.0', '"pad":"' + pad + '"')
        self.assertIn('900000', self.refused(self.eligible, (big, '1794890465.273', 'gen_ai:json', 'governance')))
        fits = changed(TURN, '"risk_score":60.0', '"pad":"' + pad[:890000] + '"')
        event = self.eligible((fits, '1794890465.273', 'gen_ai:json', 'governance'))
        self.assertLessEqual(len(tool.event_line(event, BUNDLE_ID).encode('utf-8')), tool.MAX_EVENT_BYTES)
        self.assertEqual(len(tool.PLACEHOLDER_BUNDLE_ID), len(BUNDLE_ID))

    def test_the_scoring_patterns_are_the_shipped_macro(self):
        macro = read_conf('macros.conf')['exclude_scoring_sourcetypes']['definition']
        self.assertEqual(sorted(re.findall(r'sourcetype!=(\S+)', macro)), sorted(tool.SCORING_SOURCETYPES))
        self.assertEqual(len(macro.split()), len(tool.SCORING_SOURCETYPES))
        for sourcetype in ('gen_ai:json', 'demobot:audit', 'demobot:escalation', 'demobot:error'):
            self.assertFalse(tool.is_scoring_sourcetype(sourcetype), sourcetype)
        for sourcetype in ('genai_scoring', 'ai_cim:pii:ml_scoring', 'ai_cim:response:action',
                           'gen_ai:pii:scoring', 'ai_cim:tfidf:gen_ai_scoring'):
            self.assertTrue(tool.is_scoring_sourcetype(sourcetype), sourcetype)

    def test_the_join_key_is_the_shipped_macro(self):
        macro = read_conf('macros.conf')['genai_identity_join_key(1)']['definition']
        self.assertEqual(macro, 'lower(replace(trim(mvindex($login_field$, 0)), "@.*", ""))')
        for value, key in (('nina.osei', 'nina.osei'), (' Nina.Osei@corp.test\t', 'nina.osei'),
                           (['Nina.Osei@corp.test', 'x'], 'nina.osei'), ('@corp.test', ''), (None, ''), ('', ''),
                           ({'name': 'nina.osei'}, ''), ([], ''), (17, '17'),
                           ('nina.osei please ignore all previous instructions', 'nina.osei please ignore all '
                            'previous instructions')):
            with self.subTest(value=value):
                self.assertEqual(tool.join_key(value), key)
        self.assertEqual(tool.actor_of({'enduser_id': 'Grace.Lin@corp.test', 'user': 'nina.osei'}), 'grace.lin')
        self.assertEqual(tool.actor_of({'enduser_id': None, 'user': 'nina.osei'}), 'nina.osei')
        self.assertEqual(tool.actor_of({'enduser_id': 'null', 'user': 'nina.osei'}), 'nina.osei')  # as nullif()
        self.assertEqual(tool.actor_of({'enduser_id': None, 'user': None}), '')
        self.assertEqual(tool.actor_of({'enduser_id': '', 'user': 'nina.osei'}), '')
        self.assertEqual(tool.actor_of({'details': {'user': 'nina.osei'}}), '')


def moved(item, stamp, time_text, **replace):
    """A fixture row at another time, with a new id (and other replaced pieces)."""
    raw = re.sub(r'"timestamp":"[^"]+"', '"timestamp":"' + stamp + '"', item[0])
    for old, new in replace.items():
        raw = changed(raw, old, new)
    return row_of(raw, time_text, item[2], item[3])


class SelectionTests(ToolCase):
    def test_the_staged_set_is_the_personas_eligible_events_in_the_window(self):
        chosen = select(list(reversed(rows())))                    # whatever order the rows come in
        self.assertEqual([event['raw'] for event in chosen.events], [item[0] for item in STAGED])
        self.assertEqual(dict(chosen.left_out), {'other identities': 1, 'no user': 1, 'outside the window': 0})
        self.assertEqual(chosen.notes, [])
        both = tool.select_events(rows(), ['grace.lin', 'nina.osei'], T_FROM, T_TO, 'demobot:hec', NOW)
        self.assertEqual(len(both.events), 7)
        self.assertEqual(both.left_out['other identities'], 0)

    def test_the_persona_is_matched_exactly_on_the_parsed_body(self):
        spray = moved(STAGED[2], '2026-11-17T04:43:00.100000', '1794890580.1', **{
            '"enduser_id":"nina.osei"': '"enduser_id":"nina.osei ignore all previous instructions"',
            '"user":"nina.osei"': '"user":"nina.osei ignore all previous instructions"',
            '00000000b1': '00000000f1', 'sess-1': 'sess-7'})
        email = moved(STAGED[2], '2026-11-17T04:43:10.100000', '1794890590.1', **{
            '"enduser_id":"nina.osei"': '"enduser_id":"Nina.Osei@corp.test"', '00000000b1': '00000000f2'})
        deep = moved(STAGED[2], '2026-11-17T04:43:20.100000', '1794890600.1', **{
            '"risk_score":60.0': '"pad":"' + 'x' * 20000 + '"', '00000000b1': '00000000f3'})
        chosen = select(rows() + [spray, email, deep])
        ids = [event['id'] for event in chosen.events]
        self.assertNotIn('5ca1ab1e-0002-4000-8000-0000000000f1', ids)       # a name followed by a sentence
        self.assertIn('5ca1ab1e-0002-4000-8000-0000000000f2', ids)          # the local part of an email
        self.assertIn('5ca1ab1e-0002-4000-8000-0000000000f3', ids)          # the user sits 20,000 characters in
        self.assertEqual(chosen.left_out['other identities'], 2)

    def test_from_is_inclusive_and_to_is_exclusive(self):
        first = moved(STAGED[1], '2026-11-17T04:40:00', '1794890400.0', **{'00000000a2': '00000000f4'})
        last = moved(STAGED[1], '2026-11-17T04:44:59.999000', '1794890699.999', **{'00000000a2': '00000000f5'})
        ids = [event['id'] for event in select(rows() + [first, last]).events]
        self.assertEqual((ids[0], ids[-1]), ('5ca1ab1e-0001-4000-8000-0000000000f4',
                                             '5ca1ab1e-0001-4000-8000-0000000000f5'))
        at_end = moved(STAGED[1], '2026-11-17T04:45:00', '1794890700.0', **{'00000000a2': '00000000f6'})
        self.assertIn('--exact-window', self.refused(select, rows() + [at_end]))
        kept = select(rows() + [at_end], exact_window=True, allow_partial_session=True)
        self.assertNotIn('5ca1ab1e-0001-4000-8000-0000000000f6', [event['id'] for event in kept.events])

    def test_an_event_just_outside_the_window_stops_the_export_unless_exact_window(self):
        for stamp, text, near in (('2026-11-17T04:35:00', '1794890100.0', True),             # 300 s before
                                  ('2026-11-17T04:50:00', '1794891000.0', True),             # 300 s after
                                  ('2026-11-17T04:44:59.999600', '1794890700.0', True),      # rounds onto --to
                                  ('2026-11-17T04:34:59.900000', '1794890099.9', False),     # 300.1 s before
                                  ('2026-11-17T04:50:00.100000', '1794891000.1', False)):    # 300.1 s after
            with self.subTest(stamp):
                outside = moved(STAGED[1], stamp, text, **{'00000000a2': '00000000f7', 'sess-1': 'sess-6'})
                if near:
                    self.assertIn('300 s outside the window', self.refused(select, rows() + [outside]))
                    chosen = select(rows() + [outside], exact_window=True)
                    self.assertEqual(len(chosen.notes), 1)
                    self.assertIn('--exact-window', chosen.notes[0])
                else:
                    chosen = select(rows() + [outside])
                    self.assertEqual(chosen.notes, [])
                self.assertEqual(len(chosen.events), 6)
                self.assertEqual(chosen.left_out['outside the window'], 1)
        self.assertEqual(tool.EDGE_GUARD_SECONDS, 300)

    def test_a_shared_session_stops_the_export_unless_allow_partial_session(self):
        anonymous = moved(OTHERS[1], '2026-11-17T04:43:00.100000', '1794890580.1', **{
            'sess-8': 'sess-1', '00000000e2': '00000000f8'})          # the same session before the sign-in
        later = moved(STAGED[2], '2026-11-17T05:10:00.100000', '1794892200.1', **{
            '00000000b1': '00000000f9'})                             # the persona, 25 minutes after the window
        for name, extra, count in (('no user in the session', [anonymous], 1), ('a later turn', [later], 1),
                                   ('both', [anonymous, later], 2)):
            with self.subTest(name):
                text = self.refused(select, rows() + extra)
                self.assertIn('--allow-partial-session', text)
                self.assertTrue(text.startswith('{} event(s)'.format(count)), text)
                chosen = select(rows() + extra, allow_partial_session=True)
                self.assertEqual(len(chosen.events), 6)
                self.assertIn('{} event(s) of the selected sessions are not copied'.format(count), chosen.notes[0])
        # An event with no session id, or with another one, shares nothing.
        loose = moved(OTHERS[1], '2026-11-17T04:43:00.100000', '1794890580.1', **{
            '"session_id":"sess-8",': '', '00000000e2': '00000000fa'})
        self.assertEqual(select(rows() + [loose]).notes, [])

    def test_an_ineligible_event_of_the_persona_stops_the_export(self):
        broken = moved(STAGED[2], '2026-11-17T04:43:00.100000', '1794890580.1', **{
            '"event_id":"5ca1ab1e-0002-4000-8000-0000000000b1",': ''})          # the persona's, without an id
        self.assertIn('1794890580.1', self.refused(select, rows() + [broken]))
        foreign = moved(OTHERS[0], '2026-11-17T04:43:00.100000', '1794890580.1', **{
            '"event_id":"5ca1ab1e-0002-4000-8000-0000000000e1",': ''})          # somebody else's, without an id
        chosen = select(rows() + [foreign])
        self.assertEqual((len(chosen.events), chosen.left_out['other identities']), (6, 2))
        # A row whose text did not arrive as Splunk holds it stops the export whoever it belongs to.
        torn = dict(row_of(*OTHERS[0]), rs_sha256=sha('something else'))
        self.assertIn('arrived altered', self.refused(select, rows()[:-2] + [torn]))

    def test_one_id_twice_and_an_empty_selection_are_refused(self):
        again = moved(STAGED[2], '2026-11-17T04:43:00.100000', '1794890580.1')
        self.assertIn('twice', self.refused(select, rows() + [again]))
        self.assertIn('nothing to export', self.refused(select, [row_of(*item) for item in OTHERS]))
        self.assertIn('nothing to export', self.refused(select, []))
        self.assertIn('nina.osei', self.refused(
            tool.select_events, rows(), ['nina.osei'], T_TO, T_TO + 60, 'demobot:hec', NOW, exact_window=True,
            allow_partial_session=True))

    def test_the_golden_fixture_is_one_eligible_set(self):
        # Every text the assistant's own code produced, and every hand-written splice text, passes
        # the eligibility rules, is selected, and comes out of a bundle as the golden line.
        with io.open(GOLDEN, encoding='utf-8') as handle:
            golden = json.load(handle)
        where, texts = golden['destination'], golden['cases'] + golden['splice']
        found = [row_of(case['raw'], case['time'], case['sourcetype'], case['log_type'], host=where['host'],
                        rs_indextime=str(case['resend_orig_indextime'])) for case in texts]
        chosen = tool.select_events(found, [golden['selection']['persona']],
                                    tool.parse_when(golden['selection']['from'], '--from'),
                                    tool.parse_when(golden['selection']['to'], '--to'), where['source'], NOW)
        self.assertEqual((len(chosen.events), chosen.notes), (len(texts), []))
        bundle = bundle_of(chosen.events)
        self.assertEqual({event['sourcetype'] for event in bundle['events']},
                         {'demobot:audit', 'demobot:error', 'demobot:escalation', 'gen_ai:json'})
        lines = [tool.event_line(event, golden['resend']['bundle_id']) for event in bundle['events']]
        self.assertEqual(lines, [case['resend_line'] for case in sorted(texts, key=lambda c: float(c['time']))])
        self.assertEqual(len(tool.signin_txids(bundle['events'])), 2)

    def test_the_census_count_is_the_selected_eligible_events(self):
        census = [
            {'rs_where': 'in the window', 'rs_host': 'selected host', 'rs_who': 'selected persona',
             'rs_kind': 'eligible', 'sourcetype': 'demobot:audit', 'rs_log_type': 'audit', 'events': '2'},
            {'rs_where': 'in the window', 'rs_host': 'selected host', 'rs_who': 'selected persona',
             'rs_kind': 'eligible', 'sourcetype': 'gen_ai:json', 'rs_log_type': 'governance', 'events': '4'},
            {'rs_where': 'in the window', 'rs_host': 'other host', 'rs_who': 'no user', 'rs_kind': 'no log_type',
             'sourcetype': 'genai_scoring', 'rs_log_type': 'none', 'events': '5'},
            {'rs_where': 'before the window', 'rs_host': 'selected host', 'rs_who': 'selected persona',
             'rs_kind': 'eligible', 'sourcetype': 'gen_ai:json', 'rs_log_type': 'governance', 'events': '3'},
            {'rs_where': 'in the window', 'rs_host': 'selected host', 'rs_who': 'selected persona',
             'rs_kind': 'no id', 'sourcetype': 'gen_ai:json', 'rs_log_type': 'governance', 'events': '1'}]
        self.assertEqual(tool.census_eligible(census), len(staged_events()))
        self.assertEqual(tool.census_eligible(census[2:]), 0)
        self.assertEqual(tool.census_eligible([{'events': '7'}, {}]), 0)      # absent columns never raise
        self.assertEqual(tool.CENSUS_SELECTED, ('in the window', 'selected host', 'selected persona', 'eligible'))


class OperatorInputTests(ToolCase):
    def test_a_time_needs_an_offset_and_whole_seconds(self):
        for text in ('2026-11-16T20:40:00-08:00', '2026-11-17T04:40:00Z', '2026-11-17T04:40:00+00:00',
                     '2026-11-17T04:40Z', ' 2026-11-17T10:10:00+05:30 '):
            with self.subTest(text):
                self.assertEqual(tool.parse_when(text, '--from'), T_FROM)
        for bad in ('2026-11-17T04:40:00', '2026-11-17T04:40:00.5Z', '2026-11-17T04:40:00.500Z',
                    '2026-11-17T04:40:00.500000+00:00', '2026-11-17 04:40:00Z', '2026-11-17',
                    '1794890400', 'now', '-24h', '2026-13-17T04:40:00Z', '2026-11-17T04:40:00+0000', '', None):
            with self.subTest(bad=bad):
                self.assertTrue(self.refused(tool.parse_when, bad, '--to').startswith('--to: '))

    def test_the_window_is_ordered_past_and_at_most_seven_days(self):
        self.assertEqual(tool.check_window(T_FROM, T_TO, NOW), (T_FROM, T_TO))
        self.assertEqual(tool.check_window(T_FROM, T_FROM + 7 * 86400, T_FROM + 8 * 86400)[1], T_FROM + 7 * 86400)
        self.refused(tool.check_window, T_TO, T_FROM, NOW)
        self.refused(tool.check_window, T_FROM, T_FROM, NOW)
        self.assertIn('future', self.refused(tool.check_window, T_FROM, int(NOW) + 1, NOW))
        self.assertIn('7 days', self.refused(tool.check_window, T_FROM, T_FROM + 7 * 86400 + 1, T_FROM + 9 * 86400))

    def test_a_persona_is_a_lab_persona_from_the_lookup(self):
        known = tool.known_personas()
        self.assertEqual(len(known), 7)
        self.assertIn('nina.osei', known)
        self.assertFalse([name for name in known if '|' in name or '@' in name])   # the column is name|email
        self.assertEqual(tool.check_personas(['Nina.Osei', ' nina.osei ', 'grace.lin']), ['grace.lin', 'nina.osei'])
        for bad in (['l5-ws-01'], ['l5-ws.one'], ['nina'], ['nina.osei@corp.test'], ['nina.osei x'], [''], [], None):
            with self.subTest(bad=bad):
                self.refused(tool.check_personas, bad)
        self.assertIn('--allow-unlisted-persona', self.refused(tool.check_personas, ['some.one']))
        self.assertEqual(tool.check_personas(['some.one'], allow_unlisted=True), ['some.one'])
        self.refused(tool.check_personas, ['l5-ws.one'], allow_unlisted=True)       # never a participant account
        lookup = self.path('personas.csv')
        with io.open(lookup, 'w', encoding='utf-8') as handle:
            handle.write('identity,first\nSome.One|some.one@corp.test,Some\n')
        self.assertEqual(tool.known_personas(lookup), {'some.one'})
        self.assertEqual(tool.check_personas(['some.one'], known=tool.known_personas(lookup)), ['some.one'])
        self.refused(tool.known_personas, self.path('missing.csv'))
        with io.open(lookup, 'w', encoding='utf-8') as handle:
            handle.write('name\nsome.one\n')
        self.refused(tool.known_personas, lookup)

    def test_names_urls_and_numbers_are_plain_and_never_repeated(self):
        self.assertEqual(tool.check_names(['b-host', 'a.host', 'a.host'], '--host', tool.META_RE),
                         ['a.host', 'b-host'])
        self.assertEqual(tool.check_names(['gen_ai_log'], '--index', tool.INDEX_RE), ['gen_ai_log'])
        secret = 'hunter2" OR index=*'
        for values, pattern in (([secret], tool.META_RE), (['_internal'], tool.INDEX_RE), ([], tool.META_RE),
                                (['ok', 'two words'], tool.META_RE)):
            self.assertNotIn('hunter2', self.refused(tool.check_names, values, '--host', pattern))
        self.assertEqual(tool.split_url('https://stack.example.test', '--stack', 8089),
                         ('https', 'stack.example.test', 8089, ''))
        self.assertEqual(tool.split_url('http://127.0.0.1:18089/', '--stack', 8089), ('http', '127.0.0.1', 18089, '/'))
        self.assertEqual(tool.split_url('http://localhost', '--source', 8089)[2], 8089)
        self.assertEqual(tool.split_url('https://[::1]:8443/services/collector/event', '--hec-url', 443)[1:],
                         ('::1', 8443, '/services/collector/event'))
        for bad in ('http://stack.example.test', 'https://user:hunter2@stack.example.test', 'stack.example.test',
                    'https://stack.example.test/?token=hunter2', 'https://stack.example.test/#hunter2',
                    'ftp://127.0.0.1', 'https://stack.example.test:99999', 'hunter2', '', None,
                    'http://hunter2.example.test/services/collector/event', 'splunk://hunter2'):
            with self.subTest(bad=bad):
                self.assertNotIn('hunter2', self.refused(tool.split_url, bad, '--stack', 8089))
        self.assertEqual(tool.whole_number('180', '--settle', 0, 3600), 180)
        for bad in ('-1', '3601', '1.5', 'hunter2', '', None):
            self.assertNotIn('hunter2', self.refused(tool.whole_number, bad, '--settle', 0, 3600))
        for host, loopback in (('127.0.0.1', True), ('localhost', True), ('::1', True), ('[::1]', True),
                               ('127.9.9.9', True), ('192.0.2.10', False), ('stack.example.test', False),
                               ('localhost.example.test', False), ('', False), (None, False)):
            self.assertEqual(tool.is_loopback(host), loopback, host)


class BundleTests(ToolCase):
    def test_the_digest_ignores_order_and_changes_with_every_part(self):
        events = staged_events()
        digest = tool.digest(events)
        self.assertRegex(digest, r'^[0-9a-f]{64}$')
        self.assertEqual(tool.digest(list(reversed(events))), digest)
        self.assertEqual(tool.digest([dict(event) for event in events]), digest)
        self.assertNotEqual(tool.digest(events[:-1]), digest)
        fresh = changed(TURN, '"risk_score":60.0', '"risk_score":60.5')
        variants = {'a body': dict(events[2], raw=fresh, sha256=sha(fresh)),
                    'a time': dict(events[2], time='1794890465.274'), 'a host': dict(events[2], host='other-host'),
                    'a sourcetype': dict(events[2], sourcetype='demobot:governance'),
                    'an index': dict(events[2], index='scratch_resend'),
                    'an original index time': dict(events[2], origin_indextime=1794890468)}
        seen = {digest}
        for name, event in variants.items():
            with self.subTest(name):
                seen.add(tool.digest(events[:2] + [event] + events[3:]))
        self.assertEqual(len(seen), len(variants) + 1)
        self.refused(tool.digest, events[:2] + [dict(events[2], raw=fresh)] + events[3:])   # sha256 no longer holds

    def test_the_bundle_id_is_the_utc_date_of_the_first_event_and_the_digest(self):
        bundle = bundle_of()
        self.assertEqual(bundle['bundle_id'], 'rs-20261117-' + bundle['digest'][:12])
        self.assertTrue(tool.BUNDLE_ID_RE.fullmatch(bundle['bundle_id']))
        self.assertEqual(bundle_of(list(reversed(staged_events())))['bundle_id'], bundle['bundle_id'])
        # 23:59:59.9 UTC on the 16th is still the 16th, whatever the local time zone is.
        late = dict(staged_events()[0], time='1794873599.9')
        self.assertTrue(tool.bundle_id_of([late], 'f' * 64).startswith('rs-20261116-ffffffffffff'))

    def test_a_bundle_holds_exactly_its_format_and_counts_what_is_sensitive(self):
        bundle = bundle_of()
        self.assertEqual(sorted(bundle), sorted(tool.BUNDLE_FIELDS))
        self.assertEqual((bundle['format'], bundle['review']), ('ta-gen-ai-cim/staged-resend/1', None))
        self.assertEqual([event['raw'] for event in bundle['events']], [item[0] for item in STAGED])
        self.assertEqual(bundle['privacy'], {
            'events': 6, 'events_with_client_address': 3, 'distinct_client_addresses': 1,
            'public_client_addresses': 0, 'events_with_message_text': 2})
        counted = tool.privacy_counts(bundle['events'], is_public=lambda address: address.startswith('192.0.2.'))
        self.assertEqual(counted['public_client_addresses'], 1)
        self.assertNotIn(ADDRESS, json.dumps(counted))
        self.assertEqual(tool.signin_txids(bundle['events']), [TXID])
        self.assertEqual(tool.signin_txids(bundle['events'][1:]), [])
        odd = changed(SIGNIN, TXID, 'not a txid" OR 1=1')
        self.refused(tool.signin_txids, [dict(bundle['events'][0], raw=odd, sha256=sha(odd))])
        self.refused(tool.build_bundle, [], {}, {}, {}, {})
        self.refused(tool.build_bundle, staged_events(), {'when': object()}, {}, {}, {})   # not JSON

    def test_an_edited_bundle_is_refused(self):
        def edit(change):
            bundle = json.loads(tool.bundle_text(bundle_of()))
            change(bundle)
            return bundle

        def swap(bundle):
            bundle['events'][0], bundle['events'][1] = bundle['events'][1], bundle['events'][0]

        edits = {
            'a byte of a body': lambda b: b['events'][2].update(raw=b['events'][2]['raw'].replace('60.0', '6.0')),
            'a body and its sha256': lambda b: b['events'][2].update(
                raw=changed(TURN, '60.0', '6.0'), sha256=sha(changed(TURN, '60.0', '6.0'))),
            'a time': lambda b: b['events'][2].update(time='1794890465.274'),
            'a host': lambda b: b['events'][2].update(host='other-host'),
            'an index for one event': lambda b: b['events'][2].update(index='other_index'),
            'a recorded length': lambda b: b['events'][2].update(chars=1),
            'the digest': lambda b: b.update(digest='0' * 64),
            'the bundle id': lambda b: b.update(bundle_id='rs-20261117-000000000000'),
            'the format': lambda b: b.update(format='ta-gen-ai-cim/staged-resend/2'),
            'the order': swap,
            'an event removed': lambda b: b['events'].pop(),
            'an event twice': lambda b: b['events'].append(b['events'][-1]),
            'no events': lambda b: b.update(events=[]),
            'a key added': lambda b: b.update(note='x'),
            'a key removed': lambda b: b.pop('census'),
            'a key added to an event': lambda b: b['events'][0].update(note='x'),
            'the privacy counts': lambda b: b['privacy'].update(events_with_client_address=0),
            'the expectations as a list': lambda b: b.update(expect=[]),
            'a review stamp of another shape': lambda b: b.update(review={'approved': True})}
        for name, change in edits.items():
            with self.subTest(name):
                self.refused(tool.check_bundle, edit(change))
        self.assertEqual(tool.check_bundle(edit(lambda b: None))['digest'], bundle_of()['digest'])
        self.refused(tool.check_bundle, [])
        self.refused(tool.check_bundle, {})

    def test_an_approval_covers_the_bundle_as_it_is(self):
        bundle = bundle_of()
        self.assertFalse(tool.is_approved(bundle))
        for wrong in (None, '', bundle['digest'], bundle['digest'][:11], bundle['digest'][1:13], 'approve'):
            with self.subTest(wrong=wrong):
                self.assertIn('--approve', self.refused(tool.approve, bundle, wrong, NOW))
        stamped = tool.approve(bundle, bundle['digest'][:12], NOW)
        self.assertTrue(tool.is_approved(stamped))
        self.assertIsNone(bundle['review'])                                   # the original is not changed
        self.assertEqual(stamped['review'], {'approved': bundle['digest'], 'at': int(NOW),
                                             'content': tool.content_sha256(bundle)})
        # The digest covers the events; the stamp covers the rest as well.
        edited = json.loads(tool.bundle_text(stamped))
        edited['expect']['duo']['txids_found'] = 1
        self.assertEqual(tool.check_bundle(edited)['digest'], bundle['digest'])
        self.assertFalse(tool.is_approved(edited))
        other = json.loads(tool.bundle_text(stamped))
        other['review']['approved'] = '0' * 64
        self.assertFalse(tool.is_approved(other))

    def test_a_bundle_file_is_private_and_round_trips(self):
        bundle, path = bundle_of(), self.path('nina.bundle.json')
        tool.write_bundle(path, bundle)
        self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
        with io.open(path, 'rb') as handle:
            data = handle.read()
        self.assertEqual(data, data.decode('ascii').encode('ascii'))           # ASCII on disk
        self.assertEqual(tool.load_bundle(path), bundle)
        self.assertEqual([event['raw'] for event in tool.load_bundle(path)['events']], [item[0] for item in STAGED])
        self.assertIn('not approved', self.refused(tool.load_bundle, path, need_approval=True))
        tool.replace_private(path, tool.bundle_text(tool.approve(bundle, bundle['digest'][:12], NOW)), '--bundle')
        self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
        self.assertTrue(tool.is_approved(tool.load_bundle(path, need_approval=True)))
        self.assertEqual(os.listdir(self.folder), ['nina.bundle.json'])        # no temporary file is left
        self.assertEqual(tool.ledger_path(path), path + '.ledger.jsonl')

    def test_a_bundle_is_never_written_through_a_symlink_or_over_a_file(self):
        bundle, victim, link = bundle_of(), self.path('victim.txt'), self.path('link.json')
        with io.open(victim, 'w', encoding='utf-8') as handle:
            handle.write('KEEP')
        os.chmod(victim, 0o644)
        os.symlink(victim, link)
        os.symlink(self.path('nowhere.json'), self.path('dangling.json'))
        for name in ('link.json', 'dangling.json', 'victim.txt'):
            with self.subTest(name):
                self.refused(tool.write_bundle, self.path(name), bundle)
                self.refused(tool.check_new_path, self.path(name), '--bundle')
        with io.open(victim, encoding='utf-8') as handle:
            self.assertEqual(handle.read(), 'KEEP')
        self.assertEqual(stat.S_IMODE(os.stat(victim).st_mode), 0o644)
        self.assertTrue(os.path.islink(link))
        self.assertFalse(os.path.exists(self.path('nowhere.json')))            # nothing was created at the far end
        self.refused(tool.write_bundle, self.path('no-such-folder/b.json'), bundle)
        # A second export to the same path is refused too: nothing is overwritten.
        tool.write_bundle(self.path('b.json'), bundle)
        self.refused(tool.write_bundle, self.path('b.json'), bundle)

    def test_a_bundle_never_lies_inside_a_git_work_tree(self):
        bundle = bundle_of()
        for marker in ('folder', 'file'):                      # a checkout has a .git folder, a worktree a .git file
            tree = self.path('tree-' + marker)
            os.makedirs(os.path.join(tree, 'deep', 'er'))
            if marker == 'folder':
                os.mkdir(os.path.join(tree, '.git'))
            else:
                with io.open(os.path.join(tree, '.git'), 'w', encoding='utf-8') as handle:
                    handle.write('gitdir: elsewhere\n')
            inside = os.path.join(tree, 'deep', 'er', 'b.json')
            with self.subTest(marker):
                self.assertTrue(tool.inside_git_tree(inside))
                self.assertIn('git work tree', self.refused(tool.write_bundle, inside, bundle))
                self.assertFalse(os.path.exists(inside))
                tool.write_bundle(self.path('b-%s.json' % marker), bundle)
                shutil.copy(self.path('b-%s.json' % marker), inside)        # someone moved it in afterwards
                os.chmod(inside, 0o600)
                self.assertIn('git work tree', self.refused(tool.load_bundle, inside))
                self.assertIn('git work tree', self.refused(
                    tool.open_private_append, inside + '.ledger.jsonl', 'the ledger'))
        self.assertFalse(tool.inside_git_tree(self.path('b.json')))

    def test_a_bundle_others_can_read_or_a_symlink_to_one_is_not_loaded(self):
        bundle, path = bundle_of(), self.path('b.json')
        tool.write_bundle(path, bundle)
        for mode in (0o640, 0o604, 0o660, 0o644):
            with self.subTest(mode=oct(mode)):
                os.chmod(path, mode)
                self.assertIn('chmod 600', self.refused(tool.load_bundle, path))
                self.refused(tool.replace_private, path, 'x', '--bundle')
        os.chmod(path, 0o600)
        self.assertEqual(tool.load_bundle(path)['digest'], bundle['digest'])
        os.chmod(path, 0o400)                                   # narrower than 0600 is fine
        self.assertEqual(tool.load_bundle(path)['digest'], bundle['digest'])
        os.symlink(path, self.path('link.json'))
        self.refused(tool.load_bundle, self.path('link.json'))
        self.refused(tool.replace_private, self.path('link.json'), 'x', '--bundle')
        self.refused(tool.load_bundle, self.path('missing.json'))
        self.refused(tool.load_bundle, self.folder)             # a folder
        os.mkfifo(self.path('pipe.json'), 0o600)
        keep_open = os.open(self.path('pipe.json'), os.O_RDWR)  # so that no open of it can wait
        self.addCleanup(os.close, keep_open)
        self.assertIn('not a regular file', self.refused(tool.load_bundle, self.path('pipe.json')))
        for name, text in (('not-json.json', 'events: none'), ('other.json', '{"format": "something else"}'),
                           ('list.json', '[]')):
            with self.subTest(name):
                tool.write_new_private(self.path(name), text, '--bundle')
                self.refused(tool.load_bundle, self.path(name))

    def test_the_ledger_file_is_private_append_only_and_never_a_symlink(self):
        path = self.path('b.json.ledger.jsonl')
        with tool.open_private_append(path, 'the ledger') as handle:
            handle.write('{"n":1}\n')
        self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
        with tool.open_private_append(path, 'the ledger') as handle:
            handle.write('{"n":2}\n')                            # appended, never truncated
            handle.flush()
            handle.seek(0)
            self.assertEqual(handle.read(), '{"n":1}\n{"n":2}\n')
        victim = self.path('victim.txt')
        with io.open(victim, 'w', encoding='utf-8') as handle:
            handle.write('KEEP')
        os.chmod(victim, 0o644)
        os.symlink(victim, self.path('link.jsonl'))
        os.symlink(self.path('nowhere.jsonl'), self.path('dangling.jsonl'))
        for name in ('link.jsonl', 'dangling.jsonl', 'victim.txt'):
            with self.subTest(name):
                self.refused(tool.open_private_append, self.path(name), 'the ledger')
        with io.open(victim, encoding='utf-8') as handle:
            self.assertEqual(handle.read(), 'KEEP')
        self.assertEqual(stat.S_IMODE(os.stat(victim).st_mode), 0o644)
        self.assertFalse(os.path.exists(self.path('nowhere.jsonl')))
        self.refused(tool.open_private_append, self.folder, 'the ledger')

    def test_write_out_of_lab5_steps_writes_no_file_of_this_tool(self):
        # It follows a symlink and writes into an existing wider file (review finding secrets-002).
        with io.open(os.path.join(REPO, 'tools', 'staged_resend.py'), encoding='utf-8') as handle:
            source = handle.read()
        self.assertNotIn('write_out(', source)
        self.assertNotIn('O_TRUNC', source)                      # no file of this tool is ever truncated
        self.assertIn('os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW', source)


def p1_row(event, **change):
    """The stack's row of the presence search (P1) for one event, as splunkd
    returns it: every value a string. A change of None removes the column."""
    row = {'rs_id': event['id'], 'copies': '1', 'sha256': event['sha256'], 'time': tool.time_3f(event['time']),
           'time_text': event['time'], 'host': event['host'], 'source': event['source'],
           'sourcetype': event['sourcetype'], 'index': event['index'], 'log_type': event['log_type'],
           'resend_bundle': 'none', 'first_indexed': '1794899000', 'last_indexed': '1794899000'}
    row.update(change)
    return dict((key, value) for key, value in row.items() if value is not None)


class DecisionTests(ToolCase):
    def setUp(self):
        super(DecisionTests, self).setUp()
        self.events = staged_events()
        self.turn = self.events[2]

    def verdict(self, event=None, **change):
        event = event or self.turn
        return tool.decide(event, p1_row(event, **change), BUNDLE_ID)

    def test_the_five_rows_of_the_table(self):
        self.assertEqual(tool.decide(self.turn, None, BUNDLE_ID), ('send', ()))
        self.assertEqual(self.verdict(), ('live', ()))
        self.assertEqual(self.verdict(resend_bundle=BUNDLE_ID), ('this-bundle', ()))
        self.assertEqual(self.verdict(resend_bundle='rs-20261101-aaaaaaaaaaaa'), ('other-bundle', ()))
        self.assertEqual(self.verdict(sha256=sha('another body')), ('conflict', ('sha256',)))
        self.assertEqual(self.verdict(copies='2'), ('duplicate', ()))
        self.assertEqual(tool.SKIP_VERDICTS, ('live', 'this-bundle', 'other-bundle'))
        self.assertEqual(tool.STOP_VERDICTS, ('conflict', 'duplicate'))

    def test_one_copy_that_differs_in_anything_is_a_conflict(self):
        for name, value in (('sha256', sha('x')), ('host', 'other-host'), ('source', 'http:demobot'),
                            ('sourcetype', 'demobot:audit'), ('index', 'main'), ('log_type', 'none'),
                            ('log_type', 'audit'), ('time', '1794890465.274')):
            with self.subTest(name=name, value=value):
                self.assertEqual(self.verdict(**{name: value}), ('conflict', (name,)))
                self.assertEqual(self.verdict(resend_bundle=BUNDLE_ID, **{name: value}), ('conflict', (name,)))
        both = self.verdict(host='other-host', time='1794890465.000')
        self.assertEqual(both, ('conflict', ('host', 'time')))

    def test_another_sourcetype_on_a_single_sourcetype_stack_is_a_conflict_not_a_skip(self):
        # A stack whose HEC destination wrote every record as gen_ai:json holds the sign-in under
        # that sourcetype: same id, same text, same time. It is NOT the copy this bundle would make.
        signin = self.events[0]
        self.assertEqual(signin['sourcetype'], 'demobot:audit')
        self.assertEqual(self.verdict(signin, sourcetype='gen_ai:json'), ('conflict', ('sourcetype',)))

    def test_the_time_is_compared_to_the_millisecond_never_as_text(self):
        # tostring(_time) prints one instant as ...273 on a HEC event and ...273000 on a collect-written one.
        self.assertEqual(self.verdict(time='1794890465.273', time_text='1794890465.273000'), ('live', ()))
        self.assertEqual(self.verdict(time_text=None), ('live', ()))            # informative only
        whole = self.events[3]                                                 # stored as "1794890501.0"
        self.assertEqual(whole['time'], '1794890501.0')
        self.assertEqual(self.verdict(whole, time='1794890501.000'), ('live', ()))
        self.assertEqual(self.verdict(whole, time='1794890501.001'), ('conflict', ('time',)))
        self.assertEqual(self.verdict(dict(self.turn, time='1794890465.273000')), ('live', ()))
        for bad in ('', 'yesterday', '1794890465,273', None, ['1794890465.273', '1794890465.274']):
            with self.subTest(bad=bad):
                self.assertEqual(self.verdict(time=bad), ('conflict', ('time',)))
        self.assertEqual((tool.time_3f('1794890501.0'), tool.time_3f('1794890465.5'), tool.time_3f('1794890501')),
                         ('1794890501.000', '1794890465.500', '1794890501.000'))

    def test_a_malformed_answer_never_reads_as_send_or_as_skip(self):
        # Values arrive as a string or a list of strings, and a column may be missing altogether.
        self.assertEqual(self.verdict(host=[HOST], sha256=[self.turn['sha256']], copies=['1']), ('live', ()))
        for name in ('sha256', 'host', 'source', 'sourcetype', 'index', 'log_type', 'time', 'resend_bundle'):
            with self.subTest(missing=name):
                self.assertEqual(self.verdict(**{name: None}), ('conflict', (name,)))
                self.assertEqual(self.verdict(**{name: ''}), ('conflict', (name,)))
        self.assertEqual(self.verdict(host=[HOST, 'other-host']), ('conflict', ('host',)))
        self.assertEqual(self.verdict(resend_bundle=[BUNDLE_ID, 'none']), ('conflict', ('resend_bundle',)))
        for copies in (None, '', '0', '-1', 'many', '1.5', ['1', '1']):
            with self.subTest(copies=copies):
                self.assertEqual(self.verdict(copies=copies), ('conflict', ('copies',)))
        self.assertEqual(self.verdict(copies='3', sha256=sha('x'), host=None), ('duplicate', ()))
        self.assertEqual(tool.decide(self.turn, {}, BUNDLE_ID), ('conflict', ('copies',)))

    def test_the_plan_for_a_set_of_events(self):
        events = self.events
        found = [p1_row(events[0]), p1_row(events[1], resend_bundle=BUNDLE_ID),
                 p1_row(events[2], resend_bundle='rs-20261101-aaaaaaaaaaaa'), p1_row(events[3], copies='2'),
                 p1_row(events[4], sourcetype='gen_ai:json')]            # nothing for the last event
        decisions = tool.plan(list(reversed(events)), found, BUNDLE_ID)
        self.assertEqual(list(decisions), [event['id'] for event in events])             # in time order
        self.assertEqual([decision.verdict for decision in decisions.values()],
                         ['live', 'this-bundle', 'other-bundle', 'duplicate', 'conflict', 'send'])
        self.assertEqual(dict(tool.plan_counts(decisions)), {
            'send': 1, 'live': 1, 'this-bundle': 1, 'other-bundle': 1, 'conflict': 1, 'duplicate': 1})
        self.assertEqual([d.verdict for d in tool.plan(events, [], BUNDLE_ID).values()], ['send'] * 6)
        # A row for an id nobody asked about (another event that only quotes one) changes nothing.
        stranger = dict(p1_row(events[0]), rs_id='5ca1ab1e-0009-4000-8000-000000000000')
        self.assertEqual([d.verdict for d in tool.plan(events, [stranger], BUNDLE_ID).values()], ['send'] * 6)
        # One id in two rows is two copies, whatever each row says.
        twice = tool.plan(events[:1], [p1_row(events[0]), p1_row(events[0])], BUNDLE_ID)
        self.assertEqual(twice[events[0]['id']].verdict, 'duplicate')
        for bad in ({'copies': '1'}, dict(p1_row(events[0]), rs_id=['a', 'b']), dict(p1_row(events[0]), rs_id='x')):
            with self.subTest(bad=sorted(bad)):
                self.refused(tool.plan, events, [bad], BUNDLE_ID)


class HecAnswerTests(ToolCase):
    ANSWERS = (
        # (HTTP status, body, class)
        (200, '{"text":"Success","code":0}', 'accepted'),
        (200, '{"text":"Success","code":0,"ackId":7}', 'accepted'),
        (200, '{"text":"Queue is approaching capacity","code":24}', 'accepted'),
        (200, '{"text":"ACK is approaching capacity","code":25}', 'accepted'),
        (503, '{"text":"Server is busy","code":9}', 'not sent'),
        (503, '{"text":"Server is shutting down","code":23}', 'not sent'),
        (429, '{"text":"Queue is at capacity","code":26}', 'not sent'),
        (429, '{"text":"ACK channel is at capacity","code":27}', 'not sent'),
        (401, '{"text":"Token is required","code":2}', 'refused'),
        (401, '{"text":"Invalid authorization","code":3}', 'refused'),
        (403, '{"text":"Token disabled","code":1}', 'refused'),
        (403, '{"text":"Invalid token","code":4}', 'refused'),
        (403, '<html>Forbidden</html>', 'refused'),
        (401, '', 'refused'),
        (400, '{"text":"No data","code":5}', 'refused'),
        (400, '{"text":"Data channel is missing","code":10}', 'refused'),
        (400, '{"text":"Invalid data channel","code":11}', 'refused'),
        (400, '{"text":"ACK is disabled","code":14}', 'refused'),
        (400, '{"text":"Query string authorization is not enabled","code":16}', 'refused'),
        (400, '{"text":"Invalid token","code":21}', 'refused'),
        (400, '{"text":"Token disabled","code":22}', 'refused'),
        (400, '{"text":"Invalid data format","code":6,"invalid-event-number":0}', 'refused'),
        (400, '{"text":"Incorrect index","code":7,"invalid-event-number":0}', 'refused'),
        (400, '{"text":"Event field is required","code":12,"invalid-event-number":0}', 'refused'),
        (400, '{"text":"Event field cannot be blank","code":13,"invalid-event-number":0}', 'refused'),
        (400, '{"text":"Error in handling indexed fields","code":15,"invalid-event-number":0}', 'refused'),
        (413, '{"text":"Content-Length too large"}', 'too large'),
        (413, '<html>Request Entity Too Large</html>', 'too large'),
        (413, '', 'too large'),
    )
    # Everything the table does not name. Each of these may have been indexed, or is not HEC's answer.
    UNKNOWN = (
        (503, '<html><body>upstream timed out</body></html>'),     # a gateway's 503, not HEC's
        (503, ''), (503, '{"text":"busy"}'), (503, '{"text":"Server is busy","code":"9"}'),
        (503, '{"text":"HEC is unhealthy, queues are full","code":18}'),
        (503, '{"text":"Queue is at capacity","code":26}'),         # the code of a 429 on a 503
        (429, ''), (429, '<html>Too Many Requests</html>'), (429, '{"text":"Server is busy","code":9}'),
        (500, '{"text":"Internal server error","code":8}'), (500, ''), (502, '<html>Bad Gateway</html>'),
        (504, '<html>Gateway Timeout</html>'), (599, ''),
        (400, '{"text":"Invalid data format","code":6,"invalid-event-number":3}'),   # events 0 to 2 were indexed
        (400, '{"text":"Incorrect index","code":7,"invalid-event-number":1}'),
        (400, '{"text":"Invalid data format","code":6}'),           # no event number: it cannot be told
        (400, '{"text":"Invalid data format","code":6,"invalid-event-number":false}'),
        (400, '{"text":"Invalid data format","code":6,"invalid-event-number":"0"}'),
        (400, '{"text":"something new","code":99}'), (400, '<html>Bad Request</html>'), (400, ''),
        (200, ''), (200, '<html>OK</html>'), (200, '{"text":"HEC is healthy","code":17}'),
        (200, '{"text":"Success"}'), (200, '{"text":"Success","code":"0"}'), (200, '{"code":true}'),
        (200, '[{"code":0}]'), (200, '{"text":"Success","code":0} trailing'), (200, None),
        (201, '{"text":"Success","code":0}'), (204, ''), (301, ''), (302, '<html>moved</html>'), (307, ''),
        (404, '{"text":"The requested URL was not found on this server.","code":404}'), (404, ''), (408, ''),
        (405, ''), (409, ''), (0, ''), (None, '{"text":"Success","code":0}'),
    )

    def test_every_answer_the_table_names(self):
        for status, body, state in self.ANSWERS:
            with self.subTest(status=status, body=body):
                outcome = tool.classify_answer(status, body)
                self.assertEqual((outcome.state, outcome.http), (state, status))
                self.assertEqual(tool.classify_answer(status, body.encode('utf-8')).state, state)   # bytes too
        self.assertEqual(tool.RETRY_WAITS, (5, 15, 45))
        self.assertEqual(tool.NOT_SENT_PAIRS, ((503, 9), (503, 23), (429, 26), (429, 27)))
        self.assertEqual(tool.ACCEPTED_CODES, (0, 24, 25))

    def test_every_other_answer_is_unknown(self):
        for status, body in self.UNKNOWN:
            with self.subTest(status=status, body=body):
                self.assertEqual(tool.classify_answer(status, body).state, 'unknown')
        # No status and no code outside the table can be "not sent" or "accepted": try them all.
        named = {(status, code) for status, code in tool.NOT_SENT_PAIRS}
        for status in (200, 201, 400, 429, 500, 502, 503, 504):
            for code in list(range(0, 30)) + [None]:
                body = '{}' if code is None else json.dumps({'text': 'x', 'code': code})
                state = tool.classify_answer(status, body).state
                self.assertEqual(state == 'not sent', (status, code) in named, (status, code))
                self.assertEqual(state == 'accepted', status == 200 and code in (0, 24, 25), (status, code))

    def test_what_is_shown_of_an_answer_comes_from_the_tools_own_table(self):
        echoed = 'Authorization: Splunk 00000000-fixture-token ' + PROMPT
        for status, body in ((403, json.dumps({'text': echoed, 'code': 4})), (500, echoed),
                             (400, json.dumps({'text': echoed, 'code': 6, 'invalid-event-number': 2})),
                             (200, json.dumps({'text': echoed, 'code': 0}))):
            detail = tool.classify_answer(status, body).detail
            self.out.append(detail)
            self.assertNotIn('fixture-token', detail)
        self.assertEqual(tool.classify_answer(403, '{"text":"anything","code":4}').detail,
                         'HTTP 403, HEC code 4 (Invalid token)')
        self.assertEqual(tool.classify_answer(400, '{"code":6,"invalid-event-number":2}').detail,
                         'HTTP 400, HEC code 6 (Invalid data format), at event 2')
        self.assertEqual(tool.classify_answer(503, '<html>').detail, 'HTTP 503, no HEC code')
        self.assertEqual(tool.classify_answer(400, '{"code":99}').detail, 'HTTP 400, HEC code 99 (not in the table)')
        self.assertEqual(sorted(tool.HEC_TEXT), list(range(28)))

    def test_a_failure_before_the_request_is_not_sent_and_one_after_it_is_unknown(self):
        before, after = tool.not_sent('ConnectionRefusedError'), tool.unknown('TimeoutError')
        self.assertEqual((before.state, before.http, before.code), ('not sent', None, None))
        self.assertEqual((after.state, after.http, after.code), ('unknown', None, None))
        self.assertIn('ConnectionRefusedError', before.detail)
        self.assertIn('TimeoutError', after.detail)
        self.assertEqual({tool.ACCEPTED, tool.NOT_SENT, tool.REFUSED, tool.TOO_LARGE, tool.UNKNOWN},
                         {'accepted', 'not sent', 'refused', 'too large', 'unknown'})


class CommandLineTests(ToolCase):
    SEND = ['send', '--bundle', 'b.json', '--stack', 'https://stack.example.test',
            '--hec-url', 'https://http-inputs-stack.example.test/services/collector/event']
    EXPORT = ['export', '--source', 'https://127.0.0.1:8089', '--host', HOST, '--persona', 'nina.osei',
              '--from', '2026-11-17T04:40:00Z', '--to', '2026-11-17T04:45:00Z', '--bundle', 'b.json']

    def run_tool(self, argv, **inject):
        """(exit code, everything printed): echo, and argparse's own stdout and stderr."""
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            code = tool.main(argv, env={}, clock=lambda: NOW, sleep=lambda seconds: None, echo=self.echo, **inject)
        self.out.append(stream.getvalue())
        return code, '\n'.join(self.out)

    def subparsers(self):
        actions = [a for a in tool.build_parser()._actions if getattr(a, 'choices', None)]
        return actions[0].choices

    def test_the_four_commands_and_the_exit_codes(self):
        self.assertEqual(sorted(self.subparsers()), ['export', 'review', 'send', 'verify'])
        for parser in [tool.build_parser()] + list(self.subparsers().values()):
            self.assertFalse(parser.allow_abbrev)                      # --hec-tok is not --hec-token... or --hec-file
            self.assertIsInstance(parser, tool.Parser)
        self.assertEqual((tool.EXIT_OK, tool.EXIT_FAILED, tool.EXIT_REFUSED, tool.EXIT_UNKNOWN), (0, 1, 2, 3))
        for argv in (['--help'], ['export', '--help'], ['review', '--help'], ['send', '--help'], ['verify', '--help']):
            with self.subTest(argv=argv):
                code, text = self.run_tool(argv)
                self.assertEqual(code, 0)
                self.assertIn('usage: staged_resend.py', text)
        code, text = self.run_tool([])
        self.assertEqual(code, 2)
        code, text = self.run_tool(['plan'])
        self.assertEqual(code, 2)
        self.assertIn('export, review, send, verify', text)

    def test_every_command_is_built_and_a_bug_never_prints_its_own_text(self):
        with io.open(os.path.join(REPO, 'tools', 'staged_resend.py'), encoding='utf-8') as handle:
            source = handle.read()
        for word in ('NotBuilt', 'NOT BUILT', 'STUB', 'not built yet'):
            self.assertNotIn(word, source, 'a build-stage stub is left in the tool')
        # An exception that is not a refusal is a bug. Its own text can quote a header or an event, so the
        # run ends with the kind of error and a line number: no text, no traceback. After `send` that is
        # "delivery unknown", because a request may have left.
        secret = 'fixture-secret-in-an-exception'

        def bug(opts, env, clock, sleep, echo):
            raise ValueError('Invalid header value b' + repr('Splunk ' + secret))

        verify = ['verify', '--bundle', 'b.json', '--stack', 'https://stack.example.test']
        for argv, expected in ((self.EXPORT, 1), (['review', '--bundle', 'b.json'], 1), (self.SEND, 3), (verify, 1)):
            with self.subTest(command=argv[0]):
                self.out = []
                real = getattr(tool, 'cmd_' + argv[0])
                setattr(tool, 'cmd_' + argv[0], bug)
                try:
                    code, text = self.run_tool(argv)
                finally:
                    setattr(tool, 'cmd_' + argv[0], real)
                self.assertEqual(code, expected, text)
                self.assertRegex(text, r'FAILED: an unexpected error in this tool \(ValueError at line [1-9]\d* of')
                self.assertIn('run `verify`, then `send` again' if argv[0] == 'send' else 'Nothing was sent.', text)
                self.assertNotIn(secret, text)
                self.assertNotIn('Traceback', text)
                self.assertNotIn('Invalid header', text)

    def test_no_option_takes_a_secret_or_lets_argparse_repeat_a_value(self):
        seen = set()
        for name, parser in self.subparsers().items():
            for action in parser._actions:
                for option in action.option_strings:
                    seen.add(option)
                    with self.subTest(command=name, option=option):
                        self.assertIsNone(action.type)                 # argparse would repeat a bad value
                        self.assertIsNone(action.choices)
                        self.assertNotRegex(option, r'token|password|passwd|secret|skey|credential|session-key')
                        self.assertNotRegex(str(action.default), r'(?i)token|password|secret')
        self.assertLessEqual({'--bundle', '--stack', '--hec-file', '--hec-url', '--username', '--source-username',
                              '--ca-file', '--no-verify-splunkd', '--no-verify-source', '--approve'}, seen)
        for name in (tool.ENV_HEC_TOKEN, tool.ENV_SOURCE_PASSWORD, tool.ENV_SOURCE_TOKEN, tool.ENV_STACK_PASSWORD,
                     tool.ENV_STACK_TOKEN):
            self.assertRegex(name, r'^[A-Z][A-Z_]+_(TOKEN|PASSWORD)$')
        self.assertEqual((tool.ENV_HEC_TOKEN, tool.ENV_STACK_PASSWORD), ('STAGED_RESEND_HEC_TOKEN',
                                                                        'SPLUNK_ADMIN_PASSWORD'))

    def test_a_value_after_a_mistaken_option_is_never_repeated(self):
        secret = 'hunter2-fixture-secret'
        for extra in (['--hec-token', secret], ['--password=' + secret], [secret], ['--hec-tok', secret],
                      ['--settle=' + secret, '--token', secret]):
            with self.subTest(extra=extra[0][:12]):
                self.out = []
                code, text = self.run_tool(self.SEND + extra)
                self.assertEqual(code, 2)
                self.assertNotIn(secret, text)
                self.assertNotIn('Traceback', text)
        code, text = self.run_tool(self.SEND + ['--hec-token', secret])
        self.assertIn('unrecognized arguments: --hec-token (values are not repeated', text)
        code, text = self.run_tool([secret])
        self.assertEqual(code, 2)
        self.assertNotIn(secret, text)

    def test_the_options_and_their_defaults(self):
        parse = tool.build_parser().parse_args
        export = parse(self.EXPORT + ['--host', 'second-host', '--persona', 'grace.lin'])
        self.assertEqual((export.host, export.persona), ([HOST, 'second-host'], ['nina.osei', 'grace.lin']))
        self.assertEqual((export.start, export.end), ('2026-11-17T04:40:00Z', '2026-11-17T04:45:00Z'))
        self.assertEqual((export.index, export.event_source, export.source_username),
                         ('gen_ai_log', 'demobot:hec', 'admin'))
        self.assertFalse(export.exact_window or export.allow_partial_session or export.allow_unlisted_persona
                         or export.list_only or export.no_verify_source)
        self.assertIsNone(export.check_logs)
        self.assertIsNone(export.ca_file)
        send = parse(self.SEND)
        self.assertEqual((send.username, send.settle, send.wait_finding), ('admin', '180', '0'))
        self.assertFalse(send.dry_run or send.allow_rule_off or send.without_duo or send.no_canary
                         or send.resend_unconfirmed or send.no_verify_splunkd)
        self.assertIsNone(send.hec_file)
        self.assertIsNone(send.retention_days)
        verify = parse(['verify', '--bundle', 'b.json', '--stack', 'https://stack.example.test'])
        self.assertEqual((verify.username, verify.wait, verify.ca_file, verify.no_verify_splunkd),
                         ('admin', '0', None, False))
        self.assertEqual(parse(['review', '--bundle', 'b.json']).approve, None)
        refusals = (self.SEND[:5],                                             # neither --hec-file nor --hec-url
                    self.SEND + ['--hec-file', 'stack.json'],                   # both
                    self.EXPORT + ['--no-verify-source', '--ca-file', 'ca.pem'],
                    self.EXPORT[:-4],                                           # no --to
                    ['review'], ['verify', '--bundle', 'b.json'],
                    ['send', '--bundle', 'b.json', '--hec-file', 'stack.json'])
        for argv in refusals:
            with self.subTest(argv=argv[:1] + argv[-2:]):
                self.out = []
                self.assertEqual(self.run_tool(argv)[0], 2)

    def test_a_search_text_gets_its_leading_search_only_when_it_needs_one(self):
        self.assertEqual(tool.as_search('((`a` x=1) OR y=2) | stats count'), 'search ((`a` x=1) OR y=2) | stats count')
        self.assertEqual(tool.as_search('index=_internal | head 1'), 'search index=_internal | head 1')
        self.assertEqual(tool.as_search('| tstats count where index=x'), '| tstats count where index=x')
        self.assertEqual(tool.as_search('\n  | multisearch [search a] [search b]\n'),
                         '| multisearch [search a] [search b]')
        # A text saved with its own leading "search" keeps it: "search search" would match nothing.
        for saved in ('search index=x', 'SEARCH index=x', 'search\tindex=x | stats count'):
            self.assertEqual(tool.as_search(saved), saved)
        self.assertEqual(tool.as_search('searchable=1'), 'search searchable=1')
        for empty in ('', '   ', None):
            self.refused(tool.as_search, empty)

    def test_review_lists_ids_and_counts_and_never_a_body(self):
        bundle, path = bundle_of(), self.path('b.json')
        tool.write_bundle(path, bundle)
        code, text = self.run_tool(['review', '--bundle', path])
        self.assertEqual(code, 0)
        for event in bundle['events']:
            self.assertIn(event['id'], text)
            self.assertIn(event['sha256'][:12], text)
        for shown in (bundle['bundle_id'], 'index gen_ai_log', '2026-11-17T04:40:19.556Z', '2026-11-17T04:42:00.010Z',
                      'audit identity_signin_success', 'governance chat blocked verified', 'error -',
                      '2 of 6 event(s) carry message text, 3 carry a client address (1 distinct, 0 public)',
                      '1 application sign-in(s), 1 with a Duo transaction id',
                      'Digest {} - NOT approved'.format(bundle['digest'][:12]),
                      '--approve {}'.format(bundle['digest'][:12])):
            self.assertIn(shown, text)
        self.assertNotIn(bundle['digest'][:13], text)                 # 12 digits, as --approve takes them

    def test_review_approves_by_the_digest_it_printed(self):
        bundle, path = bundle_of(), self.path('b.json')
        tool.write_bundle(path, bundle)
        with io.open(path, 'rb') as handle:
            before = handle.read()
        os.link(path, self.path('kept.json'))                       # a second name for the same file
        for wrong in ('000000000000', bundle['digest'], 'yes'):
            with self.subTest(wrong=wrong[:12]):
                code, text = self.run_tool(['review', '--bundle', path, '--approve', wrong])
                self.assertEqual(code, 2)
                self.assertIn('REFUSED: --approve', text)
                with io.open(path, 'rb') as handle:
                    self.assertEqual(handle.read(), before)                    # nothing was written
        self.out = []
        code, text = self.run_tool(['review', '--bundle', path, '--approve', bundle['digest'][:12]])
        self.assertEqual(code, 0)
        self.assertIn('Approved: digest {}'.format(bundle['digest'][:12]), text)
        approved = tool.load_bundle(path, need_approval=True)
        self.assertEqual(approved['review']['at'], int(NOW))
        with io.open(self.path('kept.json'), 'rb') as handle:      # the old file was replaced, not written into
            self.assertEqual(handle.read(), before)
        os.unlink(self.path('kept.json'))
        self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
        self.assertEqual(os.listdir(self.folder), ['b.json'])
        self.out = []
        code, text = self.run_tool(['review', '--bundle', path])
        self.assertIn('Digest {} - approved as it is'.format(bundle['digest'][:12]), text)
        self.assertNotIn('--approve', text)
        # An edit after the approval: the file still loads, and send's load refuses it.
        approved['census']['legacy_indexed_body_keys'] = 7
        tool.replace_private(path, tool.bundle_text(approved), '--bundle')
        self.assertIn('not approved as it now is', self.refused(tool.load_bundle, path, need_approval=True))
        self.out = []
        code, text = self.run_tool(['review', '--bundle', path])
        self.assertIn('NOT approved', text)

    def test_review_refuses_a_file_that_is_not_a_private_bundle(self):
        bundle, path = bundle_of(), self.path('b.json')
        tool.write_bundle(path, bundle)
        os.chmod(path, 0o644)
        code, text = self.run_tool(['review', '--bundle', path])
        self.assertEqual(code, 2)
        self.assertIn('REFUSED: --bundle is readable or writable by others (mode 644)', text)
        self.assertNotIn(bundle['events'][0]['id'], text)                      # nothing was listed
        os.chmod(path, 0o600)
        os.symlink(path, self.path('link.json'))
        for argv in (['review', '--bundle', self.path('link.json')], ['review', '--bundle', self.path('none.json')],
                     ['review', '--bundle', self.path('link.json'), '--approve', bundle['digest'][:12]]):
            self.out = []
            code, text = self.run_tool(argv)
            self.assertEqual(code, 2)
            self.assertIn('REFUSED: --bundle', text)
        self.assertTrue(os.path.islink(self.path('link.json')))
        self.assertFalse(tool.is_approved(tool.load_bundle(path)))


class ShippedConfTests(unittest.TestCase):
    """What the tool takes for granted about the TA it sits in. A missing
    stanza FAILS here; it is never a skip, because a skip reads as a pass."""

    def test_nothing_the_ta_ships_reads_the_label(self):
        word = re.compile(r'(?<![A-Za-z0-9_])(%s)(?![A-Za-z0-9_])' % '|'.join(tool.LABEL_FIELDS))
        self.assertEqual(tool.LABEL_FIELDS, ('resend', 'resend_bundle', 'resend_orig_indextime'))
        hits, files = [], 0
        for folder in ('default', 'bin', 'lookups'):
            for base, folders, names in os.walk(os.path.join(REPO, folder)):
                folders[:] = [name for name in folders if name != '__pycache__']
                for name in names:
                    files += 1
                    with io.open(os.path.join(base, name), encoding='utf-8', errors='replace') as handle:
                        for number, line in enumerate(handle, 1):
                            if word.search(line):
                                hits.append('{}:{}'.format(os.path.relpath(os.path.join(base, name), REPO), number))
        self.assertGreater(files, 50)
        self.assertEqual(hits, [], 'a shipped object reads a label field: a copy would no longer be inert')
        for stanza in read_conf('fields.conf'):
            self.assertNotIn(stanza, tool.LABEL_FIELDS, 'the label fields are searched with :: and tstats, '
                                                        'never declared')
        self.assertIsNone(word.search('resends resend_run resending'))          # whole words only
        self.assertTrue(word.search('index=gen_ai_log resend::true'))

    def test_the_joined_rule_the_tool_names_ships(self):
        searches = read_conf('savedsearches.conf')
        self.assertIn(tool.JOINED_RULE, searches,
                      'the joined rule is not in default/savedsearches.conf: this suite needs the commit that '
                      'adds it (LR-06) underneath it')
        text = searches[tool.JOINED_RULE]['search']
        self.assertIn('chain_id', text)
        self.assertIn(':takeover:', text)
        self.assertFalse(text.lstrip().startswith('|'))        # as_search() gives this one its leading "search"
        self.assertTrue(tool.as_search(text).startswith('search (('))

    def test_the_joined_rules_slot_and_its_finding_are_what_verify_times_and_looks_for(self):
        rule = read_conf('savedsearches.conf')[tool.JOINED_RULE]
        # The slot contract: every 5 minutes, one period of INDEX time that ends 2 minutes back, never skipped.
        self.assertEqual((rule['cron_schedule'], rule['dispatch.earliest_time'], rule['dispatch.latest_time'],
                          rule['realtime_schedule'], rule['enableSched']), ('*/5 * * * *', '-7m@m', '-2m@m', '0', '1'))
        for word in ('_index_earliest=', '_index_latest=', 'info_min_time', 'is_new'):
            self.assertIn(word, rule['search'])
        self.assertNotIn('dispatch.index_earliest', rule)
        self.assertNotIn('allow_data_time_skew', rule)
        self.assertEqual(tool.rule_slot(dict(rule, is_scheduled=rule['enableSched'])), (tool.Slot(5, 2), None))
        self.assertEqual(tool.judging_tick(1794900000, tool.Slot(5, 2)), 1794900300)
        # The scheduler may start a run up to allow_skew late; the grace `verify` allows covers that and the run.
        self.assertEqual(rule['allow_skew'], '5m')
        self.assertGreaterEqual(tool.FINDING_GRACE_SECONDS, 300 + 120)
        # One finding and one risk event per chain: the chain id names one sign-in of one user, a second
        # judgement of it is suppressed, and both alert actions are on.
        self.assertIn('chain_id=user . ":takeover:" . tostring(floor(chain_signin))', rule['search'])
        self.assertEqual((rule['alert.suppress'], rule['alert.suppress.fields'], rule['alert.suppress.period']),
                         ('1', 'user,chain_id', '86400s'))
        self.assertEqual((rule['action.notable'], rule['action.risk'], rule['action.correlationsearch.enabled']),
                         ('1', '1', '1'))
        self.assertEqual(rule['counttype'], 'number of events')
        self.assertTrue(tool.CHAIN_RE.fullmatch('nina.osei:takeover:1794890419'))
        # The rule ships disabled: `send` refuses a stack on which nobody enabled it (R5).
        self.assertEqual(rule['disabled'], '1')

    def test_a_missing_stanza_fails_these_tests_and_nothing_here_can_skip(self):
        with io.open(os.path.abspath(__file__).replace('.pyc', '.py'), encoding='utf-8') as handle:
            source = handle.read()
        body = source.split('class ShippedConfTests(')[1].split('\nclass ')[0]
        skip, decorate = 'skip' + 'Test(', '@unittest' + '.'          # put together here: this test names no skip
        for word in (skip, 'skip' + 'If', 'skip' + 'Unless', 'Skip' + 'Test'):
            self.assertNotIn(word, body, 'a shipped-conf test must fail, never skip')
        # The only skips of the whole suite: a Python or an openssl that cannot serve a throwaway TLS certificate,
        # and the runbook's byte comparison where Python-Markdown is missing (as in the repo's DocsTests).
        skips = [line.strip() for line in source.split('\n') if skip in line]
        self.assertEqual(len(skips), 7, skips)
        for line in skips:
            self.assertTrue('openssl' in line or 'TLS' in line or 'Python-Markdown' in line, line)
        self.assertNotIn(decorate + 'skip', source)
        self.assertNotIn(decorate + 'expectedFailure', source)
        # Without the rule's stanza the readers raise, which unittest reports as an error.
        searches = dict(read_conf('savedsearches.conf'))
        del searches[tool.JOINED_RULE]
        with self.assertRaises(KeyError):
            searches[tool.JOINED_RULE]['search']
        with self.assertRaises(AssertionError):
            self.assertIn(tool.JOINED_RULE, searches)

    def test_the_macros_and_the_lookup_the_tool_mirrors_ship(self):
        macros = read_conf('macros.conf')
        for name in ('exclude_scoring_sourcetypes', 'genai_identity_join_key(1)', 'genai_identity_ai_events',
                     'genai_identity_verified_turn', 'genai_duo_auth_events', 'genai_identity_duo_class'):
            self.assertIn(name, macros)
        self.assertEqual(macros['genai_identity_ai_events']['definition'],
                         'index={} `exclude_scoring_sourcetypes`'.format(tool.DEFAULT_INDEX))
        with io.open(tool.PERSONA_LOOKUP, encoding='utf-8') as handle:
            header = handle.readline().strip().split(',')
            first = handle.readline().split(',')[0]
        self.assertEqual(header[0], 'identity')
        self.assertRegex(first, r'^[a-z]+\.[a-z]+\|[a-z.]+@')         # name|email: the name is before the pipe
        version = read_conf('app.conf')['launcher']['version']
        self.assertGreaterEqual(tuple(int(part) for part in version.split('.')[:3]), tool.TA_FLOOR)

    def test_the_new_scripts_are_executable_and_stdlib_only(self):
        for name in ('tools/staged_resend.py', 'tools/tests/test_staged_resend.py',
                     'tools/tests/fake_resend_stack.py'):
            mode = stat.S_IMODE(os.stat(os.path.join(REPO, name)).st_mode)
            self.assertEqual(mode, 0o755, name)
        with io.open(os.path.join(REPO, 'tools', 'staged_resend.py'), encoding='utf-8') as handle:
            source = handle.read()
        lines = re.findall(r'^(?:import ([a-z0-9_]+)[a-z0-9_.]*(?: as [a-z0-9_]+)?(?:  # .*)?|'
                           r'from ([a-z0-9_]+)[a-z0-9_.]* import .*)$', source, re.M)
        imported = {first or second for first, second in lines} - {'genai_es_seed', 'lab5_steps'}
        self.assertGreater(len(imported), 10)
        self.assertLessEqual({'argparse', 'hashlib', 'json', 'urllib'}, imported)
        for name in sorted(imported):                                 # the standard library and nothing else
            origin = str(importlib.util.find_spec(name).origin)
            self.assertFalse('site-packages' in origin or origin.startswith(REPO), '{}: {}'.format(name, origin))
        self.assertTrue(source.isascii(), 'keep tools/staged_resend.py ASCII: build any other character with chr()')


NEW_FILES = ('tools/staged_resend.py', 'tools/tests/fake_resend_stack.py', 'tools/tests/test_staged_resend.py',
             'tools/tests/fixtures/staged_resend_gen.py', 'tools/tests/fixtures/staged_resend_golden.json',
             'tools/tests/staged_resend_scratch_e2e.py', 'tools/staged-resend-runbook.md',
             'tools/staged-resend-runbook.html')              # the eight files of this change, and no other


def render_runbook_html():
    """tools/staged-resend-runbook.html as it must read: the .md through
    Python-Markdown (tables, fenced_code, toc) inside the fixed head of
    tools/lab5-identity-runbook.html, titled with the .md's first line.
    Regenerate after any edit to the .md with
    `python3 -B tools/tests/test_staged_resend.py --write-runbook-html`
    (needs Python-Markdown; review finding spec-05)."""
    import html as html_lib
    import markdown
    with io.open(os.path.join(REPO, 'tools', 'staged-resend-runbook.md'), encoding='utf-8') as handle:
        md = handle.read()
    with io.open(os.path.join(REPO, 'tools', 'lab5-identity-runbook.html'), encoding='utf-8') as handle:
        ref = handle.read()
    head = ref[:ref.index('<main>') + len('<main>')]
    title = md.splitlines()[0]
    assert title.startswith('# '), title
    start, end = head.index('<title>') + len('<title>'), head.index('</title>')
    head = head[:start] + html_lib.escape(title[2:], quote=False) + head[end:]
    body = markdown.markdown(md, extensions=['tables', 'fenced_code', 'toc'])
    return head + '\n' + body.strip() + '\n</main>\n</body>\n</html>\n'


class NewFilesTests(unittest.TestCase):
    """The eight files this change adds exist, and none of them carries a
    value from a real system: the live data behind this tool holds a real
    client address and real user names, and none of it belongs in a file."""

    def read(self, name):
        with io.open(os.path.join(REPO, name), encoding='utf-8') as handle:
            return handle.read()

    def test_all_eight_files_are_there_and_the_scripts_are_executable(self):
        for name in NEW_FILES:
            path = os.path.join(REPO, name)
            self.assertTrue(os.path.isfile(path), name + ' is missing')
            self.assertFalse(os.path.islink(path), name)
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o755 if name.endswith('.py') else 0o644, '{}: mode {:o}'.format(name, mode))
            self.assertGreater(len(self.read(name)), 1000, name)

    def test_the_runbook_reads_the_stack_password_per_stack_and_unsets_it_before_the_next(self):
        """Nothing in the tool ties SPLUNK_ADMIN_PASSWORD to the --stack host,
        so the per-stack steps start by reading it and end by unsetting it,
        in both runbook files (review finding secrets-02)."""
        for name, amp in (('tools/staged-resend-runbook.md', '&&'), ('tools/staged-resend-runbook.html', '&amp;&amp;')):
            text = self.read(name)
            steps = text[text.index('Per stack, in this order:'):text.index('Afterwards: unset')]
            self.assertIn('read -rs SPLUNK_ADMIN_PASSWORD {} export SPLUNK_ADMIN_PASSWORD'.format(amp), steps, name)
            self.assertLess(steps.index('read -rs SPLUNK_ADMIN_PASSWORD'), steps.index('show_postdeploy.py'), name)
            self.assertGreater(steps.rindex('unset SPLUNK_ADMIN_PASSWORD SPLUNK_ADMIN_TOKEN'),
                               steps.rindex('Identity Activity'), name)
            self.assertIn('It must hold the password of', text, name)

    def runbooks(self):
        """Both runbook files as plain text: the .html with its tags dropped."""
        for name in ('tools/staged-resend-runbook.md', 'tools/staged-resend-runbook.html'):
            text = self.read(name)
            if name.endswith('.html'):
                text = re.sub(r'</t[dh]>', ' |', text.replace('<tr>', '| '))
                text = re.sub(r'<[^>]+>', '', text).replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
            yield name, re.sub(r'\s+', ' ', text.replace('`', ''))

    def test_the_runbook_says_a_rerun_after_exit_3_sends_nothing_new_until_a_copy_shows(self):
        """make_plan holds the never-attempted events too while held ids exist and
        no copy of this bundle is on the stack (review finding spec-01)."""
        source = self.read('tools/staged_resend.py')
        self.assertIn('if held and not proven and not no_canary:\n        send, later = [], send', source)
        for name, text in self.runbooks():
            step = text[text.index('If ids are still missing, run send again'):text.index('Only when an unconfirmed id')]
            self.assertNotIn('sends what was never attempted', step, name)
            for needle in ('sends nothing new', 'WAIT', 'HOLD', 'unless --no-canary', '--settle', 'exit 3'):
                self.assertIn(needle, step, name)

    def test_the_runbook_verify_table_says_what_v1_polls_for_when_v6_stops_and_lists_not_raised_yet(self):
        """Review finding spec-02: V1 polls only for ids the ledger sent, V6 stops at
        tick + FINDING_GRACE_SECONDS or --wait, and NOT RAISED YET has a row."""
        self.assertEqual(tool.FINDING_GRACE_SECONDS, 420)
        for name, text in self.runbooks():
            start = text.index('| Step | What must hold | Wait |')
            table = text[start:text.index('For the 16 Nov set', start)]
            v1 = table[table.index('| V1 |'):table.index('| V2 |')]
            v6 = table[table.index('| V6 |'):]
            self.assertIn('for ids the ledger says were sent; any other missing id fails at once', v1, name)
            self.assertIn('tick + 420 s', v6, name)
            self.assertIn('whichever comes first', v6, name)
            self.assertIn('none when V1 failed', v6, name)
            failures = text[text.index('When a check after sending fails'):]
            self.assertIn('V6: NOT RAISED YET (exit 1)', failures, name)

    def test_the_runbook_test_gate_names_a_floor_the_suite_meets_and_both_interpreters(self):
        """Review finding spec-03: the gate's N is a floor the real suite meets."""
        count = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]).countTestCases()
        for name, text in self.runbooks():
            floor = re.search(r'Ran N tests, with N at least (\d+), and then OK\. Under the system python3 nothing '
                              r'may be skipped\. Under Splunk\'s python3\.13 exactly one test is', text)
            self.assertTrue(floor, name)
            self.assertLessEqual(int(floor.group(1)), count, name)
            self.assertGreaterEqual(int(floor.group(1)), 200, name)
            self.assertNotIn('around 70', text, name)

    def test_every_number_in_a_runbook_synopsis_is_that_options_default(self):
        """Review finding spec-04: `[--wait 900]` read as a default of 900 while
        the built default is 0. A number in a synopsis must be the default."""
        actions = [a for a in tool.build_parser()._actions if getattr(a, 'choices', None)]
        commands = actions[0].choices
        for name, text in self.runbooks():
            checked = 0
            for command, parser in commands.items():
                start = text.index('staged_resend.py {} --bundle PATH'.format(command)
                                   if command != 'export' else 'staged_resend.py export --source URL')
                synopsis = text[start:text.index('[--', start) + 600].split(' staged_resend.py ')[0]
                defaults = {o: a.default for a in parser._actions for o in a.option_strings}
                for option, value in re.findall(r'\[(--[a-z-]+) (\d+)\]', synopsis):
                    self.assertEqual(str(defaults[option]), value, '{} {} {}'.format(name, command, option))
                    checked += 1
            self.assertGreaterEqual(checked, 1, name)                     # send's [--settle 180] at least
            verify = text[text.index('staged_resend.py verify --bundle'):]
            self.assertIn('[--wait SECONDS]', verify[:200], name)
            self.assertIn('--wait defaults to 0', verify, name)
        self.assertEqual(commands['verify'].get_default('wait'), '0')

    def test_the_runbook_html_is_the_rendered_md(self):
        """Review finding spec-05. Without Python-Markdown the comparison is
        SKIPPED, which is not a pass: run it once under a Python that has it."""
        md, page = self.read('tools/staged-resend-runbook.md'), self.read('tools/staged-resend-runbook.html')
        self.assertEqual(page.count('<h2 '), len(re.findall(r'^## ', md, flags=re.M)))
        try:
            import markdown  # noqa: F401
        except ImportError:
            self.skipTest('Python-Markdown is not installed here: the byte comparison did not run')
        self.assertEqual(render_runbook_html(), page, 'regenerate: python3 -B tools/tests/test_staged_resend.py '
                                                       '--write-runbook-html')

    def test_every_option_in_the_runbook_is_one_the_tools_parse_and_every_tool_option_is_in_it(self):
        """Review finding spec-05: an option the runbook names is the tool's,
        or show_postdeploy.py's, or the golden generator's --check; and each
        option of staged_resend.py is documented."""
        parser = tool.build_parser()
        commands = [a for a in parser._actions if getattr(a, 'choices', None)][0].choices
        ours = {o for p in [parser] + list(commands.values()) for a in p._actions for o in a.option_strings}
        ours -= {'-h', '--help'}
        theirs = set(re.findall(r"add_argument\(\s*'(--[a-z0-9-]+)'", self.read('tools/show_postdeploy.py')))
        self.assertLessEqual({'--out', '--duo', '--duo-poll-slot', '--lab5'}, theirs)
        for name, text in self.runbooks():
            text = text[text.index('Staged events re-send runbook', text.index('Staged events re-send runbook') + 1)
                        if name.endswith('.html') else 0:]                # the page, not the CSS custom properties
            named = set(re.findall(r'(?<![\w-])--[a-z][a-z0-9-]*', text))
            self.assertEqual(sorted(named - ours - theirs - {'--check'}), [], name)
            self.assertEqual(sorted(ours - named), [], name)

    def test_the_runbook_says_r4_passes_gen_ai_log_as_not_checked_when_the_macro_is_unreadable(self):
        """Review finding spec-07: where configs/conf-macros cannot be read,
        R4 accepts gen_ai_log on the shipped definition and refuses any other index."""
        source = self.read('tools/staged_resend.py')
        self.assertIn("if reads is None and index != DEFAULT_INDEX:", source)
        self.assertIn("'NOT CHECKED: which index {} reads ({}); the shipped definition reads {}", source)
        for name, text in self.runbooks():
            note = text[text.index('R4, a macro the stack does not serve.'):text.index('R4, retention.')]
            for needle in ('conf-macros', 'NOT CHECKED: which index', 'accepts a gen_ai_log bundle on the shipped '
                           'definition', 'refuses a bundle for any other index'):
                self.assertIn(needle, note, name)
            self.assertIn('marked NOT CHECKED', text[text.index('| R4 index and age |'):], name)

    def test_the_start_to_finish_steps_fall_back_to_hec_url_when_out_writes_no_file(self):
        """Review finding spec-08: on a real stack --out may write nothing and
        print `No HEC token returned`; the checklist then uses --hec-url."""
        for name, text in self.runbooks():
            steps = text[text.index('Per stack, in this order:'):text.index('Afterwards: unset')]
            gap = steps.index('No HEC token returned')
            self.assertLess(steps.index('--out <stack>.json'), gap, name)
            self.assertLess(gap, steps.index('--hec-file <stack>.json --dry-run'), name)
            send = steps[steps.index('--hec-file <stack>.json --dry-run'):steps.index('The same without --dry-run')]
            for needle in ('read -rs STAGED_RESEND_HEC_TOKEN', '--hec-url https://http-inputs-<stack>.splunkcloud.com'
                           '/services/collector/event'):
                self.assertIn(needle, send, name)
            self.assertIn('unset SPLUNK_ADMIN_PASSWORD SPLUNK_ADMIN_TOKEN STAGED_RESEND_HEC_TOKEN', steps, name)

    def test_every_test_that_runs_the_tool_ends_with_the_secrets_and_privacy_checks(self):
        module = sys.modules[self.__class__.__module__]
        classes = [value for value in vars(module).values()
                   if isinstance(value, type) and issubclass(value, unittest.TestCase)]
        self.assertGreater(len(classes), 25)
        # Everything but the two classes that only read files collects its output in ToolCase ...
        self.assertEqual(sorted(cls.__name__ for cls in classes if not issubclass(cls, ToolCase)),
                         ['NewFilesTests', 'ShippedConfTests'])
        # ... and nothing replaces the end-of-test checks: the three cases define them, each on top of the last.
        self.assertEqual(sorted(cls.__name__ for cls in classes if 'tearDown' in vars(cls)),
                         ['SourceCase', 'StackCase', 'ToolCase'])
        with io.open(os.path.join(REPO, 'tools', 'tests', 'test_staged_resend.py'), encoding='utf-8') as handle:
            source = handle.read()
        for name, base in (('SourceCase', 'ToolCase'), ('StackCase', 'SourceCase')):
            body = source.split('class {}({}):'.format(name, base))[1].split('\nclass ')[0]
            self.assertIn('super({}, self).tearDown()'.format(name), body)
        base = source.split('class ToolCase(unittest.TestCase):')[1].split('\nclass ')[0]
        self.assertIn('for needle in NEVER_SHOWN:', base)
        for needle in (ADDRESS, TXID, PROMPT):                      # what a body holds and no output may
            self.assertIn(needle, NEVER_SHOWN)

    def test_every_address_name_and_host_in_them_is_invented(self):
        quad = re.compile(r'(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])')
        mail = re.compile(r'[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})')
        host = re.compile(r'[A-Za-z0-9.-]+\.(?:splunkcloud\.com|duosecurity\.com|duo\.com|okta\.com)')
        seen = collections.Counter()
        for name in NEW_FILES:
            text = self.read(name)
            for address in quad.findall(text):
                seen['addresses'] += 1
                self.assertRegex(address, r'^(127\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)',
                                 '{}: {} is neither loopback nor an RFC 5737 address'.format(name, address))
            for domain in mail.findall(text):
                seen['mail'] += 1
                self.assertRegex(domain.lower(), r'(^|\.)(corp\.test|example\.test|example\.com)$',
                                 '{}: a mail domain that is not a reserved one'.format(name))
            for found in host.findall(text):
                seen['hosts'] += 1
                self.assertRegex(found, r'^(http-inputs[-.])?(room\d+|stack|example)\.splunkcloud\.com$',
                                 '{}: {} is not a made-up stack name'.format(name, found))
            self.assertNotIn('BEGIN ' + 'PRIVATE KEY', text, name)
            token = r'xox[abp]-[0-9A-Za-z-]{10,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}'
            self.assertIsNone(re.search(token, text), name)
        self.assertGreater(seen['addresses'], 50)                     # the scan did read something
        self.assertGreater(seen['mail'], 3)
        # The fixture values themselves are the reserved kind.
        self.assertTrue(ADDRESS.startswith('192.0.2.'))
        self.assertFalse(tool.is_public_address(ADDRESS))


BURST = 1794890100                                         # 04:35:00Z: six Duo denials, 20 s apart, before the sign-in
WINDOW = ['--from', '2026-11-17T04:40:00Z', '--to', '2026-11-17T04:45:00Z']
WRITERS = re.compile(r'\|\s*(collect|outputlookup|outputcsv|delete|sendalert|sendemail|tscollect|mcollect|'
                     r'meventcollect|script|run|dump|rest|map)\b')


ENDPOINTS = re.compile(r'GET /services/server/info|GET /services/apps/local/TA-gen_ai_cim|'
                       r'GET /servicesNS/nobody/TA-gen_ai_cim/saved/searches/[A-Za-z0-9%.-]+|'
                       r'POST /servicesNS/nobody/TA-gen_ai_cim/search/jobs')      # all a run may ask a Splunk


class SourceCase(ToolCase):
    """A fake facilitator's Splunk that holds the staged fixture (six events
    of nina.osei, two of others, her six Duo denials and the Duo record of her
    sign-in), and the tool run against it. At the end of every test: no
    credential and no body value was printed, every search was one of the
    pinned read-only texts, and no request carried anything in its URL."""

    def setUp(self):
        super(SourceCase, self).setUp()
        self.fake = fake_stack.FakeSplunk(guid=GUID, clock=lambda: NOW)
        for raw, time_text, sourcetype, log_type in STAGED + OTHERS:
            self.fake.add(raw, time_text, sourcetype, log_type, host=HOST)
        for step in range(6):
            self.fake.add_duo('nina.osei', BURST + 20 * step)
        self.fake.add_duo('nina.osei', 1794890417, action='success', txid=TXID)
        self.url = self.fake.start()
        self.addCleanup(self.fake.stop)
        self.env = {tool.ENV_SOURCE_PASSWORD: self.fake.password}
        self.naps = []
        self.bundle = self.path('nina.bundle.json')

    def tearDown(self):
        text = '\n'.join(self.out)
        for secret in (self.fake.password, self.fake.token):
            self.assertNotIn(secret, text, 'a credential was printed')
        for search in self.fake.searches:
            self.assertTrue(search['search'].startswith('search ') or search['search'].startswith('|'))
            self.assertIsNone(WRITERS.search(search['search']), 'a search that writes')
            self.assertIsNotNone(search['kind'], 'a search text the fake does not know')
            self.no_body_value_in(search)
        for request in self.fake.requests:
            self.assertEqual(request['query'], 'output_mode=json')
            self.assertTrue(ENDPOINTS.fullmatch(request['method'] + ' ' + request['path']), request['path'])
        super(SourceCase, self).tearDown()

    def no_body_value_in(self, search):
        """A search text carries ids, names the operator gave and nothing of
        a body. The one exception is the Duo transaction id of a sign-in, in
        the text that looks it up (D1), whose answer does not hold it."""
        for needle in NEVER_SHOWN:
            if not (needle == TXID and search['kind'] == 'duo_half'):
                self.assertNotIn(needle, search['search'], 'a body value was sent in a search text')

    def restart(self):
        """The end-of-test checks on what ran so far, then a fresh fake and a fresh folder."""
        self.tearDown()
        self.fake.stop()
        self.setUp()

    def export(self, *extra, **options):
        """(exit code, everything printed) of one export run. bundle=False leaves --bundle out."""
        argv = ['export', '--source', options.get('source', self.url), '--host', options.get('host', HOST),
                '--persona', options.get('persona', 'nina.osei')] + list(options.get('window', WINDOW))
        if options.get('bundle', True):
            argv += ['--bundle', self.bundle]
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            code = tool.main(argv + list(extra), env=options.get('env', self.env),
                             clock=lambda: options.get('now', NOW), sleep=self.naps.append, echo=self.echo)
        self.out.append(stream.getvalue())
        return code, '\n'.join(self.out)

    def refusal(self, *extra, **options):
        """The text of an export that must be refused: exit 2, a REFUSED line,
        no traceback, and no bundle file."""
        code, text = self.export(*extra, **options)
        self.assertEqual(code, 2, text)
        self.assertIn('REFUSED: ', text)
        self.assertNotIn('Traceback', text)
        self.assertFalse(os.path.lexists(self.bundle), 'a refused export left a bundle behind')
        return text

    def kinds(self):
        return [search['kind'] for search in self.fake.searches]

    def written(self):
        return tool.load_bundle(self.bundle)


class ExportTests(SourceCase):
    def test_export_reads_the_source_once_into_a_private_bundle(self):
        code, text = self.export()
        self.assertEqual(code, 0, text)
        self.assertEqual(stat.S_IMODE(os.lstat(self.bundle).st_mode), 0o600)
        self.assertEqual(os.listdir(self.folder), ['nina.bundle.json'])
        bundle = self.written()
        self.assertFalse(tool.is_approved(bundle))
        # The six events of the persona, each text exactly as the source holds it, and nobody else's.
        self.assertEqual([event['raw'] for event in bundle['events']], [item[0] for item in STAGED])
        self.assertEqual([event['time'] for event in bundle['events']], [item[1] for item in STAGED])
        self.assertEqual({event['host'] for event in bundle['events']}, {HOST})
        self.assertEqual(bundle['origin'], {'guid': GUID, 'splunk_version': '10.4.3', 'ta_version': '1.9.0',
                                            'read_at': int(NOW)})
        self.assertEqual(bundle['selection'], {
            'index': 'gen_ai_log', 'source': 'demobot:hec', 'hosts': [HOST], 'personas': ['nina.osei'],
            'from': T_FROM, 'to': T_TO, 'exact_window': False, 'allow_partial_session': False,
            'allow_unlisted_persona': False, 'notes': []})
        census = bundle['census']
        self.assertEqual((census['eligible'], census['legacy_indexed_body_keys'], census['log_check'],
                          census['pad_seconds']), (6, 0, None, 3600))
        self.assertEqual(census['left_out'], {'other identities': 1, 'no user': 1, 'outside the window': 0})
        self.assertIn({'where': 'in the window', 'host': 'selected host', 'who': 'selected persona',
                       'kind': 'eligible', 'sourcetype': 'demobot:audit', 'log_type': 'audit', 'events': 2},
                      census['rows'])
        # spath prints a JSON null as the text "null" and S1 drops it with nullif(): the anonymous event is
        # "no user" for Splunk, as it is for this tool, and grace.lin's is the one other identity.
        for who in ('no user', 'other identity'):
            self.assertIn({'where': 'in the window', 'host': 'selected host', 'who': who, 'kind': 'eligible',
                           'sourcetype': 'gen_ai:json', 'log_type': 'governance', 'events': 1}, census['rows'])
        expect = bundle['expect']
        self.assertEqual(expect['identity'], [{'identity_key': 'nina.osei', 'events': 6, 'copies': 6,
                                               'identity_events': 3, 'ai_turns': 2, 'ai_blocked': 1,
                                               'app_signins': 1}])
        self.assertEqual(expect['duo'], {'signins': 1, 'txids': 1, 'txids_found': 1, 'found_once': 1, 'context': [
            {'identity_user': 'nina.osei', 'action': 'failure', 'duo_class': 'denied', 'duo_events': 6, 'txids': 6},
            {'identity_user': 'nina.osei', 'action': 'success', 'duo_class': 'success', 'duo_events': 1,
             'txids': 1}]})
        self.assertEqual(expect['chains'], ['nina.osei:takeover:1794890419'])
        self.assertEqual(expect['rule'], {'name': tool.JOINED_RULE, 'found': True, 'rows': 1,
                                          'sha256': sha(self.fake.saved[tool.JOINED_RULE]['search'])})
        for shown in ('Export from --source\n  certificate: plain http to a loopback address, no certificate\n'
                      '  Splunk 10.4.3, TA-gen_ai_cim 1.9.0', 'persona(s) nina.osei',
                      'window 2026-11-17T04:40:00Z to 2026-11-17T04:45:00Z (the end is exclusive; 300 s)',
                      'Selected 6 event(s) with 6 distinct id(s), 1794890419.556 to 1794890520.01',
                      'each of the 8 event text(s) it returned equal the ones computed here',
                      'Not copied: 1 of other identities and 1 with no user in the window, 0 of the persona',
                      'finds each of the 6 id(s) once, identical',
                      'nina.osei: events 6, copies 6, identity_events 3, ai_turns 2, ai_blocked 1, app_signins 1',
                      'Duo: 1 of 1 sign-in transaction(s) found, 1 exactly once',
                      '1 chain(s) for this set\'s sign-ins: nina.osei:takeover:1794890419',
                      'Wrote bundle {} (mode 0600): 6 event(s), digest {}, NOT approved'.format(
                          bundle['bundle_id'], bundle['digest'][:12])):
            self.assertIn(shown, text)
        for event in bundle['events']:
            self.assertIn(event['id'], text)
            self.assertIn(event['sha256'][:12], text)
        self.assertNotIn('grace.lin', text)                           # nobody else is named

    def test_the_searches_of_one_export_and_their_time_ranges(self):
        self.assertEqual(self.export()[0], 0)
        first, last = 1794890419, 1794890520                          # the set's first and last whole second
        self.assertEqual([(search['kind'], search['earliest'], search['latest']) for search in self.fake.searches], [
            ('eventcount', '0', 'now'),
            ('census', str(T_FROM - 3600), str(T_TO + 3600)),         # the window padded by an hour
            ('legacy', str(T_FROM), str(T_TO)),
            ('export', str(T_FROM - 3600), str(T_TO + 3600)),         # the guards need what lies outside
            ('present', '0', '+1d'), ('expect', '0', '+1d'),
            ('duo_half', str(first - 6000), str(last + 6001)), ('duo_context', str(first - 6000), str(last + 6001)),
            ('rule', '0', 'now')])                                    # every index-time slot at once
        self.assertEqual(self.kinds().count('export'), 1)             # event text is read once
        gets = [request['path'] for request in self.fake.requests if request['method'] == 'GET']
        self.assertEqual(gets[:2], ['/services/server/info', '/services/apps/local/TA-gen_ai_cim'])
        self.assertEqual(len(gets), 3)
        for request in self.fake.requests:
            self.assertEqual(request['form'].get('exec_mode', 'oneshot'), 'oneshot')
            self.assertNotIn('nina.osei', request['path'])

    def test_the_same_selection_gives_the_same_bundle_whenever_it_is_read(self):
        self.assertEqual(self.export()[0], 0)
        first = self.written()
        os.rename(self.bundle, self.path('first.json'))
        self.fake.events.reverse()                                    # another order in the store ...
        code, text = self.export(now=NOW + 5000)                      # ... and another moment
        self.assertEqual(code, 0, text)
        second = self.written()
        self.assertEqual((second['bundle_id'], second['digest']), (first['bundle_id'], first['digest']))
        self.assertEqual(second['events'], first['events'])
        self.assertEqual(second['origin']['read_at'], int(NOW) + 5000)
        self.assertRegex(first['bundle_id'], r'^rs-20261117-[0-9a-f]{12}$')
        self.assertEqual(first['bundle_id'][-12:], first['digest'][:12])
        os.unlink(self.bundle)
        self.out = []
        code, text = self.export('--list-only', bundle=False)
        self.assertIn('gives bundle {} (digest {})'.format(first['bundle_id'], first['digest'][:12]), text)

    def test_list_only_prints_the_selection_and_writes_nothing(self):
        for extra, with_path in ((['--list-only'], False), (['--list-only'], True)):
            self.out, self.fake.searches[:] = [], []
            code, text = self.export(*extra, bundle=with_path)
            self.assertEqual(code, 0, text)
            self.assertEqual(os.listdir(self.folder), [])
            self.assertEqual(self.kinds(), ['eventcount', 'census', 'legacy', 'export'])
            for shown in ('Census: what Splunk counted', 'Selected 6 event(s)', '5ca1ab1e-0002-4000-8000-0000000000b2',
                          '--list-only: nothing was written'):
                self.assertIn(shown, text)
            self.assertNotIn('Wrote bundle', text)

    def test_the_bundle_path_is_checked_before_the_source_is_asked_anything(self):
        victim = self.path('victim.txt')
        with io.open(victim, 'w') as handle:
            handle.write('kept')
        os.chmod(victim, 0o644)
        os.makedirs(self.path('repo', '.git'))
        cases = {'it exists': victim, 'a symlink to a file': self.path('link.json'),
                 'a dangling symlink': self.path('dangling.json'),
                 'inside a git work tree': self.path('repo', 'b.json'),
                 'a folder that does not exist': self.path('none', 'b.json')}
        os.symlink(victim, cases['a symlink to a file'])
        os.symlink(self.path('nowhere'), cases['a dangling symlink'])
        for name, path in cases.items():
            with self.subTest(name):
                self.out, self.bundle = [], path
                code, text = self.export()
                self.assertEqual(code, 2)
                self.assertIn('REFUSED: --bundle', text)
                self.assertEqual(self.fake.requests, [], 'the source was contacted before the path was checked')
        with io.open(victim) as handle:
            self.assertEqual(handle.read(), 'kept')
        self.assertEqual(stat.S_IMODE(os.lstat(victim).st_mode), 0o644)
        self.assertFalse(os.path.exists(self.path('nowhere')))
        self.assertEqual(os.listdir(self.path('repo')), ['.git'])
        self.bundle = self.path('nina.bundle.json')
        self.out = []
        self.assertIn('--bundle: name the file to create', self.refusal(bundle=False))
        self.assertEqual(self.fake.requests, [])

    def test_what_the_operator_named_is_checked_before_the_source_is_asked_anything(self):
        day = ['--from', '2026-11-17T04:40:00Z']
        cases = (
            ({'window': day + ['--to', '2026-11-17T04:45:00']}, 'explicit offset'),              # no offset
            ({'window': day + ['--to', '2026-11-17T04:45:00.5Z']}, 'whole seconds'),             # a fraction
            ({'window': day + ['--to', '2026-11-17T04:40:00Z']}, '--from must be before --to'),
            ({'window': ['--from', '2026-11-09T04:40:00Z', '--to', '2026-11-17T04:40:00Z']}, 'longer than 7 days'),
            ({'window': WINDOW, 'now': T_TO - 1}, '--to is in the future'),
            ({'persona': 'nina.osie'}, 'not in lookups/pseudoco_identity_personas.csv'),
            ({'persona': 'l5-room1-01'}, 'never a participant'),
            ({'host': 'stage host'}, '--host: expected a plain name'),
            ({'env': {}}, 'neither is set'),
            ({'env': {tool.ENV_SOURCE_PASSWORD: 'a', tool.ENV_SOURCE_TOKEN: 'b'}}, 'both are set'),
            ({'env': {tool.ENV_SOURCE_TOKEN: 'fixture-token\n'}}, 'holds a line break'),
            ({'source': 'http://source.example.test:8089'}, 'must be https'),
            ({'source': self.url + '/services'}, 'with no path'))
        for options, said in cases:
            with self.subTest(said=said):
                self.out = []
                self.assertIn(said, self.refusal(**options))
                self.assertEqual(self.fake.requests, [])
        for extra, said in ((['--index', 'Gen AI'], '--index: expected a plain name'),
                            (['--event-source', 'demobot hec'], '--event-source: expected a plain name'),
                            (['--source-username', 'ad min'], 'not a plain account name'),
                            (['--check-logs', self.path('no-such-folder')], '--check-logs: expected the folder'),
                            (['--ca-file', self.path('no-such-ca.pem')], '--ca-file cannot be read')):
            with self.subTest(said=said):
                self.out = []
                self.assertIn(said, self.refusal(*extra, source='https://127.0.0.1:1'))
        self.assertEqual(self.fake.requests, [])

    def test_the_written_file_is_read_back_the_way_send_will_read_it(self):
        read = tool.load_bundle
        self.addCleanup(setattr, tool, 'load_bundle', read)
        seen = []

        def load(path, need_approval=False):
            seen.append((path, stat.S_IMODE(os.lstat(path).st_mode)))
            return read(path, need_approval)

        tool.load_bundle = load
        self.assertEqual(self.export()[0], 0)
        self.assertEqual(seen, [(self.bundle, 0o600)])                # R1 ran on the file itself
        os.unlink(self.bundle)
        tool.load_bundle = lambda path, need_approval=False: dict(read(path), bundle_id='rs-20261117-000000000000')
        self.out = []
        code, text = self.export()
        self.assertEqual(code, 2)
        self.assertIn('REFUSED: --bundle does not read back as it was written', text)
        self.assertNotIn('Wrote bundle', text)

    def test_the_window_guards_and_their_overrides(self):
        # Nothing of the persona in the window: the census is printed first, so the run shows where her events lie.
        text = self.refusal(window=['--from', '2026-11-17T04:50:00Z', '--to', '2026-11-17T04:55:00Z'])
        self.assertIn('REFUSED: no event of nina.osei in the window', text)
        self.assertIn('before the window', text)
        # The window ends 40 s early: two of her events lie within 300 s outside it.
        cut = ['--from', '2026-11-17T04:40:00Z', '--to', '2026-11-17T04:41:50Z']
        self.out = []
        text = self.refusal(window=cut)
        self.assertIn('2 event(s) of the persona lie within 300 s outside the window', text)
        self.assertIn('--exact-window', text)
        # --exact-window alone still stops: the two share a session with the selected turns.
        self.out = []
        self.assertIn('--allow-partial-session', self.refusal('--exact-window', window=cut))
        self.out = []
        code, text = self.export('--exact-window', '--allow-partial-session', window=cut)
        self.assertEqual(code, 0, text)
        chosen = self.written()['selection']
        self.assertEqual((chosen['exact_window'], chosen['allow_partial_session'], chosen['to']),
                         (True, True, 1794890510))
        self.assertEqual(chosen['notes'], [
            '--exact-window: 2 event(s) of the persona within 300 s outside the window are not copied',
            '--allow-partial-session: 2 event(s) of the selected sessions are not copied'])
        self.assertEqual(len(self.written()['events']), 4)
        self.assertEqual(self.written()['census']['left_out']['outside the window'], 2)
        self.assertIn('overrides used: --exact-window, --allow-partial-session', text)
        self.assertIn('--exact-window: 2 event(s)', text)

    def test_splunk_and_the_tool_agree_on_a_null_enduser_id_and_on_a_user_deep_in_an_event(self):
        # A JSON null enduser_id with the persona as user: S1's nullif() and actor_of both read user.
        nulled = changed(changed(changed(ERROR, '0000000000b3', '0000000000b4'), '04:41:50.5', '04:41:52.5'),
                         '"enduser_id":"nina.osei"', '"enduser_id":null')
        # enduser_id 6,000 characters into the event: eval spath() on 10.4.3 reads it however deep it sits.
        deep = changed(changed(changed(ERROR, '0000000000b3', '0000000000b5'), '04:41:50.5', '04:41:54.5'),
                       '"session_id":"sess-1",', '"session_id":"sess-1","pad":"' + 'x' * 6000 + '",')
        self.assertGreater(deep.index('"enduser_id"'), 6000)
        self.fake.add(nulled, '1794890512.5', 'demobot:error', 'error', host=HOST)
        self.fake.add(deep, '1794890514.5', 'demobot:error', 'error', host=HOST)
        code, text = self.export()
        self.assertEqual(code, 0, text)
        self.assertEqual(self.written()['census']['eligible'], 8)
        self.assertEqual(len(self.written()['events']), 8)

    def test_a_rule_saved_with_its_own_leading_search_is_dispatched_once_prefixed(self):
        rule = self.fake.saved[tool.JOINED_RULE]
        rule['search'] = 'search ' + rule['search'].strip()          # savedsearches.conf and REST allow it
        code, text = self.export()
        self.assertEqual(code, 0, text)
        self.assertEqual(self.written()['expect']['chains'], ['nina.osei:takeover:1794890419'])
        self.assertEqual(self.written()['expect']['rule']['rows'], 1)
        self.assertFalse(any(search['search'].startswith('search search') for search in self.fake.searches))

    def test_what_stops_an_export_after_the_source_was_read(self):
        def legacy(fake):
            fake.events[2]['fields']['session_id'] = 'sess-1'         # the forwarder of before 31 July indexed it

        def deep_user(fake):
            fake.spath_cutoff = 100                                   # an odd stack: the census misreads the user

        def altered(fake):
            fake.alter_raw = lambda raw: raw.replace('"actor":"user"', '"actor": "user"')

        def another_time(fake):
            fake.events[1].update(time_text='1794890452.147', time=fake.events[1]['time'] + 1)

        def twice_in_the_export(fake):
            fake.add(STARTED, '1794890451.147', 'demobot:audit', 'audit', host=HOST)

        def file_monitor_copy(fake):
            fake.add(TURN, '1794890465.273', 'gen_ai:json', host='stage-mac', source='/logs/ai_governance.json')

        def another_source(fake):
            fake.add(changed(STARTED, '00a2', '00a9'), '1794890451.147', 'demobot:audit', 'audit', host=HOST,
                     source='http:other-token')

        def hidden(fake):
            fake.hidden.add('gen_ai_log')

        def old_ta(fake):
            fake.ta_version = '1.8.0'

        def no_ta(fake):
            fake.ta_version = None

        def other_name(fake):
            fake.events[2]['raw'] = changed(TURN, '"user":"nina.osei"', '"user":"grace.lin"')

        cases = ((legacy, '1 event(s) of the selected host(s) in the window carry body keys as indexed fields'),
                 (deep_user, 'census counts 0 eligible event(s) of the persona in the window and this tool selected 6'),
                 (altered, 'arrived altered: its sha256 or its length differs'),
                 (another_time, '_time is not the timestamp in its body'),
                 (twice_in_the_export, 'an event id occurs twice in the selection'),
                 (file_monitor_copy, '1 of the selected id(s) are held more than once on the source: '
                                     '5ca1ab1e-0002-4000-8000-0000000000b1'),
                 (another_source, '1 event(s) of the persona in the window, on a selected host, are not eligible '
                                  '(another source demobot:audit)'),
                 (hidden, '--source has no index gen_ai_log that this account can search'),
                 (old_ta, '--source has no TA-gen_ai_cim 1.9.0 or later'),
                 (no_ta, '--source has no TA-gen_ai_cim 1.9.0 or later'),
                 (other_name, 'as another identity than the selected persona'))
        for break_it, said in cases:
            with self.subTest(break_it.__name__):
                self.restart()
                break_it(self.fake)
                text = self.refusal()
                self.assertIn(said, text)
                self.assertNotIn('grace.lin', text)
                self.assertNotIn('Wrote bundle', text)
        self.assertNotIn('rule', self.kinds())                        # the last case stops at E1, before the rule

    def test_what_the_ta_wrote_back_about_a_turn_is_not_a_second_copy_of_it(self):
        # An analyst ran an AI Defense response action on the blocked turn: the TA's record of it carries the
        # turn's event_id as a key of its own. A scoring write-back only quotes the id.
        turn_id = '5ca1ab1e-0002-4000-8000-0000000000b2'
        self.fake.add('{"timestamp":"2026-11-17T04:50:00","action":"suspend_user","event_id":"' + turn_id
                      + '","simulated":true}', '1794891000', 'ai_cim:response:action', host='search-head',
                      source='ai_defense_response')
        self.fake.add('{"gen_ai.event.id":"' + turn_id + '","gen_ai.pii.risk_score":0.1}', '1794890600',
                      'genai_scoring', host='search-head', source='genai_scoring')
        code, text = self.export()
        self.assertEqual(code, 0, text)
        self.assertEqual(len(self.written()['events']), 6)
        self.assertEqual(self.written()['expect']['identity'][0]['copies'], 6)
        kinds = {(row['kind'], row['sourcetype']): row['events'] for row in self.written()['census']['rows']}
        self.assertEqual(kinds[('no log_type', 'genai_scoring')], 1)
        self.assertEqual(kinds[('no log_type', 'ai_cim:response:action')], 1)

    def test_an_export_from_another_index_reads_that_index_for_everything(self):
        # The scratch rehearsal: the events are in rs_scratch_source only. gen_ai_log, which the TA's
        # identity macro reads, holds one event of the same id with another text.
        for event in self.fake.events:
            if event['index'] == 'gen_ai_log':
                event['index'] = 'rs_scratch_source'
        self.fake.indexes.add('rs_scratch_source')
        self.fake.add(changed(TURN, '60.0', '61.0'), '1794890465.273', 'gen_ai:json', 'governance', host=HOST)
        code, text = self.export('--index', 'rs_scratch_source')
        self.assertEqual(code, 0, text)
        bundle = self.written()
        self.assertEqual({event['index'] for event in bundle['events']}, {'rs_scratch_source'})
        self.assertEqual(bundle['events'][2]['raw'], TURN)
        self.assertEqual(bundle['expect']['identity'][0]['events'], 6)       # read where the events are
        self.assertIn('index rs_scratch_source is not gen_ai_log', text)
        for search in self.fake.searches:
            if search['kind'] in ('census', 'legacy', 'export', 'present', 'expect'):
                self.assertIn('index="rs_scratch_source"', search['search'])
                self.assertNotIn('genai_identity_ai_events', search['search'])

    def test_a_source_without_the_rule_or_without_duo_still_gives_a_bundle_that_says_so(self):
        del self.fake.saved[tool.JOINED_RULE]
        self.fake.events = [event for event in self.fake.events if not event['duo']]
        code, text = self.export()
        self.assertEqual(code, 0, text)
        expect = self.written()['expect']
        self.assertEqual(expect['rule'], {'name': tool.JOINED_RULE, 'found': False, 'sha256': None, 'rows': 0})
        self.assertEqual(expect['chains'], [])
        # D1 over nothing is one row that holds txids_found alone; D2 with BY is no row at all.
        self.assertEqual(expect['duo'], {'signins': 1, 'txids': 1, 'txids_found': 0, 'found_once': 0, 'context': []})
        self.assertIn('joined rule: not on the source, so no chain id is expected', text)
        self.assertIn('Duo: 0 of 1 sign-in transaction(s) found, 0 exactly once', text)
        self.assertNotIn('rule', self.kinds())

    def test_a_rule_text_that_opens_with_a_pipe_is_dispatched_as_it_is(self):
        self.fake.saved[tool.JOINED_RULE]['search'] = '| tstats count where index=gen_ai_log by host'
        code, text = self.export()
        self.assertEqual(code, 0, text)
        sent = [search['search'] for search in self.fake.searches if search['kind'] == 'rule']
        self.assertEqual(sent, ['| tstats count where index=gen_ai_log by host | table ' + tool.RULE_TABLE])
        self.assertEqual(self.written()['expect']['rule']['sha256'],
                         sha('| tstats count where index=gen_ai_log by host'))

    def test_an_event_under_15_minutes_old_is_not_exported(self):
        text = self.refusal(now=1794890520.01 + 899)
        self.assertIn('is younger than 15 minutes', text)
        self.out = []
        self.assertEqual(self.export(now=1794890520.01 + 901)[0], 0)

    def test_the_credential_and_the_user_name_that_goes_with_it(self):
        self.assertEqual(self.export('--list-only', bundle=False)[0], 0)
        sent = {request['headers'].get('Authorization') for request in self.fake.requests}
        self.assertEqual(sent, {'Basic ' + base64.b64encode(('admin:' + self.fake.password).encode()).decode()})
        self.restart()
        self.fake.user = 'ops.lead'
        text = self.refusal()                                         # the default name is admin
        self.assertIn('did not accept the credential (HTTP 401)', text)
        self.assertIn('user name', text)
        self.assertEqual(len(self.fake.requests), 1)                  # one call, and nothing after the 401
        self.out = []
        self.assertEqual(self.export('--source-username', 'ops.lead', '--list-only', bundle=False)[0], 0)
        named = base64.b64decode(self.fake.requests[-1]['headers']['Authorization'].split()[1]).decode()
        self.assertEqual(named, 'ops.lead:' + self.fake.password)
        self.restart()
        self.env = {tool.ENV_SOURCE_TOKEN: self.fake.token}
        self.assertEqual(self.export('--list-only', bundle=False)[0], 0)
        self.assertEqual({request['headers'].get('Authorization') for request in self.fake.requests},
                         {'Bearer ' + self.fake.token})
        self.restart()
        self.env = {tool.ENV_SOURCE_PASSWORD: 'not-the-password'}
        text = self.refusal()
        self.assertIn('HTTP 401', text)
        self.assertNotIn('not-the-password', text)

    def test_the_presence_search_must_see_on_the_source_what_the_export_search_returned(self):
        # The search that will later say what a stack holds is tried on the source first. If it cannot find
        # an exported event here, it could not find the copy there, and "nothing there" means "send".
        turn = '5ca1ab1e-0002-4000-8000-0000000000b1'
        self.fake.rewrite_present = lambda row: None if row['rs_id'] == turn else row
        text = self.refusal()
        self.assertIn('the presence search does not find 1 of the event(s) the export search returned: ' + turn, text)
        for change, said in (({'host': 'other-host'}, turn + ' (host)'),
                             ({'time': '1794890465.274'}, turn + ' (time)'),
                             ({'resend_bundle': 'rs-20261101-aaaaaaaaaaaa'}, turn + ' (other-bundle)'),
                             ({'sha256': ['a' * 64, 'b' * 64]}, turn + ' (sha256)')):
            with self.subTest(change=sorted(change)):
                self.restart()
                self.fake.rewrite_present = (
                    lambda row, change=change: dict(row, **change) if row['rs_id'] == turn else row)
                self.assertIn('the presence search reads 1 event(s) differently from the export search: ' + said,
                              self.refusal())
                self.assertNotIn('expect', self.kinds())               # nothing more was read

    def test_the_run_says_how_the_certificate_is_treated_before_it_asks_anything(self):
        nowhere = 'https://127.0.0.1:1'                               # nothing listens there
        for extra, said in ((['--no-verify-source'], 'certificate: NOT VERIFIED (--no-verify-source): the credential'),
                            ([], 'certificate: not verified (a loopback address; --no-verify-source is not needed)')):
            self.out = []
            text = self.refusal(*extra, source=nowhere)
            self.assertIn(said, text)
            self.assertIn('REFUSED: reading the source: no answer from --source (no connection (', text)
        self.assertEqual(self.fake.requests, [])

    def test_events_the_ta_reads_no_identity_for_are_named_as_a_count(self):
        # An error record whose body has no `user` key: it is the persona's by enduser_id, and copied, but the
        # TA's identity views group by the user field and do not count it.
        self.fake.events[4]['raw'] = changed(ERROR, ',"user":"nina.osei"', '')
        code, text = self.export()
        self.assertEqual(code, 0, text)
        self.assertEqual(len(self.written()['events']), 6)
        self.assertEqual(self.written()['expect']['identity'][0]['events'], 5)
        self.assertIn('note: the TA reads an identity for 5 of the 6 event(s)', text)


class SearchPolicyTests(SourceCase):
    """How an answer of splunkd is taken: only from a run without an error
    and without a warning, never from a redirect, never from a guess."""

    def client(self, **change):
        options = {'url': self.url, 'flag': '--source', 'kind': 'password', 'secret': self.fake.password,
                   'username': 'admin', 'verify': False}
        options.update(change)
        return tool.Splunkd(**options)

    def test_a_warning_means_ask_again_and_an_answer_is_never_taken_from_a_run_that_has_one(self):
        # splunkd attaches a warning about its own start-up time to correct answers when the box is busy.
        self.fake.warn_runs = 2
        rows = tool.run_search(self.client(), tool.spl_index_exists('gen_ai_log'), '0', 'now', 'a check', (),
                               self.naps.append)
        self.assertEqual(len(rows), 1)
        self.assertEqual((len(self.fake.searches), self.naps), (3, [tool.WARN_PAUSE, tool.WARN_PAUSE]))
        self.fake.warn_runs, self.fake.searches[:], self.naps[:] = -1, [], []          # it never goes away
        said = self.refused(tool.run_search, self.client(), tool.spl_index_exists('gen_ai_log'), '0', 'now',
                            'a check', (), self.naps.append)
        self.assertIn('still answers with a warning after 3 runs, so its answer is not used', said)
        self.assertIn('Configuration initialization for /opt/splunk/etc took longer than expected', said)
        self.assertEqual((len(self.fake.searches), len(self.naps)), (3, 2))
        self.assertEqual((tool.WARN_RETRIES, tool.WARN_PAUSE), (2, 3))

    def test_one_warning_on_every_search_does_not_stop_an_export_and_a_lasting_one_does(self):
        self.fake.warn_runs = 1
        code, text = self.export()
        self.assertEqual(code, 0, text)
        self.assertEqual(self.kinds()[:2], ['eventcount', 'eventcount'])
        self.restart()
        self.fake.warn_runs = -1
        text = self.refusal()
        self.assertIn('still answers with a warning after 3 runs', text)
        self.assertEqual(self.kinds(), ['eventcount'] * 3)

    def test_an_error_message_or_an_answer_of_another_shape_stops_at_once(self):
        for kind in ('census', 'legacy', 'export', 'present', 'expect', 'duo_half', 'duo_context', 'rule'):
            with self.subTest(kind=kind):
                self.restart()
                self.fake.fail_search = {kind: 'Search auto-finalized after disk usage limit (100MB) reached.'}
                text = self.refusal()
                self.assertIn('the search failed on --source: Search auto-finalized', text)
                self.assertEqual(self.kinds().count(kind), 1)         # not asked again
                self.assertEqual(self.kinds()[-1], kind)              # and nothing after it
        client = self.client()
        for spl, said in (('((index=gen_ai_log) OR index=duo) | stats count', 'opens with neither'),
                          ('', 'opens with neither'), (None, 'opens with neither')):
            before = len(self.fake.requests)
            self.assertIn(said, self.refused(tool.run_search, client, spl, '0', 'now', 'a check'))
            self.assertEqual(len(self.fake.requests), before)         # nothing was dispatched
        # What splunkd itself says to such texts (HTTP 400, a FATAL message), should one ever be sent:
        for spl, said in (('search | tstats count where index=gen_ai_log', 'must be the first command'),
                          ('| makeresults | eval x=1', 'not a search text the fake knows'),
                          ('search index="gen_ai_log" | delete', 'not a search text the fake knows')):
            said_by_tool = self.refused(tool.run_search, client, spl, '0', 'now', 'a check')
            self.assertIn('a check: --source answered HTTP 400: ', said_by_tool)
            self.assertIn(said, said_by_tool)
            self.fake.searches.pop()                                  # (tearDown checks the tool's own searches)

    def test_an_answer_that_may_be_cut_is_refused(self):
        limit, tool.MAX_SEARCH_ROWS = tool.MAX_SEARCH_ROWS, 8
        self.addCleanup(setattr, tool, 'MAX_SEARCH_ROWS', limit)
        self.assertEqual(limit, 20000)                                # well under splunkd's maxresultrows
        self.assertIn('S3, the export search: the search returned 8 rows or more', self.refusal())

    def test_a_redirect_is_an_answer_and_is_never_followed(self):
        other = fake_stack.FakeSplunk(guid='5CA1AB1E-0000-4000-8000-00000000F002', clock=lambda: NOW)
        self.fake.redirect_to = other.start()
        self.addCleanup(other.stop)
        code, body = self.client().call('/services/server/info')
        self.assertEqual(code, 302)
        code, body = self.client().call(tool.SEARCH_PATH, 'POST', data={'search': '| eventcount'})
        self.assertEqual(code, 302)
        text = self.refusal()
        self.assertIn('--source answered HTTP 302, a redirect. It is never followed', text)
        self.assertEqual(other.requests, [], 'the credential followed a redirect to another server')
        self.assertEqual(len(self.fake.requests), 3)

    def test_a_message_of_the_source_never_shows_a_duo_transaction_id(self):
        # An error message can quote the search text back, and D1's text holds the sign-ins' Duo transaction ids.
        self.fake.fail_search = {'duo_half': 'Error in \'search\' command: Unable to parse the search: "' + TXID
                                             + '" OR.'}
        text = self.refusal()
        self.assertIn('D1, the Duo half of the sign-ins: the search failed on --source: Error in \'search\' command: '
                      'Unable to parse the search: "<hidden>" OR.', text)
        self.assertTrue(any(TXID in search['search'] for search in self.fake.searches))   # it was in the text

    def test_the_source_must_say_who_it_is(self):
        client = self.client()
        self.assertEqual(tool.read_origin(client, NOW), {'guid': GUID, 'splunk_version': '10.4.3',
                                                         'ta_version': '1.9.0', 'read_at': int(NOW)})
        self.fake.version, self.fake.ta_version = '9.3.2408.107', '1.9.0-rc1'       # a Cloud build, a dev build
        found = tool.read_origin(client, NOW)
        self.assertEqual((found['splunk_version'], found['ta_version']), ('9.3.2408.107', '1.9.0'))
        self.assertEqual((tool.numeric_version('10.4'), tool.numeric_version('v10'), tool.numeric_version(None)),
                         ('10.4', None, None))
        for guid in ('', 'not-a-guid', None):
            self.fake.guid = guid
            self.assertIn('did not name its server GUID', self.refused(tool.read_origin, client, NOW))

    def test_an_answer_that_is_not_splunkds_json_never_reads_as_no_rows(self):
        # "No rows" from the presence search means "the Splunk holds nothing", and that means "send".
        client, text = self.client(), tool.spl_present('gen_ai_log', ['5ca1ab1e-0002-4000-8000-0000000000b1'])
        for body in ('', '<html>502 Bad Gateway</html>', '[]', 'null', '{"messages": []}',
                     '{"results": {"copies": "1"}}', '{"results": [1, 2]}', '{"results": [["rs_id", "x"]]}',
                     '{"results": [], '):
            with self.subTest(body=body[:20]):
                self.fake.odd_answer = {'present': body}
                said = self.refused(tool.run_search, client, text, '0', '+1d', 'P1')
                self.assertEqual(said, 'P1: the search answer of --source is not what splunkd writes')
        self.fake.odd_answer = {'present': '{"results": [], "messages": [{"type": "INFO", "text": "x"}], "more": 1}'}
        self.assertEqual(tool.run_search(client, text, '0', '+1d', 'P1'), [])        # this one is an answer
        self.restart()
        self.fake.odd_answer = {'present': ''}
        self.assertIn('is not what splunkd writes', self.refusal())


class ClientTests(ToolCase):
    def test_a_credential_comes_from_exactly_one_environment_variable(self):
        names = (tool.ENV_SOURCE_PASSWORD, tool.ENV_SOURCE_TOKEN)
        secret = 'fixture-secret-value'
        self.assertEqual(tool.credential({names[0]: secret}, *names), ('password', secret))
        self.assertEqual(tool.credential({names[1]: secret, names[0]: ''}, *names), ('token', secret))
        for env, said in (({}, 'neither is set'), ({names[0]: secret, names[1]: secret}, 'both are set'),
                          ({names[0]: secret + '\n'}, 'line break'), ({names[1]: ' ' + secret}, 'space'),
                          ({names[0]: secret[:7] + '\r' + secret[7:]}, 'line break')):
            text = self.refused(tool.credential, env, *names)
            self.assertIn(said, text)
            self.assertNotIn(secret, text)
            self.assertNotIn(secret[:7], text)
        self.assertIn('$STAGED_RESEND_SOURCE_PASSWORD and $STAGED_RESEND_SOURCE_TOKEN', self.refused(
            tool.credential, {}, *names))
        self.assertIn('$SPLUNK_ADMIN_PASSWORD and $SPLUNK_ADMIN_TOKEN', self.refused(
            tool.credential, {}, tool.ENV_STACK_PASSWORD, tool.ENV_STACK_TOKEN))

    def test_a_certificate_is_verified_unless_the_run_names_why_not(self):
        policy = tool.tls_policy
        self.assertEqual(policy('https', 'stack.example.test', None, False, '--no-verify-source'),
                         (True, 'verified against the system trust store'))
        self.assertEqual(policy('https', 'stack.example.test', 'ca.pem', False, '--no-verify-source'),
                         (True, 'verified against the system trust store and --ca-file'))
        verify, words = policy('https', 'stack.example.test', None, True, '--no-verify-source')
        self.assertEqual((verify, words[:34]), (False, 'NOT VERIFIED (--no-verify-source):'))
        verify, words = policy('https', 'stack.example.test', 'ca.pem', True, '--no-verify-splunkd')
        self.assertEqual((verify, words[:35]), (False, 'NOT VERIFIED (--no-verify-splunkd):'))   # the override wins
        for host in ('127.0.0.1', 'localhost', '::1'):
            verify, words = policy('https', host, None, False, '--no-verify-source')
            self.assertEqual((verify, words[:35]), (False, 'not verified (a loopback address; -'))
            self.assertTrue(policy('https', host, 'ca.pem', False, '--no-verify-source')[0])
        self.assertEqual(policy('http', '127.0.0.1', None, False, '--no-verify-source'),
                         (False, 'plain http to a loopback address, no certificate'))

    def test_the_client_is_built_only_for_a_plain_management_address(self):
        def client(url, **change):
            options = {'url': url, 'flag': '--source', 'kind': 'password', 'secret': 'fixture-secret-value',
                       'username': 'admin', 'verify': True}
            options.update(change)
            return tool.Splunkd(**options)

        for url in ('http://source.example.test:8089', 'ftp://127.0.0.1', 'https://admin:hunter2@source.example.test',
                    'https://source.example.test:8089/services', 'https://source.example.test/?x=1', 'source', ''):
            text = self.refused(client, url)
            self.assertNotIn('source.example.test', text)
            self.assertNotIn('hunter2', text)
        for name in ('ad min', 'admin:x', '', None, 'a' * 65):
            self.assertIn('not a plain account name',
                          self.refused(client, 'https://source.example.test', username=name))
        made = client('https://source.example.test')
        self.assertEqual((made.mgmt, made.dry_run, made.ctx.verify_mode, made.ctx.check_hostname),
                         ('https://source.example.test:8089', False, ssl.CERT_REQUIRED, True))
        self.assertEqual(client('https://[::1]:9089', verify=False).mgmt, 'https://[::1]:9089')
        self.assertEqual(client('https://source.example.test', verify=False).ctx.verify_mode, ssl.CERT_NONE)
        self.assertNotIn('fixture-secret-value', repr(made) + str(made))
        self.assertEqual(made._headers(), {'Authorization': 'Basic ' + base64.b64encode(
            b'admin:fixture-secret-value').decode()})
        token = client('https://source.example.test', kind='token', username=None)
        self.assertEqual(token._headers(), {'Authorization': 'Bearer fixture-secret-value'})
        self.assertIn('form data only', self.refused(made.call, '/services/server/info', 'POST', json_body={'a': 1}))
        self.assertIn('--ca-file cannot be read', self.refused(client, 'https://source.example.test',
                                                               ca_file=self.path('none.pem')))

    def test_what_is_said_about_a_failed_call_never_comes_from_the_exception(self):
        secret = 'fixture-secret-value'
        quoting = ValueError("Invalid header value b'Bearer " + secret + "\\n'")       # http.client's own words
        self.assertEqual(tool.failure_text(quoting), 'the request failed (ValueError)')
        self.assertEqual(tool.failure_text(urllib.error.URLError(ConnectionRefusedError(61, secret))),
                         'no connection (ConnectionRefusedError)')
        self.assertEqual(tool.failure_text(socket.timeout(secret)), 'no answer in time')
        self.assertEqual(tool.failure_text(urllib.error.URLError(ssl.SSLError(1, secret))), 'TLS failed (SSLError)')
        unverified = ssl.SSLCertVerificationError(1, 'certificate verify failed')
        unverified.verify_message = 'self signed certificate'
        self.assertEqual(tool.failure_text(urllib.error.URLError(unverified)),
                         'the certificate did not verify (self signed certificate)')
        # Nothing listens on port 1: the call answers (0, words), and the words are the tool's own.
        code, text = tool.Splunkd('https://127.0.0.1:1', '--source', 'token', secret, None, False).call('/x')
        self.assertEqual(code, 0)
        self.assertRegex(text, r'^no connection \([A-Za-z]+\)$')
        self.assertEqual(tool.safe_text('a\x00b\n ' + 'c' * 300, hidden=('b',))[:13], 'a <hidden> cc')
        self.assertEqual(len(tool.safe_text('c' * 300)), 243)

    def test_a_real_handshake_with_an_unknown_certificate_gets_no_request(self):
        """Not a mock: a loopback HTTPS server with a throwaway self-signed
        certificate. The verifying client gives up in the handshake, so the
        server never sees the credential; with that certificate as --ca-file
        the same client is answered, and so is one told not to verify."""
        openssl = shutil.which('openssl')
        if not openssl:
            self.skipTest('no openssl here to make a throwaway certificate')
        cert, key = self.path('cert.pem'), self.path('key.pem')
        made = subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
                               '-days', '2', '-subj', '/CN=localhost', '-addext',
                               'subjectAltName=IP:127.0.0.1,DNS:localhost'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if made.returncode != 0 or not os.path.exists(cert):
            self.skipTest('this openssl could not make a throwaway certificate with a subjectAltName')
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.headers.get('Authorization'))
                body = b'{"entry": [{"content": {"version": "10.4.3"}}]}'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        self.addCleanup(server.server_close)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        try:
            server.socket = context.wrap_socket(server.socket, server_side=True)
        except (AttributeError, OSError) as exc:
            # Splunk's own Python 3.9 on macOS cannot wrap a listening socket. The client is not involved.
            self.skipTest('this Python cannot serve TLS on loopback ({})'.format(type(exc).__name__))
        threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True).start()
        self.addCleanup(server.shutdown)
        url = 'https://127.0.0.1:{}'.format(server.server_address[1])

        def client(verify, ca_file=None):
            return tool.Splunkd(url, '--source', 'password', 'fixture-secret-value', 'admin', verify, ca_file,
                                '--no-verify-source')

        strict = client(True)
        code, text = strict.call('/services/server/info')
        self.assertEqual(code, 0)
        self.assertIn('the certificate did not verify', text)
        self.assertEqual(seen, [], 'a request reached a server whose certificate did not verify')
        said = str(strict.failure('reading the source', code, text))
        self.assertIn('pass the CA that signed it with --ca-file, or name the risk with --no-verify-source', said)
        self.assertEqual(client(True, ca_file=cert).content('/services/server/info', 'x'), {'version': '10.4.3'})
        self.assertEqual(client(False).content('/services/server/info', 'x'), {'version': '10.4.3'})
        self.assertEqual(len(seen), 2)


class SearchTextTests(ToolCase):
    """Every search text the export dispatches, written out here as the review
    settled it (spec 3.9 with its corrections), so that a change to one is a
    change someone made on purpose."""
    A, B = '5ca1ab1e-0001-4000-8000-0000000000a1', '5ca1ab1e-0002-4000-8000-0000000000b1'
    ID_EVAL = '| eval rs_id=coalesce(spath(_raw, "audit_id"), spath(_raw, "escalation_id"), spath(_raw, "event_id")) '

    def test_the_census_the_legacy_detector_and_the_export_search(self):
        hosts, personas = ['second-host', 'stage-host'], ['grace.lin', 'nina.osei']
        self.assertEqual(tool.spl_census('gen_ai_log', hosts, personas, 'demobot:hec', T_FROM, T_TO), (
            'search index="gen_ai_log" '
            '| eval rs_ids=mvappend(spath(_raw, "audit_id"), spath(_raw, "escalation_id"), spath(_raw, "event_id")), '
            'rs_user=lower(replace(trim(coalesce(nullif(spath(_raw, "enduser_id"), "null"), '
            'nullif(spath(_raw, "user"), "null"))), "@.*", "")) '
            '| eval rs_where=case(_time<1794890400, "before the window", _time>=1794890700, "after the window", '
            'true(), "in the window"), rs_host=if(in(host, "second-host", "stage-host"), "selected host", '
            '"other host"), rs_who=case(in(rs_user, "grace.lin", "nina.osei"), "selected persona", '
            'isnull(rs_user) OR rs_user=="", "no user", true(), "other identity"), '
            'rs_kind=case(isnull(log_type), "no log_type", source!="demobot:hec", "another source", '
            'isnull(rs_ids), "no id", mvcount(rs_ids)>1, "several ids", true(), "eligible"), '
            'rs_log_type=coalesce(mvjoin(log_type, ","), "none") '
            '| stats count as events by rs_where, rs_host, rs_who, rs_kind, sourcetype, rs_log_type '
            '| sort 0 rs_where, rs_host, rs_who, rs_kind, sourcetype'))
        self.assertEqual(tool.spl_legacy('gen_ai_log', hosts), (
            '| tstats count as legacy_indexed_body_keys where index="gen_ai_log" '
            '(host="second-host" OR host="stage-host") '
            '(session_id=* OR request_id=* OR trace_id=* OR enduser_id=* OR user=*)'))
        text = tool.spl_export('gen_ai_log', ['stage-host'], 'demobot:hec')
        self.assertEqual(text, (
            'search index="gen_ai_log" (host="stage-host") source="demobot:hec" '
            '(log_type::governance OR log_type::audit OR log_type::escalation OR log_type::error) '
            '| eval rs_time=tostring(_time), rs_indextime=_indextime, rs_sha256=sha256(_raw), rs_len=len(_raw), '
            'rs_log_type=mvjoin(log_type, ","), rs_bundle=coalesce(mvjoin(resend_bundle, ","), "none") '
            '| sort 0 _time '
            '| table rs_time, rs_indextime, rs_sha256, rs_len, index, host, source, sourcetype, rs_log_type, '
            'rs_bundle, _raw'))
        # The export search names no persona and reads no body key: the persona is matched in Python.
        for word in ('nina', 'enduser_id', 'spath', 'user'):
            self.assertNotIn(word, text)
        self.assertEqual(text.split('| table ')[1].split(', '), list(tool.ROW_FIELDS))
        self.assertEqual(tool.spl_index_exists('gen_ai_log'), '| eventcount summarize=false index="gen_ai_log"')
        self.assertEqual((tool.CENSUS_PAD_SECONDS, tool.EDGE_GUARD_SECONDS), (3600, 300))
        self.refused(tool.spl_census, 'gen_ai_log', hosts, personas, 'demobot:hec', '1794890400', T_TO)   # a text

    def test_the_presence_and_the_expectation_search(self):
        both = '("' + self.A + '" OR "' + self.B + '") '
        listed = '| search rs_id IN ("' + self.A + '", "' + self.B + '") '
        self.assertEqual(tool.spl_present('gen_ai_log', [self.A, self.B]), (
            'search index="gen_ai_log" sourcetype!="ai_cim:response:*" ' + both + self.ID_EVAL + listed
            + '| eval rs_sha256=sha256(_raw), rs_time=printf("%.3f", _time), rs_time_text=tostring(_time), '
            'rs_log_type=coalesce(mvjoin(log_type, ","), "none"), '
            'rs_bundle=coalesce(mvjoin(resend_bundle, ","), "none") '
            '| stats count as copies, values(rs_sha256) as sha256, values(rs_time) as time, '
            'values(rs_time_text) as time_text, values(host) as host, values(source) as source, '
            'values(sourcetype) as sourcetype, values(index) as index, values(rs_log_type) as log_type, '
            'values(rs_bundle) as resend_bundle, min(_indextime) as first_indexed, '
            'max(_indextime) as last_indexed by rs_id'))
        tail = (
            '| eval identity_key=`genai_identity_join_key(user)`, turn=if(`genai_identity_verified_turn`, 1, 0), '
            'blocked=if(turn==1 AND \'gen_ai.policy.blocked\'=="true", 1, 0), '
            'signin=if(\'gen_ai.audit.action\'=="identity_signin_success", 1, 0), '
            'identity_event=if(\'gen_ai.identity.verified\'=="true" OR like(\'gen_ai.audit.action\', '
            '"identity_%"), 1, 0) '
            '| stats dc(rs_id) as events, count as copies, sum(identity_event) as identity_events, '
            'sum(turn) as ai_turns, sum(blocked) as ai_blocked, sum(signin) as app_signins by identity_key')
        self.assertEqual(tool.spl_expect([self.A, self.B]),
                         'search `genai_identity_ai_events` ' + both + self.ID_EVAL + listed + tail)
        self.assertEqual(tool.spl_expect([self.A, self.B], 'rs_scratch_copy'),
                         'search index="rs_scratch_copy" `exclude_scoring_sourcetypes` ' + both + self.ID_EVAL
                         + listed + tail)
        # For gen_ai_log the second form is the macro's own definition, word for word.
        macro = read_conf('macros.conf')['genai_identity_ai_events']['definition']
        self.assertEqual(tool.spl_expect([self.A], 'gen_ai_log').split(' ("')[0].replace('"', ''), 'search ' + macro)
        self.assertEqual(tool.ALL_TIME, ('0', '+1d'))

    def test_the_duo_searches_and_the_rule_dry_run(self):
        one, two = '5ca1ab1e-0006-4000-8000-0000000000d1', 'DUO-TXID-2'
        self.assertEqual(tool.spl_duo_half([one, two]), (
            'search `genai_duo_auth_events` ("' + one + '" OR "' + two + '") '
            '| eval rs_txid=mvindex(txid, 0), identity_user=`genai_identity_join_key(user)` '
            '| search rs_txid IN ("' + one + '", "' + two + '") '
            '| stats count as copies, values(action) as action, values(identity_user) as identity_user, '
            'min(_time) as duo_time, min(_indextime) as first_indexed by rs_txid '
            '| stats count as txids_found, sum(eval(if(copies==1, 1, 0))) as found_once, values(action) as action, '
            'values(identity_user) as identity_user, min(duo_time) as first_duo_time, '
            'max(duo_time) as last_duo_time'))
        # The answer of D1 holds no transaction id: the last stats has no BY and no values(rs_txid).
        self.assertNotIn('txid', tool.spl_duo_half([one]).rsplit('| stats ', 1)[1].replace('txids_found', ''))
        self.assertEqual(tool.spl_duo_context(['grace.lin', 'nina.osei']), (
            'search `genai_duo_auth_events` '
            '| eval identity_user=`genai_identity_join_key(user)`, duo_class=`genai_identity_duo_class` '
            '| search identity_user IN ("grace.lin", "nina.osei") '
            '| stats count as duo_events, dc(txid) as txids by identity_user, action, duo_class'))
        table = (' | table chain_id, user, _time, burst_time, signin_time, blocked_time, blocked_turns, '
                 'duo_failures_10m, duo_app, signin_duo, guardrails')
        self.assertEqual(tool.spl_rule_dry_run('((`a` x=1) OR y=2)\n| stats count by user'),
                         'search ((`a` x=1) OR y=2)\n| stats count by user' + table)
        self.assertEqual(tool.spl_rule_dry_run('| tstats count where index=x'), '| tstats count where index=x' + table)
        self.assertNotIn('src', table)                                # the rule's client address stays out
        shipped = read_conf('savedsearches.conf')[tool.JOINED_RULE]['search']
        dry_run = tool.spl_rule_dry_run(shipped)
        self.assertTrue(dry_run.startswith('search ((`genai_duo_auth_events`'))
        self.assertLess(len(dry_run), 5000)
        self.assertEqual(tool.RULE_ALL_INDEX_TIME, ('0', 'now'))
        events = staged_events()
        self.assertEqual(tool.duo_bounds(list(reversed(events))), (1794890419 - 6000, 1794890520 + 6001))
        self.assertEqual(tool.chain_candidates(events), ['nina.osei:takeover:1794890419'])

    def test_every_text_only_reads_and_fits_a_search_bar_at_40_ids(self):
        ids = ['5ca1ab1e-0002-4000-8000-{:012x}'.format(number) for number in range(95)]
        parts = tool.chunks(ids)
        self.assertEqual(([len(part) for part in parts], tool.IDS_PER_SEARCH), ([40, 40, 15], 40))
        self.assertEqual([ident for part in parts for ident in part], ids)
        self.assertEqual(tool.chunks([]), [])
        texts = [tool.spl_index_exists('gen_ai_log'), tool.spl_legacy('gen_ai_log', [HOST]),
                 tool.spl_census('gen_ai_log', [HOST], ['nina.osei'], 'demobot:hec', T_FROM, T_TO),
                 tool.spl_export('gen_ai_log', [HOST], 'demobot:hec'), tool.spl_present('gen_ai_log', parts[0]),
                 tool.spl_expect(parts[0]), tool.spl_expect(parts[0], 'gen_ai_log'), tool.spl_duo_half(parts[0]),
                 tool.spl_duo_context(['nina.osei']),
                 tool.spl_rule_dry_run(read_conf('savedsearches.conf')[tool.JOINED_RULE]['search']),
                 tool.spl_rule_parses(read_conf('savedsearches.conf')[tool.JOINED_RULE]['search']),
                 tool.spl_rule_ticks(tool.JOINED_RULE), tool.spl_rule_errors(tool.JOINED_RULE),
                 tool.spl_label('gen_ai_log', BUNDLE_ID), tool.spl_rule_runs(tool.JOINED_RULE, 1794900300),
                 tool.spl_findings(tool.JOINED_RULE, ['p{}.q:takeover:17948904{:02d}'.format(number, number)
                                                      for number in range(40)])]
        self.assertEqual(len(texts), 16)
        for text in texts:
            with self.subTest(text=text[:40]):
                self.assertTrue(text.startswith('search ') or text.startswith('|'))
                self.assertLess(len(text), 5000)
                self.assertIsNone(WRITERS.search(text))
                self.assertNotIn('earliest', text.split('[')[0])      # time bounds travel as REST arguments
                self.assertNotIn('index=*', text)
        for name in dir(tool):                                        # no text builder was left out above
            if name.startswith('spl_'):
                self.assertIn(name, ('spl_index_exists', 'spl_legacy', 'spl_census', 'spl_export', 'spl_present',
                                     'spl_expect', 'spl_duo_half', 'spl_duo_context', 'spl_rule_dry_run',
                                     'spl_rule_parses', 'spl_rule_ticks', 'spl_rule_errors', 'spl_label',
                                     'spl_findings', 'spl_rule_runs'))

    def test_the_three_texts_of_verify_the_label_the_finding_and_the_runs(self):
        rule = '"AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule"'
        self.assertEqual(tool.spl_label('gen_ai_log', BUNDLE_ID), (
            '| tstats count as events, min(_indextime) as first_indexed, max(_indextime) as last_indexed '
            'where index="gen_ai_log" resend_bundle="rs-20261117-0123456789ab" by sourcetype, log_type, host'))
        one, two = 'nina.osei:takeover:1794890419', 'grace.lin:takeover:1794890500'
        self.assertEqual(tool.spl_findings(tool.JOINED_RULE, [one, two]), (
            'search (index=notable OR index=risk) search_name=' + rule + ' '
            '(chain_id="nina.osei:takeover:1794890419" OR chain_id="grace.lin:takeover:1794890500") '
            '| eval rs_event_time=coalesce(orig_time, _time) '
            '| stats count as rows, min(_indextime) as first_raised, values(rs_event_time) as event_time '
            'by index, chain_id'))
        self.assertEqual(tool.spl_rule_runs(tool.JOINED_RULE, 1794900300), (
            'search index=_internal sourcetype=scheduler savedsearch_name=' + rule + ' scheduled_time>=1794900300 '
            '| eval lag=dispatch_time-scheduled_time '
            '| table scheduled_time, dispatch_time, lag, status, result_count, suppressed, alert_actions'))
        # Nothing but a bundle id, chain ids and a whole second gets into them.
        for bad in ('rs-20261117-0123456789a', 'rs-20261117-0123456789ab" OR index="x', '*', None):
            self.refused(tool.spl_label, 'gen_ai_log', bad)
        for bad in ([], [one, 'nina.osei" OR chain_id="*'], ['*'], [None], ['nina.osei:takeover:x']):
            self.refused(tool.spl_findings, tool.JOINED_RULE, bad)
        for bad in ('1794900300', 1794900300.5, -1, True, None):
            self.refused(tool.spl_rule_runs, tool.JOINED_RULE, bad)
        self.assertEqual((tool.FINDING_GRACE_SECONDS, tool.FINDING_POLL_SECONDS, tool.FINDING_REACH_SECONDS,
                          tool.MAX_WAIT_SECONDS), (420, 30, 86400, 7200))

    def test_the_tick_that_judges_a_copy_is_the_first_after_its_index_second_plus_the_lag(self):
        shipped = tool.Slot(5, 2)                      # every 5 minutes, on a slot that ends 2 minutes back
        # A run at tick T reads the index-time slot [T-420, T-120): written out for the seconds around an edge.
        for indexed, tick in ((1794900000, 1794900300), (1794900179, 1794900300), (1794900180, 1794900600),
                              (1794900181, 1794900600), (1794900479, 1794900600), (1794900480, 1794900900),
                              (1794899880, 1794900300), (1794899879, 1794900000)):
            with self.subTest(indexed=indexed):
                self.assertEqual(tool.judging_tick(indexed, shipped), tick)
                self.assertTrue(tick - 420 <= indexed < tick - 120)              # the slot of that tick holds it
                self.assertEqual(tick % 300, 0)
        self.assertEqual(tool.judging_tick(1794900000, tool.Slot(15, 5)), 1794900600)     # [T-1200, T-300)
        self.assertEqual(tool.judging_tick(1794900299, tool.Slot(15, 5)), 1794900600)
        self.assertEqual(tool.judging_tick(1794900300, tool.Slot(15, 5)), 1794901500)
        self.assertEqual(tool.judging_tick('1794900000', shipped), 1794900300)            # a result value is a string
        stanza = read_conf('savedsearches.conf')[tool.JOINED_RULE]
        self.assertEqual((stanza['cron_schedule'], stanza['dispatch.earliest_time'], stanza['dispatch.latest_time']),
                         ('*/5 * * * *', '-7m@m', '-2m@m'))

    def test_a_value_that_is_not_plain_never_enters_a_text(self):
        self.assertEqual(tool.quoted(['a', 'b.c'], ' OR '), '"a" OR "b.c"')
        self.assertEqual(tool.quoted(['gen_ai_log'], ''), '"gen_ai_log"')
        for bad in ('a"b', 'a' + chr(92) + 'b', 'a*', 'a|b', 'a[b]', 'a)b', '', ' a', 'a\nb', 'a`b`', 'a=b', None, 7):
            with self.subTest(bad=bad):
                self.refused(tool.quoted, [bad], ' OR ')
                self.refused(tool.spl_present, 'gen_ai_log', [self.A, bad])
        self.refused(tool.quoted, [], ', ')
        self.refused(tool.spl_duo_half, ['x" OR index=*'])
        self.refused(tool.spl_export, 'gen_ai_log', ['stage-host'], 'demobot:hec" OR index="_internal')


class PartsTests(ToolCase):
    """What export records beside the events is held to an exact shape, so a
    listing can print it and a later command can read it."""

    def full(self):
        """A bundle with something in every part."""
        events = staged_events()
        parts = parts_of(events)
        parts['selection'].update(**{'from': T_FROM, 'to': T_TO})
        parts['census']['rows'] = [{'where': 'in the window', 'host': 'selected host', 'who': 'selected persona',
                                    'kind': 'eligible', 'sourcetype': 'gen_ai:json', 'log_type': 'governance',
                                    'events': 2}]
        parts['expect'].update(
            identity=[{'identity_key': 'nina.osei', 'events': 6, 'copies': 6, 'identity_events': 3, 'ai_turns': 2,
                       'ai_blocked': 1, 'app_signins': 1}],
            chains=['nina.osei:takeover:1794890419'],
            rule={'name': tool.JOINED_RULE, 'found': True, 'sha256': sha('rule text'), 'rows': 1})
        parts['expect']['duo'].update(txids_found=1, found_once=1, context=[
            {'identity_user': 'nina.osei', 'action': 'failure', 'duo_class': 'denied', 'duo_events': 6, 'txids': 6}])
        return tool.build_bundle(events, parts['origin'], parts['selection'], parts['census'], parts['expect'])

    def test_an_edit_to_what_export_recorded_is_refused(self):
        def edit(change):
            bundle = json.loads(tool.bundle_text(self.full()))
            change(bundle)
            return bundle

        self.assertEqual(tool.check_bundle(edit(lambda b: None))['digest'], self.full()['digest'])
        edits = {
            'a guid that is none': lambda b: b['origin'].update(guid='A-1'),
            'a key added to the origin': lambda b: b['origin'].update(url='https://source.example.test:8089'),
            'a version with words': lambda b: b['origin'].update(splunk_version='10.4.3 (build x)'),
            'a count as text': lambda b: b['census'].update(eligible='6'),
            'a flag as a count': lambda b: b['selection'].update(exact_window=1),
            'a negative count': lambda b: b['census']['left_out'].update({'no user': -1}),
            'a host the events do not have': lambda b: b['selection'].update(hosts=['other-host']),
            'no host': lambda b: b['selection'].update(hosts=[]),
            'another persona': lambda b: b['selection'].update(personas=['grace.lin']),
            'a persona that is no persona': lambda b: b['selection'].update(personas=['nina.osei', 'Nina Osei']),
            'a window that leaves an event out': lambda b: b['selection'].update(to=1794890520),
            'a window turned around': lambda b: b['selection'].update({'from': T_TO, 'to': T_FROM}),
            'another index': lambda b: b['selection'].update(index='main'),
            'another source': lambda b: b['selection'].update(source='http:other'),
            'a note with an address': lambda b: b['selection'].update(notes=['seen from ' + ADDRESS]),
            'a note with a body': lambda b: b['selection'].update(notes=[PROMPT]),
            'a census count that is not the events': lambda b: b['census'].update(eligible=5),
            'a census word of its own': lambda b: b['census']['rows'][0].update(who='grace.lin'),
            'a census row with a key more': lambda b: b['census']['rows'][0].update(user='grace.lin'),
            'a log check of another shape': lambda b: b['census'].update(log_check={'equal': 6}),
            'an expectation about someone else': lambda b: b['expect']['identity'][0].update(identity_key='grace.lin'),
            'an expectation with a count missing': lambda b: b['expect']['identity'][0].pop('ai_blocked'),
            'Duo context about someone else': lambda b: b['expect']['duo']['context'][0].update(
                identity_user='grace.lin'),
            'a Duo class that is a sentence': lambda b: b['expect']['duo']['context'][0].update(
                duo_class='denied by x y'),
            'more sign-ins than the events have': lambda b: b['expect']['duo'].update(signins=2),
            'more transactions than the events have': lambda b: b['expect']['duo'].update(txids=2),
            'a chain of no sign-in': lambda b: b['expect'].update(chains=['nina.osei:takeover:1794890451']),
            'a chain of someone else': lambda b: b['expect'].update(chains=['grace.lin:takeover:1794890419']),
            'a chain that is no chain id': lambda b: b['expect'].update(chains=['nina.osei']),
            'a chain without a rule': lambda b: b['expect']['rule'].update(found=False, sha256=None),
            'another rule': lambda b: b['expect']['rule'].update(name='Some Other Rule'),
            'a rule hash that is none': lambda b: b['expect']['rule'].update(sha256='abc'),
        }
        for name, change in edits.items():
            with self.subTest(name):
                text = self.refused(tool.check_bundle, edit(change))
                self.assertRegex(text, r"^the bundle('s [a-z0-9_. ]+ is not what `export` writes| was edited)")
                self.assertNotIn('grace', text)
        # Shape-keeping edits still load; the approval is what catches them (BundleTests).
        kept = edit(lambda b: b['expect']['duo'].update(txids_found=0))
        self.assertEqual(tool.check_bundle(kept)['bundle_id'], self.full()['bundle_id'])

    def test_the_null_parts_and_the_empty_lists_are_part_of_the_shape(self):
        bare = bundle_of()
        self.assertEqual((bare['census']['log_check'], bare['expect']['rule']['sha256'], bare['expect']['chains']),
                         (None, None, []))
        checked = json.loads(tool.bundle_text(self.full()))
        checked['census']['log_check'] = {'equal': 6, 'of': 6}
        self.assertEqual(tool.check_bundle(checked)['census']['log_check'], {'equal': 6, 'of': 6})
        self.assertEqual(list(tool.PARTS), ['origin', 'selection', 'census', 'expect'])
        self.assertEqual(sorted(tool.PARTS['expect']), ['chains', 'duo', 'identity', 'rule'])

    def test_the_census_part_is_made_of_the_searchs_own_words(self):
        mine = {'rs_where': 'in the window', 'rs_host': 'selected host', 'rs_who': 'selected persona',
                'rs_kind': 'eligible', 'sourcetype': 'gen_ai:json', 'rs_log_type': 'governance', 'events': '4'}
        odd = dict(mine, rs_host='other host', rs_who='no user', rs_kind='no log_type',
                   sourcetype='my sourcetype (v2)', rs_log_type=['a', 'b'], events='5')
        left = {'other identities': 2, 'no user': 5, 'outside the window': 0}
        part = tool.census_part([mine, odd], left, 0, None)
        self.assertEqual((part['eligible'], part['pad_seconds'], part['left_out'], part['log_check']),
                         (4, 3600, left, None))
        self.assertEqual(part['rows'][0], {'where': 'in the window', 'host': 'selected host', 'who': 'selected persona',
                                           'kind': 'eligible', 'sourcetype': 'gen_ai:json', 'log_type': 'governance',
                                           'events': 4})
        self.assertEqual((part['rows'][1]['sourcetype'], part['rows'][1]['log_type'], part['rows'][1]['events']),
                         ('other', 'other', 5))                       # a name that is not plain is not kept
        for bad in (dict(mine, rs_who='grace.lin'), dict(mine, rs_where=None),
                    dict(mine, rs_kind=['eligible', 'no id']), dict(mine, events='many'),
                    dict((key, value) for key, value in mine.items() if key != 'events')):
            self.assertNotIn('grace', self.refused(tool.census_part, [bad], left, 0, None))
        # A hole: an event of the persona, in the window, on a selected host, that is not eligible.
        holes = tool.census_part([mine, dict(mine, rs_kind='no id', events='2'),
                                  dict(mine, rs_kind='no log_type', sourcetype='genai_scoring'),
                                  dict(mine, rs_kind='another source', rs_host='other host'),
                                  dict(mine, rs_kind='no id', rs_where='before the window')], left, 0, None)
        self.assertEqual([(row['kind'], row['events']) for row in tool.census_holes(holes)], [('no id', 2)])
        self.assertEqual(tool.census_holes(part), [])

    def test_the_expected_counts_are_added_up_over_the_searches_that_read_them(self):
        row = {'identity_key': 'nina.osei', 'events': '40', 'copies': '40', 'identity_events': '7', 'ai_turns': '5',
               'ai_blocked': '2', 'app_signins': '2'}
        rest = {'identity_key': 'nina.osei', 'events': '3', 'copies': '3', 'ai_turns': '1'}   # a sum of nothing: absent
        self.assertEqual(tool.identity_part([[row], [rest], []], ['nina.osei']), [
            {'identity_key': 'nina.osei', 'events': 43, 'copies': 43, 'identity_events': 7, 'ai_turns': 6,
             'ai_blocked': 2, 'app_signins': 2}])
        self.assertEqual(tool.identity_part([[], []], ['nina.osei']), [])
        for stranger in ('grace.lin', None, ['nina.osei', 'grace.lin']):
            text = self.refused(tool.identity_part, [[dict(row, identity_key=stranger)]], ['nina.osei'])
            self.assertNotIn('grace', text)
        events = staged_events()
        duo = tool.duo_part(events, [{'txids_found': '1', 'found_once': '1'}, {'txids_found': '0'}], [
            {'identity_user': 'nina.osei', 'action': 'success', 'duo_class': 'success', 'duo_events': '1',
             'txids': '1'},
            {'identity_user': 'nina.osei', 'action': 'failure', 'duo_class': 'denied', 'duo_events': '6',
             'txids': '6'}],
            ['nina.osei'])
        self.assertEqual((duo['signins'], duo['txids'], duo['txids_found'], duo['found_once']), (1, 1, 1, 1))
        self.assertEqual([row['action'] for row in duo['context']], ['failure', 'success'])
        self.assertEqual(tool.duo_part(events, [], [], ['nina.osei'])['txids_found'], 0)
        for bad in ({'identity_user': 'grace.lin', 'action': 'failure', 'duo_class': 'denied'},
                    {'identity_user': 'nina.osei', 'action': 'failure', 'duo_class': 'denied by policy'},
                    {'identity_user': 'nina.osei', 'duo_class': 'denied'}):
            self.refused(tool.duo_part, events, [], [bad], ['nina.osei'])


class CheckLogsTests(SourceCase):
    """--check-logs: the source holds the eight events of the golden fixture,
    and a folder holds the lines the assistant's OWN log handler wrote for
    them (fixtures/staged_resend_golden.json, store_line)."""

    def setUp(self):
        super(CheckLogsTests, self).setUp()
        with io.open(GOLDEN, encoding='utf-8') as handle:
            self.golden = json.load(handle)
        self.fake.events = []
        for case in self.golden['cases']:
            self.fake.add(case['raw'], case['time'], case['sourcetype'], case['log_type'],
                          host=self.golden['destination']['host'], indexed=case['resend_orig_indextime'])
        self.logs = self.path('logs')
        os.mkdir(self.logs)
        self.lines = collections.OrderedDict()
        for case in self.golden['cases']:
            self.lines.setdefault(case['store_file'], []).append(case['store_line'])
        self.write_logs()
        self.bundle = self.path('golden.bundle.json')

    def write_logs(self):
        for name, lines in self.lines.items():
            with io.open(os.path.join(self.logs, name), 'w', encoding='utf-8') as handle:
                handle.write(''.join(line + '\n' for line in lines))

    def run_export(self, *extra):
        chosen = self.golden['selection']
        return self.export('--check-logs', self.logs, *extra, host=chosen['host'], persona=chosen['persona'],
                           window=['--from', chosen['from'], '--to', chosen['to']])

    def test_every_event_equals_the_assistants_own_log_line_in_its_compact_form(self):
        self.assertEqual(sorted(self.lines), ['ai_governance.json', 'audit_trail.json', 'errors.json',
                                              'escalations.json'])
        # The log line is NOT the stored text: the assistant logs with spaces and sends compact.
        self.assertNotIn(self.golden['cases'][0]['store_line'], [case['raw'] for case in self.golden['cases']])
        code, text = self.run_export()
        self.assertEqual(code, 0, text)
        self.assertIn('--check-logs: 8 of 8 event(s) equal to the assistant\'s own log.', text)
        bundle = self.written()
        self.assertEqual(bundle['census']['log_check'], {'equal': 8, 'of': 8})
        self.assertEqual([event['raw'] for event in bundle['events']],
                         [case['raw'] for case in sorted(self.golden['cases'], key=lambda c: float(c['time']))])
        self.out = []
        tool.main(['review', '--bundle', self.bundle], env={}, echo=self.echo)
        self.assertIn('the assistant\'s own log: 8 of 8 equal', '\n'.join(self.out))
        self.assertNotIn(self.logs, '\n'.join(self.out))              # the folder's path is not kept

    def test_a_rotated_file_is_read_and_other_lines_prove_nothing(self):
        first = self.lines['audit_trail.json'].pop(0)
        self.write_logs()
        ident = self.golden['cases'][0]['id']
        with io.open(os.path.join(self.logs, 'audit_trail_20261116_100000.json'), 'w', encoding='utf-8') as handle:
            handle.write('{"audit_id": "5ca1ab1e-0001-4000-8000-00000000ffff", "details": "quotes ' + ident + '"}\n'
                         + first[:60] + '\n' + '[1, 2, "' + ident + '"]\n' + first + '\n')
        with io.open(os.path.join(self.logs, 'notes.json'), 'w', encoding='utf-8') as handle:
            handle.write(first.replace('identity_signin_success', 'something_else') + '\n')    # not a log file
        code, text = self.run_export('--list-only')
        self.assertEqual(code, 0, text)
        self.assertIn('--check-logs: 8 of 8', text)

    def test_an_id_that_is_missing_from_the_log_or_has_another_text_there_stops_the_export(self):
        case = self.golden['cases'][1]
        kept = list(self.lines['audit_trail.json'])
        self.lines['audit_trail.json'] = [line for line in kept if case['id'] not in line]
        self.write_logs()
        text = self.refusal('--check-logs', self.logs, host=self.golden['selection']['host'],
                            window=['--from', self.golden['selection']['from'], '--to', self.golden['selection']['to']])
        self.assertIn('--check-logs: 1 of 8 event id(s) are not in the assistant\'s log in that folder', text)
        self.assertIn(case['id'], text)
        other = [line.replace('session_started', 'session_ended') if case['id'] in line else line for line in kept]
        self.assertNotEqual(other, kept)
        self.lines['audit_trail.json'] = other
        self.write_logs()
        self.out = []
        text = self.refusal('--check-logs', self.logs, host=self.golden['selection']['host'],
                            window=['--from', self.golden['selection']['from'], '--to', self.golden['selection']['to']])
        self.assertIn('--check-logs: for 1 of 8 event(s) the assistant\'s log holds another text than Splunk: '
                      + case['id'], text)
        changed_line = [line for line in other if case['id'] in line][0]
        self.assertIn('(log {}, Splunk {})'.format(
            sha(json.dumps(json.loads(changed_line), separators=(',', ':')))[:12], case['sha256'][:12]), text)
        self.assertNotIn('present', self.kinds())                     # stopped before anything else was read

    def test_an_export_keeps_every_text_exactly_as_the_source_holds_it(self):
        # The golden splice texts: odd spacing with a tab and a line break, unescaped UTF-8, uppercase hex
        # escapes, an escaped solidus, numbers written another way, a key twice. A parse and write-again
        # changes six of the seven; the bundle must hold each as it is, and make the golden line from it.
        where = self.golden['destination']['host']
        for case in self.golden['splice']:
            self.fake.add(case['raw'], case['time'], case['sourcetype'], case['log_type'], host=where,
                          indexed=case['resend_orig_indextime'])
        chosen = self.golden['selection']
        code, text = self.export(host=where, window=['--from', chosen['from'], '--to', chosen['to']])
        self.assertEqual(code, 0, text)
        held = dict((event['id'], event) for event in self.written()['events'])
        texts = self.golden['cases'] + self.golden['splice']
        self.assertEqual(len(held), len(texts))
        for case in texts:
            with self.subTest(case['name']):
                event = held[case['id']]
                self.assertEqual((event['raw'], event['time'], event['sha256']),
                                 (case['raw'], case['time'], case['sha256']))
                self.assertEqual(tool.event_line(event, self.golden['resend']['bundle_id']), case['resend_line'])
        self.assertGreaterEqual(sum(1 for case in self.golden['splice'] if not case['same_after_compact_dump']), 6)
        with io.open(self.bundle, 'rb') as handle:
            self.assertTrue(handle.read().isascii())                  # the file is ASCII; the texts in it are not
        self.assertFalse(all(event['raw'].isascii() for event in held.values()))


class ReviewOfAnExportTests(SourceCase):
    def review(self, *extra):
        self.out = []
        code = tool.main(['review', '--bundle', self.bundle] + list(extra), env={}, clock=lambda: NOW + 60,
                         echo=self.echo)
        return code, '\n'.join(self.out)

    def test_review_lists_what_export_recorded_as_ids_hashes_times_and_counts(self):
        self.assertEqual(self.export()[0], 0)
        bundle = self.written()
        code, text = self.review()
        self.assertEqual(code, 0)
        rule = bundle['expect']['rule']['sha256']
        for shown in (
                'Bundle ' + bundle['bundle_id'], '6 event(s) for index gen_ai_log',
                'Selection: index gen_ai_log, source demobot:hec, host(s) stage-host, persona(s) nina.osei',
                'window 2026-11-17T04:40:00Z to 2026-11-17T04:45:00Z (the end is exclusive; 300 s)',
                'overrides used: none',
                'Census: what Splunk counted within 3600 s of the window (nobody else is named)',
                'counted as the selection: 6. Not copied: 1 of other identities and 1 with no user in the window, '
                '0 of the persona outside it.',
                'the assistant\'s own log: not compared (no --check-logs)',
                'nina.osei: events 6, copies 6, identity_events 3, ai_turns 2, ai_blocked 1, app_signins 1',
                'Duo: 1 of 1 sign-in transaction(s) found, 1 exactly once',
                'Duo context: nina.osei failure/denied: 6 event(s), 6 transaction(s)',
                'joined rule (text {}): 1 chain(s) for this set\'s sign-ins: nina.osei:takeover:1794890419'.format(
                    rule[:12]),
                'Origin: server {}, Splunk 10.4.3, TA-gen_ai_cim 1.9.0, read 2026-11-17T07:20:00Z'.format(GUID),
                'Digest {} - NOT approved'.format(bundle['digest'][:12])):
            self.assertIn(shown, text)
        census = [line.split() for line in text.split('\n') if line.startswith('    in the window')]
        self.assertIn(['in', 'the', 'window', 'selected', 'host', 'selected', 'persona', 'eligible', 'demobot:audit',
                       'audit', '2'], census)
        # Twelve digits of a hash and no more; nobody else's name; no body value (tearDown).
        for whole in [bundle['digest'], rule] + [event['sha256'] for event in bundle['events']]:
            self.assertNotIn(whole[:13], text)
        self.assertNotIn('grace', text)
        self.assertTrue(all(' ' <= char <= '~' or char == '\n' for char in text))

    def test_an_exported_bundle_is_approved_by_its_digest_and_an_edit_undoes_it(self):
        self.assertEqual(self.export()[0], 0)
        bundle = self.written()
        self.assertIn('not approved as it now is', self.refused(tool.load_bundle, self.bundle, need_approval=True))
        code, text = self.review('--approve', bundle['digest'][:12])
        self.assertEqual(code, 0, text)
        approved = tool.load_bundle(self.bundle, need_approval=True)
        self.assertEqual((approved['review']['at'], stat.S_IMODE(os.lstat(self.bundle).st_mode)),
                         (int(NOW) + 60, 0o600))
        self.assertIn('approved as it is', self.review()[1])
        # A shape-keeping edit to what export recorded: the file loads, the approval is gone.
        approved['expect']['chains'] = []
        tool.replace_private(self.bundle, tool.bundle_text(approved), '--bundle')
        self.assertIn('not approved as it now is', self.refused(tool.load_bundle, self.bundle, need_approval=True))
        self.assertIn('NOT approved', self.review()[1])

    def test_review_shows_nothing_of_a_bundle_whose_parts_are_not_exports(self):
        self.assertEqual(self.export()[0], 0)
        bundle = json.loads(tool.bundle_text(self.written()))
        for part, key, value in (('selection', 'notes', [PROMPT + '?']), ('census', 'rows', [{'who': ADDRESS}]),
                                 ('origin', 'guid', TXID + ' and more'), ('expect', 'chains', ['caf' + E_ACUTE])):
            with self.subTest(part=part):
                edited = json.loads(json.dumps(bundle))
                edited[part][key] = value
                with io.open(self.bundle, 'w', encoding='utf-8') as handle:
                    handle.write(json.dumps(edited))
                code, text = self.review()
                self.assertEqual(code, 2)
                self.assertRegex(text, r"^REFUSED: the bundle's {}[a-z_.]* is not what `export` writes".format(part))
                self.assertNotIn(bundle['events'][0]['id'], text)     # nothing was listed
                self.assertEqual(self.review('--approve', bundle['digest'][:12])[0], 2)


class FakeFidelityTests(SourceCase):
    """The fake answers as splunkd does where a careless tool would notice
    the difference. Each shape below was seen live on Splunk 10.4.3."""

    def ask(self, spl, earliest='0', latest='+1d'):
        return self.fake.search({'search': spl, 'exec_mode': 'oneshot', 'count': '0', 'earliest_time': earliest,
                                 'latest_time': latest})

    def test_the_rule_it_serves_is_the_shipped_stanza_and_a_checkout_without_it_fails(self):
        shipped = read_conf('savedsearches.conf')[tool.JOINED_RULE]
        served = self.fake.saved[tool.JOINED_RULE]
        self.assertEqual((served['search'], served['cron_schedule'], served['dispatch.earliest_time'],
                          served['dispatch.latest_time'], served['realtime_schedule'], served['disabled']),
                         (shipped['search'], '*/5 * * * *', '-7m@m', '-2m@m', False, True))
        self.assertEqual(fake_stack.JOINED_RULE, tool.JOINED_RULE)
        keep = fake_stack.read_conf
        self.addCleanup(setattr, fake_stack, 'read_conf', keep)
        fake_stack.read_conf = lambda name: dict((key, value) for key, value in keep(name).items()
                                                 if key != tool.JOINED_RULE)
        with self.assertRaises(KeyError):                             # never a skip, never an invented stanza
            fake_stack.FakeSplunk()

    def test_a_text_is_answered_only_when_all_of_it_is_a_known_search(self):
        good = tool.spl_present('gen_ai_log', ['5ca1ab1e-0002-4000-8000-0000000000b1'])
        self.assertEqual(self.ask(good)['results'][0]['copies'], '1')
        for bad in (good[len('search '):],                            # no leading "search"
                    good + ' | head 1', good.replace('sourcetype!="ai_cim:response:*" ', ''),
                    good.replace('by rs_id', 'by rs_id, host'), 'search ' + good,
                    tool.spl_legacy('gen_ai_log', [HOST]).replace('| tstats', 'search | tstats'),
                    good.replace('index="gen_ai_log"', 'index=*')):
            with self.assertRaises(fake_stack.Reply) as refused:
                self.ask(bad)
            self.assertEqual((refused.exception.status, refused.exception.body['messages'][0]['type']), (400, 'FATAL'))
            self.fake.searches.pop()
        with self.assertRaises(fake_stack.Reply):
            self.fake.search({'search': good, 'exec_mode': 'normal', 'count': '0'})
        self.fake.searches.pop()
        # The two refusals are splunkd's own, each with its message: a text that opens with neither "search "
        # nor a pipe, the shipped rule's text as it stands in the conf among them, and a generating command
        # after "search ".
        shipped = read_conf('savedsearches.conf')[tool.JOINED_RULE]['search']
        for bad, said in ((good[len('search '):], "Error in 'SearchParser': Missing a search command before 'i'."),
                          (shipped + ' | stats count as rows', "Error in 'SearchParser': Missing a search command "
                                                               "before '('."),
                          ('search | tstats count where index=gen_ai_log',
                           "Error in 'tstats' command: This command must be the first command of a search.")):
            with self.assertRaises(fake_stack.Reply) as refused:
                self.ask(bad)
            self.assertEqual(refused.exception.body['messages'][0]['text'], said)
            self.fake.searches.pop()
        self.assertEqual(self.ask(tool.spl_rule_parses(shipped))['results'], [{'rows': '0'}])

    def test_values_are_strings_lists_or_absent_and_an_empty_answer_has_its_own_shape(self):
        turn = '5ca1ab1e-0002-4000-8000-0000000000b1'
        self.fake.add(TURN, '1794890465.273000', 'gen_ai:json', 'governance', host='second-host')
        row = self.ask(tool.spl_present('gen_ai_log', [turn]))['results'][0]
        self.assertEqual((row['copies'], row['host'], row['sha256'], row['time'], row['time_text']),
                         ('2', ['second-host', 'stage-host'], sha(TURN), '1794890465.273',
                          ['1794890465.273', '1794890465.273000']))
        self.assertEqual(tool.decide(staged_events()[2], row, BUNDLE_ID).verdict, 'duplicate')
        nobody = '5ca1ab1e-0002-4000-8000-00000000eeee'
        self.assertEqual(self.ask(tool.spl_present('gen_ai_log', [nobody]))['results'], [])       # stats ... by
        self.assertEqual(self.ask(tool.spl_expect([nobody]))['results'], [])
        self.assertEqual(self.ask(tool.spl_duo_half([nobody]))['results'], [{'txids_found': '0'}])   # stats, no BY
        self.assertEqual(self.ask(tool.spl_duo_context(['grace.lin']))['results'], [])
        self.assertEqual(self.ask(tool.spl_legacy('gen_ai_log', ['no-such-host']))['results'],
                         [{'legacy_indexed_body_keys': '0'}])                                    # tstats count
        export = self.ask(tool.spl_export('gen_ai_log', [HOST], 'demobot:hec'), '0', '+1d')['results']
        self.assertTrue(all(isinstance(value, str) for found in export for value in found.values()))
        self.assertEqual(sorted(export[0]), sorted(tool.ROW_FIELDS))
        # An index the account may not search holds nothing and says nothing.
        self.fake.hidden.add('gen_ai_log')
        for spl in (tool.spl_present('gen_ai_log', [turn]), tool.spl_index_exists('gen_ai_log'),
                    tool.spl_export('gen_ai_log', [HOST], 'demobot:hec')):
            answer = self.ask(spl)
            self.assertEqual((answer['results'], answer['messages']), ([], []))

    def test_tstats_cuts_a_time_bound_to_the_whole_second_and_search_does_not(self):
        self.fake.events[0]['fields']['session_id'] = 'identity-a1'   # the sign-in at ...419.556
        legacy, export = tool.spl_legacy('gen_ai_log', [HOST]), tool.spl_export('gen_ai_log', [HOST], 'demobot:hec')

        def count(early, late):
            return self.ask(legacy, early, late)['results'][0]['legacy_indexed_body_keys']

        def rows(early, late):
            return len(self.ask(export, early, late)['results'])

        self.assertEqual((count('1794890419.600', '1794890420'), rows('1794890419.600', '1794890420')), ('1', 0))
        self.assertEqual((count('1794890419.500', '1794890419.600'), rows('1794890419.500', '1794890419.600')),
                         ('0', 1))
        self.assertEqual((count('1794890419', '1794890420'), rows('1794890419', '1794890420')), ('1', 1))
        # So the tool gives both only whole seconds: a fraction in --from or --to is refused.
        self.refused(tool.parse_when, '2026-11-17T04:40:19.5Z', '--from')


STACK_GUID = '5CA1AB1E-0000-4000-8000-00000000F002'
STACK_ENDPOINTS = re.compile(ENDPOINTS.pattern + r'|GET /services/data/indexes/[a-z0-9_-]+|'
                             r'GET /servicesNS/nobody/TA-gen_ai_cim/configs/conf-macros/genai_identity_ai_events')
STAGED_IDS = [re.match(r'\{"\w+":"([0-9a-f-]{36})"', item[0]).group(1) for item in STAGED]
CANARY = STAGED_IDS[1]                                     # the session start: the earliest audit record, no sign-in
KIND_CANARIES = [STAGED_IDS[2], STAGED_IDS[4], STAGED_IDS[5]]  # then one of each other sourcetype and log type


def text_of(path):
    """A file's text, or '' when there is no such file."""
    if not os.path.exists(path):
        return ''
    with io.open(path, encoding='utf-8') as handle:
        return handle.read()


class StackCase(SourceCase):
    """An approved bundle, exported from the fake source, and a second fake
    Splunk that plays a stack created after the staging: another server GUID,
    its own HEC, the Duo half of the scenario, and the joined rule enabled
    and running. The clock moves only when the tool sleeps. At the end of
    every test, on top of SourceCase's checks: the stack was only asked the
    pinned read-only texts on the known endpoints, the HEC token travelled
    only in the Authorization header of a POST to the event endpoint, and
    neither the output nor the ledger holds a credential or a body value."""

    def setUp(self):
        super(StackCase, self).setUp()
        self.now = NOW
        self.assertEqual(self.export()[0], 0)
        digest12 = self.written()['digest'][:12]
        self.assertEqual(tool.main(['review', '--bundle', self.bundle, '--approve', digest12], env={},
                                   clock=lambda: NOW, sleep=self.naps.append, echo=self.echo), 0)
        self.stack = fake_stack.FakeSplunk(guid=STACK_GUID, clock=lambda: self.now)
        for step in range(6):
            self.stack.add_duo('nina.osei', BURST + 20 * step)
        self.stack.add_duo('nina.osei', 1794890417, action='success', txid=TXID)
        self.stack.saved[tool.JOINED_RULE]['disabled'] = False          # what `show_postdeploy.py --duo` does
        self.stack.tick(int(NOW) - 300)
        self.stack_url, self.hec_url = self.stack.start(), self.stack.start_hec()
        self.addCleanup(self.stack.stop)
        self.stack_env = {tool.ENV_STACK_PASSWORD: self.stack.password, tool.ENV_HEC_TOKEN: self.stack.hec_token}
        self.ledger_file = self.bundle + '.ledger.jsonl'
        self.wrong_token_ok = False

    def tearDown(self):
        text, stack = '\n'.join(self.out), self.stack
        ledger = text_of(self.ledger_file)
        for secret in (stack.password, stack.token, stack.hec_token):
            self.assertNotIn(secret, text, 'a credential was printed')
            self.assertNotIn(secret, ledger, 'a credential is in the ledger')
        for needle in NEVER_SHOWN:
            self.assertNotIn(needle, ledger, 'the ledger holds a body value')
        for search in stack.searches:
            self.assertIsNone(WRITERS.search(search['search']), 'a search that writes')
            self.assertIsNotNone(search['kind'], 'a search text the fake does not know: ' + search['search'][:60])
            self.no_body_value_in(search)
        for request in stack.requests:
            self.assertEqual(request['query'], 'output_mode=json')
            self.assertTrue(STACK_ENDPOINTS.fullmatch(request['method'] + ' ' + request['path']), request['path'])
            self.assertNotIn(stack.hec_token, json.dumps(request), 'the HEC token went to port 8089')
        for request in stack.hec_requests:
            headers = dict(request['headers'])
            given = headers.pop('Authorization', None)
            self.assertNotIn(stack.hec_token, json.dumps(headers) + request['path'])
            self.assertNotIn(stack.hec_token.encode('utf-8'), request['body'] or b'')
            self.assertNotIn(stack.password, json.dumps(headers) + str(given), 'the admin password went to HEC')
            if request['method'] == 'GET':
                self.assertIsNone(given, 'the health check carried the token')
            elif not self.wrong_token_ok:
                self.assertEqual(given, 'Splunk ' + stack.hec_token)
                self.assertEqual(request['path'], '/services/collector/event')
        super(StackCase, self).tearDown()

    def nap(self, seconds):
        self.naps.append(seconds)
        self.now += seconds

    def send(self, *extra, **options):
        """(exit code, what THIS run printed) of one `send` against the stack."""
        argv = ['send', '--bundle', options.get('bundle', self.bundle), '--stack', options.get('stack', self.stack_url)]
        if options.get('hec', True):
            argv += ['--hec-url', options.get('hec_url', self.hec_url)]
        before, stream = len(self.out), io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            code = tool.main(argv + list(extra), env=options.get('env', self.stack_env), clock=lambda: self.now,
                             sleep=options.get('sleep', self.nap), echo=options.get('echo', self.echo))
        self.out.append(stream.getvalue())
        text = '\n'.join(self.out[before:])
        self.assertNotIn('Traceback', text)
        return code, text

    def verify(self, *extra, **options):
        """(exit code, what THIS run printed) of one `verify` against the stack.
        It gets no HEC token, and it must leave HEC and the ledger alone."""
        argv = ['verify', '--bundle', options.get('bundle', self.bundle),
                '--stack', options.get('stack', self.stack_url)]
        env = options.get('env', {tool.ENV_STACK_PASSWORD: self.stack.password})
        before, stream = len(self.out), io.StringIO()
        hec, ledger = len(self.stack.hec_requests), text_of(self.ledger_file)
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            code = tool.main(argv + list(extra), env=env, clock=lambda: self.now,
                             sleep=options.get('sleep', self.nap), echo=self.echo)
        self.out.append(stream.getvalue())
        text = '\n'.join(self.out[before:])
        self.assertNotIn('Traceback', text)
        self.assertEqual(len(self.stack.hec_requests), hec, '`verify` reached HEC')
        self.assertEqual(text_of(self.ledger_file), ledger, '`verify` wrote the ledger')
        self.assertEqual(sorted(name for name in os.listdir(self.folder) if '.tmp' in name), [], 'a file was left')
        return code, text

    def copies(self):
        """{id: how many events the stack's index holds under it}, searchable or not."""
        held = collections.Counter(self.stack.own_id(event) for event in self.stack.events
                                   if event['index'] == 'gen_ai_log')
        return dict((ident, count) for ident, count in held.items() if ident)

    def ledger(self, kind=None):
        """The ledger's lines, as objects (those of one kind)."""
        lines = [json.loads(line) for line in text_of(self.ledger_file).splitlines()]
        return [line for line in lines if kind is None or line['kind'] == kind]

    def posts(self):
        return self.stack.hec_posts()

    def last_search(self, kind):
        """The stack's record of the last search of one kind."""
        return [search for search in self.stack.searches if search['kind'] == kind][-1]

    def kinds_of_stack(self):
        return [search['kind'] for search in self.stack.searches]

    def big_bundle(self, count, pad=0, index='gen_ai_log'):
        """(path, ids) of an approved bundle of `count` made-up turns of the
        persona, one a second, each padded by `pad` characters. It has no
        sign-in, so the Duo step has nothing to pair."""
        found = []
        for number in range(count):
            stamp = '2026-11-17T04:4{}:{:02d}'.format(number // 60, number % 60)
            raw = ('{"event_id":"5ca1ab1e-0009-4000-8000-%012x","operation_name":"chat","session_id":"sess-big",'
                   '"timestamp":"%s","pad":"%s","enduser_id":"nina.osei","user":"nina.osei"}'
                   % (number, stamp, 'p' * pad))
            found.append(dict(plain_event(raw, '{}.0'.format(1794890400 + number)), index=index))
        bundle = bundle_of(found)
        path = self.path('big.bundle.json')
        tool.write_bundle(path, tool.approve(bundle, bundle['digest'][:12], NOW))
        self.ledger_file = path + '.ledger.jsonl'
        return path, [event['id'] for event in found]


class SendTests(StackCase):
    def test_a_send_copies_every_event_once_canary_first_and_a_second_run_sends_nothing(self):
        code, text = self.send()
        self.assertEqual(code, 0, text)
        self.assertEqual(self.copies(), dict((ident, 1) for ident in STAGED_IDS))
        posts = self.posts()
        self.assertEqual([post['body'].count(b'"resend":"true"') for post in posts], [1, 3, 2])  # canary, kinds, rest
        self.assertIn(CANARY.encode('ascii'), posts[0]['body'])
        self.assertIn('the canary is on the stack once, identical and labelled', text)
        self.assertIn('SENT: the stack holds each of the 6 id(s) once, identical. This run sent 6; 0 were there', text)
        for number in range(1, 9):
            self.assertRegex(text, r'\[  OK\] R{}\. '.format(number))
        self.assertEqual(self.naps, [])                                   # nothing to wait for: no sleep at all
        # Each request is on record before it is made, and its events are confirmed from the stack.
        self.assertEqual([line['kind'] for line in self.ledger()],
                         ['run'] + ['intent', 'outcome', 'confirmed'] * 3)
        self.assertEqual(stat.S_IMODE(os.stat(self.ledger_file).st_mode), 0o600)
        self.assertEqual({line['stack'] for line in self.ledger()}, {STACK_GUID})
        self.assertEqual(tool.ledger_handed(text_of(self.ledger_file), STACK_GUID, self.written()['bundle_id']),
                         sorted(STAGED_IDS))
        code, text = self.send()
        self.assertEqual(code, 0, text)
        self.assertEqual(len(self.posts()), 3, 'a second run sent something')
        self.assertIn('to send 0; on the stack, identical: 6 (live 0, this bundle 6, another bundle 0)', text)
        self.assertIn('nothing to send', text)
        self.assertEqual(self.copies(), dict((ident, 1) for ident in STAGED_IDS))

    def test_the_request_is_the_assistants_own_plus_the_label_and_the_stack_holds_the_same_bytes(self):
        self.assertEqual(self.send()[0], 0)
        events = self.written()['events']
        kinds = [event for event in events if event['id'] in KIND_CANARIES]
        rest = [event for event in events if event['id'] != CANARY and event['id'] not in KIND_CANARIES]
        bundle_id = self.written()['bundle_id']
        canary, one_of_each, others = self.posts()
        self.assertEqual(others['body'], '\n'.join(tool.event_line(event, bundle_id) for event in rest).encode('utf-8'))
        self.assertEqual(one_of_each['body'],
                         '\n'.join(tool.event_line(event, bundle_id) for event in kinds).encode('utf-8'))
        self.assertEqual(canary['body'], tool.event_line(events[1], bundle_id).encode('utf-8'))
        for post in (canary, one_of_each, others):
            headers = dict((name.lower(), value) for name, value in post['headers'].items())
            self.assertEqual(headers['content-type'], 'application/json; charset=utf-8')
            self.assertEqual(headers['connection'], 'close')
            self.assertEqual(headers['authorization'], 'Splunk ' + self.stack.hec_token)
            self.assertEqual(int(headers['content-length']), len(post['body']))
            self.assertNotIn('x-splunk-request-channel', headers)        # no indexer acknowledgement
        # What the stack indexed is, byte for byte, what the source holds: the literals of this file.
        held = dict((self.stack.own_id(event), event) for event in self.stack.events if event['index'] == 'gen_ai_log')
        for raw, time_text, sourcetype, log_type in STAGED:
            event = held[re.match(r'\{"\w+":"([0-9a-f-]{36})"', raw).group(1)]
            self.assertEqual(event['raw'], raw)
            self.assertEqual((event['time_text'], event['sourcetype'], event['host'], event['source']),
                             (time_text, sourcetype, HOST, 'demobot:hec'))
            self.assertEqual(event['fields'], {'log_type': log_type, 'resend': 'true', 'resend_bundle': bundle_id,
                                               'resend_orig_indextime': str(int(float(time_text)) + 2)})

    def test_a_dry_run_reads_everything_and_sends_and_writes_nothing(self):
        code, text = self.send('--dry-run')
        self.assertEqual(code, 0, text)
        self.assertEqual(self.posts(), [])
        self.assertEqual([request['path'] for request in self.stack.hec_requests], ['/services/collector/health'])
        self.assertFalse(os.path.lexists(self.ledger_file), 'a dry run wrote the ledger')
        self.assertEqual(self.copies(), {})
        self.assertIn('(DRY RUN)', text)
        self.assertIn('DRY RUN: every step passed. Nothing was sent to HEC and the ledger was not written. A run '
                      'without --dry-run would send 6 event(s).', text)
        for ident in STAGED_IDS:                                           # per id, what a real run would do
            self.assertRegex(text, r'{}  \S+ +\S+ +send'.format(ident))
        self.assertRegex(text, CANARY + r'  audit +demobot:audit +send, first and alone \(the canary\)')
        self.assertEqual([kind for kind in self.kinds_of_stack() if kind == 'present'], ['present'])
        # A failed step fails a dry run too, and still sends nothing.
        self.stack.hec_healthy = False
        code, text = self.send('--dry-run')
        self.assertEqual((code, self.posts()), (1, []))
        self.assertIn('NOT SENT: 1 step(s) failed. Nothing was sent to HEC.', text)

    def test_no_canary_sends_everything_in_the_first_request_and_says_so(self):
        code, text = self.send('--no-canary')
        self.assertEqual(code, 0, text)
        self.assertEqual([post['body'].count(b'"resend":"true"') for post in self.posts()], [6])
        self.assertNotIn('the canary: one event first', text)
        self.assertIn('--no-canary: no event goes first and alone', text)       # an override is always named
        self.assertEqual(self.copies(), dict((ident, 1) for ident in STAGED_IDS))
        self.assertEqual([line['canary'] for line in self.ledger('intent')], [False])

    def test_a_partly_live_stack_gets_only_what_it_lacks(self):
        for raw, time_text, sourcetype, log_type in (STAGED[0], STAGED[2]):       # the sign-in and one turn, live
            self.stack.add(raw, time_text, sourcetype, log_type, host=HOST)
        code, text = self.send()
        self.assertEqual(code, 0, text)
        self.assertEqual([post['body'].count(b'"resend":"true"') for post in self.posts()], [1, 3])
        self.assertEqual(self.copies(), dict((ident, 1) for ident in STAGED_IDS))
        self.assertIn('to send 4; on the stack, identical: 2 (live 2, this bundle 0, another bundle 0)', text)
        self.assertRegex(text, STAGED_IDS[0] + r'  audit +demobot:audit +skip \(on the stack, identical: live\)')
        self.assertIn('This run sent 4; 2 were there already.', text)
        labelled = [event for event in self.stack.events if event['fields'].get('resend') == 'true']
        self.assertEqual(len(labelled), 4)                      # the live ones keep no label: nothing touched them

    def test_a_stack_that_rewrites_the_canary_gets_one_event_and_no_more(self):
        self.stack.hec_rewrite = lambda event: event.update(sourcetype='httpevent')   # one sourcetype for everything
        code, text = self.send()
        self.assertEqual(code, 1, text)
        self.assertEqual((len(self.posts()), self.copies()), (1, {CANARY: 1}))
        self.assertIn('STOPPED: the canary: the stack does not hold 1 of 1 event(s) as they were sent: '
                      '{} (sourcetype)'.format(CANARY), text)
        self.assertIn('nothing more was sent', text)
        code, text = self.send()                                 # the next run reads the stack first: a conflict
        self.assertEqual((code, len(self.posts())), (1, 1))
        self.assertRegex(text, r'\[FAIL\] R7\. what the stack holds - 1 conflict\(s\) and 0 duplicate\(s\)')
        self.assertIn('no option overrides this', text)
        self.restart()
        self.stack.hec_rewrite = lambda event: event.update(fields={'log_type': event['fields']['log_type']})
        code, text = self.send()                                 # a stack that drops the label: the copy reads as live
        self.assertEqual((code, len(self.posts())), (1, 1))
        self.assertIn('{} (live)'.format(CANARY), text)

    def test_a_stack_that_rewrites_only_one_sourcetype_gets_one_event_of_it_and_no_bulk(self):
        def only_turns(event):                                   # an ingest action on gen_ai:json, nothing else
            if event['sourcetype'] == 'gen_ai:json':
                event.update(host='rewritten-host')
        self.stack.hec_rewrite = only_turns
        code, text = self.send()
        self.assertEqual(code, 1, text)
        self.assertEqual([post['body'].count(b'"resend":"true"') for post in self.posts()], [1, 3])   # no bulk
        sent = [event for event in self.stack.events if event['fields'].get('resend') == 'true']
        self.assertEqual(sorted(event['sourcetype'] for event in sent if event['sourcetype'] == 'gen_ai:json'),
                         ['gen_ai:json'])                        # one turn, never all of them
        self.assertIn('STOPPED: the canary: the stack does not hold 1 of 3 event(s) as they were sent: {}'.format(
            KIND_CANARIES[0]), text)

    def test_a_lost_reply_is_never_followed_by_a_second_request(self):
        self.stack.hec_script = ['lost']                         # the stack takes the canary; its answer never arrives
        code, text = self.send()
        self.assertEqual(code, 0, text)
        self.assertEqual(self.copies(), dict((ident, 1) for ident in STAGED_IDS))
        self.assertEqual([post['step'] for post in self.posts()], ['lost', 'ok', 'ok'])
        self.assertIn('the answer for 1 event(s) does not say whether they were indexed (the request left and no '
                      'answer came back', text)
        self.assertIn('They are NOT sent again', text)
        self.assertEqual([line['state'] for line in self.ledger('outcome')], ['unknown', 'accepted', 'accepted'])

    def test_a_lost_reply_and_a_slow_index_never_make_a_second_copy_in_this_run_or_a_later_one(self):
        self.stack.hec_script, self.stack.index_lag = ['lost'], 600
        code, text = self.send('--no-canary', '--settle', '30')
        self.assertEqual((code, len(self.posts())), (3, 1), text)
        self.assertIn('DELIVERY UNKNOWN: after an answer that says nothing: 6 of 6 event(s) handed to HEC are not '
                      'searchable after 30 s', text)
        self.assertEqual(self.naps, [10, 10, 10])                # it asked the stack every 10 s
        self.now += 60                                           # "wait and run again", too early
        code, text = self.send('--no-canary', '--settle', '30')
        self.assertEqual((code, len(self.posts())), (3, 1), 'the second run sent again:\n' + text)
        self.assertIn('HELD 6: handed to HEC before, not on the stack, NOT sent again', text)
        # 120 s: the 30 s the first run waited, the 60 s between the runs and the 30 s this run waited.
        self.assertRegex(text, CANARY + r'  audit +demobot:audit +HOLD \(handed to HEC 120 s ago')
        self.assertIn('DELIVERY UNKNOWN: 6 id(s) that were handed to HEC before are still not on the stack', text)
        code, text = self.send('--no-canary', '--settle', '30', '--resend-unconfirmed')   # under an hour: no effect
        self.assertEqual((code, len(self.posts())), (3, 1), text)
        self.assertIn('--resend-unconfirmed let nothing through', text)
        self.now = NOW + 700                                     # the index caught up
        self.stack.tick(int(self.now) - 300)                     # and the rule kept running
        code, text = self.send('--no-canary', '--settle', '30')
        self.assertEqual((code, len(self.posts())), (0, 1), text)
        self.assertEqual(self.copies(), dict((ident, 1) for ident in STAGED_IDS))
        self.assertEqual(sorted(self.ledger('confirmed')[-1]['ids']), sorted(STAGED_IDS))

    def test_a_released_id_whose_new_request_is_refused_is_still_held_by_the_next_run(self):
        self.stack.hec_script, self.stack.index_lag = ['lost'], 10 ** 6   # taken, and not searchable for days
        self.assertEqual(self.send('--no-canary', '--settle', '10')[0], 3)
        self.now = NOW + 3700
        self.stack.tick(int(self.now) - 300)
        self.stack.hec_script = [('answer', 403, {'text': 'Invalid token', 'code': 4}, False)]   # an expired token
        code, text = self.send('--no-canary', '--settle', '10', '--resend-unconfirmed')
        self.assertEqual((code, len(self.posts())), (1, 2), text)
        self.assertEqual(self.ledger('outcome')[-1]['state'], 'refused')
        code, text = self.send('--no-canary', '--settle', '10')       # no override: the first request is still open
        self.assertEqual((code, len(self.posts())), (3, 2), text)
        self.assertIn('HELD 6: handed to HEC before, not on the stack, NOT sent again', text)

    def test_a_second_file_of_the_same_bundle_holds_what_the_first_handed_over(self):
        self.stack.hec_script, self.stack.index_lag = ['lost'], 10 ** 6
        self.assertEqual(self.send('--no-canary', '--settle', '10')[0], 3)
        copy = self.path('again.json')                         # a re-export: same id, a new path, no ledger beside it
        shutil.copyfile(self.bundle, copy)
        os.chmod(copy, 0o600)
        code, text = self.send('--no-canary', '--settle', '10', bundle=copy)
        self.assertEqual((code, len(self.posts())), (3, 1), 'the second file sent again:\n' + text)
        self.assertIn('HELD 6: handed to HEC before, not on the stack, NOT sent again', text)
        self.assertFalse(os.path.exists(copy + '.ledger.jsonl') and tool.read_ledger(
            text_of(copy + '.ledger.jsonl'), STACK_GUID)[0])           # it put nothing new on record as handed
        journal = os.path.join(self.state_dir, 'journal.jsonl')
        self.assertEqual(stat.S_IMODE(os.stat(journal).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.state_dir).st_mode) & 0o077, 0)

    def test_another_search_head_of_the_same_stack_still_holds_what_was_handed_over(self):
        self.stack.hec_script, self.stack.index_lag = ['lost'], 10 ** 6
        code, text = self.send('--no-canary', '--settle', '10')
        self.assertEqual(code, 3, text)
        self.assertIn('the ledger: stack GUID {} and its HEC endpoint'.format(STACK_GUID), text)
        self.stack.guid = '5CA1AB1E-0000-4000-8000-00000000F0AA'          # --stack reaches another search head
        code, text = self.send('--no-canary', '--settle', '10')
        self.assertEqual((code, len(self.posts())), (3, 1), 'sent again through another search head:\n' + text)
        self.assertIn('HELD 6: handed to HEC before, not on the stack, NOT sent again', text)
        self.assertEqual({line['hec'] for line in self.ledger()}, {tool.ledger_key(
            tool.HecTarget('http', '127.0.0.1', int(self.hec_url.split(':')[2].split('/')[0]), '', ''),
            'gen_ai_log')})

    def test_a_live_copy_never_confirms_what_this_bundle_handed_over(self):
        self.stack.hec_script, self.stack.index_lag = ['lost'], 10 ** 6
        self.assertEqual(self.send('--no-canary', '--settle', '10')[0], 3)
        for raw, time_text, sourcetype, log_type in STAGED:      # the same events arrive live meanwhile
            self.stack.add(raw, time_text, sourcetype, log_type, host=HOST)
        code, text = self.send('--no-canary', '--settle', '10')
        self.assertEqual((code, len(self.posts())), (3, 1), text)
        self.assertIn('6 id(s) that were handed to HEC before show only a copy that is not theirs', text)
        self.assertEqual(self.ledger('confirmed'), [])

    def test_a_slow_index_is_waited_for_and_past_settle_it_is_exit_3_without_a_second_request(self):
        self.stack.index_lag = 25
        code, text = self.send('--settle', '60')
        self.assertEqual(code, 0, text)
        self.assertEqual(self.naps, [10] * 9)                    # three looks for each canary request and the rest
        self.assertEqual((len(self.posts()), self.copies()), (3, dict((ident, 1) for ident in STAGED_IDS)))
        self.restart()
        self.stack.index_lag = 500
        code, text = self.send('--settle', '20')
        self.assertEqual((code, len(self.posts())), (3, 1), text)       # the canary was accepted and is not seen
        self.assertIn('DELIVERY UNKNOWN: the canary: 1 of 1 event(s) handed to HEC are not searchable after 20 s', text)
        self.now += 100
        code, text = self.send('--settle', '20')                 # nothing new goes before the canary is accounted for
        self.assertEqual((code, len(self.posts())), (3, 1), text)
        self.assertIn('WAITING 5: nothing new is sent before the event(s) handed over earlier are on the stack', text)
        self.assertRegex(text, STAGED_IDS[0] + r'  audit +demobot:audit +WAIT ')
        self.assertIn('5 more id(s) were not sent in this run.', text)
        self.now += 500
        self.stack.index_lag = 0
        code, text = self.send('--settle', '20')                 # the canary is there now: it proves its own kind only
        self.assertEqual((code, self.copies()), (0, dict((ident, 1) for ident in STAGED_IDS)), text)
        self.assertEqual([post['body'].count(b'"resend":"true"') for post in self.posts()], [1, 1, 2, 2])
        self.assertIn('the canary: one event first, alone ({})'.format(KIND_CANARIES[0]), text)

    def hec_goes_away(self, back_after):
        """echo and sleep for a run during which HEC stops listening after the
        health check and is back after `back_after` sleeps (None: never)."""
        port = int(self.hec_url.split(':')[2].split('/')[0])

        def echo(line=''):
            self.echo(line)
            if str(line).startswith('Sending to HEC'):
                self.stack.stop_hec()

        def nap(seconds):
            self.nap(seconds)
            if back_after is not None and len(self.naps) == back_after:
                self.stack.start_hec(port)
        return {'echo': echo, 'sleep': nap}

    def test_a_refused_connection_is_tried_again_because_nothing_left_this_machine(self):
        code, text = self.send(**self.hec_goes_away(back_after=2))
        self.assertEqual(code, 0, text)
        self.assertEqual(self.naps, [5, 15])
        self.assertEqual(self.copies(), dict((ident, 1) for ident in STAGED_IDS))
        self.assertIn('not sent, nothing was indexed (no request left this machine (no connection '
                      '(ConnectionRefusedError))): again in 5 s', text)
        self.assertEqual([(line['kind'], line.get('state')) for line in self.ledger()][1:3],
                         [('intent', None), ('outcome', 'accepted')])       # one intent for the three attempts

    def test_after_5_15_and_45_seconds_it_gives_up_and_the_next_run_may_send(self):
        code, text = self.send(**self.hec_goes_away(back_after=None))
        self.assertEqual((code, self.naps, self.copies()), (1, [5, 15, 45], {}), text)
        self.assertIn('STOPPED: HEC did not take a request of 1 event(s) (not sent; no request left this machine', text)
        self.assertIn('Nothing of it was indexed and nothing after it was sent', text)
        self.assertEqual(self.ledger('outcome')[-1]['state'], 'not sent')
        self.hec_url = self.stack.start_hec()
        code, text = self.send()                                 # "not sent" proves nothing was indexed: not held
        self.assertEqual((code, self.copies()), (0, dict((ident, 1) for ident in STAGED_IDS)), text)
        self.assertNotIn('HELD', text)

    def test_hecs_own_busy_answers_are_tried_again_and_only_those(self):
        busy = [(503, 'Server is busy', 9), (429, 'Queue is at capacity', 26), (503, 'Server is shutting down', 23),
                (429, 'ACK channel is at capacity', 27)]
        steps = [('answer', status, {'text': words, 'code': code}, False) for status, words, code in busy]
        self.stack.hec_script = steps[:3] + ['ok', steps[3], 'ok']
        code, text = self.send()
        self.assertEqual(code, 0, text)
        self.assertEqual((self.naps, len(self.posts())), ([5, 15, 45, 5], 7))     # 4 + 2 tries, then the rest
        self.assertEqual(self.copies(), dict((ident, 1) for ident in STAGED_IDS))
        self.assertIn('(HTTP 503, HEC code 9 (Server is busy)): again in 5 s', text)
        self.assertIn('(HTTP 429, HEC code 26 (Queue is at capacity)): again in 15 s', text)

    def test_a_503_or_429_that_is_not_hecs_own_is_sent_once_and_never_again(self):
        gateway = '<html><body>upstream timed out</body></html>'
        for status, body, taken in ((503, gateway, True), (503, gateway, False), (429, '', True),
                                    (503, {'text': 'HEC is unhealthy, queues are full', 'code': 18}, True)):
            with self.subTest(status=status, taken=taken):
                self.restart()
                self.stack.hec_script, self.stack.index_lag = [('answer', status, body, taken)], 900
                code, text = self.send('--no-canary', '--settle', '20')
                self.assertEqual((code, len(self.posts())), (3, 1), text)       # one POST, exit 3
                self.assertEqual(self.naps, [10, 10])                          # it only asked the stack: no retry wait
                self.assertEqual(self.copies(), dict((ident, 1) for ident in STAGED_IDS) if taken else {})
                self.assertEqual(self.ledger('outcome')[-1]['state'], 'unknown')
                self.assertIn('They are NOT sent again', text)
                self.assertNotIn('upstream', text)                              # a gateway's page is never printed
                self.now += 30
                code, text = self.send('--no-canary', '--settle', '10')
                self.assertEqual((code, len(self.posts())), (3, 1), text)

    def test_every_other_answer_is_followed_by_a_look_at_the_stack_never_by_a_second_request(self):
        for status, body in ((500, {'text': 'Internal server error', 'code': 8}), (502, '<html>Bad Gateway</html>'),
                             (404, ''), (302, ''), (200, ''), (200, {'text': 'HEC is healthy', 'code': 17}),
                             (408, ''), (201, {'text': 'Success', 'code': 0})):
            with self.subTest(status=status, body=str(body)[:20]):
                self.restart()
                self.stack.hec_script = [('answer', status, body, True)] * 3
                code, text = self.send()
                self.assertEqual((code, len(self.posts())), (0, 3), text)       # the stack showed them: confirmed
                self.assertEqual(self.copies(), dict((ident, 1) for ident in STAGED_IDS))
                self.assertEqual([line['state'] for line in self.ledger('outcome')], ['unknown'] * 3)
                self.assertEqual(len(self.ledger('confirmed')), 3)

    def test_200_with_code_24_or_25_is_accepted(self):
        self.stack.hec_script = [('answer', 200, {'text': 'Queue is approaching capacity', 'code': 24}, True),
                                 ('answer', 200, {'text': 'ACK is approaching capacity', 'code': 25}, True)]
        code, text = self.send()
        self.assertEqual((code, len(self.posts()), self.naps), (0, 3, []), text)
        self.assertEqual([line['state'] for line in self.ledger('outcome')], ['accepted'] * 3)
        self.assertIn('1 event(s) accepted by HEC (HTTP 200, HEC code 24 (Queue is approaching capacity))', text)

    def test_more_than_50_events_go_in_requests_of_at_most_50(self):
        path, ids = self.big_bundle(120)
        code, text = self.send(bundle=path)
        self.assertEqual(code, 0, text)
        self.assertEqual([post['body'].count(b'"resend":"true"') for post in self.posts()], [1, 50, 50, 19])
        self.assertEqual(self.copies(), dict((ident, 1) for ident in ids))
        self.assertIn('[SKIP] R6. the Duo half - the bundle has no sign-in with a Duo transaction id', text)
        self.assertEqual(self.kinds_of_stack().count('present'), 3 + 1 + 3)     # 40 ids a search: R7, canary, the end

    def test_a_413_halves_the_request_and_one_event_that_is_too_large_stops_the_run(self):
        path, ids = self.big_bundle(12)
        self.stack.hec_max_bytes = 3000                          # this HEC takes less than the 11 events need
        code, text = self.send(bundle=path)
        self.assertEqual(code, 0, text)
        self.assertEqual([post['body'].count(b'"resend":"true"') for post in self.posts()], [1, 11, 5, 6])
        self.assertEqual([line['state'] for line in self.ledger('outcome')],
                         ['accepted', 'too large', 'accepted', 'accepted'])
        self.assertEqual(self.copies(), dict((ident, 1) for ident in ids))
        self.assertIn('11 event(s) are too large for one request (HTTP 413, ', text)
        self.restart()
        path, ids = self.big_bundle(3)
        self.stack.hec_max_bytes = 100
        code, text = self.send(bundle=path)
        self.assertEqual((code, len(self.posts()), self.copies()), (1, 1, {}), text)
        self.assertIn('STOPPED: HEC did not take a request of 1 event(s) (too large; HTTP 413', text)
        self.now += 5
        code, text = self.send(bundle=path)                      # a 413 proves nothing was indexed: not held
        self.assertNotIn('HELD', text)
        self.assertEqual(len(self.posts()), 2)

    def test_a_413_on_two_events_splits_them_one_and_one(self):
        """Halving stops only at one event: a request of two that is too large
        is split 1+1, not given up (review finding tests-02)."""
        path, ids = self.big_bundle(3)
        bundle = tool.load_bundle(path)
        lines = [len(tool.event_line(event, bundle['bundle_id']).encode('utf-8'))
                 for event in bundle['events'] if event['id'] != ids[0]]           # all but the canary
        self.stack.hec_max_bytes = max(lines) + 1                # each event fits, the two together do not
        code, text = self.send(bundle=path)
        self.assertEqual(code, 0, text)
        self.assertEqual([post['body'].count(b'"resend":"true"') for post in self.posts()], [1, 2, 1, 1])
        self.assertEqual([line['state'] for line in self.ledger('outcome')],
                         ['accepted', 'too large', 'accepted', 'accepted'])
        self.assertEqual(self.copies(), dict((ident, 1) for ident in ids))

    def test_a_duplicate_of_an_id_this_run_did_not_send_seen_after_sending_stops_the_run(self):
        """The last presence poll is the only guard for an id that was on the
        stack before: judge() checks only the ids this run sent (review finding
        tests-01)."""
        self.assertEqual(self.send()[0], 0)
        polls = {'n': 0}

        def doubled(row):
            if row['rs_id'] == STAGED_IDS[0]:
                polls['n'] += 1
                if polls['n'] > 1:                               # R7 sees it once; the last poll twice
                    return dict(row, copies='2')
            return row
        self.stack.rewrite_present = doubled
        self.now += 5
        code, text = self.send()
        self.assertEqual((code, polls['n'] > 1), (1, True), text)
        self.assertIn('STOPPED: after sending, the stack holds 1 id(s) twice or in another form: ' + STAGED_IDS[0],
                      text)
        self.assertNotIn('SENT:', text)

    def test_an_answer_is_still_read_when_writing_the_request_failed(self):
        """splunkd answers 413 from the headers and closes while the body is
        still being written: request() then raises, and the 413 is there."""
        said = []

        class Answer(object):
            def __init__(self, status, body):
                self.status, self.body = status, body

            def read(self, limit=None):
                return self.body

        class Connection(object):
            def __init__(self, steps):
                self.steps = steps

            def connect(self):
                self.step('connect')

            def request(self, *args, **kwargs):
                self.step('request')

            def getresponse(self):
                return self.step('answer')

            def step(self, name):
                said.append(name)
                found = self.steps.get(name)
                if isinstance(found, Exception):
                    raise found
                return found

            def close(self):
                said.append('close')

        def post(**steps):
            class Client(tool.Hec):
                def _connection(self):
                    return Connection(steps)
            del said[:]
            outcome = Client(tool.HecTarget('http', '127.0.0.1', 9, 'fixture-hec-token-0001', 'a test')).post(b'{}')
            self.out.append(outcome.detail)
            return outcome.state, list(said)

        broken = BrokenPipeError('Authorization: Splunk fixture-hec-token-0001')
        self.assertEqual(post(request=broken, answer=Answer(413, b'')),
                         ('too large', ['connect', 'request', 'answer', 'close']))
        self.assertEqual(post(request=broken, answer=ConnectionResetError())[0], 'unknown')
        self.assertEqual(post(answer=socket.timeout())[0], 'unknown')
        self.assertEqual(post(connect=ConnectionRefusedError()), ('not sent', ['connect', 'close']))
        self.assertEqual(post(connect=ssl.SSLError('bad'))[0], 'not sent')
        self.assertEqual(post(answer=Answer(200, b'{"text":"Success","code":0}'))[0], 'accepted')
        self.assertNotIn('fixture-hec-token-0001', '\n'.join(self.out))

    def test_a_real_413_from_the_headers_is_too_large_or_unknown_and_never_not_sent(self):
        """Over a real socket: the fake answers 413 from the headers and
        closes with the 600 kB body unread. Whether the answer survives the
        reset is the kernel's call, so both honest readings are accepted."""
        target = tool.HecTarget('http', '127.0.0.1', int(self.hec_url.split(':')[2].split('/')[0]),
                                self.stack.hec_token, 'a test')
        for size in (1000, 600000):
            with self.subTest(size=size):
                self.stack.hec_script = ['early413']
                outcome = tool.Hec(target, timeout=10).post(b'x' * size)
                self.assertIn(outcome.state, ('too large',) if size == 1000 else ('too large', 'unknown'))
                self.assertIsNone(self.posts()[-1]['body'], 'the fake read the body before it answered')

    def test_a_400_past_the_first_event_is_unknown_and_only_an_hour_and_the_override_send_the_rest_again(self):
        self.stack.hec_script = [('partial', 3)]                 # events 0 to 2 are indexed, 3 to 5 are not
        code, text = self.send('--no-canary', '--settle', '10')
        self.assertEqual((code, len(self.posts())), (3, 1), text)
        self.assertEqual(self.copies(), dict((ident, 1) for ident in STAGED_IDS[:3]))
        self.assertIn('3 of 6 event(s) handed to HEC are not searchable after 10 s', text)
        last = self.ledger('outcome')[-1]
        self.assertEqual((last['state'], last['http'], last['code']), ('unknown', 400, 6))
        self.now += 600
        code, text = self.send('--no-canary', '--settle', '10', '--resend-unconfirmed')
        self.assertEqual((code, len(self.posts())), (3, 1), text)       # ten minutes are not an hour
        self.assertIn('HELD 3: handed to HEC before, not on the stack, NOT sent again', text)
        self.assertIn('--resend-unconfirmed let nothing through', text)
        self.now = NOW + 3700
        self.stack.tick(int(self.now) - 300)
        code, text = self.send('--no-canary', '--settle', '10')         # an hour, without the override
        self.assertEqual((code, len(self.posts())), (3, 1), text)
        code, text = self.send('--no-canary', '--settle', '10', '--resend-unconfirmed')
        self.assertEqual(code, 0, text)
        self.assertEqual(self.copies(), dict((ident, 1) for ident in STAGED_IDS))
        self.assertEqual(self.posts()[-1]['body'].count(b'"resend":"true"'), 3)
        self.assertIn('3 sent AGAIN (--resend-unconfirmed): if the stack did take one, it becomes a duplicate', text)
        self.assertRegex(text, STAGED_IDS[3] + r'  \S+ +\S+ +SEND AGAIN \(--resend-unconfirmed: handed to HEC 37\d\d s')
        self.assertEqual(sorted(self.ledger('released')[0]['ids']), sorted(STAGED_IDS[3:]))

    def test_the_intent_is_on_disk_before_the_request_so_a_run_that_dies_is_never_followed_by_a_second_send(self):
        real, self.stack.index_lag = tool.Hec.post, 900
        self.addCleanup(setattr, tool.Hec, 'post', real)

        def dies(hec, body):
            self.assertEqual([line['kind'] for line in self.ledger()], ['run', 'intent'])   # already on disk
            real(hec, body)                                      # the stack takes the request ...
            raise KeyboardInterrupt()                            # ... and the run dies before it reads the answer

        tool.Hec.post = dies
        with self.assertRaises(KeyboardInterrupt):
            self.send('--no-canary')
        tool.Hec.post = real
        self.assertEqual([line['kind'] for line in self.ledger()], ['run', 'intent'])       # no outcome was written
        self.assertEqual(sorted(self.ledger('intent')[0]['ids']), sorted(STAGED_IDS))
        self.now += 30
        code, text = self.send('--no-canary', '--settle', '20')
        self.assertEqual((code, len(self.posts())), (3, 1), 'a run after a crash sent again:\n' + text)
        self.assertIn('HELD 6', text)
        self.now = NOW + 1000
        self.stack.tick(int(self.now) - 300)
        code, text = self.send('--no-canary')
        self.assertEqual((code, len(self.posts()), self.copies()), (0, 1, dict((ident, 1) for ident in STAGED_IDS)))

    def test_two_runs_on_one_bundle_cannot_send_side_by_side(self):
        second, self.stack.index_lag = [], 15
        copy = self.path('again.json')                           # the same bundle at another path: the same lock
        shutil.copyfile(self.bundle, copy)
        os.chmod(copy, 0o600)

        def nap(seconds):
            self.nap(seconds)
            if not second:
                second.append(None)                              # while the first run waits for its canary:
                second[:] = [self.send(), self.send('--dry-run'), self.send(bundle=copy)]
        code, text = self.send(sleep=nap)
        self.assertEqual(code, 0, text)
        for other, said in second:
            self.assertEqual(other, 2)
            self.assertIn('REFUSED: another `send` on this machine is running (one send at a time, whatever the '
                          'bundle', said)                                  # the journal's lock is taken first
        self.assertEqual((len(self.posts()), self.copies()), (3, dict((ident, 1) for ident in STAGED_IDS)))
        # R7, three looks for each canary request, three at the end: the refused runs read nothing of the stack.
        self.assertEqual(self.kinds_of_stack().count('present'), 1 + 3 + 3 + 3)

    def test_a_token_hec_refuses_stops_the_run_and_is_never_printed(self):
        self.wrong_token_ok = True
        wrong = dict(self.stack_env, **{tool.ENV_HEC_TOKEN: 'fixture-wrong-hec-token-0002'})
        code, text = self.send(env=wrong)
        self.assertEqual((code, len(self.posts()), self.copies()), (1, 1, {}), text)
        self.assertIn('STOPPED: HEC did not take a request of 1 event(s) (refused; HTTP 403, HEC code 4 (Invalid '
                      'token))', text)
        self.assertNotIn('fixture-wrong-hec-token-0002', text + text_of(self.ledger_file))
        code, text = self.send()                                 # refused proves nothing was indexed: not held
        self.assertEqual((code, self.copies()), (0, dict((ident, 1) for ident in STAGED_IDS)), text)


class PreconditionTests(StackCase):
    """R1 to R8, one failure at a time. A failed step sends nothing; R1 and
    R2 fail before anything is contacted at all."""

    def refused_send(self, *extra, **options):
        """The text of a `send` that is refused before any contact (exit 2)."""
        code, text = self.send(*extra, **options)
        self.assertEqual(code, 2, text)
        self.assertIn('REFUSED: ', text)
        self.assertEqual((self.stack.requests, self.stack.hec_requests), ([], []), 'something was contacted')
        self.assertFalse(os.path.lexists(self.ledger_file), 'a refused run made a ledger')
        return text

    def failed_send(self, *extra, **options):
        """The text of a `send` that a step stops (exit 1): nothing reached HEC but, at most, its health check."""
        before = self.copies()
        code, text = self.send(*extra, **options)
        self.assertEqual(code, 1, text)
        self.assertEqual((self.posts(), self.copies()), ([], before), 'a failed step sent something')
        self.assertRegex(text, r'NOT SENT: \d step\(s\) failed\. Nothing was sent to HEC\.')
        return text

    def hec_file(self, mode=0o600, **content):
        path = self.path('stack.json')
        if os.path.lexists(path):
            os.unlink(path)
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), 'w') as handle:
            json.dump(content, handle)
        os.chmod(path, mode)
        return path

    def test_r1_the_bundle_is_private_approved_and_unedited(self):
        approved = self.written()
        fresh = self.path('fresh.bundle.json')
        tool.write_bundle(fresh, dict(approved, review=None))
        self.assertIn('--bundle is not approved as it now is', self.refused_send(bundle=fresh))
        edited = json.loads(text_of(self.bundle))
        edited['census']['pad_seconds'] = 1
        with io.open(self.bundle, 'w', encoding='utf-8') as handle:
            handle.write(tool.bundle_text(edited))
        self.assertIn('--bundle is not approved as it now is', self.refused_send())
        os.chmod(fresh, 0o644)
        self.assertIn('readable or writable by others (mode 644)', self.refused_send(bundle=fresh))
        link = self.path('link.bundle.json')
        os.symlink(fresh, link)
        self.assertIn('--bundle cannot be read (missing, or a symlink)', self.refused_send(bundle=link))
        self.assertIn('--bundle cannot be read', self.refused_send(bundle=self.path('none.json')))

    def test_r2_the_hec_file_is_private_whole_for_this_index_and_not_the_lab5_one(self):
        good = dict(hec_url=self.hec_url, hec_token=self.stack.hec_token, index='gen_ai_log', sourcetype='gen_ai:json')
        no_token = {tool.ENV_STACK_PASSWORD: self.stack.password}
        cii = 'fixture-cii-token-0003'
        cases = ((dict(good), 0o644, 'readable or writable by others (mode 644)'),
                 (dict(good, index='cisco_identity'), 0o600, 'for another index than the bundle\'s (gen_ai_log)'),
                 ({'hec_url': self.hec_url}, 0o600, '--hec-file has no hec_url and hec_token'),
                 ({'stack': 'room1', 'cii_hec_url': self.hec_url, 'cii_hec_token': cii}, 0o600,
                  '--hec-file is the file `show_postdeploy.py --lab5 --out` wrote'),
                 (dict(good, hec_url=self.hec_url.replace('/event', '/raw')), 0o600, 'never /raw'),
                 (dict(good, hec_token='two words'), 0o600, 'the HEC token is not one plain value'))
        for content, mode, said in cases:
            with self.subTest(said=said):
                text = self.refused_send('--hec-file', self.hec_file(mode, **content), hec=False, env=no_token)
                self.assertIn(said, text)
                self.assertNotIn(cii, text)
        with io.open(self.path('stack.json'), 'w', encoding='utf-8') as handle:
            handle.write('[1, 2]')
        self.assertIn('--hec-file is not the JSON object', self.refused_send(
            '--hec-file', self.path('stack.json'), hec=False, env=no_token))
        code, text = self.send('--hec-file', self.hec_file(**good), hec=False, env=no_token)
        self.assertEqual((code, self.copies()), (0, dict((ident, 1) for ident in STAGED_IDS)), text)
        self.assertIn('[  OK] R2. HEC - token from --hec-file; the endpoint is the stack\'s; index gen_ai_log', text)

    def test_r2_the_hec_url_is_https_the_event_endpoint_and_the_stacks_own(self):
        other = 'https://http-inputs-room2.example.test/services/collector/event'
        for url, env, said in (
                (self.hec_url, {tool.ENV_STACK_PASSWORD: self.stack.password},
                 'set the HEC token in $STAGED_RESEND_HEC_TOKEN'),
                (other, self.stack_env, 'the HEC host is not the one of the stack named with --stack'),
                ('http://http-inputs-room1.example.test/services/collector/event', self.stack_env, 'must be https'),
                (self.hec_url.replace('/event', ''), self.stack_env, 'must end in /services/collector/event'),
                (self.hec_url + '?token=x', self.stack_env, 'with no user name, query or fragment'),
                (self.hec_url, dict(self.stack_env, **{tool.ENV_HEC_TOKEN: 'line\nbreak-fixture'}),
                 'not one plain value')):
            with self.subTest(said=said):
                self.assertIn(said, self.refused_send(hec_url=url, env=env))
        for stack, hec, fits in (('room1.splunkcloud.com', 'http-inputs-room1.splunkcloud.com', True),
                                 ('room1.splunkcloud.com', 'http-inputs.room1.splunkcloud.com', True),
                                 ('room1.splunkcloud.com', 'room1.splunkcloud.com', True),
                                 ('room1.splunkcloud.com', 'http-inputs-room10.splunkcloud.com', False),
                                 ('room1.splunkcloud.com', 'http-inputs-room2.splunkcloud.com', False),
                                 ('room1.splunkcloud.com', '127.0.0.1', False), ('127.0.0.1', 'localhost', True),
                                 ('localhost', 'http-inputs-room1.splunkcloud.com', False)):
            self.assertEqual(tool.hec_belongs(stack, hec), fits, (stack, hec))

    def test_r3_the_stack_answers_takes_the_credential_and_is_not_where_the_bundle_came_from(self):
        hec = {tool.ENV_HEC_TOKEN: self.stack.hec_token}
        code, text = self.send(stack=self.url, env=dict(hec, **{tool.ENV_STACK_PASSWORD: self.fake.password}))
        self.assertEqual((code, self.stack.hec_requests), (2, []), text)
        self.assertIn('REFUSED: --stack is the Splunk this bundle was exported from', text)
        for env, said in ((dict(hec, **{tool.ENV_STACK_PASSWORD: 'fixture-wrong-password'}),
                           '--stack did not accept the credential (HTTP 401). With a password, check the user name'),
                          (hec, 'set exactly one of $SPLUNK_ADMIN_PASSWORD and $SPLUNK_ADMIN_TOKEN'),
                          (dict(self.stack_env, **{tool.ENV_STACK_TOKEN: self.stack.token}), 'both are set')):
            with self.subTest(said=said):
                code, text = self.send(env=env)
                self.assertEqual((code, self.stack.hec_requests), (2, []), text)
                self.assertIn(said, text)
        self.stack.ta_version = '1.8.0'
        code, text = self.send()
        self.assertEqual((code, self.stack.hec_requests), (2, []), text)
        self.assertIn('--stack has no TA-gen_ai_cim 1.9.0 or later', text)
        self.stack.ta_version, self.stack.redirect_to = '1.9.0', 'http://127.0.0.1:1'
        code, text = self.send()
        self.assertEqual(code, 2, text)
        self.assertIn('a redirect. It is never followed', text)
        self.assertFalse(os.path.lexists(self.ledger_file))

    def test_r3_a_token_or_another_account_name_works_and_the_override_is_named_before_any_request(self):
        self.stack.user = 'sc_admin'                             # the admin account of a Cloud stack
        code, text = self.send()
        self.assertEqual(code, 2, text)
        self.assertIn('check the user name option', text)
        self.assertEqual(self.send('--username', 'sc_admin', '--dry-run')[0], 0)
        token = {tool.ENV_STACK_TOKEN: self.stack.token, tool.ENV_HEC_TOKEN: self.stack.hec_token}
        self.assertEqual(self.send('--dry-run', env=token)[0], 0)
        self.assertEqual(self.stack.requests[-1]['headers']['Authorization'], 'Bearer ' + self.stack.token)
        with socket.socket() as taken:                           # an address nothing listens on
            taken.bind(('127.0.0.1', 0))
            closed = 'https://127.0.0.1:{}'.format(taken.getsockname()[1])
        code, text = self.send('--no-verify-splunkd', stack=closed)
        self.assertEqual(code, 2, text)
        self.assertIn('certificate of port 8089: NOT VERIFIED (--no-verify-splunkd): the credential goes to a server '
                      'nobody authenticated', text)
        self.assertIn('no answer from --stack', text)
        self.assertEqual(tool.hec_tls_policy('https', 'http-inputs-room1.example.test', None),
                         (True, 'verified against the system trust store'))
        self.assertEqual(tool.hec_tls_policy('https', '127.0.0.1', None), (False, 'not verified (a loopback address)'))
        self.assertTrue(tool.hec_tls_policy('https', '127.0.0.1', 'ca.pem')[0])
        self.assertFalse(tool.hec_tls_policy('http', '127.0.0.1', 'ca.pem')[0])

    def test_r4_an_index_the_account_cannot_search_stops_the_run_before_what_the_stack_holds_is_read(self):
        self.stack.hidden.add('gen_ai_log')                      # there, but not for this account's role
        text = self.failed_send()
        self.assertRegex(text, r'\[FAIL\] R4\. index gen_ai_log - this account can search no index of that name')
        self.assertIn('[SKIP] R7. what the stack holds - not read: without a searchable index "nothing there" '
                      'proves nothing', text)
        self.assertNotIn('present', self.kinds_of_stack())
        self.assertNotIn('Per id', text)
        self.assertEqual(self.ledger(), [])                      # the lock was taken, and nothing was written

    def test_r4_the_index_is_the_one_the_stacks_identity_macro_reads(self):
        self.stack.macro_index['genai_identity_ai_events'] = 'ai_main'
        self.stack.indexes.add('ai_main')
        text = self.failed_send()
        self.assertIn('the stack\'s macro genai_identity_ai_events reads index ai_main: Identity Activity and the '
                      'joined rule would never read a copy in gen_ai_log', text)
        self.stack.macro_index['genai_identity_ai_events'] = 'gen_ai_log'
        for change in ({'macro_status': 403}, {'macro_status': 404},
                       {'macro_text': '(index=gen_ai_log OR index=ai_main) `exclude_scoring_sourcetypes`'}):
            with self.subTest(change=change):
                vars(self.stack).update(macro_status=200, macro_text=None)
                vars(self.stack).update(change)
                code, text = self.send('--dry-run')
                self.assertEqual(code, 0, text)
                self.assertIn('NOT CHECKED: which index genai_identity_ai_events reads (', text)
                self.assertIn('the shipped definition reads gen_ai_log', text)
        # A bundle of another index (a scratch rehearsal) needs a stack whose macro reads that index.
        vars(self.stack).update(macro_status=200, macro_text=None)
        path, ids = self.big_bundle(3, index='scratch_ai')
        self.stack.indexes.add('scratch_ai')
        self.assertIn('reads index gen_ai_log', self.failed_send(bundle=path))
        self.stack.macro_status = 403
        self.assertIn('could not be told (the stack did not show the macro (HTTP 403)), and the bundle\'s index is '
                      'not gen_ai_log', self.failed_send(bundle=path))
        self.stack.macro_status, self.stack.macro_index['genai_identity_ai_events'] = 200, 'scratch_ai'
        code, text = self.send(bundle=path)
        self.assertEqual((code, self.copies()), (0, {}), text)   # copies() counts gen_ai_log: nothing went there
        self.assertEqual(sorted(self.stack.own_id(event) for event in self.stack.events
                                if event['index'] == 'scratch_ai'), sorted(ids))

    def test_r4_the_index_keeps_the_copy_and_a_stack_that_reports_no_retention_needs_the_operators_number(self):
        self.stack.retention_seconds = 5 * 86400
        self.assertIn('it keeps 5 days (read from the stack) and the oldest event is 0.1 days old: the copy would '
                      'be frozen within 7 days of arriving', self.failed_send())
        self.stack.retention_seconds, self.stack.index_disabled = 90 * 86400, True
        self.assertIn('the index is disabled on the stack', self.failed_send())
        self.stack.index_disabled = False
        code, text = self.send('--dry-run', '--retention-days', '30')
        self.assertEqual(code, 0, text)
        self.assertIn('keeps 90 days (read from the stack; --retention-days was not needed and is not used)', text)
        for status in (403, 404):                                # a search head that does not serve data/indexes
            with self.subTest(status=status):
                self.stack.index_status = status
                text = self.failed_send()
                self.assertIn('the stack does not report the index\'s retention (data/indexes answered HTTP {}): '
                              'state its searchable days with --retention-days N'.format(status), text)
                self.assertIn('STATED with --retention-days, not read', self.failed_send('--retention-days', '3'))
                code, text = self.send('--dry-run', '--retention-days', '90')
                self.assertEqual(code, 0, text)
                self.assertIn('keeps 90 days (STATED with --retention-days, not read (data/indexes answered HTTP '
                              '{}))'.format(status), text)
        requests = len(self.stack.requests)
        for bad in ('ninety', '0', '-5', '99999'):
            code, text = self.send('--retention-days', bad)
            self.assertEqual((code, len(self.stack.requests)), (2, requests), text)
            self.assertIn('--retention-days: expected a whole number from 1 to 36500', text)

    def test_r4_the_events_are_old_enough_to_be_inert_and_young_enough_to_be_judged(self):
        self.now = 1794890520.01 + 899                           # the newest event is under 15 minutes old
        self.assertRegex(self.failed_send(),
                         r'\[FAIL\] R4\. index gen_ai_log - the newest event is under 15 minutes old')
        self.now = 1794890419.556 + 181 * 86400
        self.stack.tick(int(self.now) - 300)
        self.assertIn('the oldest event is over 180 days old: the joined rule reads back 181 days and would never '
                      'judge its copy', self.failed_send())

    def test_r5_the_rule_is_on_and_its_schedule_tiles_index_time(self):
        rule = self.stack.saved[tool.JOINED_RULE]
        shipped = dict(rule)
        cases = (({'disabled': True}, 'it is disabled: enable it first (show_postdeploy.py --duo)'),
                 ({'dispatch.earliest_time': '-10m@m'}, 'its time range is 8 min wide but it runs every 5 min: '
                                                        'index-time slots would overlap'),
                 ({'dispatch.latest_time': '-5m@m'}, 'index-time slots would leave gaps'),
                 ({'cron_schedule': '*/7 * * * *', 'dispatch.earliest_time': '-9m@m'}, 'does not divide the hour'),
                 ({'cron_schedule': '3 * * * *'}, 'its schedule is not every N minutes over -Xm@m to -Ym@m'),
                 ({'dispatch.earliest_time': '-1d@d'}, 'its schedule is not every N minutes'),
                 ({'realtime_schedule': True}, 'realtime_schedule is on: a run the scheduler skips is a slot never'),
                 ({'is_scheduled': False}, 'it is not scheduled'),
                 ({'search': 'search index=gen_ai_log | stats count'}, 'it does not judge by index time'))
        for change, said in cases:
            with self.subTest(change=change):
                rule.clear()
                rule.update(shipped, **change)
                text = self.failed_send()
                self.assertRegex(text, r'\[FAIL\] R5\. the joined rule - ')
                self.assertIn(said, text)
                self.assertIn('(--allow-rule-off sends for the dashboards alone)', text)
        del self.stack.saved[tool.JOINED_RULE]                  # a TA build from before the rule
        self.assertIn('it is not on this stack', self.failed_send())
        self.assertEqual(tool.rule_slot(shipped), (tool.Slot(5, 2), None))
        ten = dict(shipped, **{'cron_schedule': '*/10 * * * *', 'dispatch.earliest_time': '-12min@m'})
        self.assertEqual(tool.rule_slot(ten), (tool.Slot(10, 2), None))

    def test_r5_the_shipped_stanza_passes_the_tools_own_contract(self):
        stanza = read_conf('savedsearches.conf')[tool.JOINED_RULE]
        self.assertEqual(tool.rule_slot(dict(stanza, is_scheduled=stanza['enableSched'])), (tool.Slot(5, 2), None))
        self.assertEqual((stanza['cron_schedule'], stanza['dispatch.earliest_time'], stanza['dispatch.latest_time'],
                          stanza['realtime_schedule'], stanza['disabled']), ('*/5 * * * *', '-7m@m', '-2m@m', '0', '1'))
        self.assertIn('_index_earliest=', stanza['search'])
        self.assertIn('_index_latest=', stanza['search'])

    def test_r5_a_run_is_judged_per_tick_and_a_failing_rule_is_named_with_its_message(self):
        tick = int(NOW) - 300
        del self.stack.ticks[:]                                  # enabled a minute ago: no run yet
        text = self.failed_send()
        self.assertIn('no successful scheduled run in the last 15 min: wait for the next tick plus about two minutes '
                      'and run `send` again', text)
        for kind in ('rule_ticks', 'rule_errors'):               # 2 periods + 5 min, on the STACK's clock
            self.assertEqual((self.last_search(kind)['earliest'], self.last_search(kind)['latest']), ('-15m', 'now'))
        self.stack.tick(tick, 'continued')                       # deferred, not run yet
        self.stack.tick(tick, 'skipped')
        self.assertIn('no successful scheduled run in the last 15 min (1 tick(s) deferred and not run yet)',
                      self.failed_send())
        self.stack.tick(tick, 'success', logged=tick + 200)      # the same tick, run late: lag, not failure
        code, text = self.send('--dry-run')
        self.assertEqual(code, 0, text)
        self.assertIn('last successful tick {}; 1 tick(s) were deferred first (lag, not failure)'.format(
            tool.utc_second(tick)), text)
        self.assertNotIn('rule_errors', self.kinds_of_stack()[-6:])         # nobody asks for errors of a rule that runs
        del self.stack.ticks[:]
        self.stack.tick(int(NOW) - 1200)                         # a run 20 minutes ago is not "running"
        self.assertIn('no successful scheduled run in the last 15 min', self.failed_send())
        # A run that fails writes no status line: only an ERROR line that names the search by its id.
        self.stack.rule_errors = [(int(NOW) - 400, 'old'), (int(NOW) - 100, 'Error in \'lookup\' command: Could not '
                                                           'construct lookup \'x\'. No actions executed')]
        text = self.failed_send()
        self.assertIn('its scheduled runs FAIL (2 error line(s) in the last 15 min): Error in \'lookup\' command: '
                      'Could not construct lookup \'x\'. No actions executed', text)

    def test_r5_the_rules_own_text_must_run_here_whether_or_not_it_opens_with_a_pipe(self):
        self.stack.fail_search['rule_parses'] = 'Error in \'SearchParser\': The search specifies a macro ' \
                                                '\'genai_duo_auth_events\' that cannot be found.'
        text = self.failed_send()
        self.assertIn('its text does not run on this stack (R5, parsing the rule: the search failed on --stack: '
                      'Error in \'SearchParser\': The search specifies a macro', text)
        parse = self.last_search('rule_parses')
        self.assertEqual((parse['earliest'], parse['latest']), ('1', '2'))  # parsed and expanded, nothing read
        self.assertTrue(parse['search'].startswith('search ((`genai_duo_auth_events`'))
        self.assertTrue(parse['search'].endswith(' | stats count as rows'))
        del self.stack.fail_search['rule_parses']
        # A stack whose text of the rule opens with a generating command: `search | tstats` would be FATAL.
        self.stack.saved[tool.JOINED_RULE]['search'] = ('| tstats count where index=duo _index_earliest=-7m '
                                                         '_index_latest=-2m by user')
        code, text = self.send('--dry-run')
        self.assertEqual(code, 0, text)
        self.assertEqual(self.last_search('rule_parses')['search'],
                         '| tstats count where index=duo _index_earliest=-7m _index_latest=-2m by user '
                         '| stats count as rows')

    def test_r5_allow_rule_off_sends_for_the_dashboards_alone_and_says_what_that_costs(self):
        self.stack.saved[tool.JOINED_RULE]['disabled'] = True
        code, text = self.send('--allow-rule-off')
        self.assertEqual((code, self.copies()), (0, dict((ident, 1) for ident in STAGED_IDS)), text)
        self.assertRegex(text, r'\[SKIP\] R5\. the joined rule - it is disabled.*Sent all the same '
                               r'\(--allow-rule-off\): NO FINDING will be raised for this copy')
        self.restart()
        code, text = self.send('--allow-rule-off', '--dry-run')  # given without need: named all the same
        self.assertEqual(code, 0, text)
        self.assertRegex(text, r'\[  OK\] R5\. the joined rule - .*; --allow-rule-off was not needed')

    def test_r6_the_duo_half_of_every_sign_in_is_on_the_stack_exactly_once(self):
        duo = [event for event in self.stack.events if event['duo']]
        signin = [event for event in duo if event['duo']['txid'] == TXID][0]
        self.stack.events.remove(signin)                         # the first Duo poll has not brought it yet
        text = self.failed_send()
        self.assertRegex(text, r'\[FAIL\] R6\. the Duo half - the Duo authentication of 0 of 1 sign-in\(s\) is on '
                               r'the stack exactly once \(0 found at all\)')
        self.assertIn('(--without-duo sends without it)', text)
        self.stack.events.extend([signin, dict(signin)])         # indexed twice (two inputs on one account)
        self.assertIn('of 0 of 1 sign-in(s) is on the stack exactly once (1 found at all)', self.failed_send())
        self.stack.events.remove(signin)
        failure = [event for event in duo if event['duo']['action'] == 'failure'][0]
        self.stack.events.remove(failure)                        # five denials here, six where it was staged
        text = self.failed_send()
        self.assertIn('nina.osei has 5 Duo failure(s) on the stack and had 6 where the bundle was exported', text)
        code, text = self.send('--without-duo')
        self.assertEqual((code, self.copies()), (0, dict((ident, 1) for ident in STAGED_IDS)), text)
        self.assertRegex(text, r'\[SKIP\] R6\. the Duo half - nina.osei has 5 Duo failure.*Sent all the same '
                               r'\(--without-duo\): no chain can form until Duo\'s events arrive')
        self.restart()
        code, text = self.send('--without-duo', '--dry-run')
        self.assertRegex(text, r'\[  OK\] R6\. the Duo half - 1 of 1 sign-in\(s\) paired exactly once; Duo failures: '
                               r'nina.osei 6; --without-duo was not needed')
        half = self.last_search('duo_half')
        self.assertEqual((half['earliest'], half['latest']), (str(1794890419 - 6000), str(1794890520 + 6001)))

    def test_r7_a_conflict_or_a_duplicate_on_the_stack_stops_everything_and_nothing_overrides_it(self):
        raw, time_text, sourcetype, log_type = STAGED[2]
        other = raw.replace('"risk_score":60.0', '"risk_score":61.0')
        self.stack.add(other, time_text, sourcetype, log_type, host=HOST)
        for extra in ((), ('--resend-unconfirmed', '--no-canary', '--allow-rule-off', '--without-duo')):
            text = self.failed_send(*extra)
            self.assertRegex(text, r'\[FAIL\] R7\. what the stack holds - 1 conflict\(s\) and 0 duplicate\(s\): '
                                   + STAGED_IDS[2] + r' \(sha256\)\. Nothing is sent and no option overrides this')
            self.assertRegex(text, STAGED_IDS[2] + r'  governance +gen_ai:json +STOP \(conflict: sha256\)')
        self.restart()
        for _ in range(2):                                       # the same turn twice, live
            self.stack.add(raw, time_text, sourcetype, log_type, host=HOST)
        text = self.failed_send()
        self.assertIn('0 conflict(s) and 1 duplicate(s): {} (copies)'.format(STAGED_IDS[2]), text)
        self.assertRegex(text, STAGED_IDS[2] + r'  governance +gen_ai:json +STOP \(duplicate\)')

    def test_r7_what_only_quotes_an_id_is_not_a_copy_and_another_bundles_copy_is_one(self):
        raw, time_text, sourcetype, log_type = STAGED[3]         # the blocked turn
        action = ('{"timestamp":"2026-11-17T05:00:00Z","action":"suspend_user","simulated":true,"event_id":"'
                  + STAGED_IDS[3] + '","user":"nina.osei"}')    # what the TA's response action writes back
        self.stack.add(action, '1794891600.0', 'ai_cim:response:action', host='sh1', source='ai_defense_response')
        self.stack.add('{"score":0.9,"scored":{"event_id":"' + STAGED_IDS[3] + '"}}', '1794890600.0', 'genai_scoring',
                       host='sh1')                               # a scoring result quotes the id and owns none
        self.stack.add(raw, time_text, sourcetype, log_type, host=HOST,
                       fields={'resend': 'true', 'resend_bundle': 'rs-20261101-aaaaaaaaaaaa',
                               'resend_orig_indextime': '1794890503'})
        code, text = self.send()
        self.assertEqual(code, 0, text)
        self.assertIn('to send 5; on the stack, identical: 1 (live 0, this bundle 0, another bundle 1)', text)
        self.assertEqual(self.copies()[STAGED_IDS[3]], 2)        # the turn, and the response record with its id
        self.assertEqual(self.send()[0], 0)                      # and a second run still sees no duplicate
        self.assertEqual(len(self.posts()), 3)                   # the canary, one of each other kind, the rest

    def test_r7_a_ledger_that_is_not_private_or_not_this_tools_stops_the_run(self):
        victim = self.path('victim.txt')
        with io.open(victim, 'w', encoding='utf-8') as handle:
            handle.write('keep me\n')
        os.symlink(victim, self.ledger_file)
        code, text = self.send()
        self.assertEqual((code, self.posts(), text_of(victim)), (2, [], 'keep me\n'), text)
        self.assertIn('REFUSED: the ledger beside the bundle cannot be opened (a symlink', text)
        os.unlink(self.ledger_file)
        # A dry run only reads the ledger, and it does not read it through a symlink either, not
        # even to a private file (review finding tests-03).
        private = self.path('private.jsonl')
        os.close(os.open(private, os.O_WRONLY | os.O_CREAT, 0o600))
        os.chmod(private, 0o600)
        os.symlink(private, self.ledger_file)
        code, text = self.send('--dry-run')
        self.assertEqual((code, self.posts()), (2, []), text)
        self.assertIn('REFUSED: the ledger beside the bundle cannot be read (a symlink?)', text)
        os.unlink(self.ledger_file)
        with os.fdopen(os.open(self.ledger_file, os.O_WRONLY | os.O_CREAT, 0o644), 'w') as handle:
            handle.write('')
        os.chmod(self.ledger_file, 0o644)
        for extra in ((), ('--dry-run',)):
            code, text = self.send(*extra)
            self.assertEqual((code, self.posts()), (2, []), text)
            self.assertIn('the ledger beside the bundle is readable or writable by others (mode 644)', text)
        os.chmod(self.ledger_file, 0o600)
        with io.open(self.ledger_file, 'w', encoding='utf-8') as handle:
            handle.write('{"kind":"intent","ids":["' + CANARY + '"]}\n')        # not a line of this tool
        code, text = self.send()
        self.assertEqual((code, self.posts()), (2, []), text)
        self.assertIn('the ledger beside the bundle has a line (number 1) that this tool did not write: nothing is '
                      'sent', text)

    def test_r8_an_unhealthy_or_absent_hec_stops_the_run_and_the_health_check_carries_no_token(self):
        self.stack.hec_healthy = False
        text = self.failed_send()
        self.assertIn('[FAIL] R8. HEC health - the HEC endpoint did not say it is healthy (HTTP 503, HEC code 18 '
                      '(HEC is unhealthy, queues are full))', text)
        self.assertEqual([(request['method'], request['path']) for request in self.stack.hec_requests],
                         [('GET', '/services/collector/health')])
        self.assertNotIn('Authorization', self.stack.hec_requests[0]['headers'])
        self.stack.stop_hec()
        self.assertIn('[FAIL] R8. HEC health - no answer from the HEC endpoint (no connection '
                      '(ConnectionRefusedError))', self.failed_send())

    def test_options_are_checked_before_anything_is_contacted(self):
        for extra, said in ((('--settle', 'soon'), '--settle: expected a whole number from 0 to 3600'),
                            (('--settle', '99999'), '--settle: expected a whole number'),
                            (('--wait-finding', '-1'), '--wait-finding: expected a whole number from 0 to 7200'),
                            (('--wait-finding', '7201'), '--wait-finding: expected a whole number from 0 to 7200')):
            self.assertIn(said, self.refused_send(*extra))
        self.assertEqual((self.stack.requests, self.stack.hec_requests), ([], []))

    def test_one_bundle_and_one_ledger_serve_every_stack(self):
        self.stack.hec_script, self.stack.index_lag = ['lost'], 900
        self.assertEqual(self.send('--no-canary', '--settle', '10')[0], 3)       # stack one: unconfirmed
        other = fake_stack.FakeSplunk(guid='5CA1AB1E-0000-4000-8000-00000000F003', clock=lambda: self.now)
        for event in [event for event in self.stack.events if event['duo']]:
            other.events.append(dict(event))
        other.saved[tool.JOINED_RULE]['disabled'] = False
        other.tick(int(NOW) - 300)
        first, self.stack = self.stack, other
        self.addCleanup(other.stop)
        env = {tool.ENV_STACK_PASSWORD: other.password, tool.ENV_HEC_TOKEN: other.hec_token}
        code, text = self.send(stack=other.start(), hec_url=other.start_hec(), env=env)
        self.assertEqual((code, self.copies()), (0, dict((ident, 1) for ident in STAGED_IDS)), text)
        self.assertNotIn('HELD', text)                           # what stack one may hold says nothing here
        self.assertEqual({line['stack'] for line in self.ledger()}, {STACK_GUID, other.guid})
        self.assertEqual(len(first.hec_posts()), 1)

    def test_what_the_stack_indexes_is_the_stored_text_byte_for_byte_whatever_its_json_looks_like(self):
        """One request with two events whose texts a parse-and-write-again
        would change in every way: odd spacing, a line break and a tab between
        keys, unescaped UTF-8, an uppercase hex escape, an escaped solidus,
        numbers written another way and an unread key twice. Literals, never
        json.dumps output."""
        odd = ('{ "event_id" : "5ca1ab1e-0002-4000-8000-000000000201",  "a":1 ,"b" : [ 1,2 ],\n\t"note":"caf'
               + E_ACUTE + ' ' + DASH + ' caf' + U + '00E9 <' + BS + '/x>","small":1E-5,"price":2.50,"k":1,"k":2, '
               '"enduser_id":"nina.osei","user":"nina.osei" }')
        plain = ('{"event_id":"5ca1ab1e-0002-4000-8000-000000000202","tiny":1e-05,"big":12345678901234567890,'
                 '"enduser_id":"nina.osei","user":"nina.osei"}')
        self.assertNotEqual(json.dumps(json.loads(odd), separators=(',', ':')), odd)
        bundle = bundle_of([plain_event(odd, '1794890465.273'), plain_event(plain, '1794890466.5')])
        path = self.path('odd.bundle.json')
        tool.write_bundle(path, tool.approve(bundle, bundle['digest'][:12], NOW))
        self.ledger_file = path + '.ledger.jsonl'
        code, text = self.send('--no-canary', bundle=path)
        self.assertEqual(code, 0, text)
        tail = ',"fields":{{"log_type":"governance","resend":"true","resend_bundle":"{}",' \
               '"resend_orig_indextime":"1794890421"}}}}'.format(bundle['bundle_id'])
        self.assertEqual(self.posts()[0]['body'], (
            '{"time":1794890465.273,"host":"stage-host","source":"demobot:hec","sourcetype":"gen_ai:json",'
            '"index":"gen_ai_log","event":' + odd + tail + '\n'
            '{"time":1794890466.5,"host":"stage-host","source":"demobot:hec","sourcetype":"gen_ai:json",'
            '"index":"gen_ai_log","event":' + plain + tail).encode('utf-8'))
        held = [event for event in self.stack.events if event['index'] == 'gen_ai_log']
        self.assertEqual([(event['raw'], event['time_text']) for event in held],
                         [(odd, '1794890465.273'), (plain, '1794890466.5')])
        self.assertNotIn(E_ACUTE, text)

    def test_the_hec_certificate_is_verified_against_the_ca_file_and_the_token_never_meets_an_unknown_server(self):
        """Not a mock: the fake HEC serves https with a throwaway
        certificate. With another CA as --ca-file the handshake fails, so no
        request reaches it; with its own certificate as --ca-file the copy
        goes through, and so it does unverified, which a loopback address is
        allowed."""
        openssl = shutil.which('openssl')
        if not openssl:
            self.skipTest('no openssl here to make a throwaway certificate')
        made = []
        for name in ('hec', 'other'):
            cert, key = self.path(name + '-cert.pem'), self.path(name + '-key.pem')
            done = subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out',
                                   cert, '-days', '2', '-subj', '/CN=localhost', '-addext',
                                   'subjectAltName=IP:127.0.0.1,DNS:localhost'],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if done.returncode != 0 or not os.path.exists(cert):
                self.skipTest('this openssl could not make a throwaway certificate with a subjectAltName')
            made.append((cert, key))
        self.stack.stop_hec()
        try:
            hec_url = self.stack.start_hec(tls=made[0])
        except (AttributeError, OSError) as exc:
            self.skipTest('this Python cannot serve TLS on loopback ({})'.format(type(exc).__name__))
        self.assertTrue(hec_url.startswith('https://127.0.0.1:'))
        code, text = self.send('--ca-file', made[1][0], hec_url=hec_url)
        self.assertEqual((code, self.stack.hec_requests), (1, []), text)        # not even the health check got there
        self.assertIn('certificate of HEC: verified against the system trust store and --ca-file', text)
        self.assertIn('[FAIL] R8. HEC health - no answer from the HEC endpoint (the certificate did not verify', text)
        target = tool.HecTarget('https', '127.0.0.1', int(hec_url.split(':')[2].split('/')[0]),
                                self.stack.hec_token, 'a test')
        outcome = tool.Hec(target, made[1][0]).post(b'{}')
        self.assertEqual((outcome.state, self.stack.hec_requests), ('not sent', []))
        self.assertIn('the certificate did not verify', outcome.detail)
        code, text = self.send('--ca-file', made[0][0], hec_url=hec_url)
        self.assertEqual((code, self.copies()), (0, dict((ident, 1) for ident in STAGED_IDS)), text)
        code, text = self.send('--dry-run', hec_url=hec_url)
        self.assertEqual(code, 0, text)
        self.assertIn('certificate of HEC: not verified (a loopback address)', text)
        self.refused(tool.Hec, target, self.path('none.pem'))

    def test_a_warning_on_a_search_means_ask_again_and_a_lasting_one_stops_before_anything_is_sent(self):
        self.stack.warn_runs = 2                                 # splunkd's slow-start warning, on a busy stack
        code, text = self.send()
        self.assertEqual((code, self.copies()), (0, dict((ident, 1) for ident in STAGED_IDS)), text)
        self.assertEqual(self.naps, [tool.WARN_PAUSE, tool.WARN_PAUSE])
        self.restart()
        self.stack.warn_runs = -1
        code, text = self.send()
        self.assertEqual((code, self.posts(), self.copies()), (2, [], {}), text)
        self.assertIn('REFUSED: R4, looking for the index: the search on --stack still answers with a warning after '
                      '3 runs, so its answer is not used', text)

    def test_a_stack_that_cannot_be_read_after_a_request_is_delivery_unknown_not_a_refusal(self):
        def breaks(event):                                       # the canary is indexed, then searches start to fail
            self.stack.fail_search['present'] = 'Search process did not exit cleanly, exit_code=255'

        self.stack.hec_rewrite = breaks
        code, text = self.send()
        self.assertEqual((code, len(self.posts()), self.copies()), (3, 1, {CANARY: 1}), text)
        self.assertIn('DELIVERY UNKNOWN: 1 event(s) were handed to HEC in this run, and then the stack could not be '
                      'read (P1, the canary: the search failed on --stack: Search process did not exit cleanly', text)
        self.assertNotIn('REFUSED', text)
        self.stack.hec_rewrite, self.stack.fail_search = None, {}
        code, text = self.send()                                 # the canary is there: the rest goes, nothing twice
        self.assertEqual((code, self.copies()), (0, dict((ident, 1) for ident in STAGED_IDS)), text)
        self.assertEqual([post['body'].count(b'"resend":"true"') for post in self.posts()], [1, 1, 2, 2])

    def test_a_dry_run_after_a_send_reads_the_ledger_and_leaves_it_as_it_is(self):
        self.stack.hec_script, self.stack.index_lag = ['lost'], 900
        self.assertEqual(self.send('--no-canary', '--settle', '10')[0], 3)
        before = text_of(self.ledger_file)
        code, text = self.send('--dry-run')
        self.assertEqual((code, len(self.posts()), text_of(self.ledger_file)), (0, 1, before), text)
        self.assertIn('HELD 6: handed to HEC before, not on the stack, NOT sent again', text)
        self.assertIn('A run without --dry-run would send 0 event(s).', text)
        self.assertEqual(self.naps, [10])                        # a dry run does not wait for what is held


class SendPartsTests(ToolCase):
    """The pieces `send` is made of, one at a time."""
    A, B, C = STAGED_IDS[0], STAGED_IDS[1], STAGED_IDS[2]
    OTHER_STACK = '5CA1AB1E-0000-4000-8000-00000000F009'

    def test_the_three_texts_that_read_the_rule(self):
        rule = tool.JOINED_RULE
        self.assertEqual(tool.spl_rule_ticks(rule), (
            'search index=_internal sourcetype=scheduler savedsearch_name="' + rule + '" '
            '| stats count(eval(status=="success")) as ok, count(eval(status=="continued")) as deferred, '
            'count(eval(status=="skipped")) as skipped by scheduled_time '
            '| sort 0 - scheduled_time'))
        self.assertEqual(tool.spl_rule_errors(rule), (
            'search index=_internal sourcetype=scheduler log_level=ERROR '
            'savedsearch_id="*;TA-gen_ai_cim;' + rule + '" '
            '| stats count as errors, latest(message) as message, max(_time) as last_error'))
        self.assertEqual(tool.spl_rule_parses('((`a` x=1) OR y=2)\n| stats count by user'),
                         'search ((`a` x=1) OR y=2)\n| stats count by user | stats count as rows')
        self.assertEqual(tool.spl_rule_parses('| tstats count where index=x'),
                         '| tstats count where index=x | stats count as rows')
        self.assertEqual(tool.RULE_PARSE_TIME, ('1', '2'))
        for bad in ('x" OR index="_audit', 'a*', 'a|b', ''):
            self.refused(tool.spl_rule_ticks, bad)
            self.refused(tool.spl_rule_errors, bad)

    def line(self, kind, ids=(), stack=STACK_GUID, at=1794900000, **more):
        line = dict(more, v=1, kind=kind, stack=stack, bundle=BUNDLE_ID, at=at)
        if ids:
            line['ids'] = list(ids)
        return json.dumps(line, sort_keys=True)

    def test_unconfirmed_is_per_request_a_later_refusal_never_clears_an_earlier_unknown_one(self):
        def pending(*lines):
            return tool.read_ledger(''.join(line + '\n' for line in lines), STACK_GUID)[0]

        first = self.line('intent', [self.A], at=1000, bytes=1, canary=True)
        unknown = self.line('outcome', [self.A], at=1001, state='unknown', http=None, code=None)
        released = self.line('released', [self.A], at=5000)
        again = self.line('intent', [self.A], at=5001, bytes=1, canary=False)
        for state in tool.PROVES_NOTHING_INDEXED:
            with self.subTest(state=state):
                refused = self.line('outcome', [self.A], at=5002, state=state, http=401, code=3)
                lines = (first, unknown, released, again, refused)
                self.assertEqual(pending(*lines), {self.A: 5001})       # the first request may still be indexed
                text = ''.join(line + '\n' for line in lines)
                self.assertEqual(tool.ledger_handed(text, STACK_GUID, BUNDLE_ID), [self.A])   # verify agrees
                self.assertEqual(pending(*lines + (self.line('confirmed', [self.A], at=5100),)), {})
                path = self.path('per-request-{}.ledger.jsonl'.format(state.replace(' ', '-')))
                with io.open(path, 'w', encoding='utf-8') as handle:
                    handle.write(''.join(line + '\n' for line in (first, unknown, released)))
                os.chmod(path, 0o600)
                ledger = tool.Ledger(path, STACK_GUID, BUNDLE_ID, lambda: 5001).open()
                self.addCleanup(ledger.close)
                ledger.intent([self.A], 1, False)
                ledger.outcome([self.A], tool.Outcome(state, 401, 3, 'fixture'))
                self.assertEqual(ledger.pending, {self.A: 5001})        # the run itself holds it as well
                ledger.close()

    def test_a_ledger_line_counts_for_the_stack_by_its_guid_or_by_its_hec_endpoint(self):
        key = tool.ledger_key(tool.HecTarget('https', 'http-inputs-acme.splunkcloud.test', 443, 't', 'o'), 'x')
        self.assertRegex(key, r'^[0-9]{16}$')
        intent = self.line('intent', [self.A], stack=self.OTHER_STACK, bytes=1, canary=True, hec=key)
        text = intent + '\n'
        self.assertEqual(tool.read_ledger(text, STACK_GUID)[0], {})               # another GUID, no key: not ours
        self.assertEqual(tool.read_ledger(text, STACK_GUID, key)[0], {self.A: 1794900000})   # same HEC: ours
        self.assertEqual(tool.read_ledger(text, STACK_GUID, '1' * 16)[0], {})
        self.refused(tool.read_ledger, self.line('intent', [self.A], hec='not-a-key', bytes=1, canary=True) + '\n',
                     STACK_GUID)

    def test_a_ledger_line_counts_for_verify_by_the_stack_address_whatever_member_answered(self):
        class Member(object):
            host, port = 'Acme.splunkcloud.test.', 8089
        key = tool.stack_ledger_key(Member)
        self.assertRegex(key, r'^[0-9]{16}$')
        Member.host = 'acme.splunkcloud.test'
        self.assertEqual(tool.stack_ledger_key(Member), key)                       # case and a final dot aside
        Member.port = 8090
        self.assertNotEqual(tool.stack_ledger_key(Member), key)
        text = self.line('intent', [self.A], stack=self.OTHER_STACK, bytes=1, canary=True, mgmt=key) + '\n'
        self.assertEqual(tool.read_ledger(text, STACK_GUID)[0], {})
        self.assertEqual(tool.read_ledger(text, STACK_GUID, mgmt=key)[0], {self.A: 1794900000})
        self.assertEqual(tool.ledger_handed(text, STACK_GUID, self.line_bundle(text)), [])
        self.assertEqual(tool.ledger_handed(text, STACK_GUID, self.line_bundle(text), key), [self.A])
        self.refused(tool.read_ledger, self.line('intent', [self.A], mgmt='acme', bytes=1, canary=True) + '\n',
                     STACK_GUID)

    def line_bundle(self, text):
        return json.loads(text)['bundle']

    def test_an_id_is_unconfirmed_from_its_intent_until_the_stack_shows_it_or_an_answer_proves_nothing_went(self):
        def pending(*lines):
            return tool.read_ledger(''.join(line + '\n' for line in lines), STACK_GUID)[0]

        intent = self.line('intent', [self.A, self.B, self.C], bytes=10, canary=False)
        self.assertEqual(pending(intent), {self.A: 1794900000, self.B: 1794900000, self.C: 1794900000})
        for state, left in (('accepted', 3), ('unknown', 3), ('not sent', 0), ('refused', 0), ('too large', 0)):
            with self.subTest(state=state):
                outcome = self.line('outcome', [self.A, self.B, self.C], state=state, http=None, code=None)
                self.assertEqual(len(pending(intent, outcome)), left)
        self.assertEqual(sorted(pending(intent, self.line('confirmed', [self.A]))), sorted([self.B, self.C]))
        self.assertEqual(len(pending(intent, self.line('released', [self.A, self.B, self.C]))), 3)   # says nothing
        self.assertEqual(pending(intent, self.line('confirmed', [self.A, self.B, self.C]),
                                 self.line('intent', [self.A], at=1794903700, bytes=1, canary=True)),
                         {self.A: 1794903700})                   # handed over again: the clock starts again
        # Another stack's lines say nothing about this one; the GUID's case does not matter.
        self.assertEqual(pending(self.line('intent', [self.A], stack=self.OTHER_STACK, bytes=1, canary=True)), {})
        self.assertEqual(len(pending(self.line('intent', [self.A], stack=STACK_GUID.lower(), bytes=1, canary=True))), 1)
        self.assertEqual(tool.read_ledger('', STACK_GUID), ({}, False))
        self.assertEqual(tool.PROVES_NOTHING_INDEXED, ('not sent', 'refused', 'too large'))

    def test_a_line_this_tool_did_not_write_is_refused_and_a_cut_off_last_line_is_not(self):
        intent = self.line('intent', [self.A], bytes=1, canary=True)
        for bad in ('garbage', '{}', '[]', intent.replace('"v": 1', '"v": 2'), intent.replace('intent', 'sent'),
                    intent.replace(self.A, 'not-an-id'), intent.replace(STACK_GUID, 'somewhere'),
                    self.line('outcome', [self.A], state='delivered'), ''):
            with self.subTest(bad=bad[:30]):
                said = self.refused(tool.read_ledger, intent + '\n' + bad + '\n' + intent + '\n', STACK_GUID)
                self.assertIn('has a line (number 2) that this tool did not write', said)
        # A last line without its line end is a write that was cut off. It proves nothing and is not an error ...
        self.assertEqual(tool.read_ledger(intent + '\n' + intent[:40], STACK_GUID), ({self.A: 1794900000}, True))
        # ... and once the tool has ended it and said so, it is still accepted where it stands.
        marked = intent + '\n' + intent[:40] + '\n' + self.line('torn') + '\n' + self.line('confirmed', [self.A]) + '\n'
        self.assertEqual(tool.read_ledger(marked, STACK_GUID), ({}, False))
        path = self.path('b.json.ledger.jsonl')
        with io.open(path, 'w', encoding='utf-8') as handle:
            handle.write(intent + '\n' + intent[:40])
        os.chmod(path, 0o600)
        ledger = tool.Ledger(path, STACK_GUID, BUNDLE_ID, lambda: 1794900100).open()
        self.addCleanup(ledger.close)
        self.assertEqual((ledger.torn, ledger.pending), ({'the ledger beside the bundle': True}, {self.A: 1794900000}))
        ledger.confirmed([self.A])
        ledger.close()
        self.assertEqual(text_of(path), intent + '\n' + intent[:40] + '\n'
                         + json.dumps(json.loads(self.line('torn', at=1794900100)), sort_keys=True,
                                      separators=(',', ':')) + '\n'
                         + json.dumps(json.loads(self.line('confirmed', [self.A], at=1794900100)), sort_keys=True,
                                      separators=(',', ':')) + '\n')
        reader = tool.Ledger(path, STACK_GUID, BUNDLE_ID, lambda: 1, write=False).open()
        self.addCleanup(reader.close)
        self.assertEqual(reader.pending, {})
        self.refused(reader.intent, [self.A], 1, True)           # a dry run cannot write the ledger

    def test_what_one_bundle_handed_to_one_stack_is_read_back_from_the_ledger(self):
        took = self.line('outcome', [self.A], state='accepted', http=200, code=0)
        text = '\n'.join((
            self.line('intent', [self.A], bytes=1, canary=True), took,
            self.line('intent', [self.B, self.C], bytes=2, canary=False),
            self.line('outcome', [self.B, self.C], state='too large', http=413, code=None),      # nothing indexed
            self.line('intent', [self.B], bytes=1, canary=False),
            self.line('outcome', [self.B], state='unknown', http=None, code=None),
            self.line('intent', [self.C], bytes=1, canary=False),                                 # the run died here
            self.line('intent', [STAGED_IDS[3]], stack=self.OTHER_STACK, bytes=1, canary=False),
            self.line('intent', [STAGED_IDS[4]], bytes=1, canary=False).replace(BUNDLE_ID, 'rs-20261101-aaaaaaaaaaaa'),
            'not a line', '')) + '\n'
        self.assertEqual(tool.ledger_handed(text, STACK_GUID, BUNDLE_ID), sorted([self.A, self.B, self.C]))
        self.assertEqual(tool.ledger_handed(text, self.OTHER_STACK, BUNDLE_ID), [STAGED_IDS[3]])
        self.assertEqual(tool.ledger_handed(text, STACK_GUID, 'rs-20261101-aaaaaaaaaaaa'), [STAGED_IDS[4]])
        self.assertEqual(tool.ledger_handed('', STACK_GUID, BUNDLE_ID), [])
        only_refused = '\n'.join((self.line('intent', [self.A], bytes=1, canary=True),
                                  self.line('outcome', [self.A], state='refused', http=403, code=4)))
        self.assertEqual(tool.ledger_handed(only_refused, STACK_GUID, BUNDLE_ID), [])

    def test_the_plan_sends_holds_releases_waits_or_stops(self):
        events = staged_events()
        ids = [event['id'] for event in events]

        def plan(verdicts, pending, resend=False, no_canary=False):
            decisions = collections.OrderedDict((ident, tool.Decision(verdicts.get(ident, tool.SEND), ()))
                                                for ident in ids)
            found = tool.make_plan(list(reversed(events)), decisions, pending, NOW, resend, no_canary)
            return tuple([event['id'] for event in part]
                         for part in (found.send, found.held, found.released, found.later, found.stop))

        rest = [ids[0]] + ids[2:]
        self.assertEqual(plan({}, {}), (ids, [], [], [], []))
        # Handed to HEC before and not on the stack: held, and with nothing proven the others wait ...
        self.assertEqual(plan({}, {ids[1]: NOW - 100}), ([], [ids[1]], [], rest, []))
        # ... unless a copy of this bundle is there (the stack keeps an event as sent), or --no-canary.
        self.assertEqual(plan({ids[0]: tool.THIS_BUNDLE}, {ids[1]: NOW - 100}), (ids[2:], [ids[1]], [], [], []))
        self.assertEqual(plan({}, {ids[1]: NOW - 100}, no_canary=True), (rest, [ids[1]], [], [], []))
        self.assertEqual(plan({ids[0]: tool.LIVE}, {ids[1]: NOW - 100})[3], ids[2:])       # a live copy proves nothing
        # An hour AND the override release it; either alone does not.
        self.assertEqual(plan({}, {ids[1]: NOW - 3600}, resend=True), (rest, [], [ids[1]], [], []))
        self.assertEqual(plan({}, {ids[1]: NOW - 3599}, resend=True)[1:3], ([ids[1]], []))
        self.assertEqual(plan({}, {ids[1]: NOW - 999999})[1:3], ([ids[1]], []))
        # On the stack after all: neither sent nor held. A conflict or a duplicate stops.
        self.assertEqual(plan({ids[1]: tool.LIVE}, {ids[1]: NOW - 100}), (rest, [], [], [], []))
        self.assertEqual(plan({ids[2]: tool.CONFLICT, ids[3]: tool.DUPLICATE}, {})[4], [ids[2], ids[3]])
        self.assertEqual((tool.RESEND_UNCONFIRMED_AFTER, tool.POLL_SECONDS, tool.SETTLE_SECONDS), (3600, 10, 180))

    def test_the_canary_is_the_earliest_audit_record_that_is_not_a_sign_in(self):
        events = staged_events()
        self.assertEqual(tool.canary_of(events)['id'], CANARY)
        self.assertEqual(tool.canary_of(list(reversed(events)))['id'], CANARY)
        self.assertEqual(tool.canary_of([event for event in events if event['id'] != CANARY])['id'], STAGED_IDS[0])
        self.assertEqual(tool.canary_of(events[2:])['id'], STAGED_IDS[2])       # no audit record: the earliest event
        options = tool.build_parser().parse_args(CommandLineTests.SEND)

        def first(verdicts, **change):
            decisions = dict((event['id'], tool.Decision(verdicts.get(event['id'], tool.SEND), ())) for event in events)
            vars(options).update(no_canary=False)
            vars(options).update(change)
            found = tool.first_of(tool.make_plan(events, decisions, {}, NOW, False, options.no_canary), options)
            return found[0]['id'] if found else None

        self.assertEqual(first({}), CANARY)
        self.assertEqual([event['id'] for event in tool.canaries_of(events)], [CANARY] + KIND_CANARIES)
        self.assertEqual([event['id'] for event in tool.canaries_of(list(reversed(events)))], [CANARY] + KIND_CANARIES)
        # Per kind: a copy of this bundle proves its own kind only.
        decisions = dict((event['id'], tool.Decision(tool.THIS_BUNDLE if event['id'] == CANARY else tool.SEND, ()))
                         for event in events)
        plan = tool.make_plan(events, decisions, {}, NOW, False)
        self.assertEqual([event['id'] for event in tool.first_of(plan, options, events)], KIND_CANARIES)
        self.assertIsNone(first({}, no_canary=True))
        self.assertEqual(first({CANARY: tool.LIVE}), STAGED_IDS[0])             # a live copy is no proof: a new canary
        self.assertIsNone(first({CANARY: tool.THIS_BUNDLE}))                    # an earlier run's canary is
        self.assertIsNone(first(dict((ident, tool.THIS_BUNDLE) for ident in STAGED_IDS)))   # nothing to send

    def test_the_stack_is_asked_every_10_seconds_until_it_holds_everything_or_the_time_is_up(self):
        event, now, naps = staged_events()[1], [NOW], []

        class Stack(object):
            flag = '--stack'

            def __init__(self, answers):
                self.answers, self.asked = list(answers), 0

            def call(self, path, method='GET', data=None, timeout=60):
                self.asked += 1
                rows = self.answers.pop(0) if self.answers else []
                return 200, json.dumps({'results': rows, 'messages': []})

        def nap(seconds):
            naps.append(seconds)
            now[0] += seconds

        def look(answers, seconds):
            del naps[:]
            stack = Stack(answers)
            found = tool.poll_presence(stack, 'gen_ai_log', [event], BUNDLE_ID, seconds, lambda: now[0], nap, 'a test')
            return found[event['id']].verdict, list(naps), stack.asked

        there = [p1_row(event, resend_bundle=BUNDLE_ID)]
        self.assertEqual(look([there], 180), ('this-bundle', [], 1))
        self.assertEqual(look([[], [], there], 180), ('this-bundle', [10, 10], 3))
        self.assertEqual(look([], 25), ('send', [10, 10, 5], 4))                # a last look when the time is up
        self.assertEqual(look([], 0), ('send', [], 1))
        self.assertEqual(look([[], [p1_row(event, sha256='0' * 64)]], 60), ('conflict', [10], 2))

class StackFakeFidelityTests(StackCase):
    """The stack's side of the fake answers as HEC and splunkd do, so that a
    test that passes against it says something about a real stack."""

    def post(self, body, token=True, path='/services/collector/event'):
        self.wrong_token_ok = True
        port = int(self.hec_url.split(':')[2].split('/')[0])
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
        self.addCleanup(conn.close)
        headers = {} if token is None else {'Authorization': 'Splunk ' + (self.stack.hec_token if token is True
                                                                          else token)}
        conn.request('POST', path, body=body.encode('utf-8'), headers=headers)
        answer = conn.getresponse()
        return answer.status, json.loads(answer.read().decode('utf-8'))

    def test_hec_answers_with_its_own_codes_and_indexes_what_stands_before_a_bad_event(self):
        line = '{"time":1794890600.5,"host":"h","source":"s","sourcetype":"st","index":"gen_ai_log","event":{"a":1}}'
        self.assertEqual(self.post(line, token=None), (401, {'text': 'Token is required', 'code': 2}))
        self.assertEqual(self.post(line, token='fixture-wrong-hec-token-0002'),
                         (403, {'text': 'Invalid token', 'code': 4}))
        self.assertEqual(self.post(line, path='/services/collector/raw')[0], 404)
        self.assertEqual(self.copies(), {})
        self.assertEqual(self.post(line), (200, {'text': 'Success', 'code': 0}))
        bad_index = line.replace('gen_ai_log', 'no_such_index')
        self.assertEqual(self.post(line + '\n' + line + '\n' + bad_index + '\n' + line),
                         (400, {'text': 'Incorrect index', 'code': 7, 'invalid-event-number': 2}))
        self.assertEqual(len([event for event in self.stack.events if event['host'] == 'h']), 3)   # 1, and 2 of the 4
        self.assertEqual(self.post('{"time":1,"index":"gen_ai_log"}')[1]['code'], 12)
        self.assertEqual(self.post('not json')[1],
                         {'text': 'Invalid data format', 'code': 6, 'invalid-event-number': 0})

    def test_hec_keeps_the_text_of_the_event_and_of_the_time_and_never_splits_on_line_breaks(self):
        odd = '{ "event_id" : "5ca1ab1e-0002-4000-8000-000000000301",\n\t"k":1,"k":2 ,"n":1E-5 }'
        body = ('{"time":1794890600.50,"host":"h","source":"s","sourcetype":"st","index":"gen_ai_log","event":' + odd
                + ',"fields":{"log_type":"governance"}}\n\n  {"time":1794890601,"host":"h","source":"s",'
                '"sourcetype":"st","index":"gen_ai_log","event":"plain text"}')
        self.assertEqual(self.post(body)[0], 200)
        first, second = [event for event in self.stack.events if event['host'] == 'h']
        self.assertEqual((first['raw'], first['time_text'], first['fields']),
                         (odd, '1794890600.50', {'log_type': 'governance'}))
        self.assertEqual((second['raw'], second['time_text']), ('"plain text"', '1794890601'))
        self.assertEqual(fake_stack.envelopes('')[:], [])
        self.stack.index_lag = 30                                # accepted now, searchable in half a minute
        self.assertEqual(self.post(body.replace('0301', '0302'))[0], 200)
        self.assertEqual(len(self.stack.seen('gen_ai_log', 0, 10 ** 11)), 2)
        self.now += 30
        self.assertEqual(len(self.stack.seen('gen_ai_log', 0, 10 ** 11)), 4)

    def test_the_schedulers_log_has_splunkds_shapes(self):
        tick = int(NOW) - 300
        self.stack.tick(tick, 'continued')
        rows = self.stack.q_rule_ticks(0, 10 ** 11, '"' + tool.JOINED_RULE + '"')
        self.assertEqual(rows, [{'scheduled_time': str(tick), 'ok': '1', 'deferred': '1', 'skipped': '0'}])
        self.assertEqual(self.stack.q_rule_ticks(0, 10 ** 11, '"Another - Rule"'), [])            # stats ... by: no row
        self.assertEqual(self.stack.q_rule_errors(0, 10 ** 11, tool.JOINED_RULE), [{'errors': '0'}])   # the count alone
        self.stack.rule_errors = [(tick, 'first'), (tick + 60, 'second')]
        self.assertEqual(self.stack.q_rule_errors(0, 10 ** 11, tool.JOINED_RULE),
                         [{'errors': '2', 'message': 'second', 'last_error': str(tick + 60)}])
        self.assertEqual(self.stack.bound('-15m'), self.stack.bound('now') - 900)


CHAIN = 'nina.osei:takeover:1794890419'                    # the sign-in's whole second, as the rule writes it
TICK = 1794900300                                          # 07:25:00Z: the first tick after NOW + 120
V_STEPS = ('V1. the copies', 'V2. the label', 'V3. the counts the dashboards read', 'V4. the Duo half',
           'V5. the rule, run by hand', 'V6. the finding')


class VerifyCase(StackCase):
    """A stack that got the bundle at NOW (07:20:00Z) by a clean `send`, with
    its scheduler running from then on: the copies are indexed at NOW, so the
    run of the tick 07:25:00Z judges them, starts 80 s later and raises the
    finding. Nothing here waits in real time: the clock moves when the tool
    sleeps."""

    def setUp(self):
        super(VerifyCase, self).setUp()
        self.stack.auto_schedule = int(NOW)

    def sent(self, *extra):
        code, text = self.send(*extra)
        self.assertEqual(code, 0, text)
        del self.naps[:]
        return text

    def steps(self, text):
        """{step: (status, detail)} of the rows one run printed."""
        found = re.findall(r'^  \[ *(OK|FAIL|SKIP)\] (V\d\. [^\n]*?)(?: - ([^\n]*))?$', text, re.M)
        return collections.OrderedDict((step, (status, detail)) for status, step, detail in found)

    def statuses(self, text):
        return [self.steps(text).get(step, ('MISSING',))[0] for step in V_STEPS]


class VerifyTests(VerifyCase):
    def test_verify_through_another_member_of_a_search_head_cluster_reads_what_send_handed_over(self):
        # A load-balanced :8089: every answer of server/info comes from the next member, with its own GUID.
        members = (STACK_GUID, '5CA1AB1E-0000-4000-8000-00000000F0AA', '5CA1AB1E-0000-4000-8000-00000000F0AB')
        self.stack.member_guids = members
        self.sent()
        self.assertEqual({line['stack'] for line in self.ledger()}, {STACK_GUID})
        self.assertEqual(len({line['mgmt'] for line in self.ledger()}), 1)  # the --stack address, hashed
        code, text = self.verify('--wait', '900')
        self.assertEqual(code, 0, text)
        self.assertEqual(self.stack.info_answers, 2)                          # verify was answered by F0AA
        self.assertEqual(self.steps(text)['V2. the label'], (
            'OK', "6 event(s) carry this bundle's label, the 6 the ledger records as handed to this stack"))

    def test_verify_proves_the_copies_the_label_the_counts_the_duo_half_the_chain_and_the_finding(self):
        self.sent()
        self.assertEqual(self.written()['expect']['chains'], [CHAIN])
        before, asked = len(self.stack.searches), len(self.stack.requests)
        code, text = self.verify('--wait', '900')
        self.assertEqual(code, 0, text)
        steps = self.steps(text)
        self.assertEqual([steps[step] for step in V_STEPS], [
            ('OK', "each of the 6 id(s) is on the stack once, identical: 6 under this bundle's label, 0 delivered "
                   "live, 0 under another bundle's label"),
            ('OK', "6 event(s) carry this bundle's label, the 6 the ledger records as handed to this stack"),
            ('OK', 'nina.osei: events 6, copies 6, identity_events 3, ai_turns 2, ai_blocked 1, app_signins 1, as on '
                   'the source'),
            ('OK', 'the Duo authentication of each of the 1 sign-in(s) is on the stack exactly once'),
            ('OK', "1 chain(s) for this set's sign-ins: " + CHAIN),
            ('OK', 'one finding and one risk event for each of the 1 chain(s), first raised 2026-11-17T07:26:25Z')])
        self.assertIn('VERIFIED: the stack holds the 6 event(s) of bundle ' + self.written()['bundle_id'], text)
        self.assertIn('certificate of port 8089: plain http to a loopback address', text)
        # The copies were indexed at 07:20:00Z, so the tick 07:25:00Z judges them; its run starts 80 s later.
        # The finding was looked for every 30 s and the wait ended when it was there, not after 900 s.
        self.assertEqual(self.naps, [30] * 13)
        ran = [(search['kind'], search['earliest'], search['latest']) for search in self.stack.searches[before:]]
        self.assertEqual(ran[:6], [
            ('eventcount', '0', 'now'), ('present', '0', '+1d'), ('label', '0', '+1d'), ('expect', '0', '+1d'),
            ('duo_half', str(1794890419 - 6000), str(1794890520 + 6001)), ('rule', '0', 'now')])
        self.assertEqual(ran[6:], [('findings', str(1794890419 - 86400), '+1d')] * 14)
        # The counts are read through the stack's own macro, which is what the dashboards read.
        self.assertTrue(self.last_search('expect')['search'].startswith('search `genai_identity_ai_events` ("'))
        paths = [request['method'] + ' ' + request['path'] for request in self.stack.requests[asked:]]
        self.assertEqual(paths[:2], ['GET /services/server/info', 'GET /services/apps/local/TA-gen_ai_cim'])
        self.assertFalse([path for path in paths if '/data/indexes/' in path])
        self.assertEqual({path.split(' ')[0] for path in paths}, {'GET', 'POST'})
        # Once raised, a later run finds everything at once and waits for nothing.
        del self.naps[:]
        code, text = self.verify()
        self.assertEqual((code, self.naps, self.statuses(text)), (0, [], ['OK'] * 6), text)

    def test_v6_without_wait_it_looks_once_and_says_which_tick_judges_the_copy_and_when_its_finding_is_due(self):
        self.sent()
        code, text = self.verify()
        self.assertEqual((code, self.naps), (1, []), text)
        self.assertEqual(self.statuses(text), ['OK'] * 5 + ['FAIL'])
        self.assertEqual(self.steps(text)[V_STEPS[5]][1], (
            'NOT RAISED YET ({}: 0 finding(s), 0 risk event(s)). The scheduled run that judges the copy is the tick '
            '2026-11-17T07:25:00Z, and its finding is due by 2026-11-17T07:32:00Z: run `verify --wait 780`, or run '
            'it again after that time'.format(CHAIN)))
        self.assertIn('NOT VERIFIED: 1 step(s) failed.', text)
        self.assertNotIn('scheduler\'s record', text)                  # nothing is late yet
        self.assertEqual([kind for kind in self.kinds_of_stack() if kind in ('rule_runs', 'rule_errors')], [])
        # A wait that ends before the finding is due says the same, and never calls the finding late.
        code, text = self.verify('--wait', '100')
        self.assertEqual((code, self.naps), (1, [30, 30, 30, 10]), text)
        self.assertIn('NOT RAISED YET', text)
        self.assertIn('due by 2026-11-17T07:32:00Z: run `verify --wait 680`', text)
        # Copies that were indexed later are judged by a later tick: 07:23:00Z + 120 s is the tick 07:25:00Z
        # exactly, which belongs to the next slot.
        for indexed, tick, due in ((int(NOW) + 179, '07:25:00Z', '07:32:00Z'),
                                   (int(NOW) + 180, '07:30:00Z', '07:37:00Z')):
            for event in self.stack.events:
                if event['fields'].get('resend') == 'true':
                    event['indexed'] = indexed
            code, text = self.verify()
            self.assertIn('is the tick 2026-11-17T{}, and its finding is due by 2026-11-17T{}'.format(tick, due), text)

    def test_send_with_wait_finding_sends_then_verifies_and_waits_without_holding_the_ledger(self):
        free = []

        def nap(seconds):
            if seconds == 30 and not free:                             # while it waits for the finding
                with io.open(self.ledger_file, 'a') as handle:
                    tool.fcntl.flock(handle.fileno(), tool.fcntl.LOCK_EX | tool.fcntl.LOCK_NB)   # a send could start
                    free.append(True)
            self.nap(seconds)

        code, text = self.send('--wait-finding', '900', sleep=nap)
        self.assertEqual(code, 0, text)
        self.assertEqual(free, [True], 'the ledger was still locked while `send` waited for the finding')
        self.assertIn('SENT: the stack holds each of the 6 id(s) once', text)
        self.assertIn('--wait-finding 900: reading the stack again, as `verify --wait 900` does', text)
        self.assertEqual(self.statuses(text), ['OK'] * 6)
        self.assertLess(text.index('SENT: '), text.index('[  OK] V1. '))
        self.assertEqual(len(self.posts()), 3)                         # the canaries and the rest: nothing more
        self.assertEqual(self.naps, [30] * 13)
        # Without the finding the send itself is still complete, and the exit code says what is not proven.
        self.restart()
        self.stack.auto_schedule = None
        code, text = self.send('--wait-finding', '60')
        self.assertEqual((code, self.copies()), (1, dict((ident, 1) for ident in STAGED_IDS)), text)
        self.assertIn('SENT: ', text)
        self.assertIn('NOT RAISED YET', text)
        # A dry run sends nothing and therefore waits for nothing.
        self.restart()
        code, text = self.send('--dry-run', '--wait-finding', '900')
        self.assertEqual((code, self.naps, self.posts()), (0, [], []), text)
        self.assertIn('--wait-finding is not used in a dry run', text)
        self.assertNotIn('V1. ', text)

    def late(self, **knobs):
        """The text of a `verify` 800 s after a send whose finding never came:
        80 s past the time it was due. Exit 1, and nothing is waited for."""
        self.restart()
        for name, value in knobs.items():
            setattr(self.stack, name, value)
        self.sent()
        self.now = NOW + 800
        code, text = self.verify('--wait', '900')
        self.assertEqual((code, self.naps), (1, []), text)
        self.assertEqual(self.statuses(text), ['OK'] * 5 + ['FAIL'])
        self.assertIn('NOT RAISED ({}: 0 finding(s), 0 risk event(s)): the tick 2026-11-17T07:25:00Z judged the copy '
                      'and its finding was due by 2026-11-17T07:32:00Z'.format(CHAIN), text)
        self.assertIn('The scheduler\'s record of the rule from the tick 2026-11-17T07:25:00Z on:', text)
        self.assertEqual((self.last_search('rule_runs')['earliest'], self.last_search('rule_runs')['latest']),
                         (str(TICK - 60), 'now'))
        self.assertEqual(self.last_search('rule_errors')['earliest'], str(TICK - 60))
        return text

    def test_v6_a_late_finding_is_followed_by_the_schedulers_own_record_and_what_it_means(self):
        # The run failed: an ERROR line that names the search only by its id, and no status line at all.
        text = self.late(run_fails='Error in \'apply\' command: the model is missing ' + TXID)
        self.assertIn('2 error line(s); the last: Error in \'apply\' command: the model is missing <hidden>', text)
        self.assertIn('-> a run FAILED, and a failed run loses its slot', text)
        self.assertNotIn('      tick 2026', text)                      # a failing run writes no status line
        # The scheduler is behind: `continued`, and no run yet.
        text = self.late(dispatch_delay=5000)
        self.assertIn('      tick 2026-11-17T07:25:00Z: continued, 0 result(s), suppressed 0, actions none', text)
        self.assertIn('-> deferred or skipped and not run yet: the scheduler is behind', text)
        # The run succeeded and found nothing new in its slot.
        self.restart()
        self.stack.raised.add(CHAIN)                                   # as if an earlier run had judged the chain
        self.sent()
        self.now = NOW + 800
        text = self.verify()[1]
        self.assertIn('      tick 2026-11-17T07:25:00Z: success, started 80 s after the tick, 0 result(s), '
                      'suppressed 0, actions none', text)
        self.assertIn('      tick 2026-11-17T07:30:00Z: success, started 80 s after the tick, 0 result(s)', text)
        self.assertIn('-> success with 0 results: the copy was not the last missing step in its slot. Check V4', text)
        # The run returned the chain and no alert action wrote anything.
        text = self.late(actions_run=False)
        self.assertIn('tick 2026-11-17T07:25:00Z: success, started 80 s after the tick, 1 result(s), suppressed 0, '
                      'actions none', text)
        self.assertIn('-> a run returned results, but no finding is searchable', text)
        self.assertNotIn('can search no index', text)
        # A stack without Enterprise Security has neither index: said, because no finding can ever be shown.
        self.stack.indexes -= {'notable', 'risk'}
        text = self.verify()[1]
        self.assertIn('This account can search no index notable on the stack', text)
        self.assertIn('This account can search no index risk on the stack', text)
        # No line at all, and a line that says the chain was suppressed.
        text = self.late(auto_schedule=None)
        self.assertIn('(no line) -> the scheduler recorded no run of the rule for that tick', text)
        self.stack.tick(TICK, results=1, suppressed=1, actions='notable,risk')
        text = self.verify()[1]
        self.assertIn('tick 2026-11-17T07:25:00Z: success, started 78 s after the tick, 1 result(s), suppressed 1, '
                      'actions notable,risk', text)
        self.assertIn('-> suppressed: the chain was already raised in the last 24 hours', text)

    def test_v6_the_wait_ends_when_the_finding_is_overdue_not_when_the_time_is_used_up(self):
        self.stack.run_fails = 'Error in \'search\' command: a lookup is missing'
        self.sent()
        code, text = self.verify('--wait', '5000')
        self.assertEqual(code, 1, text)
        self.assertEqual((sum(self.naps), set(self.naps)), (720, {30}))            # to 07:32:00Z and no longer
        self.assertIn('NOT RAISED (', text)
        # By then the runs of 07:25:00Z and of 07:30:00Z have both failed.
        self.assertIn('2 error line(s); the last: Error in \'search\' command: a lookup is missing', text)

    def test_v1_an_id_nobody_handed_over_is_missing_at_once_and_everything_after_it_says_so(self):
        code, text = self.verify('--wait', '900')                # a stack that was never sent to
        self.assertEqual((code, self.naps), (1, []), text)       # nothing is in flight: no wait, not "unknown"
        self.assertEqual(self.statuses(text), ['FAIL', 'OK', 'FAIL', 'OK', 'FAIL', 'FAIL'])
        steps = self.steps(text)
        self.assertEqual(steps[V_STEPS[0]][1], '6 id(s) are not on the stack and the ledger records no send of them '
                         'to it: {} .... Run `send`'.format(', '.join(STAGED_IDS[:5])))
        self.assertEqual(steps[V_STEPS[1]][1], "0 event(s) carry this bundle's label, the 0 the ledger records as "
                         'handed to this stack')
        self.assertIn('the stack gives [no identity row] and the source gave [nina.osei: events 6, copies 6, '
                      'identity_events 3, ai_turns 2, ai_blocked 1, app_signins 1]', steps[V_STEPS[2]][1])
        self.assertIn("the stack's rule returns 0 of the 1 chain(s) the source's returned; not " + CHAIN,
                      steps[V_STEPS[4]][1])
        self.assertIn('NOT RAISED ({}: 0 finding(s), 0 risk event(s)): the copies are not all on the stack as they '
                      'were sent (V1), so no run was waited for'.format(CHAIN), steps[V_STEPS[5]][1])
        self.assertIn('NOT VERIFIED: 4 step(s) failed.', text)
        self.assertNotIn('DELIVERY UNKNOWN', text)
        self.assertFalse(os.path.lexists(self.ledger_file), '`verify` made a ledger')

    def test_v1_ids_that_were_handed_to_hec_are_asked_for_every_10_s_for_180_s_and_then_it_is_exit_3(self):
        self.stack.hec_script, self.stack.index_lag = ['lost'], 600
        self.assertEqual(self.send('--no-canary', '--settle', '0')[0], 3)
        del self.naps[:]
        code, text = self.verify('--wait', '900')
        self.assertEqual((code, self.naps), (3, [10] * 18), text)
        self.assertIn('6 id(s) that were handed to HEC are not searchable yet: asking again every 10 s, for up to '
                      '180 s', text)
        self.assertRegex(text, r'\[FAIL\] V1\. the copies - 6 id\(s\) were handed to HEC and are not searchable '
                               r'after 180 s: .* DELIVERY UNKNOWN: they are not to be sent again')
        self.assertIn('DELIVERY UNKNOWN: event(s) that were handed to HEC are not searchable. Nothing is to be sent '
                      'again', text)
        self.assertEqual(len(self.posts()), 1)
        # The same stack 20 s before its index catches up: three more looks, and the copies are proven.
        self.now, self.naps = NOW + 580, []
        code, text = self.verify()
        self.assertEqual((self.naps, self.statuses(text)[:5]), ([10, 10], ['OK'] * 5), text)
        self.assertEqual(code, 1)                                # only the finding is not due yet
        self.assertIn('NOT RAISED YET', text)

    def test_v1_a_copy_the_stack_changed_or_holds_twice_fails_and_is_never_delivery_unknown(self):
        self.stack.hec_rewrite = lambda event: event.update(sourcetype='httpevent')
        self.assertEqual(self.send()[0], 1)                      # the canary went, was read back, and the run stopped
        code, text = self.verify()
        self.assertEqual(code, 1, text)
        steps = self.steps(text)
        self.assertIn('1 id(s) are there in another form and 0 more than once: {} (sourcetype). Neither can be '
                      'removed from the stack'.format(CANARY), steps[V_STEPS[0]][1])
        self.assertIn('5 id(s) are not on the stack and the ledger records no send of them to it', steps[V_STEPS[0]][1])
        # V2 counts by kind: one labelled event, one on record, but not under its original's sourcetype.
        self.assertEqual(steps[V_STEPS[1]], ('FAIL', "1 event(s) carry this bundle's label and the ledger records 1 "
                                             'handed to this stack: a copy is under another sourcetype, log_type or '
                                             'host than its original'))
        self.restart()
        self.sent()
        raw, time_text, sourcetype, log_type = STAGED[2]
        self.stack.add(raw, time_text, sourcetype, log_type, host=HOST, fields={
            'resend': 'true', 'resend_bundle': self.written()['bundle_id'], 'resend_orig_indextime': '1794890467'})
        code, text = self.verify('--wait', '900')
        self.assertEqual(code, 1, text)
        self.assertIn('0 id(s) are there in another form and 1 more than once: {} (more than one copy)'.format(
            STAGED_IDS[2]), text)
        # The finding is looked for once and not waited for: the copies are wrong, and no wait can mend that.
        self.assertEqual(self.naps, [])
        self.assertIn('NOT RAISED ({}: 0 finding(s), 0 risk event(s)): the copies are not all on the stack as they '
                      'were sent (V1), so no run was waited for'.format(CHAIN), text)
        self.assertNotIn('scheduler\'s record', text)             # the run that judges them is still to come
        self.stack.auto_schedule = None                          # no run ever comes ...
        self.now = NOW + 800                                     # ... and once it is overdue, the record is shown
        self.assertIn('The scheduler\'s record of the rule from the tick 2026-11-17T07:25:00Z on:', self.verify()[1])
        self.assertRegex(text, r"\[FAIL\] V2\. the label - 7 event\(s\) carry this bundle's label and the ledger "
                               r'records 6 handed to this stack: events were sent that this ledger does not record')

    def test_v1_the_tas_own_record_of_an_action_on_a_copied_turn_is_not_a_second_copy_of_it(self):
        self.sent()
        # An analyst runs Suspend user on the copied blocked turn: the TA writes a record into the same index
        # that carries the turn's event_id as a key of its own.
        action = ('{"timestamp":"2026-11-17T07:21:00Z","action":"suspend_user","simulated":true,"event_id":"'
                  + STAGED_IDS[3] + '","user":"nina.osei","resend_bundle":"' + self.written()['bundle_id'] + '"}')
        self.stack.add(action, '1794900060.0', 'ai_cim:response:action', host='sh1', source='ai_defense_response')
        self.assertEqual(self.copies()[STAGED_IDS[3]], 2)
        code, text = self.verify('--wait', '900')
        self.assertEqual((code, self.statuses(text)), (0, ['OK'] * 6), text)
        self.assertIn('each of the 6 id(s) is on the stack once, identical', text)
        code, text = self.send()                                 # and a second send still sends nothing
        self.assertEqual((code, len(self.posts())), (0, 3), text)
        self.assertIn('nothing to send', text)

    def test_v1_and_v2_on_a_stack_that_got_part_of_the_set_live(self):
        for raw, time_text, sourcetype, log_type in STAGED[:2]:  # delivered live, before the bundle existed
            self.stack.add(raw, time_text, sourcetype, log_type, host=HOST)
        self.sent()
        code, text = self.verify('--wait', '900')
        self.assertEqual((code, self.statuses(text)), (0, ['OK'] * 6), text)
        self.assertIn("identical: 4 under this bundle's label, 2 delivered live, 0 under another bundle's label", text)
        self.assertIn("4 event(s) carry this bundle's label, the 4 the ledger records as handed to this stack", text)

    def test_v2_the_label_is_held_against_the_ledger_and_the_ledger_is_only_ever_read(self):
        self.sent()
        self.now = NOW + 400                                     # the finding is there: only the ledger is at issue
        kept = text_of(self.ledger_file)
        os.unlink(self.ledger_file)                              # "the second machine has no ledger"
        code, text = self.verify()
        self.assertEqual((code, self.statuses(text)), (1, ['OK', 'FAIL', 'OK', 'OK', 'OK', 'OK']), text)
        self.assertIn("6 event(s) carry this bundle's label and the ledger records 0 handed to this stack: events "
                      'were sent that this ledger does not record', text)
        self.assertFalse(os.path.lexists(self.ledger_file), '`verify` made a ledger')
        # What another stack was handed is not what this one was handed: another GUID and another address.
        key = json.loads(kept.split('\n')[0])['mgmt']
        with io.open(self.ledger_file, 'w', encoding='utf-8') as handle:
            handle.write(kept.replace(STACK_GUID, GUID[:-1] + '9').replace(key, '1' * 16))
        os.chmod(self.ledger_file, 0o600)
        self.assertIn('the ledger records 0 handed to this stack', self.verify()[1])
        # A ledger others can read, a symlink to one, and a line this tool did not write: nothing is read.
        os.chmod(self.ledger_file, 0o644)
        self.assertIn('REFUSED: the ledger beside the bundle is readable or writable by others', self.verify()[1])
        os.unlink(self.ledger_file)
        with io.open(self.path('elsewhere.jsonl'), 'w', encoding='utf-8') as handle:
            handle.write(kept)
        os.chmod(self.path('elsewhere.jsonl'), 0o600)
        os.symlink(self.path('elsewhere.jsonl'), self.ledger_file)
        self.assertIn('REFUSED: the ledger beside the bundle cannot be read (a symlink?)', self.verify()[1])
        os.unlink(self.ledger_file)
        with io.open(self.ledger_file, 'w', encoding='utf-8') as handle:
            handle.write(kept + '{"kind":"intent","note":"typed by hand"}\n')
        os.chmod(self.ledger_file, 0o600)
        code, text = self.verify()
        self.assertEqual(code, 2)
        self.assertIn('REFUSED: the ledger beside the bundle has a line (number 11) that this tool did not write', text)
        # While a `send` holds the ledger, its requests are under way: nothing is judged.
        with io.open(self.ledger_file, 'w', encoding='utf-8') as handle:
            handle.write(kept)
        with io.open(self.ledger_file, 'a') as holder:           # (not blocking: an earlier `verify` kept no lock)
            tool.fcntl.flock(holder.fileno(), tool.fcntl.LOCK_EX | tool.fcntl.LOCK_NB)
            searches = len(self.stack.searches)
            code, text = self.verify()
            self.assertEqual((code, len(self.stack.searches)), (2, searches), text)
            self.assertIn('REFUSED: a `send` of this bundle is running (it holds the ledger)', text)
        self.assertEqual(self.verify()[0], 0)

    def test_v3_and_v5_say_nothing_through_a_macro_that_reads_another_index_than_the_copies_are_in(self):
        # A scratch rehearsal: the copies go to another index than the one the stack's macro fixes. Through the
        # macro, the counts and the rule would be read from gen_ai_log, where the ORIGINALS of a dev Splunk are.
        path, ids = self.big_bundle(3, index='rs_scratch_copy')
        self.stack.indexes.add('rs_scratch_copy')
        for raw, time_text, sourcetype, log_type in STAGED:      # the same scenario, held live in gen_ai_log
            self.stack.add(raw, time_text, sourcetype, log_type, host=HOST)
        for ident in ids:                                        # the copies, as a send would have left them
            event = [item for item in tool.load_bundle(path)['events'] if item['id'] == ident][0]
            self.stack.add(event['raw'], event['time'], event['sourcetype'], event['log_type'], host=HOST,
                           index='rs_scratch_copy', fields={'resend': 'true', 'resend_orig_indextime': '1',
                                                            'resend_bundle': tool.load_bundle(path)['bundle_id']})
        code, text = self.verify(bundle=path)
        self.assertEqual(code, 1, text)
        self.assertEqual(self.statuses(text), ['OK', 'FAIL', 'FAIL', 'SKIP', 'SKIP', 'SKIP'])
        self.assertIn("the stack's macro genai_identity_ai_events reads index gen_ai_log and the copies are in "
                      'rs_scratch_copy: read through it, nothing would be said about them',
                      self.steps(text)[V_STEPS[2]][1])
        self.assertNotIn('expect', self.kinds_of_stack())        # the search that would have passed was not run
        self.assertEqual(self.last_search('present')['search'].split(' ')[1], 'index="rs_scratch_copy"')
        self.assertEqual(self.last_search('label')['search'].split('where ')[1].split(' ')[0],
                         'index="rs_scratch_copy"')
        # A stack whose macro does read that index is read through the macro, and so reads the copies.
        self.stack.macro_index['genai_identity_ai_events'] = 'rs_scratch_copy'
        code, text = self.verify(bundle=path)
        self.assertTrue(self.last_search('expect')['search'].startswith('search `genai_identity_ai_events` ("'))
        # (This made-up bundle recorded no expected row; what counts is that the three copies were the ones read.)
        self.assertIn('the stack gives [nina.osei: events 3, copies 3, identity_events 0, ai_turns 0, ai_blocked 0, '
                      'app_signins 0] and the source gave [no identity row]', text)
        # A macro the stack will not show: the shipped index passes with a note, any other index does not.
        self.stack.macro_status = 404
        self.assertIn('which index the stack\'s macro genai_identity_ai_events reads could not be told (the stack '
                      'did not show the macro (HTTP 404)), and the bundle\'s index is not gen_ai_log',
                      self.verify(bundle=path)[1])
        self.restart()
        self.stack.macro_status = 404
        self.sent()
        text = self.verify()[1]
        self.assertRegex(text, r'\[  OK\] V3\. .*as on the source; NOT CHECKED: which index genai_identity_ai_events '
                               r'reads \(the stack did not show the macro \(HTTP 404\)\)')

    def test_v3_a_stack_whose_ta_reads_the_copies_differently_fails_although_every_copy_is_identical(self):
        self.sent()
        real = self.stack.read_as_ta
        self.stack.read_as_ta = lambda event: real(event)[:2] + (False,) + real(event)[3:]   # no turn reads as blocked
        code, text = self.verify()
        self.assertEqual((code, self.statuses(text)[:3]), (1, ['OK', 'OK', 'FAIL']), text)
        self.assertIn('the stack gives [nina.osei: events 6, copies 6, identity_events 3, ai_turns 2, ai_blocked 0, '
                      'app_signins 1] and the source gave [nina.osei: events 6, copies 6, identity_events 3, '
                      'ai_turns 2, ai_blocked 1, app_signins 1]', text)
        self.assertIn('look for a local override of its macros or props', text)
        # Events the stack's TA files under another identity are a failure of this step, not a crash.
        self.stack.read_as_ta = lambda event: ('grace.lin',) + real(event)[1:]
        code, text = self.verify()
        self.assertEqual((code, self.statuses(text)[2]), (1, 'FAIL'), text)
        self.assertIn('V3. the counts the dashboards read - not read: the TA reads some of the selected events as '
                      'another identity than the selected persona', text)

    def duo_events(self, action):
        return [event for event in self.stack.events if event['duo'] and event['duo']['action'] == action]

    def test_v4_the_duo_authentication_of_every_sign_in_is_on_the_stack_exactly_once(self):
        record = self.duo_events('success')[0]
        self.stack.events.remove(record)                         # Duo's record of the sign-in never arrived
        self.sent('--without-duo')
        code, text = self.verify()
        self.assertEqual((code, self.statuses(text)[3]), (1, 'FAIL'), text)
        self.assertIn('V4. the Duo half - the Duo authentication of 0 of 1 sign-in(s) is on the stack exactly once '
                      '(0 found at all): the Duo half is missing or from another tenant', text)
        self.assertEqual(self.last_search('duo_half')['search'].count(TXID), 2)   # asked for by id, never printed
        self.stack.events.extend([record, dict(record)])         # and a stack that holds it twice
        text = self.verify()[1]
        self.assertIn('the Duo authentication of 0 of 1 sign-in(s) is on the stack exactly once (1 found at all)', text)
        # A set without a sign-in has nothing to pair, and says so: a skipped step is not a failed one.
        path = self.big_bundle(2)[0]
        text = self.verify(bundle=path)[1]
        self.assertIn('[SKIP] V4. the Duo half - the bundle has no sign-in with a Duo transaction id', text)
        self.assertIn('[SKIP] V5. the rule, run by hand - the set has no application sign-in: no chain can form', text)
        self.assertIn('[SKIP] V6. the finding - the bundle expects no chain, so there is no finding to look for', text)

    def test_v5_a_missing_chain_fails_and_the_finding_is_then_overdue_with_a_run_that_found_nothing(self):
        for event in self.duo_events('failure'):                 # the denial burst never reached this stack
            self.stack.events.remove(event)
        self.sent('--without-duo')
        code, text = self.verify('--wait', '900')
        self.assertEqual((code, self.statuses(text)), (1, ['OK', 'OK', 'OK', 'OK', 'FAIL', 'FAIL']), text)
        self.assertIn("V5. the rule, run by hand - the stack's rule returns 0 of the 1 chain(s) the source's "
                      'returned; not {}: a Duo denial burst, a sign-in or a blocked turn of that chain is not on '
                      'the stack (V1, V4)'.format(CHAIN), text)
        self.assertEqual(sum(self.naps), 720)                    # waited until it was overdue, then read the record
        self.assertIn('tick 2026-11-17T07:25:00Z: success, started 80 s after the tick, 0 result(s)', text)
        self.assertIn('-> success with 0 results', text)

    def test_v5_the_stacks_own_rule_text_is_what_runs_whether_or_not_it_opens_with_a_pipe(self):
        self.sent()
        self.stack.saved[tool.JOINED_RULE]['search'] = '| tstats count where index=gen_ai_log by user'
        code, text = self.verify()
        self.assertEqual(self.statuses(text)[4], 'OK', text)
        self.assertTrue(self.last_search('rule')['search'].startswith('| tstats count where index=gen_ai_log by user '
                                                                      '| table chain_id, user, _time'))
        # A text splunkd cannot parse fails this step; the others are still judged.
        self.stack.saved[tool.JOINED_RULE]['search'] = '((`a_macro_this_stack_lacks`) OR x=1)'
        self.stack.fail_search = {'rule': 'Error in \'SearchParser\': The search specifies a macro that cannot be '
                                          'found.'}
        code, text = self.verify()
        self.assertEqual((code, self.statuses(text)[:5]), (1, ['OK', 'OK', 'OK', 'OK', 'FAIL']), text)
        self.assertIn('V5. the rule, run by hand - its text does not run on this stack (V5, the joined rule on the '
                      'stack: the search failed on --stack: Error in \'SearchParser\': The search specifies a macro '
                      'that cannot be found.)', text)
        # A stack without the rule: the chain the bundle expects cannot be shown, and no run is waited for.
        self.stack.fail_search = {}
        del self.stack.saved[tool.JOINED_RULE]
        del self.naps[:]
        code, text = self.verify('--wait', '900')
        self.assertEqual((code, self.naps), (1, []), text)
        self.assertIn('V5. the rule, run by hand - the joined rule is not on this stack, and the bundle expects 1 '
                      'chain(s)', text)
        self.assertIn('NOT RAISED ({}: 0 finding(s), 0 risk event(s)): the joined rule is not on this stack: no '
                      'scheduled run judges the copy'.format(CHAIN), text)

    def test_v6_wants_exactly_one_finding_and_one_risk_event_for_each_chain(self):
        self.sent()
        self.stack.auto_schedule = None
        self.now = NOW + 400
        blocked = '1794890501.000'
        for notable, risk, said in (
                (1, 0, 'NOT RAISED YET ({}: 1 finding(s), 0 risk event(s))'),
                (0, 1, 'NOT RAISED YET ({}: 0 finding(s), 1 risk event(s))'),
                (2, 1, 'a chain was raised more than once ({}: 2 finding(s), 1 risk event(s)): one finding and one '
                       'risk event are expected for each'),
                (1, 2, 'a chain was raised more than once ({}: 1 finding(s), 2 risk event(s))')):
            with self.subTest(notable=notable, risk=risk):
                self.stack.findings = []
                self.stack.raise_finding(CHAIN, NOW + 385, blocked, notable=notable, risk=risk)
                code, text = self.verify()
                self.assertEqual((code, self.statuses(text)), (1, ['OK'] * 5 + ['FAIL']), text)
                self.assertIn(said.format(CHAIN), text)
        # A finding of another rule, or for another chain, is not this chain's finding.
        self.stack.findings = []
        self.stack.raise_finding(CHAIN, NOW + 385, blocked, rule='AI Governance - Duo Authentication Fraud or Denial '
                                                                   'Burst - Rule')
        self.stack.raise_finding('nina.osei:takeover:1794890999', NOW + 385, blocked)
        self.assertIn('NOT RAISED YET ({}: 0 finding(s), 0 risk event(s))'.format(CHAIN), self.verify()[1])
        # The risk event is dated at the blocked turn, hours before it was raised: the search reaches back for it.
        self.stack.findings = []
        self.stack.raise_finding(CHAIN, NOW + 385, blocked)
        code, text = self.verify()
        self.assertEqual((code, self.statuses(text)), (0, ['OK'] * 6), text)
        self.assertEqual([float(item['time']) for item in self.stack.findings], [NOW + 385, 1794890501.0])
        self.assertEqual(self.last_search('findings')['earliest'], str(1794890419 - 86400))
        # An account that may not search the two indexes sees no finding, and is told why.
        self.stack.hidden |= {'notable', 'risk'}
        self.now = NOW + 800
        text = self.verify()[1]
        self.assertIn('NOT RAISED (', text)
        self.assertIn('This account can search no index notable on the stack', text)

    def test_v6_no_run_is_waited_for_when_the_rule_is_off_or_cannot_be_timed(self):
        self.sent()
        for change, why in (
                ({'disabled': True}, 'the joined rule is disabled on this stack: no scheduled run judges the copy'),
                ({'realtime_schedule': True}, 'the joined rule\'s runs cannot be timed (realtime_schedule is on: a '
                                              'run the scheduler skips is a slot never judged)'),
                ({'cron_schedule': '*/7 * * * *'}, 'the joined rule\'s runs cannot be timed (it runs every 7 min, '
                                                   'which does not divide the hour: its slots would overlap)')):
            with self.subTest(change=change):
                rule = dict(self.stack.saved[tool.JOINED_RULE])
                self.stack.saved[tool.JOINED_RULE] = dict(rule, **change)
                self.stack.auto_schedule = None                  # (the fake's own scheduler reads the same stanza)
                del self.naps[:]
                code, text = self.verify('--wait', '900')
                self.stack.saved[tool.JOINED_RULE] = rule
                self.assertEqual((code, self.naps), (1, []), text)
                self.assertIn('NOT RAISED ({}: 0 finding(s), 0 risk event(s)): {}'.format(CHAIN, why), text)

    def refused_verify(self, *extra, **options):
        """The text of a `verify` that is refused before the stack is asked anything (exit 2)."""
        asked = len(self.stack.requests)
        code, text = self.verify(*extra, **options)
        self.assertEqual(code, 2, text)
        self.assertIn('REFUSED: ', text)
        self.assertEqual(len(self.stack.requests), asked, 'the stack was asked something')
        return text

    def test_verify_checks_its_bundle_its_option_and_its_credential_before_it_asks_the_stack_anything(self):
        for value in ('soon', '-1', '7201', '900s'):
            self.assertIn('--wait: expected a whole number from 0 to 7200', self.refused_verify('--wait', value))
        self.assertIn('set exactly one of $SPLUNK_ADMIN_PASSWORD and $SPLUNK_ADMIN_TOKEN in the environment '
                      '(neither is set)', self.refused_verify(env={}))
        self.assertIn('(both are set)', self.refused_verify(env={tool.ENV_STACK_PASSWORD: self.stack.password,
                                                                  tool.ENV_STACK_TOKEN: self.stack.token}))
        self.assertIn('--stack', self.refused_verify(stack='http://stack.example.test:8089'))   # plain http
        self.assertIn('--ca-file cannot be read as a CA bundle', self.refused_verify(
            '--ca-file', self.bundle, stack='https://127.0.0.1:1'))
        fresh = self.path('unapproved.bundle.json')
        tool.write_bundle(fresh, bundle_of())
        self.assertIn('--bundle is not approved as it now is', self.refused_verify(bundle=fresh))
        os.chmod(fresh, 0o644)
        self.assertIn('--bundle is readable or writable by others', self.refused_verify(bundle=fresh))
        self.assertIn('--bundle cannot be read (missing, or a symlink)', self.refused_verify(bundle=self.path('none')))
        # It takes no HEC option and no secret on the command line.
        for extra in (('--hec-url', self.hec_url), ('--hec-file', 'x.json'), ('--password', 'fixture-typed-secret')):
            code, text = self.verify(*extra)
            self.assertEqual((code, self.stack.requests), (2, []), text)
            self.assertIn('unrecognized arguments: ' + extra[0], text)
            self.assertNotIn('fixture-typed-secret', text)

    def test_verify_never_reads_the_splunk_the_bundle_came_from_and_says_who_it_asked(self):
        code, text = self.verify(stack=self.url, env={tool.ENV_STACK_PASSWORD: self.fake.password})
        self.assertEqual(code, 2, text)
        self.assertIn('REFUSED: --stack is the Splunk this bundle was exported from', text)
        self.assertEqual([search for search in self.fake.searches if search['kind'] == 'label'], [])
        # A token works as well as a password, another account name is sent as given, and the override of
        # the certificate check is named before the first request is made.
        self.sent()
        for env in ({tool.ENV_STACK_TOKEN: self.stack.token}, {tool.ENV_STACK_PASSWORD: self.stack.password}):
            asked = len(self.stack.requests)
            code, text = self.verify(env=env)
            self.assertEqual(self.statuses(text)[:5], ['OK'] * 5, text)
            given = self.stack.requests[asked]['headers']['Authorization']
            self.assertEqual(given.split(' ')[0], 'Bearer' if tool.ENV_STACK_TOKEN in env else 'Basic')
        self.stack.user = 'sc_admin'
        self.assertIn('did not accept the credential (HTTP 401). With a password, check the user name option',
                      self.verify()[1])
        code, text = self.verify('--username', 'sc_admin')
        self.assertEqual(self.statuses(text)[:5], ['OK'] * 5, text)
        given = base64.b64decode(self.stack.requests[-1]['headers']['Authorization'].split(' ')[1]).decode('ascii')
        self.assertEqual(given.split(':')[0], 'sc_admin')
        self.assertEqual(tool.tls_policy('https', 'stack.example.test', None, True, '--no-verify-splunkd'), (
            False, 'NOT VERIFIED (--no-verify-splunkd): the credential goes to a server nobody authenticated'))
        options = dict((action.dest, action) for action in tool.build_parser()._actions[-1].choices['verify']._actions)
        self.assertEqual(sorted(name for name in options if name != 'help'),
                         ['bundle', 'ca_file', 'no_verify_splunkd', 'stack', 'username', 'wait'])
        self.assertEqual((options['wait'].default, options['username'].default), ('0', 'admin'))

    def test_an_index_the_account_cannot_search_is_not_read_as_a_stack_that_holds_nothing(self):
        self.sent()
        self.stack.hidden.add('gen_ai_log')                      # every search on it answers "no events", no message
        before = len(self.stack.searches)
        code, text = self.verify('--wait', '900')
        self.assertEqual((code, self.naps), (1, []), text)
        self.assertIn('[FAIL] V1. the copies - this account can search no index gen_ai_log on the stack', text)
        self.assertIn('NOT VERIFIED: the index cannot be searched.', text)
        self.assertEqual([search['kind'] for search in self.stack.searches[before:]], ['eventcount'])
        self.assertNotIn('Run `send`', text)                     # never the advice to send again

    def test_a_warning_on_a_search_means_ask_again_and_an_error_never_reads_as_nothing_there(self):
        self.sent()
        self.stack.warn_runs = 1                                 # splunkd's own start-up warning, once
        before = len(self.stack.searches)
        code, text = self.verify()
        self.assertEqual(self.statuses(text)[:5], ['OK'] * 5, text)
        self.assertEqual([search['kind'] for search in self.stack.searches[before:]][:2], ['eventcount', 'eventcount'])
        self.assertEqual(self.naps, [tool.WARN_PAUSE])
        self.stack.warn_runs = -1                                # a warning that stays: no answer is used
        code, text = self.verify()
        self.assertEqual(code, 2, text)
        self.assertIn('still answers with a warning after 3 runs, so its answer is not used', text)
        self.assertNotIn('[  OK]', text)
        self.stack.warn_runs = 0
        for kind, step in (('present', 'V1, the presence search'), ('label', 'V2, the labelled events'),
                           ('duo_half', 'V4, the Duo half'), ('findings', 'V6, the findings')):
            with self.subTest(kind=kind):
                self.stack.fail_search = {kind: 'Search not executed: the indexers are busy'}
                code, text = self.verify()
                self.assertEqual(code, 2, text)                  # refused: neither "missing" nor "verified"
                self.assertIn('REFUSED: {}: the search failed on --stack: Search not executed'.format(step), text)
                self.assertNotIn('VERIFIED', text.replace('NOT VERIFIED', ''))
        # splunkd quotes the search text in a parse error, and V4's text carries the Duo transaction ids.
        self.stack.fail_search = {'duo_half': 'Error in \'search\' command: Unable to parse the search: "' + TXID + '"'}
        self.assertIn('V4, the Duo half: the search failed on --stack: Error in \'search\' command: Unable to parse '
                      'the search: "<hidden>"', self.verify()[1])
        self.stack.fail_search = {}

    def test_what_a_stack_answers_is_read_by_shape_and_printed_only_as_counts_times_and_plain_words(self):
        self.sent()
        self.now = NOW + 800
        self.stack.auto_schedule = None
        hostile = PROMPT + ' ' + ADDRESS
        # V6b: columns that are missing, lists where one value belongs, and values that are not plain words.
        self.stack.odd_answer = {'rule_runs': json.dumps({'messages': [], 'results': [
            {'scheduled_time': str(TICK), 'status': hostile, 'alert_actions': hostile, 'result_count': 'many'},
            {'scheduled_time': [str(TICK), str(TICK + 300)], 'status': ['success', 'continued']},
            {}, {'status': 'continued', 'lag': hostile}]}),
            'rule_errors': json.dumps({'messages': [], 'results': [{'errors': '0'}]})}
        code, text = self.verify()
        self.assertEqual(code, 1, text)
        self.assertIn('      tick 2026-11-17T07:25:00Z: other, 0 result(s), suppressed 0, actions other', text)
        self.assertIn('      tick unknown: none, 0 result(s), suppressed 0, actions none', text)
        self.assertIn('      tick unknown: continued, 0 result(s), suppressed 0, actions none', text)
        self.assertIn('-> deferred or skipped and not run yet', text)
        # An error message of the scheduler is cleaned and cut; a Duo transaction id in it is hidden.
        self.stack.odd_answer['rule_errors'] = json.dumps({'messages': [], 'results': [
            {'errors': '3', 'message': 'bad\x1b[31m lookup ' + TXID + ' ' + 'x' * 400, 'last_error': '1'}]})
        text = self.verify()[1]
        self.assertIn('3 error line(s); the last: bad [31m lookup <hidden> xxx', text)
        self.assertNotIn('x' * 241, text)
        # V5 and V6: a row for a chain nobody asked about is not printed and does not count.
        self.stack.odd_answer = {
            'rule': json.dumps({'messages': [], 'results': [{'chain_id': hostile}, {'chain_id': [CHAIN, hostile]},
                                                            {'user': 'nina.osei'}, {'chain_id': CHAIN}]}),
            'findings': json.dumps({'messages': [], 'results': [
                {'index': 'notable', 'chain_id': hostile, 'rows': '1'},
                {'index': hostile, 'chain_id': CHAIN, 'rows': '1'},
                {'index': 'notable', 'chain_id': CHAIN}, {'index': 'risk', 'chain_id': CHAIN, 'rows': hostile},
                {'chain_id': CHAIN, 'rows': '1'}]})}
        code, text = self.verify()
        self.assertIn("[  OK] V5. the rule, run by hand - 1 chain(s) for this set's sign-ins: " + CHAIN, text)
        self.assertIn('NOT RAISED ({}: 0 finding(s), 0 risk event(s))'.format(CHAIN), text)
        # P2: a row without a column, or with two values in one, never adds up to "as recorded".
        self.stack.odd_answer = {'label': json.dumps({'messages': [], 'results': [
            {'sourcetype': ['demobot:audit', 'gen_ai:json'], 'log_type': 'audit', 'host': HOST, 'events': '6'}]})}
        self.assertIn("[FAIL] V2. the label - 6 event(s) carry this bundle's label and the ledger records 6 handed "
                      'to this stack: a copy is under another sourcetype, log_type or host', self.verify()[1])
        self.stack.odd_answer = {'label': json.dumps({'messages': [], 'results': [{'events': hostile}]})}
        self.assertIn("[FAIL] V2. the label - 0 event(s) carry this bundle's label and the ledger records 6",
                      self.verify()[1])
        # P1: a row for an id that was not asked about is no copy of anything, and nothing trips over it.
        rows = self.stack.search({'search': tool.spl_present('gen_ai_log', STAGED_IDS), 'exec_mode': 'oneshot',
                                  'count': '0', 'earliest_time': '0', 'latest_time': '+1d'})['results']
        stray = dict(rows[0], rs_id='5ca1ab1e-0009-4000-8000-00000000ffff')
        self.stack.odd_answer = {'present': json.dumps({'messages': [], 'results': rows + [stray]})}
        code, text = self.verify()
        self.assertEqual(self.statuses(text)[:2], ['OK', 'OK'], text)
        self.assertIn('each of the 6 id(s) is on the stack once', text)
        self.assertNotIn('unexpected error', text)

    def test_the_schedulers_record_is_bounded_and_a_time_a_stack_names_is_never_made_a_date_unchecked(self):
        self.sent()
        self.stack.auto_schedule = None
        then = int(NOW) - 2 * 86400                              # as if the copies had been indexed two days ago
        for event in self.stack.events:
            if event['fields'].get('resend') == 'true':
                event['indexed'] = then
        tick = then + 300                                        # NOW is on a tick, so two days earlier is one too
        for number in range(20):
            self.stack.tick(tick + 300 * number)
        code, text = self.verify('--wait', '900')
        self.assertEqual((code, self.naps), (1, []), text)       # long overdue: nothing is waited for
        self.assertIn('the tick 2026-11-15T07:25:00Z judged the copy and its finding was due by 2026-11-15T07:32:00Z',
                      text)
        # One day of the record from that tick, not everything since, and twelve lines of it.
        self.assertEqual((self.last_search('rule_runs')['earliest'], self.last_search('rule_runs')['latest']),
                         (str(tick - 60), str(tick + 86400)))
        self.assertEqual(self.last_search('rule_errors')['latest'], str(tick + 86400))
        self.assertEqual(len(re.findall(r'^      tick 2026-11-15T', text, re.M)), 12)
        self.assertIn('      ... and 8 later line(s)', text)
        # Numbers no clock ever showed: printed as "unknown", never handed to the date functions.
        absurd = '9' * 17
        self.stack.odd_answer = {'rule_runs': json.dumps({'messages': [], 'results': [
            {'scheduled_time': absurd, 'status': 'success', 'lag': '5', 'result_count': absurd}]})}
        text = self.verify()[1]
        self.assertIn('      tick unknown: success, started 5 s after the tick, ' + absurd + ' result(s)', text)
        self.stack.odd_answer = {'findings': json.dumps({'messages': [], 'results': [
            {'index': name, 'chain_id': CHAIN, 'rows': '1', 'first_raised': absurd} for name in ('notable', 'risk')]})}
        code, text = self.verify()
        self.assertEqual(code, 0, text)
        self.assertIn('one finding and one risk event for each of the 1 chain(s), first raised unknown', text)
        self.stack.odd_answer = {}
        self.stack.rewrite_present = lambda row: dict(row, first_indexed=absurd, last_indexed=absurd)
        code, text = self.verify('--wait', '900')
        self.assertEqual((code, self.naps), (1, []), text)
        self.assertIn('NOT RAISED ({}: 0 finding(s), 0 risk event(s)): the stack does not say when the copies were '
                      'indexed'.format(CHAIN), text)
        self.assertNotIn('scheduler\'s record', text.split('NOT RAISED (')[-1])


class VerifyFakeFidelityTests(VerifyCase):
    """The fake's scheduler and its findings behave as splunkd and Enterprise
    Security do where `verify` would notice the difference. The slot is read
    from the shipped stanza by the fake itself, not through the tool."""
    RULE = '"' + fake_stack.JOINED_RULE + '"'

    def raised_by(self, indexed):
        """The cron tick whose run raises the chain when the copies were indexed at `indexed`."""
        self.restart()
        self.sent()
        for event in self.stack.events:
            if event['fields'].get('resend') == 'true':
                event['indexed'] = indexed
        self.now = NOW + 3000
        self.stack.schedule()
        lines = [line for line in self.stack.ticks if line.get('result_count')]
        self.assertEqual(len(lines), 1, 'the chain was raised by more than one run, or by none')
        return lines[0]['scheduled_time']

    def test_a_run_judges_one_slot_of_index_time_and_the_tool_names_the_same_tick(self):
        self.assertEqual(self.stack.slot_seconds(), (300, 420, 120))      # from the shipped stanza
        for indexed, tick in ((int(NOW), TICK), (int(NOW) + 179, TICK), (int(NOW) + 180, TICK + 300),
                              (int(NOW) + 479, TICK + 300), (int(NOW) + 480, TICK + 600)):
            with self.subTest(indexed=indexed):
                self.assertEqual(self.raised_by(indexed), tick)
                self.assertEqual(tool.judging_tick(indexed, tool.Slot(5, 2)), tick)

    def test_a_chain_is_raised_once_as_a_finding_dated_now_and_a_risk_event_dated_at_the_event(self):
        self.sent()
        self.now = TICK + 79
        self.stack.schedule()
        self.assertEqual((self.stack.findings, [line for line in self.stack.ticks if line['scheduled_time'] == TICK]),
                         ([], []))                                   # the run of 07:25:00Z has not started
        self.now = TICK + 3000
        self.stack.schedule()
        notable, risk = self.stack.findings                           # ten later runs raised nothing more
        self.assertEqual((notable['index'], float(notable['time']), notable['orig_time'], notable['indexed']),
                         ('notable', TICK + 83.0, '1794890501.000', TICK + 85))
        self.assertEqual((risk['index'], float(risk['time']), risk['orig_time']), ('risk', 1794890501.0, None))
        asked = 'chain_id="' + CHAIN + '"'
        self.assertEqual(self.stack.q_findings(0, 10 ** 11, self.RULE, asked), [
            {'index': 'notable', 'chain_id': CHAIN, 'rows': '1', 'first_raised': str(TICK + 85),
             'event_time': '1794890501.000'},
            {'index': 'risk', 'chain_id': CHAIN, 'rows': '1', 'first_raised': str(TICK + 85),
             'event_time': '1794890501.000'}])
        # stats ... by over nothing is no row; a range that starts after the event misses the risk event only.
        self.assertEqual(self.stack.q_findings(0, 10 ** 11, self.RULE, 'chain_id="x.y:takeover:1794890000"'), [])
        self.assertEqual([row['index'] for row in self.stack.q_findings(TICK, 10 ** 11, self.RULE, asked)], ['notable'])
        runs = self.stack.q_rule_runs(0, 10 ** 11, self.RULE, str(TICK))
        self.assertEqual(runs[-1], {'scheduled_time': str(TICK), 'dispatch_time': str(TICK + 80), 'lag': '80',
                                    'status': 'success', 'result_count': '1', 'suppressed': '0',
                                    'alert_actions': 'notable,risk'})
        self.assertEqual(runs[0], {'scheduled_time': str(TICK + 2700), 'dispatch_time': str(TICK + 2780),
                                   'lag': '80', 'status': 'success', 'result_count': '0', 'suppressed': '0',
                                   'alert_actions': ''})                # logged as alert_actions=""
        self.assertEqual(self.stack.q_rule_runs(0, 10 ** 11, self.RULE, str(TICK + 2701)), [])
        self.stack.tick(TICK + 3000, 'continued')
        self.assertEqual(self.stack.q_rule_runs(0, 10 ** 11, self.RULE, str(TICK + 3000)),
                         [{'scheduled_time': str(TICK + 3000), 'status': 'continued'}])
        # A piece of the chain that is indexed again later puts the chain into a later slot. The rule has
        # judged it and its suppression is keyed on the chain id: no second finding.
        for event in self.stack.events:
            if event['fields'].get('resend') == 'true':
                event['indexed'] = TICK + 3100
        self.now = TICK + 4000
        self.stack.schedule()
        self.assertEqual(len(self.stack.findings), 2)
        self.assertEqual([line['result_count'] for line in self.stack.ticks if line.get('result_count')], [1])

    def test_the_label_is_counted_from_indexed_fields_with_whole_second_bounds(self):
        self.sent()
        mine = '"' + self.written()['bundle_id'] + '"'
        rows = self.stack.q_label(0, 10 ** 11, '"gen_ai_log"', mine)
        self.assertEqual([(row['sourcetype'], row['log_type'], row['host'], row['events']) for row in rows], [
            ('demobot:audit', 'audit', HOST, '2'), ('demobot:error', 'error', HOST, '1'),
            ('demobot:escalation', 'escalation', HOST, '1'), ('gen_ai:json', 'governance', HOST, '2')])
        self.assertEqual({row['first_indexed'] for row in rows}, {str(int(NOW))})
        self.assertEqual(self.stack.q_label(0, 10 ** 11, '"gen_ai_log"', '"rs-20261101-aaaaaaaaaaaa"'), [])   # no row
        self.assertEqual(self.stack.q_label(0, 10 ** 11, '"duo"', mine), [])
        # tstats cuts both bounds to the whole second: 04:40:19.556 is inside [..19.9, ..20.0), which search would miss.
        edge = fake_stack.decimal.Decimal('1794890419.9')
        self.assertEqual([row['events'] for row in self.stack.q_label(edge, edge + 1, '"gen_ai_log"', mine)], ['1'])


if __name__ == '__main__':
    if sys.argv[1:] == ['--write-runbook-html']:
        with io.open(os.path.join(REPO, 'tools', 'staged-resend-runbook.html'), 'w', encoding='utf-8') as out:
            out.write(render_runbook_html())
        sys.exit(0)
    unittest.main()
