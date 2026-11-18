# encoding=utf-8
"""
Live SPL fixtures for the Cisco Duo content (TA-gen_ai_cim 1.9.0): makeresults
rows run through the TA's own props expressions, eventtype searches, the
genai_duo_* macros, the pipeline of "AI Governance - Duo Authentication Fraud
or Denial Burst - Rule" and of the joined rule "AI Governance - Duo Denial
Burst to Blocked AI Turn Correlation - Rule" (LR-06) after their base searches,
and the identity lookup gen up to (never including) its outputlookup.
R-CONF-003: a config that parses is not a config that fires.

makeresults rows get no props, so a fixture names conf text by token and
resolve() puts in this branch's own text:
  <<props:STANZA|KEY>>   the EVAL expression, parenthesized, on one line
  <<alias:STANZA|KEY>>   the FIELDALIAS as eval assignments: new='orig', ...
  <<eventtype:NAME>>     the eventtype's search string
  <<persona_key>>        the first key of lookups/pseudoco_identity_personas.csv
                         (read at run time, so no persona login is copied here)
  <<persona_email>>      the first key holding "@" in that file's first row
A fixture with "tail" runs its rows through a saved search's own search text,
from the "from" marker up to the "to" marker (exclusive), then "append".
A fixture with "window" ([earliest, latest], epoch) is dispatched over that job
time range: the rule's time range is the slot of INDEX time it judges, so each
rule fixture names its slot and gives every row an _indextime before or in it.

What the fixtures cannot show, and what dispatches the FULL text of the two
rules (base search and subsearches included) instead; all of it read-only, a
dispatched search runs no alert action:
  * DuoRuleDispatchTests / DuoChainDispatchTests: one slot as scheduled, 31
    days of index time, all time with and without an end; no error.
  * DuoSlotEdgeTests: the edge each rule compares index time with is the job's
    own earliest. A fixture's rows are makeresults rows, where addinfo returns
    the job's time range anywhere; in the dispatched search the base search
    carries the event-time range its subsearch wrote, and addinfo in the MAIN
    pipeline returns that instead. The joined rule first shipped that way: all
    its fixtures passed while every row counted as new.
  * DuoRuleTilingTests / DuoChainTilingTests: the index-time slots the
    SCHEDULER gives each rule (their edges sit dispatch.latest_time back from
    the cron ticks) are judged one by one and must raise what one pass raises,
    nothing twice, and what a plain event-time reference search with no
    index-time logic at all finds (REFERENCE_BURSTS, REFERENCE_CHAINS): the
    rule's own finder is not its own oracle.
  * DuoRuleSplitTests / DuoChainSplitTests: index time is cut at every second
    at which an event of a burst or chain was indexed, and the pieces, judged
    in order, must raise it exactly once.
  * DuoContextTests: what a run READS. For a slot, the rule's base search must
    return exactly the events a plain search finds in the event-time window
    around the slot's new events (3,600 s back and 601 forward for the Duo
    rule, 6,000 and 6,001 for the joined rule). Nothing else exercises that
    reach: drop the look-back and a late sixth failure is read alone, with
    every other test green on the dev data.

Needs a Splunk where this branch's conf is visible from SPLUNK_TEST_APP
(default TA-gen_ai_cim); skipped otherwise:

    SPLUNK_TEST_URL=https://localhost:8090 SPLUNK_TEST_USER=admin \\
    SPLUNK_TEST_PASSWORD=... python3 -m unittest tools.tests.test_duo_spl -v

(or SPLUNK_TEST_TOKEN for a bearer token). Read-only: only makeresults and the
searches above, and the lookup gen is cut before its outputlookup.

A skip is not a pass. Two things keep a change to either rule's text from going
green on skips:
  * SPLUNK_TEST_REQUIRED=1 makes every live test FAIL when no Splunk is
    configured. Set it for the run that gates such a change.
  * fixtures/duo_rule_proof.json records, per rule, the digest of the text its
    fixtures were last run against (the search and every macro it uses). The
    offline suite fails while the text differs from it. Without credentials,
    the fixtures go through the read-only Splunk MCP instead:

        python3 tools/tests/test_duo_spl.py --fixtures chain     # or: rule
        python3 tools/tests/test_duo_spl.py --verify chain results.json
        python3 tools/tests/test_duo_spl.py --record-proof chain results.json "how it was run"

    --fixtures prints each fixture's window, expected rows and resolved search
    (each fits the MCP's 5,000 characters); --verify compares the rows that
    came back ({"<number or name>": [rows]}) with what each fixture expects;
    --record-proof writes the digest, and only from a results file that agrees
    with every fixture ("live" in its place runs them through SPLUNK_TEST_*).
    Never edit the digest by hand to make the suite green.
"""

import csv
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
from test_lab5_conf import read_conf  # noqa: E402
from test_lab5_spl import APP, URL, USER, export  # noqa: E402

FIXTURES = os.path.join(HERE, 'fixtures', 'duo_spl.json')
PROOF = os.path.join(HERE, 'fixtures', 'duo_rule_proof.json')
TOKEN = re.compile(r'<<(props|alias|eventtype):(?:([^|>]+)\|)?([^>]+)>>|<<persona_key>>|<<persona_email>>')
ALIAS_PAIR = re.compile(r'(\S+)\s+AS\s+(\S+)')
WRITES = re.compile(r'\|\s*(outputlookup|outputcsv|collect|stash|summaryindex|sumindex|sendalert|sendemail|delete|'
                    r'tscollect|mcollect|meventcollect|dump)\b')
RULE = 'AI Governance - Duo Authentication Fraud or Denial Burst - Rule'
CHAIN = 'AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule'
GROUPS = {'rule': RULE, 'chain': CHAIN}
MCP_LIMIT = 5000                      # characters the read-only Splunk MCP takes in one search
LIVE = bool(URL and (os.environ.get('SPLUNK_TEST_PASSWORD') or os.environ.get('SPLUNK_TEST_TOKEN')))
REQUIRED = os.environ.get('SPLUNK_TEST_REQUIRED', '').strip().lower() in ('1', 'true', 'yes')
NEEDS = 'set SPLUNK_TEST_URL and SPLUNK_TEST_PASSWORD (or SPLUNK_TEST_TOKEN)'


def live(cls):
    """Class decorator for the tests that need a Splunk. Without one they are
    skipped; with SPLUNK_TEST_REQUIRED=1 each of them FAILS instead, so the run
    that gates a change to a rule's text cannot go green on skips."""
    if LIVE:
        return cls
    if not REQUIRED:
        return unittest.skip(NEEDS)(cls)

    def refuse(self):
        self.fail('SPLUNK_TEST_REQUIRED is set and no Splunk is configured: ' + NEEDS)

    for name in [n for n in dir(cls) if n.startswith('test')]:
        setattr(cls, name, refuse)
    return cls


def _persona_keys():
    with io.open(os.path.join(REPO, 'lookups', 'pseudoco_identity_personas.csv'), encoding='utf-8') as handle:
        row = next(csv.DictReader(handle))
    return [k.strip().lower() for k in row['identity'].split('|') if k.strip()]


def persona_key():
    return _persona_keys()[0]


def persona_email():
    return [k for k in _persona_keys() if '@' in k][0]


def alias_assignments(value):
    pairs = ALIAS_PAIR.findall(value)
    if not pairs:
        raise KeyError('not a FIELDALIAS value: %r' % value)
    return ', '.join("%s='%s'" % (new, orig) for orig, new in pairs)


def tail(spec, searches):
    text = searches[spec['search']]['search']
    start = text.index(spec['from'])
    end = text.index(spec['to'], start) if spec.get('to') else len(text)
    return ' ' + re.sub(r'\s*\n\s*', ' ', text[start:end]).strip()


def resolve(fx, confs=None):
    """The fixture's full SPL with every token replaced. A missing key raises KeyError."""
    confs = confs or {'props': read_conf('props.conf'), 'eventtypes': read_conf('eventtypes.conf'),
                      'searches': read_conf('savedsearches.conf'), 'persona': persona_key(),
                      'persona_email': persona_email()}

    def sub(m):
        if m.group(0) == '<<persona_key>>':
            return confs['persona']
        if m.group(0) == '<<persona_email>>':
            return confs['persona_email']
        kind, stanza, key = m.groups()
        if kind == 'eventtype':
            return confs['eventtypes'][key]['search']
        value = confs['props'][stanza][key].replace('\n', ' ')
        return alias_assignments(value) if kind == 'alias' else '(' + value + ')'

    spl = fx['spl'] + (tail(fx['tail'], confs['searches']) if fx.get('tail') else '') + fx.get('append', '')
    return TOKEN.sub(sub, spl)


def load():
    with io.open(FIXTURES, encoding='utf-8') as handle:
        return json.load(handle)


def group(name):
    """The fixtures that run a rule's own text: 'rule' or 'chain'."""
    return [fx for fx in load() if fx.get('tail', {}).get('search') == GROUPS[name]]


def mismatch(fx, rows):
    """Why `rows` are not what a fixture expects; None when they are. Every key
    an expected row names must be equal; a row may carry more."""
    if len(rows) != len(fx['expect']):
        return 'expected {} row(s), got {}: {!r}'.format(len(fx['expect']), len(rows), rows)
    for n, (got, want) in enumerate(zip(rows, fx['expect']), 1):
        for key, value in want.items():
            if got.get(key) != value:
                return 'row {}: {} is {!r}, expected {!r}'.format(n, key, got.get(key), value)
    return None


def rule_search(name=RULE):
    return re.sub(r'\s*\n\s*', ' ', read_conf('savedsearches.conf')[name]['search']).strip()


###############################################################################
# The proof record: which text the fixtures were last run against
###############################################################################

MACRO_REF = re.compile(r'`([A-Za-z_]\w*)(\([^`]*\))?`')


def macro_stanza(name, args, macros):
    if not args:
        return name
    count = len(args[1:-1].split(','))
    return '{}({})'.format(name, count)


def proven_text(name, searches=None, macros=None):
    """Everything a rule's result depends on in this app's conf: its search on
    one line, then the definition of every macro it uses, macros used by those
    macros included, in name order."""
    searches = searches or read_conf('savedsearches.conf')
    macros = macros or read_conf('macros.conf')
    text = re.sub(r'\s*\n\s*', ' ', searches[name]['search']).strip()
    seen, todo = {}, [text]
    while todo:
        for ref, args in MACRO_REF.findall(todo.pop()):
            stanza = macro_stanza(ref, args, macros)
            if stanza not in seen:
                seen[stanza] = re.sub(r'\s*\n\s*', ' ', macros[stanza]['definition']).strip()
                todo.append(seen[stanza])
    return '\n'.join([text] + ['[{}] {}'.format(stanza, seen[stanza]) for stanza in sorted(seen)])


def digest(name):
    return hashlib.sha256(proven_text(name).encode('utf-8')).hexdigest()


def load_proof():
    with io.open(PROOF, encoding='utf-8') as handle:
        return json.load(handle)


###############################################################################
# Index-time slots, as the scheduler cuts them
###############################################################################

def slot_grid(stanza):
    """(period, phase) in seconds of the index-time slots the scheduler gives a
    rule. A run at cron tick T judges [T - earliest, T - latest), so the slot
    edges sit dispatch.latest_time back from the ticks: with */10 and -2m@m
    they fall on minutes ending in 8, never on the ten-minute marks."""
    period = int(re.match(r'^\*/(\d+) \* \* \* \*$', stanza['cron_schedule']).group(1)) * 60
    back = [int(re.match(r'^-(\d+)m@m$', stanza[key]).group(1)) * 60
            for key in ('dispatch.earliest_time', 'dispatch.latest_time')]
    if back[0] - back[1] != period:
        raise ValueError('the time range is not one cron period wide')
    return period, (-back[1]) % period


def slot_eval(period, phase):
    """SPL: the start of the scheduler's slot an event was indexed in."""
    return 'eval slot=floor((_indextime-{0})/{1})*{1}+{0}'.format(phase, period)


def pieces(cuts, width):
    """Consecutive job time ranges [cut, next cut) and a last one `width` long."""
    cuts = sorted(set(int(cut) for cut in cuts))
    return list(zip(cuts, cuts[1:] + [cuts[-1] + width])) if cuts else []


EDGE = re.compile(r' \| where isnotnull\(\w+\) \| eval is_new=if\(indexed>=([^,]+), 1, 0\)')


def edge_probe(spl):
    """A rule's own text up to the filter before its is_new eval, then one row:
    the edge it compares index time with. For a text that reads the slot's
    start where it must (an append subsearch), that is the job's earliest
    whatever the base search read; for one that reads it with addinfo in the
    main pipeline it is the event-time range the base search was given."""
    m = EDGE.search(spl)
    if not m:
        raise ValueError('no is_new eval of the expected shape in the search')
    return spl[:m.start()] + ' | stats max(eval({})) as edge'.format(m.group(1))


###############################################################################
# Reference searches: event time only, no finder, no slot
###############################################################################

DUO_EVENTS = '`genai_duo_auth_events` (action="failure" OR signature_id="user_marked_fraud")'
CHAIN_STEPS = ('((`genai_duo_auth_events` action="failure") OR (`genai_identity_activity_events` '
               '(gen_ai.audit.action="identity_signin_success" OR (gen_ai.operation.name="chat" '
               'gen_ai.policy.blocked="true"))))')
IDENTITY = ('| eval identity_user=`genai_identity_join_key(user)` '
            '| where isnotnull(identity_user) AND NOT in(identity_user, "", "unknown", "null") '
            '| `genai_identity_participant_filter` ')
# What the Duo rule must have raised from everything indexed before <<end>>,
# written without any of the rule's index-time machinery: every failure, by
# event time, in one read. It shares the rule's definition of a burst (a run
# with no gap over 10 minutes; 5 failures within 10 minutes; a fraud report is
# a fraud report only) and nothing else.
REFERENCE_BURSTS = (
    DUO_EVENTS + ' _index_latest=<<end>> ' + IDENTITY +
    '| eval ref_event=coalesce(txid, _bkt . ":" . _cd) | dedup identity_user, ref_event '
    '| eval ref_fraud=if(lower(signature_id)=="user_marked_fraud", 1, 0), '
    'ref_fail=if(action=="failure" AND ref_fraud==0, 1, 0) | sort 0 _time '
    '| streamstats current=f last(_time) as ref_prev by identity_user '
    '| eval ref_opens=if(isnull(ref_prev) OR _time-ref_prev>600, 1, 0) '
    '| streamstats sum(ref_opens) as ref_seq by identity_user '
    '| streamstats time_window=10m sum(ref_fail) as ref_fail_10m by identity_user '
    '| stats min(eval(if(ref_fail_10m>=5, _time, null()))) as ref_burst, '
    'min(eval(if(ref_fraud==1, _time, null()))) as ref_fraud by identity_user, ref_seq '
    '| where isnotnull(ref_burst) OR isnotnull(ref_fraud) '
    '| eval burst_id=mvappend(if(isnotnull(ref_burst), identity_user . ":burst:" . tostring(floor(ref_burst)), null()), '
    'if(isnotnull(ref_fraud), identity_user . ":fraud:" . tostring(floor(ref_fraud)), null())) '
    '| mvexpand burst_id | table burst_id')
# The same for the joined rule: burst, then sign-in within 30 minutes, then a
# blocked verified turn within 60, by event time, in one read.
REFERENCE_CHAINS = (
    CHAIN_STEPS + ' _index_latest=<<end>> ' + IDENTITY +
    '| eval ref_step=case(\'gen_ai.audit.action\'=="identity_signin_success", "signin", '
    'isnotnull(\'gen_ai.audit.action\'), null(), `genai_identity_verified_turn` AND '
    '\'gen_ai.policy.blocked\'=="true", "blocked", isnotnull(\'gen_ai.operation.name\') OR '
    'isnotnull(\'gen_ai.provider.name\'), null(), action=="failure", "failure") | where isnotnull(ref_step) '
    '| eval ref_event=coalesce(txid, \'details.duo_txid\', mvindex(\'gen_ai.event.id\', 0), _bkt . ":" . _cd) '
    '| dedup identity_user, ref_event | eval ref_fail=if(ref_step=="failure", 1, 0) | sort 0 _time '
    '| streamstats time_window=10m sum(ref_fail) as ref_fail_10m by identity_user '
    '| eval ref_burst=if(ref_fail==1 AND ref_fail_10m>=5, _time, null()) '
    '| streamstats time_window=30m last(ref_burst) as ref_near by identity_user '
    '| eval ref_signin=if(ref_step=="signin" AND isnotnull(ref_near), _time, null()) '
    '| streamstats last(ref_signin) as ref_chain by identity_user '
    '| where ref_step=="blocked" AND _time-ref_chain<=3600 | stats count by identity_user, ref_chain '
    '| eval chain_id=identity_user . ":takeover:" . tostring(floor(ref_chain)) | table chain_id')
REACH = '-181d@d'                     # how far back either rule reads events (Duo keeps 180 days)
# What the joined rule's base search reads: its steps, and the successful Duo
# authentications that only describe a sign-in.
CHAIN_READS = ('((`genai_duo_auth_events` (action="failure" OR action="success")) OR (`genai_identity_activity_events` '
               '(gen_ai.audit.action="identity_signin_success" OR (gen_ai.operation.name="chat" '
               'gen_ai.policy.blocked="true"))))')
# Per rule: what counts as NEW in a slot, what the base search reads, and how far
# around the new events it reads by event time (seconds back, seconds forward).
# Written here from the design, not derived from the conf: a changed margin has
# to be changed in both places, on purpose.
CONTEXT = {RULE: (DUO_EVENTS, DUO_EVENTS, 3600, 601), CHAIN: (CHAIN_STEPS, CHAIN_READS, 6000, 6001)}


def reference(text, end):
    return text.replace('<<end>>', str(int(end)))


class DuoSplFixtureFileTests(unittest.TestCase):
    """Offline: every token resolves, every tail marker exists, nothing writes."""

    def test_tokens_and_tails_resolve(self):
        fixtures = load()
        seen = set()
        for fx in fixtures:
            with self.subTest(fx['name']):
                spl = resolve(fx)
                self.assertIsNone(TOKEN.search(spl), spl)
                self.assertTrue(spl.startswith('| makeresults'), spl[:40])
                self.assertIsNone(WRITES.search(spl), 'fixtures must stay read-only')
                seen.update(re.findall(r'<<(props|alias|eventtype|persona_key|persona_email)', fx['spl']))
                if fx.get('tail'):
                    seen.add('tail:' + fx['tail']['search'])
        for kind in ('props', 'alias', 'eventtype', 'persona_key', 'persona_email',
                     'tail:AI Governance - Duo Authentication Fraud or Denial Burst - Rule',
                     'tail:' + CHAIN, 'tail:GenAI - Identity - Duo Identity Lookup Gen'):
            self.assertIn(kind, seen)

    def test_fixtures_use_only_documentation_addresses_and_invented_names(self):
        with io.open(FIXTURES, encoding='utf-8') as handle:
            text = handle.read()
        for ip in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', text):
            self.assertRegex(ip, r'^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$', ip)
        for email in re.findall(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+', text):
            self.assertTrue(email.endswith('@corp.test'), email)
        self.assertNotRegex(text.lower(), r'example\.com|pseudocoassistant|ikey|skey|secret')

    def test_fixture_file_matches_its_generator(self):
        gen = os.path.join(HERE, 'fixtures', 'duo_spl_gen.py')
        proc = subprocess.run([sys.executable, '-I', gen, '--check'], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
        self.assertEqual(proc.returncode, 0, proc.stdout.decode())

    def test_alias_assignments(self):
        self.assertEqual(alias_assignments('application.name AS app application.name AS dest'),
                         "app='application.name', dest='application.name'")


@live
class DuoSplFixtureTests(unittest.TestCase):

    def test_fixtures(self):
        for fx in load():
            with self.subTest(fx['name']):
                if fx.get('window'):
                    rows, errors = export_window(resolve(fx), *fx['window'])
                else:
                    rows, errors = export(resolve(fx))
                self.assertEqual(errors, [], fx['name'])
                self.assertIsNone(mismatch(fx, rows), fx['name'])


def export_window(spl, earliest, latest='now'):
    """export() with a time range: (results, FATAL/ERROR messages)."""
    import base64
    import ssl
    import urllib.parse
    import urllib.request
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    if os.environ.get('SPLUNK_TEST_TOKEN'):
        headers['Authorization'] = 'Bearer ' + os.environ['SPLUNK_TEST_TOKEN']
    else:
        cred = '{}:{}'.format(USER, os.environ.get('SPLUNK_TEST_PASSWORD', ''))
        headers['Authorization'] = 'Basic ' + base64.b64encode(cred.encode()).decode()
    params = {'search': spl if spl.startswith('|') else 'search ' + spl, 'earliest_time': str(earliest),
              'output_mode': 'json', 'exec_mode': 'oneshot', 'count': 0}
    if str(latest):                          # '' = no latest (an all-time search)
        params['latest_time'] = str(latest)
    body = urllib.parse.urlencode(params).encode()
    path = '/servicesNS/{}/{}/search/jobs'.format(urllib.parse.quote(USER), urllib.parse.quote(APP))
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # local dev splunkd, self-signed
    req = urllib.request.Request(URL.rstrip('/') + path, data=body, headers=headers, method='POST')
    with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
        payload = json.loads(resp.read().decode())
    errors = [m for m in payload.get('messages', []) if m.get('type') in ('FATAL', 'ERROR')]
    return payload.get('results', []), errors


class DuoRuleSearchTextTests(unittest.TestCase):
    """Offline: the text DuoRuleDispatchTests dispatches is the rule's own, and read-only."""

    def test_dispatched_text_is_the_full_rule_search(self):
        spl = rule_search()
        self.assertTrue(spl.startswith('`genai_duo_auth_events` (action="failure" OR '
                                       'signature_id="user_marked_fraud") [| makeresults | addinfo '), spl[:120])
        self.assertTrue(spl.endswith('burst_epoch, fraud_epoch'), spl[-60:])
        self.assertNotRegex(spl, r'\|\s*tstats\b|datamodel')   # (eventstats and streamstats are fine)
        self.assertIsNone(WRITES.search(spl))

    def test_every_rule_fixture_names_its_index_time_slot(self):
        """A rule fixture without a window would run over all time, where every row
        is new: it could not tell a late arrival from a first sight."""
        rule = group('rule')
        self.assertGreaterEqual(len(rule), 20)
        for fx in rule:
            with self.subTest(fx['name']):
                earliest, latest = fx['window']
                self.assertEqual(latest - earliest, 600)
                self.assertIn('_indextime=', fx['spl'])
                self.assertIn('txid=', fx['spl'])
        timing = [fx for fx in rule if fx['name'].startswith('rule timing: ')]
        for needle in ('late arrival', 'repeat burst', '30-day backfill', 'backfill equals live', 'sent twice'):
            self.assertTrue([fx for fx in timing if needle in fx['name']], needle)
        # The timing fixtures replay the lab's staged scenarios: they name the two
        # lab personas by short name, and every other fixture an invented identity.
        for fx in timing:
            self.assertRegex(fx['spl'], r'"(nina\.osei|jordan\.reyes)"', fx['name'])
            self.assertNotRegex(fx['spl'], r'dana\.ortiz|lee\.park', fx['name'])
        # ... and so do the joined rule's chain fixtures (LR-06), checked below.
        for fx in load():
            if fx not in timing and not fx['name'].startswith('chain: '):
                self.assertNotRegex(fx['spl'], r'nina\.osei|jordan\.reyes', fx['name'])

    def test_every_chain_fixture_names_its_index_time_slot(self):
        """LR-06: a chain fixture runs over one 5-minute slot and says, per row, whether
        it was indexed in the slot's first second (the kind in capitals) or in the
        last second before it (the kind in lower case)."""
        chain = group('chain')
        self.assertGreaterEqual(len(chain), 40)
        for fx in chain:
            with self.subTest(fx['name']):
                self.assertTrue(fx['name'].startswith('chain: '), fx['name'])
                earliest, latest = fx['window']
                self.assertEqual(latest - earliest, 300)
                self.assertIn('K=mvindex(f, 1), k=upper(K), ', fx['spl'])
                self.assertIn('_indextime=if(k==K, %d, %d)' % (earliest, earliest - 1), fx['spl'])
                self.assertIn('txid=', fx['spl'])
                self.assertIn(' details.duo_txid=if(k=="S", l, null()),', fx['spl'])
                spec = re.search(r'split\(mvindex\(split\("([^"]+)", ";"\), n-1\), "\|"\)', fx['spl']).group(1)
                for row in spec.split(';'):
                    # offset|kind[|link]; a default id is "r<row>", so no link starts with r.
                    self.assertRegex(row, r'^\d+\|[FDSXBGACfdsxbgac](\|[a-qs-z]\w*)?$', fx['name'])
                # The staged scenario's personas by short name only, never by email;
                # the one email-form Duo username is an invented identity.
                self.assertRegex(fx['spl'], r' user=("(nina\.osei|jordan\.reyes|l5-ws1-01)"|'
                                            r'if\(k=="F", "Dana\.Ortiz@corp\.test", "dana\.ortiz"\)), ')
                self.assertNotRegex(fx['spl'], r'(nina\.osei|jordan\.reyes)@', fx['name'])
                # What a finding carries for the drill-down is compared too.
                self.assertTrue(fx['append'].endswith(', chain_earliest, chain_latest'), fx['append'])
                for row in fx['expect']:
                    self.assertEqual(sorted(set(('user', 'at', 'chain_id', 'chain_earliest', 'chain_latest'))
                                            - set(row)), [], fx['name'])
                    self.assertGreater(int(row['chain_latest']), int(row['chain_earliest']) + 600)
        names = [fx['name'] for fx in chain]
        self.assertEqual(len(names), len(set(names)))
        for needle in ('backfill - burst, sign-in', 'backfill equals live', 'live order',
                       'wholly before the slot', 'record of the sign-in arriving after the chain was judged',
                       'comes after the sign-in', '30 min 05 s', '29 min 59 s', '61 minutes',
                       'exactly 60 minutes', '60 min 01 s',
                       'second blocked turn', 'late sign-in record between', 'late sign-in record ahead of two',
                       'late sign-in record after the turn that completed', 'participant', 'allowed turns only',
                       '4 failures', 'email-form', 'sent twice', 'only claims the name',
                       'sign-in failure records are not Duo failures', 'sign-in failure record is not a sign-in',
                       'two sign-ins after one burst', 'Identity Risk Gate',
                       'successful Duo authentication alone', 'last one before the sign-in',
                       'failures after the sign-in', 'sent again',
                       # A chain is raised in the run that indexes its last missing step, whichever it is.
                       'arrival order - the blocked turn indexed last',
                       'arrival order - the sign-in record indexed last',
                       'arrival order - the sign-in record indexed after Duo',
                       'arrival order - the application\'s events indexed after the whole burst',
                       'arrival order - a burst split over two slots',
                       # A second chain within the hour, its burst indexed last.
                       'second chain - more blocked turns of a judged sign-in',
                       'second chain - its burst indexed last',
                       'second chain - the same events indexed in one slot raise both',
                       # What the finding names is what was indexed when it was raised.
                       'nearest burst - raised while the nearer burst is not indexed',
                       'nearest burst - the nearer burst arriving after',
                       'nearest burst - the same events indexed in one slot'):
            self.assertEqual(len([n for n in names if needle in n]), 1, needle)

        def one(needle):
            hits = [fx for fx in chain if needle in fx['name']]
            self.assertEqual(len(hits), 1, needle)
            return hits[0]

        def spec(fx):
            return re.search(r'split\(mvindex\(split\("([^"]+)", ";"\)', fx['spl']).group(1)

        # Backfill equals live: the two fixtures expect the very same row.
        pair = [one('backfill - burst, sign-in'), one('backfill equals live')]
        self.assertEqual(pair[0]['expect'], pair[1]['expect'])
        self.assertNotEqual(pair[0]['spl'], pair[1]['spl'])
        self.assertRegex(pair[0]['expect'][0]['chain_id'], r'^nina\.osei:takeover:\d+$')
        # A chain is raised in the run that indexes its LAST missing step. The first
        # 25 fixtures had only one such order (the whole burst last): a search that
        # ignored an old burst, an old sign-in or an old turn passed them all. Among
        # the fixtures that expect a finding, each of these pairs (a step indexed
        # before the slot, another one in it) now occurs.
        raised = [spec(fx) for fx in chain if fx['expect']]
        for old_kind, new_kind in (('f', 'B'), ('f', 'S'), ('s', 'B'), ('b', 'S'), ('b', 'F'), ('s', 'F'), ('d', 'S'),
                                   ('f', 'F')):
            self.assertTrue([s for s in raised if re.search(r'\|%s(\||;|$)' % old_kind, s)
                             and re.search(r'\|%s(\||;|$)' % new_kind, s)], (old_kind, new_kind))
        # The second chain: the "indexed last" and the "one slot" fixture hold the same
        # events and differ only in what was indexed before the slot; one pass raises
        # both chains, the live order the second one (the first was raised before).
        last, both = one('second chain - its burst indexed last'), one('second chain - the same events indexed')
        self.assertEqual(spec(last).upper(), spec(both))
        self.assertNotEqual(spec(last), spec(both))
        self.assertEqual(len(both['expect']), 2)
        self.assertEqual(last['expect'], both['expect'][1:])
        self.assertEqual(one('second chain - more blocked turns of a judged sign-in')['expect'], [])
        # The burst a finding names is the nearest one INDEXED when it was raised.
        early, late, whole = (one('nearest burst - ' + n) for n in (
            'raised while the nearer burst is not indexed', 'the nearer burst arriving after',
            'the same events indexed in one slot'))
        self.assertEqual(spec(late).upper(), spec(whole))
        self.assertEqual(late['expect'], [])
        self.assertEqual(early['expect'][0]['chain_id'], whole['expect'][0]['chain_id'])
        self.assertEqual(early['expect'][0]['at'], whole['expect'][0]['at'])
        self.assertNotEqual(early['expect'][0]['chain_earliest'], whole['expect'][0]['chain_earliest'])

    def test_a_fraud_report_is_pinned_apart_from_a_burst(self):
        """A fraud report is never one of the 5 failures: five of them are one finding."""
        names = [fx['name'] for fx in group('rule')]
        for needle in ('five fraud reports and one other failure raise one finding (80)',
                       '4 failures and a fraud report within 10 minutes are not a burst',
                       'a burst of 5 other failures and a fraud report indexed together raise both'):
            self.assertTrue([n for n in names if needle in n], needle)

    def test_fixtures_fit_the_read_only_mcp(self):
        """Each resolved fixture can be pasted into the Splunk MCP (5,000 characters)."""
        for fx in load():
            self.assertLessEqual(len(resolve(fx)), MCP_LIMIT, fx['name'])


class DuoChainSearchTextTests(unittest.TestCase):
    """Offline: the text the chain tests dispatch is the joined rule's own, and read-only."""

    def test_dispatched_text_is_the_full_chain_search(self):
        spl = rule_search(CHAIN)
        self.assertTrue(spl.startswith('((`genai_duo_auth_events` (action="failure" OR action="success")) OR '
                                       '(`genai_identity_activity_events` '), spl[:140])
        self.assertTrue(spl.endswith('| fields - identity_user, already, chain_signin, chain_burst, lastTime'),
                        spl[-80:])
        self.assertNotRegex(spl, r'\|\s*tstats\b|datamodel')
        self.assertIsNone(WRITES.search(spl))
        self.assertLessEqual(len(spl), 4900)       # it must stay pasteable into the read-only MCP (5,000)


class DuoSlotGridTests(unittest.TestCase):
    """Offline: the helpers the live tests cut index time with."""

    def test_slots_are_cut_where_the_scheduler_cuts_them(self):
        """Both rules end their slot 2 minutes back from the cron tick, so the
        edges are at minutes ending in 8 (and 3): never on the clock's own
        ten- or five-minute marks, which is where the first tiling tests cut."""
        searches = read_conf('savedsearches.conf')
        self.assertEqual(slot_grid(searches[RULE]), (600, 480))
        self.assertEqual(slot_grid(searches[CHAIN]), (300, 180))
        self.assertEqual(slot_eval(600, 480), 'eval slot=floor((_indextime-480)/600)*600+480')

        def slot(indexed, period, phase):
            return (indexed - phase) // period * period + phase

        # The staged burst of 16 Nov 2026 16:42 PST: five failures indexed at 16:46:02
        # and the sixth at 16:48:03. The scheduler's edge at 16:48:00 parts them (the
        # late arrival the rule must not raise again); a clock-aligned grid does not.
        first, late = 1794876362, 1794876483
        self.assertNotEqual(slot(first, 600, 480), slot(late, 600, 480))
        self.assertEqual(slot(late, 600, 480), 1794876480)
        self.assertEqual(slot(first, 600, 0), slot(late, 600, 0))
        self.assertEqual(slot(late, 600, 480) % 600, 480)
        with self.assertRaises(ValueError):
            slot_grid(dict(searches[RULE], **{'dispatch.earliest_time': '-30m@m'}))

    def test_pieces_follow_each_other_with_no_gap(self):
        self.assertEqual(pieces(['30', 10, 20, 10], 300), [(10, 20), (20, 30), (30, 330)])
        self.assertEqual(pieces([], 300), [])

    def test_edge_probe_is_the_rules_own_text_up_to_its_is_new_eval(self):
        for name in (RULE, CHAIN):
            spl = rule_search(name)
            probe = edge_probe(spl)
            cut = probe[:probe.rindex(' | stats max(eval(')]
            self.assertTrue(spl.startswith(cut), name)
            # Both rules read the slot's start in an append subsearch, where addinfo
            # gives the job's own time range ...
            self.assertTrue(probe.endswith('| append [| makeresults | addinfo | eval slot_earliest=floor(info_min_time) '
                                           '| fields slot_earliest ] | eventstats max(slot_earliest) as slot_earliest '
                                           '| stats max(eval(slot_earliest)) as edge'), probe[-220:])
            self.assertIsNone(WRITES.search(probe))
            self.assertLessEqual(len(probe), MCP_LIMIT)
        # ... and the probe would show a text that reads it in the main pipeline instead.
        broken = rule_search(CHAIN).replace(
            '| append [| makeresults | addinfo | eval slot_earliest=floor(info_min_time) | fields slot_earliest ] '
            '| eventstats max(slot_earliest) as slot_earliest | where isnotnull(step) '
            '| eval is_new=if(indexed>=slot_earliest, 1, 0)',
            '| addinfo | where isnotnull(step) | eval is_new=if(indexed>=floor(info_min_time), 1, 0)')
        self.assertNotEqual(broken, rule_search(CHAIN))
        self.assertTrue(edge_probe(broken).endswith('by identity_user, chain_event | addinfo '
                                                    '| stats max(eval(floor(info_min_time))) as edge'))
        with self.assertRaises(ValueError):
            edge_probe('search index=main | stats count')

    def test_the_context_each_rule_reads_is_the_one_the_live_test_expects(self):
        """DuoContextTests compares what a run reads with these terms and margins."""
        for name, (new, reads, back, forward) in CONTEXT.items():
            spl = rule_search(name)
            self.assertTrue(spl.startswith(reads + ' [| makeresults | addinfo '), name)
            self.assertIn('[ search {} earliest={} latest=now [| makeresults'.format(new, REACH), spl)
            self.assertIn('"earliest=" . tostring(floor(oldest)-{}) . " latest=" . tostring(floor(newest)+{}), '
                          '"earliest=1 latest=2")'.format(back, forward), spl)
            head = spl[:spl.index(' | eval identity_user=')]
            self.assertEqual(head.count('['), head.count(']'))
            self.assertEqual(head.count('['), 3)           # the base search carries its three subsearches whole
        self.assertEqual(CONTEXT[CHAIN][2], 600 + 1800 + 3600)

    def test_reference_searches_share_no_finder_and_write_nothing(self):
        """The oracle of the tiling tests: one read by event time. It must not
        hold the rules' finder (the -181d@d subsearch), their slot, or a literal
        index or sourcetype; it only bounds what was indexed by the pass's end."""
        for text, name, field in ((REFERENCE_BURSTS, RULE, 'burst_id'), (REFERENCE_CHAINS, CHAIN, 'chain_id')):
            spl = reference(text, 1794894000)
            self.assertIn(' _index_latest=1794894000 ', spl)
            self.assertNotIn('<<', spl)
            self.assertNotRegex(spl, r'\[|addinfo|_index_earliest|slot_earliest|is_new|earliest=|latest=now')
            self.assertNotRegex(spl, r'\bindex\s*=|sourcetype\s*=|\|\s*tstats\b|datamodel')
            self.assertIsNone(WRITES.search(spl))
            self.assertTrue(spl.endswith('| table ' + field), spl[-40:])
            self.assertLessEqual(len(spl), MCP_LIMIT)
            # It reads the same events as the rule's finder and names ids the rule's way.
            rule = rule_search(name)
            self.assertIn('[ search ' + (DUO_EVENTS if name == RULE else CHAIN_STEPS) + ' earliest=' + REACH + ' latest=now ',
                          rule)
            self.assertIn(IDENTITY.strip(), rule)
        self.assertIn('":burst:"', REFERENCE_BURSTS)
        self.assertIn('":fraud:"', REFERENCE_BURSTS)
        self.assertIn('":takeover:"', REFERENCE_CHAINS)
        self.assertIn('burst_id=user . ":" . judged . ":" . tostring(floor(_time))', rule_search())
        self.assertIn('chain_id=user . ":takeover:" . tostring(floor(chain_signin))', rule_search(CHAIN))


class DuoRuleProofTests(unittest.TestCase):
    """Offline, and the point of it: this suite cannot run SPL, so it cannot
    tell a working rule from a dead one (a review changed max() to min(), a
    command name and a comparison in the two rules and every offline test
    stayed green). What it can do is refuse a text nobody has run: each rule's
    search, with every macro it uses, must be the text its fixtures were last
    run against."""

    def test_each_rule_text_is_the_text_its_fixtures_were_run_against(self):
        proof = load_proof()
        self.assertEqual(sorted(proof), sorted(GROUPS.values()))
        for key, name in sorted(GROUPS.items()):
            record = proof[name]
            self.assertEqual(
                record['sha256'], digest(name),
                '\nThe search of "{}" (or a macro it uses) is not the text its fixtures were last run against.\n'
                'Run every "{}" fixture over its window - with SPLUNK_TEST_* set the live tests do it; without, '
                'print them with\n    python3 tools/tests/test_duo_spl.py --fixtures {}\nrun each through the '
                'read-only Splunk MCP, compare with --verify, and record the new text with --record-proof '
                '(see this module\'s docstring).'.format(name, key, key))
            self.assertEqual(record['fixtures'], len(group(key)), name)
            self.assertEqual(record['characters'], len(rule_search(name)), name)
            self.assertRegex(record['proven'], r'^20\d\d-\d\d-\d\d$')
            self.assertGreater(len(record['how']), 20, name)

    def test_the_digest_covers_the_search_and_every_macro_it_uses(self):
        searches, macros = read_conf('savedsearches.conf'), read_conf('macros.conf')
        for name, used in ((RULE, ['genai_duo_auth_events', 'genai_duo_index', 'genai_identity_join_key(1)',
                                   'genai_identity_participant_filter']),
                           (CHAIN, ['exclude_scoring_sourcetypes', 'genai_duo_auth_events', 'genai_duo_index',
                                    'genai_identity_activity_events', 'genai_identity_ai_events',
                                    'genai_identity_join_key(1)', 'genai_identity_participant_filter',
                                    'genai_identity_verified_turn'])):
            text = proven_text(name, searches, macros)
            lines = text.split('\n')
            self.assertEqual(lines[0], rule_search(name))
            self.assertEqual([line.split('] ')[0][1:] for line in lines[1:]], used, name)
            # One changed character anywhere changes the digest: in the search ...
            changed = dict(searches)
            changed[name] = dict(searches[name], search=searches[name]['search'].replace(
                'max(failures_10m) as max_failures_10m', 'min(failures_10m) as max_failures_10m').replace(
                'where blocked_turns>0 AND already==0', 'where blocked_turns>0 AND already==0 AND signin_duo!=""'))
            self.assertNotEqual(changed[name]['search'], searches[name]['search'], name)
            self.assertNotEqual(proven_text(name, changed, macros), text)
            # ... and in a macro two levels down.
            deep = dict(macros)
            deep['genai_duo_index'] = dict(macros['genai_duo_index'], definition='index=other')
            self.assertNotEqual(proven_text(name, searches, deep), text)

    def run_module(self, *args, **env):
        environ = dict((k, v) for k, v in os.environ.items() if not k.startswith('SPLUNK_TEST_'))
        environ.update(env)
        return subprocess.run([sys.executable, '-I', os.path.abspath(__file__)] + list(args), env=environ,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def test_a_skip_can_be_made_a_failure(self):
        """SPLUNK_TEST_REQUIRED=1 with no Splunk configured: every live test fails."""
        proc = self.run_module('DuoSplFixtureTests', 'DuoSlotEdgeTests')
        self.assertEqual(proc.returncode, 0, proc.stdout.decode())
        self.assertIn('skipped=', proc.stdout.decode())
        proc = self.run_module('DuoSplFixtureTests', 'DuoSlotEdgeTests', SPLUNK_TEST_REQUIRED='1')
        text = proc.stdout.decode()
        self.assertEqual(proc.returncode, 1, text)
        self.assertIn('SPLUNK_TEST_REQUIRED is set and no Splunk is configured', text)
        self.assertNotIn('skipped=', text)
        # Every class that needs a Splunk goes through the same gate.
        with io.open(os.path.abspath(__file__), encoding='utf-8') as handle:
            source = handle.read()
        self.assertEqual(re.findall(r'^@unittest\.skip', source, flags=re.M), [])
        self.assertEqual(len(re.findall(r'^@live\nclass ', source, flags=re.M)), 9)

    def test_fixtures_can_be_run_and_compared_without_credentials(self):
        """--fixtures prints what to paste into the read-only Splunk MCP; --verify
        compares what came back; --record-proof writes the digest only from
        results that agree with every fixture."""
        import tempfile
        chain = group('chain')
        proc = self.run_module('--fixtures', 'chain')
        text = proc.stdout.decode()
        self.assertEqual(proc.returncode, 0, text)
        self.assertEqual(len(re.findall(r'^### \d+\. chain: ', text, flags=re.M)), len(chain))
        self.assertIn('### 1. ' + chain[0]['name'], text)
        self.assertIn('window: {} {}'.format(*chain[0]['window']), text)
        self.assertIn(resolve(chain[0]), text)
        work = tempfile.mkdtemp()
        self.addCleanup(__import__('shutil').rmtree, work, True)
        results, proof = os.path.join(work, 'results.json'), os.path.join(work, 'proof.json')
        answers = dict((str(n), fx['expect']) for n, fx in enumerate(chain, 1))
        with open(results, 'w') as handle:
            json.dump(answers, handle)
        proc = self.run_module('--verify', 'chain', results)
        self.assertEqual(proc.returncode, 0, proc.stdout.decode())
        self.assertIn('{0} of {0} fixtures agree'.format(len(chain)), proc.stdout.decode())
        proc = self.run_module('--record-proof', 'chain', results, 'a test run, written to a scratch file',
                               DUO_RULE_PROOF_FILE=proof)
        self.assertEqual(proc.returncode, 0, proc.stdout.decode())
        with open(proof) as handle:
            written = json.load(handle)
        self.assertEqual(written[CHAIN]['sha256'], digest(CHAIN))
        self.assertEqual(written[CHAIN]['fixtures'], len(chain))
        # A row that differs, a fixture left out, and a row too many are each refused,
        # and nothing is recorded from them.
        os.remove(proof)
        raised = [n for n, fx in enumerate(chain, 1) if fx['expect']][0]
        silent = [n for n, fx in enumerate(chain, 1) if not fx['expect']][0]
        for change, needle in ((dict(answers, **{str(raised): [dict(chain[raised - 1]['expect'][0], at='1')]}), 'at is'),
                               (dict((k, v) for k, v in answers.items() if k != '3'), 'no result for'),
                               (dict(answers, **{str(silent): [{'user': 'nina.osei'}]}), 'expected 0 row(s), got 1')):
            with open(results, 'w') as handle:
                json.dump(change, handle)
            for args in (('--verify', 'chain', results), ('--record-proof', 'chain', results, 'must not be written')):
                proc = self.run_module(*args, DUO_RULE_PROOF_FILE=proof)
                self.assertEqual(proc.returncode, 1, proc.stdout.decode())
                self.assertIn(needle, proc.stdout.decode())
            self.assertFalse(os.path.exists(proof))


def ids(rows, field):
    return [row[field] for row in rows]


def run_rule(test, spl, earliest, latest):
    rows, errors = export_window(spl, str(earliest), str(latest))
    test.assertEqual(errors, [])
    return rows


@live
class DuoRuleDispatchTests(unittest.TestCase):
    """R-CONF-003: the fixtures cover the rule's pipeline after its base search
    only; this dispatches its whole search, subsearches included, so a term the
    parser refuses fails here and not silently in scheduler.log. Read-only: a
    dispatched search runs no alert action."""

    def test_rule_search_parses_and_runs(self):
        """One slot as scheduled, a 31-day catch-up, and all time with and without
        an end. With no end info_max_time is "+Infinity": unguarded, the search
        wrote _index_latest=Null and splunkd refused the term."""
        found = {}
        for earliest, latest in (('-12m@m', '-2m@m'), ('-31d@m', '-2m@m'), ('0', '-2m@m'), ('0', '')):
            with self.subTest(earliest=earliest, latest=latest):
                rows, errors = export_window(rule_search(), earliest, latest)
                self.assertEqual(errors, [])
                for row in rows:             # any finding it does return names its user and burst
                    self.assertTrue(row.get('user'), row)
                    self.assertRegex(row.get('burst_id', ''), r'^.+:(burst|fraud):\d+$')
                self.assertEqual(len({row['burst_id'] for row in rows}), len(rows))
                found[(earliest, latest)] = {row['burst_id'] for row in rows}
        # All time with no end raises what all time up to 2 minutes ago raises. A
        # burst younger than 30 minutes may still be arriving between the two runs.
        settled = time.time() - 1800
        self.assertEqual({b for b in found[('0', '')] if int(b.rsplit(':', 1)[1]) < settled},
                         {b for b in found[('0', '-2m@m')] if int(b.rsplit(':', 1)[1]) < settled})


class TilingCase(unittest.TestCase):
    """Shared by the two rules. The newest CAP slots of INDEX time that hold one
    of the rule's events, cut where the scheduler cuts them (slot_grid), are
    judged one by one with the rule's own text. Anchored on the data, not on the
    clock: "the last six hours" would compare nothing on an instance whose last
    burst is older. Read-only.

    Three comparisons, because the first alone lets the rule be its own oracle
    (cut its finder's reach to one day and it raises the same wrong answer slot
    by slot and in one pass):
      1. nothing is raised in two slots;
      2. the slots raise what one pass over their span raises;
      3. one pass over ALL index time up to the last slot's end raises exactly
         what the reference search finds by event time alone, and so do the
         slots when they cover every slot the instance holds.
    Equality with one pass rests on both feeds delivering in event-time order."""

    NAME, EVENTS, REFERENCE, FIELD, CAP = None, None, None, None, 36

    def replay(self):
        searches = read_conf('savedsearches.conf')
        spl = rule_search(self.NAME)
        period, phase = slot_grid(searches[self.NAME])
        rows = run_rule(self, '{} | {} | stats count by slot | sort 0 - slot | head {}'.format(
            self.EVENTS, slot_eval(period, phase), self.CAP + 1), REACH, 'now')
        slots = sorted(int(row['slot']) for row in rows)
        if not slots:
            self.skipTest('none of the rule\'s events is indexed: nothing to replay')
        whole = len(slots) <= self.CAP                # every slot the instance holds is replayed
        slots = slots[-self.CAP:]
        end = slots[-1] + period
        by_slot = []
        for slot in slots:
            by_slot += ids(run_rule(self, spl, slot, slot + period), self.FIELD)
        self.assertEqual(len(by_slot), len(set(by_slot)), 'raised in two slots')
        self.assertEqual(sorted(by_slot), sorted(ids(run_rule(self, spl, slots[0], end), self.FIELD)))
        expected = sorted(ids(run_rule(self, reference(self.REFERENCE, end), REACH, 'now'), self.FIELD))
        self.assertEqual(sorted(ids(run_rule(self, spl, 0, end), self.FIELD)), expected,
                         'one pass over all index time does not raise what the events hold by event time')
        if whole:
            self.assertEqual(sorted(by_slot), expected)
        else:
            with self.subTest('reference'):
                self.skipTest('more than {} slots hold events: the slots were compared with one pass over their '
                              'span, not with the reference search'.format(self.CAP))
        # Say so, rather than pass quietly, when this data replays no late arrival.
        split = run_rule(self, '{} {}| {} | bin _time span=10m | stats dc(slot) as slots by identity_user, _time '
                               '| where slots>1 | stats count'.format(self.EVENTS, IDENTITY, slot_eval(period, phase)),
                         REACH, 'now')
        if not int((split[0] if split else {}).get('count') or 0):
            with self.subTest('late arrival'):
                self.skipTest('no ten minutes of one identity\'s events were indexed in two slots: this data '
                              'replays no late arrival (the fixtures and the split tests cover it)')


@live
class DuoRuleTilingTests(TilingCase):
    """LR-07 on whatever Duo data the instance holds: ten-minute slots with their
    edges at minutes ending in 8, as the scheduler runs them. A failure that
    arrives out of order can move a burst's 5th failure, and with it the burst_id."""

    NAME, EVENTS, REFERENCE, FIELD, CAP = RULE, DUO_EVENTS, REFERENCE_BURSTS, 'burst_id', 36

    def test_slots_tile_and_equal_one_pass_and_the_reference(self):
        self.replay()


@live
class DuoSlotEdgeTests(unittest.TestCase):
    """The edge a rule compares index time with is the job's own earliest. Not
    visible to any fixture: their rows are makeresults rows, where addinfo
    returns the job's time range wherever it stands. In the dispatched search
    the base search carries the event-time range its subsearch wrote, and
    addinfo in the main pipeline returns that. Read-only."""

    def test_the_edge_is_the_jobs_own_earliest(self):
        searches = read_conf('savedsearches.conf')
        for name, events in ((RULE, DUO_EVENTS), (CHAIN, CHAIN_STEPS)):
            period, phase = slot_grid(searches[name])
            probe = edge_probe(rule_search(name))
            # A slot of yesterday (whatever it holds), and the newest slot that holds one
            # of the rule's events: there the base search reads a real event-time range.
            windows = [(int(time.time()) - 86400 - phase) // period * period + phase]
            rows = run_rule(self, '{} | {} | stats count by slot | sort 0 - slot | head 1'.format(
                events, slot_eval(period, phase)), REACH, 'now')
            windows += [int(row['slot']) for row in rows]
            for start in windows:
                with self.subTest(rule=name, slot=start):
                    rows = run_rule(self, probe, start, start + period)
                    self.assertEqual(len(rows), 1, rows)
                    self.assertEqual(rows[0].get('edge'), str(start),
                                     'the rule compares index time with something other than its slot\'s start')


@live
class DuoContextTests(unittest.TestCase):
    """What a run reads. The finder subsearch turns the slot's new events into an
    event-time range for the base search: from `back` seconds before the oldest
    to `forward` after the newest. Here the same range is worked out from a
    plain search, and the base search of the rule (its own text, cut before the
    first eval) must return exactly as many events as a plain search over it.
    On the dev data the slot that indexed a burst's late sixth failure reads 6
    events with the look-back and 1 without. Read-only."""

    NEWEST = 6

    def test_a_run_reads_the_events_around_its_new_ones(self):
        searches = read_conf('savedsearches.conf')
        for name, (new, reads, back, forward) in sorted(CONTEXT.items()):
            period, phase = slot_grid(searches[name])
            spl = rule_search(name)
            head = spl[:spl.index(' | eval identity_user=')] + ' | stats count'
            rows = run_rule(self, '{} | {} | stats count by slot | sort 0 - slot | head {}'.format(
                new, slot_eval(period, phase), self.NEWEST), REACH, 'now')
            slots = sorted(int(row['slot']) for row in rows)
            if not slots:
                continue
            widened = False
            for slot in slots:
                end = slot + period
                fresh = run_rule(self, '{} _index_earliest={} _index_latest={} | stats count, min(_time) as oldest, '
                                       'max(_time) as newest'.format(new, slot, end), REACH, 'now')[0]
                count = int(fresh.get('count') or 0)
                self.assertGreater(count, 0, slot)
                earliest = int(float(fresh['oldest'])) - back
                latest = int(float(fresh['newest'])) + forward
                expected = int(run_rule(self, '{} _index_latest={} | stats count'.format(reads, end),
                                        earliest, latest)[0]['count'])
                got = int(run_rule(self, head, slot, end)[0]['count'])
                with self.subTest(rule=name, slot=slot):
                    self.assertEqual(got, expected, 'the base search did not read the events around its new ones')
                    self.assertGreaterEqual(expected, count)
                widened = widened or expected > count
            if not widened:
                with self.subTest(rule=name, margins='not exercised'):
                    self.skipTest('no replayed slot had older or later events around its new ones: on this data '
                                  'the margins were read but could not be told from none')


class SplitCase(unittest.TestCase):
    """Shared by the two rules. For each of the newest findings one pass raises,
    index time is cut at every second at which one of its events was indexed,
    and the pieces are judged in order with the rule's own text: together they
    must raise it exactly once. This is the live order made as hard as the data
    allows (every later piece sees the earlier ones as already judged), and it
    is what failed while the joined rule read its slot's start in the main
    pipeline. Read-only. Rests on in-order delivery, as the tiling tests do."""

    NAME, EVENTS, FIELD, RANGE, NEWEST = None, None, None, None, 4

    def split(self):
        spl = rule_search(self.NAME)
        period, _phase = slot_grid(read_conf('savedsearches.conf')[self.NAME])
        found = run_rule(self, spl, 0, 'now')
        if not found:
            self.skipTest('one pass over all index time raises nothing: nothing to split')
        newest = sorted(found, key=lambda row: int(row[self.RANGE[1]]))[-self.NEWEST:]
        cut_somewhere = False
        for row in newest:
            # A value from the data is never put into the search: the rows are filtered here.
            seen = run_rule(self, '{} {}| stats count by identity_user, _indextime'.format(self.EVENTS, IDENTITY),
                            row[self.RANGE[0]], row[self.RANGE[1]])
            cuts = [int(r['_indextime']) for r in seen if r['identity_user'] == row['user']]
            parts = pieces(cuts, period)
            if len(parts) < 2:
                continue                      # all its events were indexed in one second
            cut_somewhere = True
            raised = []
            for earliest, latest in parts:
                raised += ids(run_rule(self, spl, earliest, latest), self.FIELD)
            with self.subTest(finding=row[self.FIELD], pieces=len(parts)):
                self.assertEqual(raised.count(row[self.FIELD]), 1, raised)
                self.assertEqual(len(raised), len(set(raised)), raised)
        if not cut_somewhere:
            self.skipTest('every finding\'s events were indexed in one second: nothing to split')


@live
class DuoRuleSplitTests(SplitCase):
    NAME, EVENTS, FIELD, RANGE = RULE, DUO_EVENTS, 'burst_id', ('burst_earliest', 'burst_latest')

    def test_a_burst_cut_at_every_index_second_is_raised_once(self):
        self.split()


@live
class DuoChainDispatchTests(unittest.TestCase):
    """R-CONF-003 for the joined rule (LR-06): its whole search, base search and
    subsearches included, over one slot as scheduled, a 31-day catch-up and all
    time with and without an end. Read-only: a dispatched search runs no action."""

    def test_chain_search_parses_and_runs(self):
        found = {}
        for earliest, latest in (('-7m@m', '-2m@m'), ('-31d@m', '-2m@m'), ('0', '-2m@m'), ('0', '')):
            with self.subTest(earliest=earliest, latest=latest):
                rows, errors = export_window(rule_search(CHAIN), earliest, latest)
                self.assertEqual(errors, [])
                for row in rows:             # any finding it does return names its user and chain
                    self.assertTrue(row.get('user'), row)
                    self.assertRegex(row.get('chain_id', ''), r'^.+:takeover:\d+$')
                    self.assertTrue(row.get('burst_time') and row.get('signin_time') and row.get('blocked_time'))
                    self.assertTrue(row.get('signin_duo'), row)
                    self.assertGreaterEqual(int(row['duo_failures_10m']), 5)
                    self.assertGreaterEqual(int(row['blocked_turns']), 1)
                    self.assertGreater(int(row['chain_latest']), int(row['chain_earliest']) + 600)
                self.assertEqual(len({row['chain_id'] for row in rows}), len(rows))
                found[(earliest, latest)] = {row['chain_id'] for row in rows}
        # A chain younger than two hours may still be arriving between the two runs.
        settled = time.time() - 7200
        self.assertEqual({c for c in found[('0', '')] if int(c.rsplit(':', 1)[1]) < settled},
                         {c for c in found[('0', '-2m@m')] if int(c.rsplit(':', 1)[1]) < settled})


@live
class DuoChainTilingTests(TilingCase):
    """LR-06 on whatever the instance holds: five-minute slots with their edges at
    minutes ending in 3 and 8. A sign-in record that arrives after a later one of
    the same identity was judged can move a blocked turn to another sign-in, and
    with it the chain_id."""

    NAME, EVENTS, REFERENCE, FIELD, CAP = CHAIN, CHAIN_STEPS, REFERENCE_CHAINS, 'chain_id', 48

    def test_slots_tile_and_equal_one_pass_and_the_reference_for_the_chain(self):
        self.replay()


@live
class DuoChainSplitTests(SplitCase):
    NAME, EVENTS, FIELD, RANGE = CHAIN, CHAIN_STEPS, 'chain_id', ('chain_earliest', 'chain_latest')

    def test_a_chain_cut_at_every_index_second_is_raised_once(self):
        self.split()


###############################################################################
# Without credentials: print the fixtures, compare what came back, record it
###############################################################################

def print_fixtures(key):
    for n, fx in enumerate(group(key), 1):
        spl = resolve(fx)
        print('### {}. {}'.format(n, fx['name']))
        print('window: {} {}'.format(*fx['window']))
        print('expect: {}'.format(json.dumps(fx['expect'], sort_keys=True)))
        print('search ({} characters):'.format(len(spl)))
        print(spl)
        print()
    return 0


def verify(key, path):
    """Compare a results file ({"<number or name>": [rows]}) with the fixtures."""
    with io.open(path, encoding='utf-8') as handle:
        results = json.load(handle)
    fixtures = group(key)
    wrong = 0
    for n, fx in enumerate(fixtures, 1):
        rows = results.get(str(n), results.get(fx['name']))
        problem = 'no result for it in the file' if rows is None else mismatch(fx, rows)
        if problem:
            wrong += 1
            print('MISMATCH {}. {}: {}'.format(n, fx['name'], problem))
    print('{} of {} fixtures agree'.format(len(fixtures) - wrong, len(fixtures)))
    return 1 if wrong else 0


def run_live(key):
    return dict((str(n), export_window(resolve(fx), *fx['window'])[0]) for n, fx in enumerate(group(key), 1))


def record_proof(key, path, how):
    """Write the rule's digest, only from results that agree with every fixture."""
    proof_path = os.environ.get('DUO_RULE_PROOF_FILE') or PROOF
    if path == 'live':
        if not LIVE:
            print(NEEDS)
            return 1
        import tempfile
        handle, path = tempfile.mkstemp(suffix='.json')
        with os.fdopen(handle, 'w') as out:
            json.dump(run_live(key), out)
    if verify(key, path):
        print('not recorded')
        return 1
    name = GROUPS[key]
    proof = {}
    if os.path.exists(proof_path):
        with io.open(proof_path, encoding='utf-8') as handle:
            proof = json.load(handle)
    proof[name] = {'sha256': digest(name), 'characters': len(rule_search(name)), 'fixtures': len(group(key)),
                   'proven': time.strftime('%Y-%m-%d'), 'how': how}
    with io.open(proof_path, 'w', encoding='utf-8') as handle:
        handle.write(json.dumps(proof, indent=1, sort_keys=True) + '\n')
    print('recorded {} for "{}" in {}'.format(proof[name]['sha256'][:12], name, proof_path))
    return 0


if __name__ == '__main__':
    argv = sys.argv[1:]
    usage = ('usage: test_duo_spl.py --fixtures rule|chain | --verify rule|chain RESULTS.json | '
             '--record-proof rule|chain RESULTS.json|live "how the fixtures were run"')
    if argv and argv[0] in ('--fixtures', '--verify', '--record-proof'):
        wanted = {'--fixtures': 2, '--verify': 3, '--record-proof': 4}[argv[0]]
        if len(argv) != wanted or argv[1] not in GROUPS:
            print(usage)
            sys.exit(2)
        sys.exit({'--fixtures': print_fixtures, '--verify': verify, '--record-proof': record_proof}[argv[0]](*argv[1:]))
    unittest.main()
