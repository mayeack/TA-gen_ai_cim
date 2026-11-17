# encoding=utf-8
"""
Live SPL fixtures for the Cisco Duo content (TA-gen_ai_cim 1.9.0): makeresults
rows run through the TA's own props expressions, eventtype searches, the
genai_duo_* macros, the post-tstats pipeline of "AI Governance - Duo
Authentication Fraud or Denial Burst - Rule" and the identity lookup gen up to
(never including) its outputlookup. R-CONF-003: a config that parses is not a
config that fires.

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
DuoRuleDispatchTests also dispatches the rule's FULL search text (its tstats
head included) over the last 15 minutes and asserts it parses and runs with
no error; it is read-only (a dispatched search runs no alert action).

Needs a Splunk where this branch's conf is visible from SPLUNK_TEST_APP
(default TA-gen_ai_cim); skipped otherwise:

    SPLUNK_TEST_URL=https://localhost:8090 SPLUNK_TEST_USER=admin \\
    SPLUNK_TEST_PASSWORD=... python3 -m unittest tools.tests.test_duo_spl -v

(or SPLUNK_TEST_TOKEN for a bearer token). Read-only: only makeresults, and the
lookup gen is cut before its outputlookup.
"""

import csv
import io
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
from test_lab5_conf import read_conf  # noqa: E402
from test_lab5_spl import APP, URL, USER, export  # noqa: E402

FIXTURES = os.path.join(HERE, 'fixtures', 'duo_spl.json')
TOKEN = re.compile(r'<<(props|alias|eventtype):(?:([^|>]+)\|)?([^>]+)>>|<<persona_key>>|<<persona_email>>')
ALIAS_PAIR = re.compile(r'(\S+)\s+AS\s+(\S+)')
WRITES = re.compile(r'\|\s*(outputlookup|outputcsv|collect|sendalert|sendemail|delete|tscollect|mcollect)\b')
RULE = 'AI Governance - Duo Authentication Fraud or Denial Burst - Rule'


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
                     'tail:GenAI - Identity - Duo Identity Lookup Gen'):
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
        import subprocess
        gen = os.path.join(HERE, 'fixtures', 'duo_spl_gen.py')
        proc = subprocess.run([sys.executable, '-I', gen, '--check'], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
        self.assertEqual(proc.returncode, 0, proc.stdout.decode())

    def test_alias_assignments(self):
        self.assertEqual(alias_assignments('application.name AS app application.name AS dest'),
                         "app='application.name', dest='application.name'")


@unittest.skipUnless(URL and (os.environ.get('SPLUNK_TEST_PASSWORD') or os.environ.get('SPLUNK_TEST_TOKEN')),
                     'set SPLUNK_TEST_URL and SPLUNK_TEST_PASSWORD (or SPLUNK_TEST_TOKEN)')
class DuoSplFixtureTests(unittest.TestCase):

    def test_fixtures(self):
        for fx in load():
            with self.subTest(fx['name']):
                rows, errors = export(resolve(fx))
                self.assertEqual(errors, [], fx['name'])
                self.assertEqual(len(rows), len(fx['expect']), (fx['name'], rows))
                for got, want in zip(rows, fx['expect']):
                    for key, value in want.items():
                        self.assertEqual(got.get(key), value, (fx['name'], key, got))


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
    body = urllib.parse.urlencode({'search': spl if spl.startswith('|') else 'search ' + spl,
                                   'earliest_time': earliest, 'latest_time': latest,
                                   'output_mode': 'json', 'exec_mode': 'oneshot', 'count': 0}).encode()
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
        self.assertTrue(spl.startswith('| tstats '), spl[:40])
        self.assertIn(' span=1s | rename "Authentication.*" as * |', spl)
        self.assertIsNone(WRITES.search(spl))


def rule_search():
    return re.sub(r'\s*\n\s*', ' ', read_conf('savedsearches.conf')[RULE]['search']).strip()


@unittest.skipUnless(URL and (os.environ.get('SPLUNK_TEST_PASSWORD') or os.environ.get('SPLUNK_TEST_TOKEN')),
                     'set SPLUNK_TEST_URL and SPLUNK_TEST_PASSWORD (or SPLUNK_TEST_TOKEN)')
class DuoRuleDispatchTests(unittest.TestCase):
    """R-CONF-003: the fixtures cover the rule's post-tstats pipeline only; this
    dispatches its whole search, tstats head included, so a BY clause tstats
    cannot parse (or a macro that breaks its WHERE) fails here and not silently
    in scheduler.log. Read-only: a dispatched search runs no alert action."""

    def test_rule_search_parses_and_runs(self):
        rows, errors = export_window(rule_search(), '-15m')
        self.assertEqual(errors, [])
        for row in rows:                     # any finding it does return names its user
            self.assertTrue(row.get('user'), row)


if __name__ == '__main__':
    unittest.main()
