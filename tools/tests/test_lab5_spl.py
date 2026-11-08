# encoding=utf-8
"""
Live SPL fixtures for the AI Trust Lab 5 macros: makeresults rows run through
`genai_cii_extract`, `genai_cii_failed_check_rows`, `genai_identity_join_key`
and `genai_identity_ai_attack_join` on a real splunkd, so the macro text itself
is what is tested (R-CONF-003: a config that parses is not a config that fires).

makeresults rows get no props, so a fixture names a props.conf expression as
<<props:KEY>> (stanza [gen_ai:json]) or <<props:STANZA|KEY>>, and resolve()
puts in that key's text from this branch's default/props.conf: the identity
fields are tested against the TA's own EVALs, not a copy of them.

Needs a Splunk where this branch's macros are visible from SPLUNK_TEST_APP
(default TA-gen_ai_cim); skipped otherwise:

    SPLUNK_TEST_URL=https://localhost:8090 SPLUNK_TEST_USER=admin \\
    SPLUNK_TEST_PASSWORD=... python3 -m unittest tools.tests.test_lab5_spl -v

(or SPLUNK_TEST_TOKEN for a bearer token). Read-only: only makeresults.
"""

import base64
import json
import os
import re
import ssl
import sys
import unittest
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from test_lab5_conf import read_conf  # noqa: E402

FIXTURES = os.path.join(HERE, 'fixtures', 'lab5_spl.json')
URL = os.environ.get('SPLUNK_TEST_URL')
APP = os.environ.get('SPLUNK_TEST_APP', 'TA-gen_ai_cim')
USER = os.environ.get('SPLUNK_TEST_USER', 'admin')
PROPS_TOKEN = re.compile(r'<<props:(?:([^|>]+)\|)?([^>]+)>>')


def resolve(spl, props=None):
    """spl with every <<props:[STANZA|]KEY>> replaced by that props.conf
    expression, parenthesized and on one line. A missing key raises KeyError."""
    props = props if props is not None else read_conf('props.conf')
    return PROPS_TOKEN.sub(
        lambda m: '(' + props[m.group(1) or 'gen_ai:json'][m.group(2)].replace('\n', ' ') + ')', spl)


def export(spl):
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    if os.environ.get('SPLUNK_TEST_TOKEN'):
        headers['Authorization'] = 'Bearer ' + os.environ['SPLUNK_TEST_TOKEN']
    else:
        cred = '{}:{}'.format(USER, os.environ.get('SPLUNK_TEST_PASSWORD', ''))
        headers['Authorization'] = 'Basic ' + base64.b64encode(cred.encode()).decode()
    body = urllib.parse.urlencode({'search': spl if spl.startswith('|') else 'search ' + spl,
                                   'output_mode': 'json', 'exec_mode': 'oneshot', 'count': 0}).encode()
    path = '/servicesNS/{}/{}/search/jobs'.format(urllib.parse.quote(USER), urllib.parse.quote(APP))
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # local dev splunkd, self-signed
    req = urllib.request.Request(URL.rstrip('/') + path, data=body, headers=headers, method='POST')
    with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
        payload = json.loads(resp.read().decode())
    errors = [m for m in payload.get('messages', []) if m.get('type') in ('FATAL', 'ERROR')]
    return payload.get('results', []), errors


class Lab5SplFixtureFileTests(unittest.TestCase):
    """Offline: every props token resolves, so a renamed props key fails here too."""

    def test_props_tokens_resolve(self):
        with open(FIXTURES) as handle:
            fixtures = json.load(handle)
        props = read_conf('props.conf')
        for fx in fixtures:
            with self.subTest(fx['name']):
                self.assertNotIn('<<props:', resolve(fx['spl'], props))
        self.assertTrue(any('<<props:' in fx['spl'] for fx in fixtures))


@unittest.skipUnless(URL and (os.environ.get('SPLUNK_TEST_PASSWORD') or os.environ.get('SPLUNK_TEST_TOKEN')),
                     'set SPLUNK_TEST_URL and SPLUNK_TEST_PASSWORD (or SPLUNK_TEST_TOKEN)')
class Lab5SplFixtureTests(unittest.TestCase):

    def test_fixtures(self):
        with open(FIXTURES) as handle:
            fixtures = json.load(handle)
        props = read_conf('props.conf')
        for fx in fixtures:
            with self.subTest(fx['name']):
                rows, errors = export(resolve(fx['spl'], props))
                self.assertEqual(errors, [], fx['name'])
                self.assertEqual(len(rows), len(fx['expect']), (fx['name'], rows))
                for got, want in zip(rows, fx['expect']):
                    for key, value in want.items():
                        self.assertEqual(got.get(key), value, (fx['name'], key, got))


if __name__ == '__main__':
    unittest.main()
