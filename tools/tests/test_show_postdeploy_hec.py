#!/usr/bin/env python3
# encoding=utf-8
"""
Offline tests for how tools/show_postdeploy.py reads a stack's HEC token from
the Admin Config Service (ACS), and for the management port in --stack.

The fake ACS below answers the way Splunk documents ("Manage HTTP Event
Collector (HEC) tokens in Splunk Cloud Platform", ACS manual): the token value
sits BESIDE `spec`, a create answers 202 with the name only, and a GET by name
answers 404 `404-hec-not-found` until the token exists. Nothing here reaches a
real ACS or stack, and every token value is made up.
"""
import json
import os
import sys
import unittest

TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_ROOT = os.path.dirname(TOOLS)
sys.path[:0] = [TOOLS, os.path.join(APP_ROOT, 'bin')]

import genai_es_seed as seed  # noqa: E402
import lab5_steps as lab5  # noqa: E402
import show_postdeploy as tool  # noqa: E402

TOKEN = '11111111-2222-4333-8444-555555550001'       # made up
LIST = '/inputs/http-event-collectors'


def one(name, token=None, **spec):
    body = {'spec': dict(spec, name=name)}
    if token:
        body['token'] = token
    return json.dumps({'http-event-collector': body})


class FakeAcs(object):
    """ACS for one stack. `tokens` maps a name to its value; `appears_after`
    is how many GETs by name answer 404 after a create (None: it never does)."""

    def __init__(self, tokens=None, appears_after=0, token='x', dry_run=False, create_code=202):
        self.tokens = dict(tokens or {})
        self.pending = {}
        self.appears_after = appears_after
        self.token = token
        self.dry_run = dry_run
        self.create_code = create_code
        self.calls = []

    def call(self, path, method='GET', data=None, timeout=120):
        if not self.token:
            return None, 'no ACS token supplied'
        self.calls.append((method, path))
        if method == 'POST' and path == LIST:
            if self.dry_run:
                return 200, '{}'
            if self.create_code not in (200, 201, 202):
                return self.create_code, '{"code": "400-bad-request", "message": "refused"}'
            self.pending[data['name']] = self.appears_after
            return 202, one(data['name'])                 # the name only, as documented
        if method == 'GET' and path.startswith(LIST + '/'):
            name = path[len(LIST) + 1:]
            if name in self.pending:
                left = self.pending[name]
                if left is not None and left <= 0:
                    self.tokens[name] = TOKEN
                    del self.pending[name]
                elif left is not None:
                    self.pending[name] = left - 1
            if name in self.tokens:
                return 200, one(name, self.tokens[name], defaultIndex='gen_ai_log')
            return 404, '{"code": "404-hec-not-found", "message": "Hec not found"}'
        if method == 'GET' and path == LIST:
            raise AssertionError('the list is one page of 30: read the token by name')
        raise AssertionError('unexpected ACS call {} {}'.format(method, path))


def run_step(step, acs, **kw):
    rep, out, naps = seed.Reporter(), {}, []
    step(acs, rep, False, out, sleep=naps.append, **kw)
    return rep.rows, out, naps


class HecTokenTests(unittest.TestCase):
    def test_an_existing_token_is_read_from_beside_spec(self):
        rows, out, naps = run_step(tool.step_hec, FakeAcs({tool.HEC_TOKEN_NAME: TOKEN}))
        self.assertEqual(out, {'hec_token': TOKEN})
        self.assertEqual([r[0] for r in rows], ['OK'])
        self.assertEqual(naps, [])

    def test_a_created_token_is_waited_for_and_then_read(self):
        acs = FakeAcs(appears_after=2)
        rows, out, naps = run_step(tool.step_hec, acs)
        self.assertEqual(out, {'hec_token': TOKEN})
        self.assertEqual([r[0] for r in rows], ['OK'])
        self.assertEqual(naps, [10, 10])
        self.assertEqual([m for m, _ in acs.calls], ['GET', 'POST', 'GET', 'GET', 'GET'])

    def test_a_token_that_never_appears_is_a_failure_and_nothing_is_written(self):
        rows, out, naps = run_step(tool.step_hec, FakeAcs(appears_after=None), wait_seconds=30)
        self.assertEqual(out, {})
        self.assertEqual(rows[-1][0], 'FAIL')
        self.assertIn('run again', rows[-1][2])
        self.assertEqual(sum(naps), 30)

    def test_a_refused_create_is_a_failure(self):
        rows, out, _ = run_step(tool.step_hec, FakeAcs(create_code=400))
        self.assertEqual((rows[-1][0], out), ('FAIL', {}))

    def test_a_dry_run_creates_nothing_and_does_not_wait(self):
        acs = FakeAcs(dry_run=True)
        rows, out, naps = run_step(tool.step_hec, acs)
        self.assertEqual((out, naps, rows[-1][0]), ({}, [], 'OK'))
        self.assertIn('would be created', rows[-1][2])

    def test_no_acs_token_is_a_skip(self):
        rows, out, _ = run_step(tool.step_hec, FakeAcs(token=''))
        self.assertEqual((rows[-1][0], out), ('SKIP', {}))

    def test_the_value_is_never_in_a_report_row(self):
        for acs in (FakeAcs({tool.HEC_TOKEN_NAME: TOKEN}), FakeAcs(appears_after=1)):
            rows, _, _ = run_step(tool.step_hec, acs)
            self.assertNotIn(TOKEN, repr(rows))

    def test_the_second_token_follows_the_same_rules(self):
        rows, out, naps = run_step(lab5.step_cii_hec, FakeAcs(appears_after=1))
        self.assertEqual(out.get('cii_hec_token'), TOKEN)
        self.assertEqual(naps, [10])
        self.assertNotIn(TOKEN, repr(rows))                 # last four characters at most
        rows, out, _ = run_step(lab5.step_cii_hec, FakeAcs(appears_after=None), wait_seconds=20)
        self.assertEqual((rows[-1][0], out), ('FAIL', {}))

    def test_a_value_inside_spec_is_still_read(self):
        text = json.dumps({'http-event-collector': {'spec': {'name': 'n', 'token': TOKEN}}})
        self.assertEqual(lab5.hec_token_value(text), TOKEN)
        self.assertIsNone(lab5.hec_token_value('not json'))
        self.assertIsNone(lab5.hec_token_value(one('n')))


class StackAddressTests(unittest.TestCase):
    def test_the_management_port_is_8089_unless_the_stack_names_one(self):
        cases = {
            'https://esp-shw-abc.splunkcloud.com': ('esp-shw-abc.splunkcloud.com', 'esp-shw-abc',
                                                    'https://esp-shw-abc.splunkcloud.com:8089'),
            'https://esp-shw-abc.splunkcloud.com/': ('esp-shw-abc.splunkcloud.com', 'esp-shw-abc',
                                                     'https://esp-shw-abc.splunkcloud.com:8089'),
            'esp-shw-abc.splunkcloud.com': ('esp-shw-abc.splunkcloud.com', 'esp-shw-abc',
                                            'https://esp-shw-abc.splunkcloud.com:8089'),
            'https://localhost:8090': ('localhost', 'localhost', 'https://localhost:8090'),
            'localhost:8090': ('localhost', 'localhost', 'https://localhost:8090'),
        }
        for stack, expected in cases.items():
            self.assertEqual(tool.stack_endpoints(stack), expected, stack)

    def test_a_port_that_is_not_a_number_is_refused_without_repeating_it(self):
        for bad in ('https://host:port', 'https://:8089', ''):
            with self.assertRaises(ValueError) as caught:
                tool.stack_endpoints(bad)
            if bad:
                self.assertNotIn(bad, str(caught.exception))

    def test_main_refuses_it_before_any_request(self):
        self.assertEqual(tool.main(['--stack', 'https://host:port', '--skip-acs']), 2)


if __name__ == '__main__':
    unittest.main()
