# encoding=utf-8
"""
Offline tests for the MedAdvice Identity Provider SOAR stub app.

Run from the repo root with either Splunk interpreter:

    PYTHONPATH=tools/soar/tests/phantom_shim:default/data/soar_apps/medadvice_idp \
        /opt/splunk104/bin/splunk cmd python3.13 -m unittest discover -s tools/soar/tests -v

The phantom_shim package stands in for Splunk SOAR's `phantom` modules, so the
same handle_action() code path the SOAR action runner uses is exercised here.
"""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
APP_DIR = os.path.join(REPO, 'default', 'data', 'soar_apps', 'medadvice_idp')
for path in (os.path.join(HERE, 'phantom_shim'), APP_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

import phantom.app as phantom  # noqa: E402
from medadvice_idp_connector import MedadviceIdpConnector  # noqa: E402


def run(action_id, param=None, config=None):
    connector = MedadviceIdpConnector()
    connector._shim_prepare(config or {}, action_id)
    assert connector.initialize() == phantom.APP_SUCCESS
    status = connector.handle_action(dict(param or {}))
    connector.finalize()
    results = connector.get_action_results()
    assert len(results) == 1, 'expected exactly one ActionResult'
    return status, results[0], connector


class ManifestTests(unittest.TestCase):

    def setUp(self):
        with open(os.path.join(APP_DIR, 'medadvice_idp.json')) as handle:
            self.manifest = json.load(handle)

    def test_manifest_identity(self):
        m = self.manifest
        self.assertEqual(m['name'], 'MedAdvice Identity Provider')
        self.assertEqual(m['type'], 'identity management')
        self.assertTrue(m['package_name'].startswith('phantom_'))
        self.assertEqual(m['main_module'], 'medadvice_idp_connector.py')
        self.assertEqual(len(m['appid']), 36)
        for logo in (m['logo'], m['logo_dark']):
            self.assertTrue(os.path.exists(os.path.join(APP_DIR, logo)), logo)

    def test_every_action_is_complete_and_handled(self):
        # Dict literals with constant keys compile to one tuple constant.
        handled = set()
        for const in MedadviceIdpConnector().handle_action.__code__.co_consts:
            if isinstance(const, tuple):
                handled.update(c for c in const if isinstance(c, str))
            elif isinstance(const, str):
                handled.add(const)
        for action in self.manifest['actions']:
            self.assertIn(action['identifier'], handled, action['action'])
            for key in ('description', 'type', 'read_only', 'parameters', 'output', 'versions'):
                self.assertIn(key, action, '{} lacks {}'.format(action['action'], key))
            if action['action'] != 'test connectivity':
                self.assertIn('render', action)
                username = action['parameters']['username']
                self.assertTrue(username['required'] and username['primary'])
                self.assertEqual(username['contains'], ['user name', 'user id', 'email'])

    def test_disable_user_is_a_contain_action_with_undo(self):
        disable = [a for a in self.manifest['actions'] if a['action'] == 'disable user'][0]
        self.assertEqual(disable['type'], 'contain')
        self.assertEqual(disable['undo'], 'enable user')
        self.assertFalse(disable['read_only'])


class ActionTests(unittest.TestCase):

    def test_test_connectivity(self):
        status, result, connector = run('test_connectivity')
        self.assertEqual(status, phantom.APP_SUCCESS)
        self.assertIn('mode=simulate', result.get_message())
        self.assertIn('Test Connectivity Passed', connector.progress)

    def test_disable_known_user(self):
        status, result, _ = run('disable_user', {'username': 't.nguyen', 'reason': 'lab'})
        self.assertEqual(status, phantom.APP_SUCCESS)
        self.assertEqual(result.get_message(), 'Account t.nguyen disabled (simulated)')
        data = result.get_data()[0]
        self.assertEqual(data['status'], 'disabled')
        self.assertEqual(data['previous_status'], 'active')
        self.assertEqual(data['email'], 't.nguyen@medadvice.example.com')
        self.assertTrue(data['simulated'])
        self.assertTrue(data['known'])
        self.assertEqual(data['reason'], 'lab')
        self.assertEqual(len(data['transaction_id']), 36)
        summary = result.get_summary()
        self.assertEqual(summary['status'], 'disabled')
        self.assertTrue(summary['simulated'])

    def test_disable_is_stateless(self):
        for _ in range(2):
            status, result, _ = run('disable_user', {'username': 't.nguyen'})
            self.assertEqual(status, phantom.APP_SUCCESS)
            self.assertEqual(result.get_data()[0]['previous_status'], 'active')
        status, result, _ = run('get_user', {'username': 't.nguyen'})
        self.assertEqual(result.get_data()[0]['status'], 'active')

    def test_enable_user(self):
        status, result, _ = run('enable_user', {'username': 'T.Nguyen'})
        self.assertEqual(status, phantom.APP_SUCCESS)
        self.assertEqual(result.get_data()[0]['status'], 'active')
        self.assertEqual(result.get_summary()['username'], 't.nguyen')

    def test_get_user_by_email_and_unknown(self):
        status, result, _ = run('get_user', {'username': 'X.Collins@medadvice.example.com'})
        self.assertEqual(status, phantom.APP_SUCCESS)
        data = result.get_data()[0]
        self.assertEqual(data['username'], 'x.collins')
        self.assertEqual(data['category'], 'threat_actor')
        self.assertTrue(data['watchlist'])
        self.assertTrue(data['user_id'].startswith('MA-'))

        status, result, _ = run('get_user', {'username': 'nobody.here'})
        self.assertEqual(status, phantom.APP_SUCCESS)
        data = result.get_data()[0]
        self.assertFalse(data['known'])
        self.assertEqual(data['email'], 'nobody.here@medadvice.example.com')
        self.assertIn('synthesised', result.get_message())

    def test_sessions_list_and_clear(self):
        status, listed, _ = run('list_user_sessions', {'username': 't.nguyen'})
        self.assertEqual(status, phantom.APP_SUCCESS)
        self.assertGreaterEqual(len(listed.get_data()), 1)
        self.assertEqual(listed.get_data()[0]['app'], 'MedAdvice DemoBot')
        status, cleared, _ = run('clear_user_sessions', {'username': 't.nguyen'})
        self.assertEqual(status, phantom.APP_SUCCESS)
        self.assertEqual(cleared.get_summary()['sessions_revoked'], len(listed.get_data()))
        self.assertTrue(all(s['status'] == 'revoked' for s in cleared.get_data()))

    def test_unresolved_token_is_rejected(self):
        for bad in ('$user$', '$result.user$', '%24user%24', 'two words'):
            status, result, _ = run('disable_user', {'username': bad})
            self.assertEqual(status, phantom.APP_ERROR, bad)
            self.assertIn('unresolved token', result.get_message())
            self.assertEqual(result.get_data(), [])

    def test_missing_username(self):
        status, result, _ = run('disable_user', {})
        self.assertEqual(status, phantom.APP_ERROR)
        self.assertEqual(result.get_message(), 'username is required')

    def test_unsupported_mode(self):
        status, result, _ = run('disable_user', {'username': 't.nguyen'}, {'mode': 'live'})
        self.assertEqual(status, phantom.APP_ERROR)
        self.assertIn("only 'simulate'", result.get_message())

    def test_unknown_action(self):
        status, result, _ = run('reset_password', {'username': 't.nguyen'})
        self.assertEqual(status, phantom.APP_ERROR)


if __name__ == '__main__':
    unittest.main()
