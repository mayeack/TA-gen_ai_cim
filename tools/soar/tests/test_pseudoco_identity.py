# encoding=utf-8
"""
Offline tests for the PseudoCo Identity SOAR connector (AI Trust Lab 5) against a
fake Duo Admin API. The fake re-derives Duo's v5 signature independently and
rejects a request whose signature does not match, so the signing code is tested
against the documented algorithm, not against itself.

    PYTHONPATH=tools/soar/tests/phantom_shim \
        /opt/splunk104/bin/splunk cmd python3.13 -m unittest discover -s tools/soar/tests -v
"""

import base64
import hashlib
import hmac
import io
import json
import os
import sys
import tarfile
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
APP_DIR = os.path.join(REPO, 'soar_apps', 'pseudoco_identity')
for path in (os.path.join(HERE, 'phantom_shim'), APP_DIR, os.path.join(REPO, 'bin')):
    if path not in sys.path:
        sys.path.insert(0, path)

import phantom.app as phantom  # noqa: E402
import pseudoco_identity_connector as conn  # noqa: E402
import pseudoco_identity_duo as duo  # noqa: E402
import genai_es_seed as seed  # noqa: E402

HOST = 'api-9ddddfdb.duosecurity.com'
IKEY = 'DIXXXXXXXXXXXXXXXXXX'
SKEY = 'test-secret-key-0123456789abcdefghijklmnopq'
DATE = 'Thu, 05 Nov 2026 18:00:00 -0000'
VICTIM = 'avery.kim'


class FakeDuo(object):
    """Duo Admin API double: users by username, status changes, v5 auth."""

    def __init__(self, users=None, fail_with=None):
        self.users = dict((u['username'], dict(u)) for u in (users or []))
        self.calls = []
        self.fail_with = fail_with

    @staticmethod
    def expected_auth(method, path, query, body, date):
        params = '&'.join('{}={}'.format(urllib.parse.quote(k, safe='~'),
                                         urllib.parse.quote(v, safe='~'))
                          for k, v in sorted(query.items()))
        canon = '\n'.join([date, method, HOST, path, params,
                           hashlib.sha512(body.encode()).hexdigest(),
                           hashlib.sha512(b'').hexdigest()])
        sig = hmac.new(SKEY.encode(), canon.encode(), hashlib.sha512).hexdigest()
        return 'Basic ' + base64.b64encode('{}:{}'.format(IKEY, sig).encode()).decode()

    def __call__(self, method, url, headers, body):
        parts = urllib.parse.urlsplit(url)
        query = dict(urllib.parse.parse_qsl(parts.query))
        self.calls.append((method, parts.path, query, body, dict(headers)))
        if headers.get('Authorization') != self.expected_auth(method, parts.path, query, body,
                                                              headers.get('Date')):
            return 401, json.dumps({'stat': 'FAIL', 'code': 40103, 'message': 'Invalid signature in request credentials'})
        if self.fail_with:
            return self.fail_with
        if method == 'GET' and parts.path == '/admin/v1/users':
            user = self.users.get(query.get('username', ''))
            return 200, json.dumps({'stat': 'OK', 'response': [user] if user else []})
        if method == 'POST' and parts.path.startswith('/admin/v1/users/'):
            assert headers.get('Content-Type') == 'application/json'
            user_id = parts.path.rsplit('/', 1)[1]
            for user in self.users.values():
                if user['user_id'] == user_id:
                    user.update(json.loads(body))
                    return 200, json.dumps({'stat': 'OK', 'response': user})
            return 404, json.dumps({'stat': 'FAIL', 'code': 40401, 'message': 'Resource not found'})
        return 405, json.dumps({'stat': 'FAIL', 'code': 40501, 'message': 'Method not allowed'})


def persona(username, status='active'):
    return {'username': username, 'user_id': 'DU' + username.replace('.', '').upper()[:18],
            'email': username + '@pseudocoassistant.com', 'status': status, 'is_enrolled': True,
            'last_login': 1793900000, 'lockout_reason': None, 'directory_key': None,
            'phones': [{'number': '+15555550100'}], 'groups': [{'name': 'PseudoCo Workforce'}]}


def run(action_id, param=None, config=None, fake=None):
    fake = fake if fake is not None else FakeDuo([persona(VICTIM), persona('marcus.bell')])
    cfg = {'api_host': HOST, 'ikey': IKEY, 'skey': SKEY, 'victim_username': VICTIM, 'room': 'ws1-room1'}
    cfg.update(config or {})
    connector = conn.PseudocoIdentityConnector()
    connector._shim_prepare(cfg, action_id)
    assert connector.initialize() == phantom.APP_SUCCESS
    if connector._client is not None:
        connector._client.transport = fake
        connector._client.now = lambda: DATE
    status = connector.handle_action(dict(param or {}))
    results = connector.get_action_results()
    assert len(results) == 1
    return status, results[0], fake


class SigningTests(unittest.TestCase):

    def test_get_and_post_are_signed_like_the_documented_v5_scheme(self):
        fake = FakeDuo([persona(VICTIM)])
        client = duo.DuoAdminClient(HOST, IKEY, SKEY, transport=fake, now=lambda: DATE)
        user = client.find_user(VICTIM)
        updated = client.set_status(user['user_id'], 'disabled')
        self.assertEqual(updated['status'], 'disabled')
        (m1, p1, q1, b1, h1), (m2, p2, q2, b2, h2) = fake.calls
        self.assertEqual((m1, p1, q1, b1), ('GET', '/admin/v1/users', {'username': VICTIM}, ''))
        self.assertEqual((m2, b2), ('POST', '{"status":"disabled"}'))
        self.assertEqual(q2, {})
        self.assertEqual(h1['Date'], DATE)
        self.assertNotIn(SKEY, json.dumps([h1, h2]))

    def test_bad_secret_surfaces_duo_message_without_the_secret(self):
        fake = FakeDuo([persona(VICTIM)])
        client = duo.DuoAdminClient(HOST, IKEY, 'wrong-' + SKEY, transport=fake, now=lambda: DATE)
        with self.assertRaises(duo.DuoError) as ctx:
            client.find_user(VICTIM)
        self.assertIn('HTTP 401', str(ctx.exception))
        self.assertIn('40103', str(ctx.exception))
        self.assertNotIn(SKEY, str(ctx.exception))

    def test_canon_params_sorts_and_encodes(self):
        self.assertEqual(duo.canon_params({'username': 'a b@x', 'limit': '1'}),
                         'limit=1&username=a%20b%40x')

    def test_api_host_must_be_duo(self):
        for bad in ('evil.example.com', 'api-1.duosecurity.com.evil.io', 'https://' + HOST, ''):
            with self.assertRaises(duo.DuoError):
                duo.DuoAdminClient(bad, IKEY, SKEY)
        duo.DuoAdminClient('API-ABC123.DUOSECURITY.COM', IKEY, SKEY)


class ManifestTests(unittest.TestCase):

    def setUp(self):
        with open(os.path.join(APP_DIR, 'pseudoco_identity.json')) as handle:
            self.manifest = json.load(handle)

    def test_identity_and_actions(self):
        m = self.manifest
        self.assertEqual(m['name'], seed.IDENTITY_SOAR_APP_NAME)
        self.assertEqual(m['type'], 'identity management')
        self.assertEqual(m['configuration']['skey']['data_type'], 'password')
        self.assertEqual([a['action'] for a in m['actions']], ['test connectivity', 'get user', 'disable user'])
        for logo in (m['logo'], m['logo_dark']):
            self.assertTrue(os.path.exists(os.path.join(APP_DIR, logo)), logo)

    def test_disable_user_is_contain_with_no_undo(self):
        disable = [a for a in self.manifest['actions'] if a['action'] == 'disable user'][0]
        self.assertEqual(disable['type'], 'contain')
        self.assertFalse(disable['read_only'])
        self.assertNotIn('undo', disable)
        self.assertFalse([a for a in self.manifest['actions'] if a['action'] == 'enable user'])

    def test_every_action_is_handled(self):
        handled = set()
        for const in conn.PseudocoIdentityConnector().handle_action.__code__.co_consts:
            if isinstance(const, tuple):
                handled.update(c for c in const if isinstance(c, str))
            elif isinstance(const, str):
                handled.add(const)
        for action in self.manifest['actions']:
            self.assertIn(action['identifier'], handled)


class ActionTests(unittest.TestCase):

    def test_connectivity_finds_the_victim(self):
        status, result, _ = run('test_connectivity')
        self.assertEqual(status, phantom.APP_SUCCESS, result.get_message())
        self.assertIn('room victim avery.kim is active', result.get_message())

    def test_connectivity_fails_when_the_victim_is_missing(self):
        status, result, _ = run('test_connectivity', fake=FakeDuo([]))
        self.assertEqual(status, phantom.APP_ERROR)
        self.assertIn("no user 'avery.kim'", result.get_message())

    def test_get_user_reads_status_and_is_not_simulated(self):
        status, result, _ = run('get_user', {'username': 'Marcus.Bell@PseudoCoAssistant.com'})
        self.assertEqual(status, phantom.APP_SUCCESS, result.get_message())
        data = result.get_data()[0]
        self.assertEqual((data['username'], data['status'], data['simulated']), ('marcus.bell', 'active', False))
        self.assertFalse(data['is_room_victim'])
        self.assertNotIn('phones', data)

    def test_disable_the_victim(self):
        status, result, fake = run('disable_user', {'username': VICTIM, 'reason': 'INV-1 compromised identity'})
        self.assertEqual(status, phantom.APP_SUCCESS, result.get_message())
        data = result.get_data()[0]
        self.assertEqual((data['status'], data['previous_status'], data['simulated']), ('disabled', 'active', False))
        self.assertEqual(data['reason'], 'INV-1 compromised identity')
        self.assertEqual([c[0] for c in fake.calls], ['GET', 'POST'])

    def test_disable_is_idempotent(self):
        fake = FakeDuo([persona(VICTIM, status='disabled')])
        status, result, fake = run('disable_user', {'username': VICTIM + '@pseudocoassistant.com'}, fake=fake)
        self.assertEqual(status, phantom.APP_SUCCESS)
        self.assertIn('already disabled', result.get_message())
        self.assertEqual([c[0] for c in fake.calls], ['GET'])

    def test_disable_refuses_anyone_but_the_victim_before_any_call(self):
        for other in ('marcus.bell', 'jordan.reyes', 'l5-ws1-03', 'myeack', 'l5-ws1-03@pseudocoassistant.com',
                      'avery.kim@other.example.com'):
            status, result, fake = run('disable_user', {'username': other})
            self.assertEqual(status, phantom.APP_ERROR, other)
            self.assertEqual(fake.calls, [], other)

    def test_unresolved_tokens_are_refused(self):
        for bad in ('$user$', '%24user%24', 'avery kim'):
            status, result, fake = run('disable_user', {'username': bad})
            self.assertEqual(status, phantom.APP_ERROR)
            self.assertIn('unresolved token', result.get_message())
            self.assertEqual(fake.calls, [])

    def test_participant_or_trusted_victim_config_is_an_error(self):
        for victim in ('l5-ws1-03', 'marcus.bell', 'someone.else'):
            status, result, fake = run('test_connectivity', config={'victim_username': victim})
            self.assertEqual(status, phantom.APP_ERROR, victim)
            self.assertIn('not a Lab 5 victim persona', result.get_message())
            self.assertEqual(fake.calls, [])

    def test_bad_host_is_a_config_error(self):
        status, result, _ = run('get_user', {'username': VICTIM}, config={'api_host': 'evil.example.com'})
        self.assertEqual(status, phantom.APP_ERROR)
        self.assertIn('not a Duo API hostname', result.get_message())

    def test_unconfirmed_disable_fails(self):
        class Stubborn(FakeDuo):
            def __call__(self, method, url, headers, body):
                code, text = FakeDuo.__call__(self, method, url, headers, body)
                if method == 'POST':
                    payload = json.loads(text)
                    payload['response']['status'] = 'active'
                    return code, json.dumps(payload)
                return code, text
        status, result, _ = run('disable_user', {'username': VICTIM}, fake=Stubborn([persona(VICTIM)]))
        self.assertEqual(status, phantom.APP_ERROR)
        self.assertIn('did not confirm', result.get_message())


class PackageTests(unittest.TestCase):
    TGZ = os.path.join(REPO, 'soar_apps', 'pseudoco_identity.tgz')

    def test_committed_tarball_matches_source_shape(self):
        def members(**kw):
            with tarfile.open(mode='r:gz', **kw) as tar:
                return sorted((m.name.rstrip('/'), m.isdir()) for m in tar.getmembers())
        self.assertTrue(os.path.exists(self.TGZ), 'run bash tools/soar/build.sh')
        committed = members(name=self.TGZ)
        self.assertEqual(committed, members(fileobj=io.BytesIO(seed.build_soar_app_tgz(APP_DIR))))
        self.assertIn(('pseudoco_identity/pseudoco_identity_personas.py', False), committed)

    def test_source_is_kept_out_of_the_ta_package(self):
        with open(os.path.join(REPO, 'package.sh')) as handle:
            self.assertIn("--exclude='soar_apps/pseudoco_identity'", handle.read())


if __name__ == '__main__':
    unittest.main()
