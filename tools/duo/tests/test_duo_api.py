# encoding=utf-8
"""
Offline tests for bin/ta_gen_ai_cim_duo_api.py: v5 signing (and parity with
the Lab 5 SOAR connector's signer), host validation, verified TLS with a 20 s
timeout, v2/v1 paging and 429 classification - against tools/duo/fake_duo.py.

    python3 -m unittest discover -s tools/duo/tests -v
"""

import importlib.util
import json
import os
import ssl
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
for _p in (os.path.join(REPO, 'bin'), os.path.join(REPO, 'lib'), os.path.dirname(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import fake_duo  # noqa: E402
import ta_gen_ai_cim_duo_api as duo_api  # noqa: E402

SOAR_SIGNER = os.path.join(REPO, 'soar_apps', 'pseudoco_identity', 'pseudoco_identity_duo.py')
DATE = 'Tue, 21 Aug 2012 17:29:18 -0000'
HOST = 'api-fake0001.duosecurity.com'


def load_soar_signer():
    spec = importlib.util.spec_from_file_location('pseudoco_identity_duo_under_test', SOAR_SIGNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def client(fake, **kw):
    return duo_api.DuoAdminClient('https://' + fake.host, fake.ikey, fake.skey,
                                  transport=fake.transport, now=lambda: DATE, **kw)


class SignerParityTests(unittest.TestCase):
    """Both signers, and the fake's independent one, agree on fixed vectors."""

    VECTORS = [
        ('GET', '/admin/v1/users', {'username': 'dana.ortiz'}, ''),
        ('GET', '/admin/v2/logs/authentication',
         {'mintime': 1700000000000, 'maxtime': 1700000300000, 'limit': 1000, 'sort': 'ts:asc',
          'next_offset': '1700000123456,0a1b2c3d-0000-4000-8000-000000000001'}, ''),
        ('GET', '/admin/v1/users', {'username': 'ana maría+o~k*', 'z': 'last', 'a': '1'}, ''),
        ('GET', '/admin/v1/users', {}, ''),
        ('POST', '/admin/v1/users/DUFAKEUSER000000001', {}, '{"status":"disabled"}'),
    ]

    def setUp(self):
        self.soar = load_soar_signer()

    def test_canonical_strings_and_signatures_match(self):
        for method, path, params, body in self.VECTORS:
            with self.subTest(method=method, path=path, params=params):
                ours = duo_api.canonical_string(DATE, method, HOST, path, params, body)
                theirs = self.soar.canonical_string(DATE, method, HOST, path, params, body)
                self.assertEqual(ours, theirs)
                self.assertEqual(duo_api.authorization(fake_duo.IKEY, fake_duo.SKEY, ours),
                                 self.soar.authorization(fake_duo.IKEY, fake_duo.SKEY, theirs))

    def test_matches_independent_signer_for_get(self):
        for method, path, params, body in self.VECTORS:
            if method != 'GET':
                continue
            pairs = [(str(k), str(v)) for k, v in params.items()]
            canonical = duo_api.canonical_string(DATE, method, HOST, path, params, body)
            self.assertEqual(duo_api.authorization(fake_duo.IKEY, fake_duo.SKEY, canonical),
                             fake_duo.expected_authorization(fake_duo.IKEY, fake_duo.SKEY, DATE, method,
                                                             HOST, path, pairs, body))

    def test_canonical_layout(self):
        canonical = duo_api.canonical_string(DATE, 'get', 'API-FAKE0001.duosecurity.com',
                                             '/admin/v1/users', {'b': '2', 'a': 'x y'}, '')
        lines = canonical.split('\n')
        self.assertEqual(lines[:5], [DATE, 'GET', HOST, '/admin/v1/users', 'a=x%20y&b=2'])
        self.assertEqual(lines[5], lines[6])          # empty body hash == empty headers hash
        self.assertEqual(len(lines[5]), 128)


class HostTests(unittest.TestCase):

    def test_accepts_duo_hosts(self):
        for url, host in (('https://api-fake0001.duosecurity.com', HOST),
                          ('https://API-fake0001.duosecurity.com/', HOST),
                          ('api-fake0002.duofederal.com', 'api-fake0002.duofederal.com')):
            self.assertEqual(duo_api.parse_api_host(url), host)

    def test_rejects_everything_else(self):
        for url in ('http://api-fake0001.duosecurity.com', 'https://api-fake0001.duosecurity.com/admin',
                    'https://api-fake0001.duosecurity.com:8443', 'https://u:p@api-fake0001.duosecurity.com',
                    'https://api-fake0001.duosecurity.com.corp.test', 'https://corp.test', '', None):
            with self.subTest(url=url):
                with self.assertRaises(duo_api.DuoError):
                    duo_api.parse_api_host(url)

    def test_a_rejected_url_is_never_echoed(self):
        pasted = 'FakeSkeyAbCdEfGhIjKlMnOpQrStUvWxYz012345'          # invented, key-shaped
        for url in (pasted, 'https://' + pasted, 'https://' + pasted + '/', pasted + '.duosecurity.com'):
            with self.subTest(url=url):
                with self.assertRaises(duo_api.DuoError) as ctx:
                    duo_api.parse_api_host(url)
                self.assertNotIn(pasted.lower(), str(ctx.exception).lower())

    def test_keys_required_and_never_in_repr(self):
        with self.assertRaises(duo_api.DuoError):
            duo_api.DuoAdminClient(HOST, '', fake_duo.SKEY)
        c = duo_api.DuoAdminClient(HOST, fake_duo.IKEY, fake_duo.SKEY)
        self.assertNotIn(fake_duo.SKEY, repr(c))
        self.assertNotIn(fake_duo.IKEY, repr(c))


class TransportTests(unittest.TestCase):

    def test_tls_verified_and_20s_timeout(self):
        seen = {}

        class Resp(object):
            headers = {'Content-Type': 'application/json'}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def getcode(self):
                return 200

            def read(self):
                return b'{"stat":"OK","response":[]}'

        def fake_urlopen(request, context=None, timeout=None):
            seen.update(url=request.full_url, context=context, timeout=timeout)
            return Resp()

        with mock.patch.object(duo_api.urllib.request, 'urlopen', fake_urlopen):
            status, text, headers = duo_api.urllib_transport('GET', 'https://' + HOST + '/admin/v1/users',
                                                             {'Host': HOST}, '')
        self.assertEqual(status, 200)
        self.assertEqual(seen['timeout'], 20)
        self.assertEqual(duo_api.TIMEOUT_SECONDS, 20)
        self.assertEqual(seen['context'].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(seen['context'].check_hostname)

    def test_network_error_names_only_the_type(self):
        def boom(*a, **k):
            raise OSError('connect to ' + fake_duo.SKEY)
        with mock.patch.object(duo_api.urllib.request, 'urlopen', boom):
            with self.assertRaises(duo_api.DuoError) as ctx:
                duo_api.urllib_transport('GET', 'https://' + HOST + '/x', {}, '')
        self.assertEqual(str(ctx.exception), 'cannot reach the Duo Admin API: OSError')


class PagingTests(unittest.TestCase):

    def setUp(self):
        self.fake = fake_duo.FakeDuo()
        for i in range(5):
            self.fake.add_auth(1700000000000 + i * 1000, 'tx-{:02d}'.format(i))

    def test_v2_paging_ascending_with_list_next_offset(self):
        c = client(self.fake)
        records, offset = c.log_page(duo_api.AUTH_LOGS_PATH, 1700000000000, 1700000010000, limit=2)
        self.assertEqual([r['txid'] for r in records], ['tx-00', 'tx-01'])
        self.assertEqual(offset, '1700000001000,tx-01')
        records, offset = c.log_page(duo_api.AUTH_LOGS_PATH, 1700000000000, 1700000010000, offset, limit=2)
        self.assertEqual([r['txid'] for r in records], ['tx-02', 'tx-03'])
        records, offset = c.log_page(duo_api.AUTH_LOGS_PATH, 1700000000000, 1700000010000, offset, limit=2)
        # Like Duo, the last page with records still carries a next_offset ...
        self.assertEqual(([r['txid'] for r in records], offset), (['tx-04'], '1700000004000,tx-04'))
        # ... and only the call after it comes back with no records and none.
        records, offset = c.log_page(duo_api.AUTH_LOGS_PATH, 1700000000000, 1700000010000, offset, limit=2)
        self.assertEqual((records, offset), ([], None))
        for path, params in self.fake.requests:
            self.assertEqual(params['sort'], 'ts:asc')

    def test_fake_defaults_to_descending(self):
        status, text, _ = self.fake.transport('GET', 'x', {}, '')   # unsigned: rejected
        self.assertEqual(status, 400)
        c = client(self.fake)
        with mock.patch.object(c, 'request', wraps=c.request) as spy:
            def no_sort(path, params=None):
                params = dict(params)
                params.pop('sort', None)
                return duo_api.DuoAdminClient.request(c, path, params)
            spy.side_effect = no_sort
            records, _ = c.log_page(duo_api.AUTH_LOGS_PATH, 1700000000000, 1700000010000, limit=5)
        self.assertEqual([r['txid'] for r in records][0], 'tx-04')

    def test_activity_string_next_offset(self):
        for i in range(3):
            self.fake.add_activity(1700000000000 + i, 'act-{}'.format(i))
        records, offset = client(self.fake).log_page(duo_api.ACTIVITY_LOGS_PATH, 1700000000000,
                                                     1700000000009, limit=2)
        self.assertEqual([r['activity_id'] for r in records], ['act-0', 'act-1'])
        self.assertEqual(offset, '1700000000001,act-1')

    def test_mintime_must_be_below_maxtime(self):
        with self.assertRaises(duo_api.DuoError):
            client(self.fake).log_page(duo_api.AUTH_LOGS_PATH, 5, 5)
        self.assertEqual(self.fake.requests, [])

    def test_v1_users_offset_paging(self):
        self.fake.users = [{'user_id': 'DU{:018d}'.format(i), 'username': 'u{}'.format(i)} for i in range(5)]
        c = client(self.fake)
        page, nxt, total = c.users_page(0, limit=2)
        self.assertEqual((len(page), nxt, total), (2, 2, 5))
        page, nxt, total = c.users_page(4, limit=2)
        self.assertEqual((len(page), nxt), (1, None))

    def test_rate_limit_and_errors(self):
        self.fake.queue_failure(429, 42901, headers={'Retry-After': '30'})
        with self.assertRaises(duo_api.DuoRateLimited) as ctx:
            client(self.fake).users_page()
        self.assertEqual((ctx.exception.http_status, ctx.exception.retry_after), (429, 30))
        self.fake.queue_failure(400, 42901)          # Duo's code alone is enough
        with self.assertRaises(duo_api.DuoRateLimited):
            client(self.fake).users_page()
        bad = duo_api.DuoAdminClient(HOST, fake_duo.IKEY, 'wrong-secret', transport=self.fake.transport)
        with self.assertRaises(duo_api.DuoError) as ctx:
            bad.users_page()
        self.assertNotIsInstance(ctx.exception, duo_api.DuoRateLimited)
        self.assertIn('HTTP 401 code 40103', str(ctx.exception))
        self.assertNotIn('wrong-secret', str(ctx.exception))

    def test_loopback_http_server(self):
        server = self.fake.serve()
        try:
            c = duo_api.DuoAdminClient(HOST, fake_duo.IKEY, fake_duo.SKEY,
                                       transport=fake_duo.LoopbackTransport(server.server_address[1]))
            records, offset = c.log_page(duo_api.AUTH_LOGS_PATH, 1700000000000, 1700000010000)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual([r['txid'] for r in records], ['tx-0{}'.format(i) for i in range(5)])
        self.assertEqual(offset, '1700000004000,tx-04')
        json.dumps(records)

    def test_server_errors_and_unreachable_duo_are_transient(self):
        self.fake.queue_failure(503, 50301, 'Service Unavailable')
        with self.assertRaises(duo_api.DuoUnavailable) as ctx:
            client(self.fake).users_page()
        self.assertEqual(ctx.exception.http_status, 503)
        self.assertIsInstance(ctx.exception, duo_api.DuoError)
        for status in (400, 401, 404):
            self.fake.queue_failure(status, 40000 + status, 'no')
            with self.assertRaises(duo_api.DuoError) as ctx:
                client(self.fake).users_page()
            self.assertNotIsInstance(ctx.exception, duo_api.DuoUnavailable)

        def boom(*a, **k):
            raise OSError('timed out')
        with mock.patch.object(duo_api.urllib.request, 'urlopen', boom):
            with self.assertRaises(duo_api.DuoUnavailable):
                duo_api.urllib_transport('GET', 'https://' + HOST + '/x', {}, '')

    def test_fake_last_page_and_echo_options(self):
        fake = fake_duo.FakeDuo(echo_offset=True)
        fake.add_auth(1700000000000, 'tx-00')
        c = client(fake)
        records, offset = c.log_page(duo_api.AUTH_LOGS_PATH, 1700000000000, 1700000010000)
        self.assertEqual(offset, '1700000000000,tx-00')
        records, echoed = c.log_page(duo_api.AUTH_LOGS_PATH, 1700000000000, 1700000010000, offset)
        self.assertEqual((records, echoed), ([], offset))
        fake = fake_duo.FakeDuo(last_page_offset=False)
        fake.add_auth(1700000000000, 'tx-00')
        self.assertEqual(client(fake).log_page(duo_api.AUTH_LOGS_PATH, 1700000000000, 1700000010000)[1], None)


if __name__ == '__main__':
    unittest.main()
