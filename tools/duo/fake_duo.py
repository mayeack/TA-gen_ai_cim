# encoding=utf-8
"""
fake_duo.py - an in-memory Duo Admin API for the ta_gen_ai_cim_duo tests.
Dev only (tools/ is never packaged).

It checks every request the way Duo does, with its own v5 signer (written
from https://duo.com/docs/adminapi, not imported from the code under test):
Date present, Authorization = Basic ikey:HMAC-SHA512(skey, canonical).

Behaviour that makes a careless client fail a test:
  * v2 logs default to DESCENDING order; only sort=ts:asc returns oldest first;
  * mintime >= maxtime is rejected (HTTP 400, code 40002), as Duo does;
  * both bounds are inclusive, so a client that restarts at maxtime instead of
    maxtime + 1 ms re-reads the boundary record;
  * like Duo, every page that has records carries a next_offset, the last one
    included (Duo's documented example: total_objects 1 with a next_offset);
    only the call after the last page answers with no records and none.
    FakeDuo(last_page_offset=False) omits it on the last page instead, and
    FakeDuo(echo_offset=True) answers an empty page with the next_offset it
    was sent (a behaviour reported on Duo's community forum);
  * queue_failure() makes the next call answer 429 / 42901 (or anything else).

Use FakeDuo.transport as DuoAdminClient(transport=...), or serve() to put the
same fake behind a real loopback HTTP server and LoopbackTransport to reach it.

All data is synthetic: invented users at corp.test and RFC 5737 addresses.
"""

import base64
import datetime
import hashlib
import hmac
import http.client
import http.server
import json
import threading
import urllib.parse

HOST = 'api-fake0001.duosecurity.com'
IKEY = 'DIFAKEINTEGRATIONKEY'
SKEY = 'fake-secret-key-for-offline-tests-only-0000'


def _sha512(text):
    return hashlib.sha512(text.encode('utf-8')).hexdigest()


def expected_authorization(ikey, skey, date, method, host, path, query_pairs, body=''):
    params = '&'.join('{}={}'.format(urllib.parse.quote(k, safe='~'), urllib.parse.quote(v, safe='~'))
                      for k, v in sorted(query_pairs))
    canonical = '\n'.join([date, method.upper(), host.lower(), path, params, _sha512(body), _sha512('')])
    sig = hmac.new(skey.encode('utf-8'), canonical.encode('utf-8'), hashlib.sha512).hexdigest()
    return 'Basic ' + base64.b64encode('{}:{}'.format(ikey, sig).encode('utf-8')).decode('ascii')


def _iso(ts_ms):
    stamp = datetime.datetime.fromtimestamp(ts_ms / 1000.0, tz=datetime.timezone.utc)
    return stamp.isoformat()


class FakeDuo(object):

    def __init__(self, ikey=IKEY, skey=SKEY, host=HOST, last_page_offset=True, echo_offset=False):
        self.ikey, self.skey, self.host = ikey, skey, host
        self.last_page_offset, self.echo_offset = last_page_offset, echo_offset
        self.auth_logs = []      # (ts_ms, txid, record)
        self.activity = []       # (ts_ms, activity_id, record)
        self.users = []
        self.requests = []       # (path, {param: value})
        self.failures = []       # (status, code, message, headers), next calls
        self.fail_at = {}        # request number (1-based) -> failure
        self.auth_headers = []   # every Authorization header seen

    # -- data --------------------------------------------------------------
    def add_auth(self, ts_ms, txid, user='dana.ortiz', result='success', **extra):
        record = {'txid': txid, 'timestamp': ts_ms // 1000, 'isotimestamp': _iso(ts_ms),
                  'event_type': 'authentication', 'result': result, 'factor': 'duo_push',
                  'reason': 'user_approved' if result == 'success' else 'user_marked_fraud',
                  'user': {'name': user, 'key': 'DU' + txid[:18].upper()},
                  'application': {'name': 'PseudoCo VPN', 'key': 'DIAPPFAKE0000000001'},
                  'access_device': {'ip': '198.51.100.10', 'browser': 'Chrome'},
                  'email': '{}@corp.test'.format(user)}
        record.update(extra)
        self.auth_logs.append((ts_ms, txid, record))
        return record

    def add_activity(self, ts_ms, activity_id, action='admin_login'):
        record = {'activity_id': activity_id, 'ts': _iso(ts_ms), 'action': {'name': action},
                  'actor': {'name': 'ari.admin', 'type': 'admin'},
                  'access_device': {'ip': {'address': '203.0.113.7'}}, 'outcome': {'result': 'success'}}
        self.activity.append((ts_ms, activity_id, record))
        return record

    def queue_failure(self, status=429, code=42901, message='Too Many Requests', headers=None,
                      at_request=None):
        failure = (status, code, message, headers or {})
        if at_request is None:
            self.failures.append(failure)
        else:
            self.fail_at[at_request] = failure

    # -- transport ---------------------------------------------------------
    def transport(self, method, url, headers, body, timeout=None):
        parts = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        params = dict(pairs)
        self.requests.append((parts.path, params))
        self.auth_headers.append(headers.get('Authorization', ''))
        if parts.scheme != 'https' or parts.hostname != self.host or headers.get('Host') != self.host:
            return self._error(400, 40000, 'wrong scheme or host')
        if 'Date' not in headers:
            return self._error(401, 40102, 'Missing request date')
        wanted = expected_authorization(self.ikey, self.skey, headers['Date'], method, self.host,
                                        parts.path, pairs, body or '')
        if not hmac.compare_digest(headers.get('Authorization', ''), wanted):
            return self._error(401, 40103, 'Invalid signature in request credentials')
        failure = self.fail_at.pop(len(self.requests), None)
        if failure is None and self.failures:
            failure = self.failures.pop(0)
        if failure is not None:
            status, code, message, extra = failure
            return self._error(status, code, message, extra)
        if method != 'GET':
            return self._error(405, 40500, 'only GET is faked')
        if parts.path == '/admin/v2/logs/authentication':
            return self._logs(self.auth_logs, params, 'authlogs', as_list=True)
        if parts.path == '/admin/v2/logs/activity':
            return self._logs(self.activity, params, 'items', as_list=False)
        if parts.path == '/admin/v1/users':
            return self._users(params)
        return self._error(404, 40400, 'Resource not found')

    def _error(self, status, code, message, headers=None):
        return status, json.dumps({'stat': 'FAIL', 'code': code, 'message': message}), dict(headers or {})

    def _logs(self, store, params, key, as_list):
        try:
            mintime, maxtime = int(params['mintime']), int(params['maxtime'])
            limit = int(params.get('limit', 100))
        except (KeyError, ValueError):
            return self._error(400, 40002, 'Invalid request parameters')
        if mintime >= maxtime or not 1 <= limit <= 1000:
            return self._error(400, 40002, 'Invalid request parameters')
        ascending = params.get('sort') == 'ts:asc'
        rows = sorted((r for r in store if mintime <= r[0] <= maxtime),
                      key=lambda r: (r[0], r[1]), reverse=not ascending)
        start = 0
        if params.get('next_offset'):
            ts_text, _, ident = params['next_offset'].partition(',')
            marker = (int(ts_text), ident)
            start = len(rows)
            for i, row in enumerate(rows):
                after = (row[0], row[1]) > marker if ascending else (row[0], row[1]) < marker
                if after:
                    start = i
                    break
        page = rows[start:start + limit]
        more = start + limit < len(rows)
        next_offset = None
        if page and (more or self.last_page_offset):
            next_offset = [str(page[-1][0]), page[-1][1]] if as_list else '{},{}'.format(page[-1][0], page[-1][1])
        elif not page and self.echo_offset and params.get('next_offset'):
            sent = params['next_offset']
            next_offset = sent.split(',', 1) if as_list else sent
        response = {key: [dict(r[2]) for r in page],
                    'metadata': {'next_offset': next_offset,
                                 'total_objects': {'value': len(rows), 'relation': 'eq'}}}
        return 200, json.dumps({'stat': 'OK', 'response': response}), {}

    def _users(self, params):
        try:
            offset, limit = int(params.get('offset', 0)), int(params.get('limit', 100))
        except ValueError:
            return self._error(400, 40002, 'Invalid request parameters')
        if not 1 <= limit <= 300:
            return self._error(400, 40002, 'Invalid request parameters')
        page = self.users[offset:offset + limit]
        metadata = {'total_objects': len(self.users)}
        if offset + limit < len(self.users):
            metadata['next_offset'] = offset + limit
        if offset:
            metadata['prev_offset'] = max(0, offset - limit)
        return 200, json.dumps({'stat': 'OK', 'response': page, 'metadata': metadata}), {}

    # -- loopback HTTP server ----------------------------------------------
    def serve(self):
        """Start a loopback HTTP server in front of this fake; returns it
        (call .shutdown() and .server_close())."""
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                headers = dict(self.headers.items())
                status, text, extra = fake.transport('GET', 'https://{}{}'.format(headers.get('Host', ''),
                                                                                 self.path), headers, '')
                data = text.encode('utf-8')
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                for k, v in extra.items():
                    self.send_header(k, v)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server


class LoopbackTransport(object):
    """Test-only transport: sends the signed request over plain HTTP to the
    loopback fake, keeping the Duo Host header. Production code always uses
    ta_gen_ai_cim_duo_api.urllib_transport (verified TLS)."""

    def __init__(self, port):
        self.port = port

    def __call__(self, method, url, headers, body, timeout=20):
        parts = urllib.parse.urlsplit(url)
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=timeout)
        try:
            target = parts.path + ('?' + parts.query if parts.query else '')
            conn.request(method, target, body=body or None, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read().decode('utf-8'), dict(resp.getheaders())
        finally:
            conn.close()
