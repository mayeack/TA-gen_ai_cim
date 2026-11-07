# encoding=utf-8
"""
pseudoco_identity_duo.py - the minimal Duo Admin API client behind the
"PseudoCo Identity" SOAR connector (AI Trust Lab 5).

Standard library only (Python 3.9 and 3.13), so the app installs on SOAR with no
dependency. Requests are signed with Duo's v5 scheme, the one
https://duo.com/docs/adminapi recommends and every Duo client on GitHub uses:

    canonical = "\\n".join([date, METHOD, host, path, sorted query params,
                           sha512_hex(body), sha512_hex(x-duo headers)])
    Authorization: Basic base64(ikey + ":" + hex(HMAC-SHA512(skey, canonical)))

POST parameters travel as a JSON body (Content-Type: application/json) and the
query-params line is then blank. No X-Duo-* header is sent, so the headers hash
is the SHA-512 of the empty string. TLS is verified against the system trust
store; the secret key never leaves this process (only the HMAC does) and is
never logged or returned.

Only two endpoints are used:
  GET  /admin/v1/users?username=<u>   ("Grant resource - Read")
  POST /admin/v1/users/<user_id>      ("Grant resource - Write"), {"status": "disabled"}

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import base64
import email.utils
import hashlib
import hmac
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

API_HOST_RE = re.compile(r'^api-[a-z0-9]+\.(duosecurity|duofederal)\.com$')
USERS_PATH = '/admin/v1/users'
TIMEOUT_SECONDS = 20


class DuoError(Exception):
    """A Duo API failure, already sanitized for display (no secrets, no URL
    beyond the host)."""

    def __init__(self, message, http_status=None, code=None):
        super(DuoError, self).__init__(message)
        self.http_status = http_status
        self.code = code


def sha512_hex(text):
    return hashlib.sha512(text.encode('utf-8')).hexdigest()


def canon_params(params):
    """key=value pairs, URL-encoded (unreserved characters A-Z a-z 0-9 _ . ~ -
    left as they are, uppercase hex otherwise) and sorted by key."""
    pairs = []
    for key in sorted(params or {}):
        pairs.append('{}={}'.format(urllib.parse.quote(str(key), safe='~'),
                                    urllib.parse.quote(str(params[key]), safe='~')))
    return '&'.join(pairs)


def canonical_string(date, method, host, path, params, body):
    return '\n'.join([date, method.upper(), host.lower(), path, canon_params(params),
                      sha512_hex(body or ''), sha512_hex('')])


def authorization(ikey, skey, canonical):
    signature = hmac.new(skey.encode('utf-8'), canonical.encode('utf-8'),
                         hashlib.sha512).hexdigest()
    token = base64.b64encode('{}:{}'.format(ikey, signature).encode('utf-8')).decode('ascii')
    return 'Basic ' + token


def urllib_transport(method, url, headers, body, timeout=TIMEOUT_SECONDS):
    """(status, text). TLS is always verified."""
    data = body.encode('utf-8') if body else None
    request = urllib.request.Request(url, data=data, method=method)
    for key, value in headers.items():
        request.add_header(key, value)
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, context=context, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode('utf-8', 'replace')
    except Exception as exc:  # DNS, TLS, timeout - no secret is in the text
        raise DuoError('cannot reach the Duo Admin API: {}'.format(type(exc).__name__))


class DuoAdminClient(object):

    def __init__(self, host, ikey, skey, transport=None, now=None):
        host = (host or '').strip().lower()
        if not API_HOST_RE.match(host):
            raise DuoError('api_host "{}" is not a Duo API hostname '
                           '(api-XXXXXXXX.duosecurity.com)'.format(host))
        if not ikey or not skey:
            raise DuoError('the Admin API integration key and secret key are required')
        self.host = host
        self.ikey = ikey.strip()
        self.skey = skey.strip()
        self.transport = transport or urllib_transport
        self.now = now   # test hook: returns an RFC 2822 date string

    def _date(self):
        return self.now() if self.now else email.utils.formatdate(usegmt=False)

    def request(self, method, path, params=None):
        """GET carries params in the query string; POST as a JSON body. Returns
        the "response" member of a stat=OK reply, else raises DuoError."""
        method = method.upper()
        date = self._date()
        if method == 'GET':
            query, body = dict(params or {}), ''
        else:
            query, body = {}, json.dumps(params or {}, sort_keys=True, separators=(',', ':'))
        headers = {'Date': date, 'Host': self.host, 'Accept': 'application/json',
                   'Authorization': authorization(self.ikey, self.skey,
                                                  canonical_string(date, method, self.host,
                                                                   path, query, body))}
        if method != 'GET':
            headers['Content-Type'] = 'application/json'
        url = 'https://{}{}'.format(self.host, path)
        if query:
            url += '?' + canon_params(query)
        status, text = self.transport(method, url, headers, body)
        try:
            payload = json.loads(text)
        except ValueError:
            payload = {}
        if status == 200 and payload.get('stat') == 'OK':
            return payload.get('response')
        detail = ' ({})'.format(payload['message_detail']) if payload.get('message_detail') else ''
        raise DuoError('Duo Admin API {} {} -> HTTP {}{}: {}{}'.format(
            method, path, status,
            ' code {}'.format(payload['code']) if payload.get('code') else '',
            payload.get('message') or 'no message', detail), status, payload.get('code'))

    def find_user(self, username):
        """The single user with this username, or None."""
        users = self.request('GET', USERS_PATH, {'username': username}) or []
        for user in users:
            if str(user.get('username', '')).lower() == username.lower():
                return user
        return None

    def set_status(self, user_id, status):
        return self.request('POST', '{}/{}'.format(USERS_PATH, user_id), {'status': status})
