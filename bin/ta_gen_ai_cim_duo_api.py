# encoding=utf-8
"""
ta_gen_ai_cim_duo_api.py - the read-only Duo Admin API client behind the
ta_gen_ai_cim_duo modular input (bin/ta_gen_ai_cim_duo_input.py).

Standard library only (Python 3.9 and 3.13). This module is the TA's canonical
Duo client and never imports soar_apps/ (that folder is excluded from the
package). Its v5 signer is the same algorithm as
soar_apps/pseudoco_identity/pseudoco_identity_duo.py, and
tools/duo/tests/test_duo_api.py proves the two produce identical signatures
for fixed vectors:

    canonical = "\\n".join([date, METHOD, host, path, sorted query params,
                           sha512_hex(body), sha512_hex(x-duo headers)])
    Authorization: Basic base64(ikey + ":" + hex(HMAC-SHA512(skey, canonical)))

Endpoints (all GET, all read-only; the Admin API application needs only
"Grant read log" and "Grant resource - Read"):

    /admin/v2/logs/authentication   mintime/maxtime in ms, sort, next_offset
    /admin/v2/logs/activity         same paging (Duo marks it public preview)
    /admin/v1/users                 offset/limit paging, limit <= 300

TLS is always verified against the system trust store, every call has a 20 s
timeout, and the API host must be api-<x>.duosecurity.com or
api-<x>.duofederal.com over https. The integration key, the secret key, the
Authorization header and the signature are never logged, never put in an
exception message and never returned, and neither is a rejected account url
(a secret pasted into that field must not reach a log). HTTP 429 / Duo code
42901 raises DuoRateLimited so the caller can back off (the input persists
backoff_until); a network failure or an HTTP 5xx raises DuoUnavailable, which
the users snapshot retries within its run.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import base64
import email.utils
import hashlib
import hmac
import json
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger('ta_gen_ai_cim_duo_api')

API_HOST_RE = re.compile(r'^api-[a-z0-9]+\.(duosecurity|duofederal)\.com$')
TIMEOUT_SECONDS = 20

AUTH_LOGS_PATH = '/admin/v2/logs/authentication'
ACTIVITY_LOGS_PATH = '/admin/v2/logs/activity'
USERS_PATH = '/admin/v1/users'

LOG_PAGE_LIMIT = 1000      # Duo's maximum for the v2 log endpoints
USERS_PAGE_LIMIT = 300     # Duo's maximum for /admin/v1/users
RATE_LIMIT_CODE = 42901


class DuoError(Exception):
    """A Duo API failure, already sanitized for display: it names the method,
    path, HTTP status and Duo's code/message, never a key or a header."""

    def __init__(self, message, http_status=None, code=None):
        super(DuoError, self).__init__(message)
        self.http_status = http_status
        self.code = code


class DuoRateLimited(DuoError):
    """HTTP 429 or Duo code 42901. retry_after is the server's Retry-After
    hint in seconds when it sent one, else None."""

    def __init__(self, message, http_status=None, code=None, retry_after=None):
        super(DuoRateLimited, self).__init__(message, http_status, code)
        self.retry_after = retry_after


class DuoUnavailable(DuoError):
    """A transient failure: Duo could not be reached (DNS, TLS, timeout) or
    answered HTTP 5xx. Worth retrying; a 4xx other than 429 is not."""


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


def signature_hex(skey, canonical):
    return hmac.new(skey.encode('utf-8'), canonical.encode('utf-8'), hashlib.sha512).hexdigest()


def authorization(ikey, skey, canonical):
    token = base64.b64encode('{}:{}'.format(ikey, signature_hex(skey, canonical))
                             .encode('utf-8')).decode('ascii')
    return 'Basic ' + token


def parse_api_host(url):
    """The Duo API hostname from an account url: https://api-<x>.duosecurity.com
    (or duofederal.com), optionally with a trailing slash. Anything else -
    http://, a path, a port, credentials, another domain - raises DuoError.
    The value is never echoed: the input logs this error at ERROR, and a url
    written by hand or through configs/conf-ta_gen_ai_cim_account skips the
    handler's validation, so it may hold a pasted secret."""
    text = (url or '').strip()
    if '://' in text:
        parts = urllib.parse.urlsplit(text)
        if parts.scheme.lower() != 'https':
            raise DuoError('the Duo API url must use https')
        if parts.username or parts.password or parts.port or parts.query or parts.fragment \
                or parts.path not in ('', '/'):
            raise DuoError('the Duo API url must be https://api-XXXXXXXX.duosecurity.com '
                           'with no path, port or credentials')
        host = (parts.hostname or '').lower()
    else:
        host = text.lower().rstrip('/')
    if not API_HOST_RE.match(host):
        raise DuoError('the account url is not a Duo Admin API hostname '
                       '(api-XXXXXXXX.duosecurity.com or .duofederal.com)')
    return host


def urllib_transport(method, url, headers, body, timeout=TIMEOUT_SECONDS):
    """(status, text, response headers). TLS is always verified."""
    data = body.encode('utf-8') if body else None
    request = urllib.request.Request(url, data=data, method=method)
    for key, value in headers.items():
        request.add_header(key, value)
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, context=context, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode('utf-8', 'replace'), dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode('utf-8', 'replace'), dict((exc.headers or {}).items())
    except Exception as exc:  # DNS, TLS, timeout - no secret is in the text
        raise DuoUnavailable('cannot reach the Duo Admin API: {}'.format(type(exc).__name__))


def _retry_after(headers):
    for key, value in (headers or {}).items():
        if str(key).lower() == 'retry-after':
            try:
                return max(0, int(str(value).strip()))
            except ValueError:
                return None
    return None


def normalize_next_offset(value):
    """v2 next_offset as the string Duo accepts back ("<ms>,<txid>"), or None
    when the window is exhausted. Authentication logs return a two-element
    list, activity logs a comma-joined string."""
    if value is None or value == '' or value == []:
        return None
    if isinstance(value, (list, tuple)):
        return ','.join(str(part) for part in value)
    return str(value)


class DuoAdminClient(object):
    """GET-only Duo Admin API client. transport and now are test hooks."""

    def __init__(self, host, ikey, skey, transport=None, now=None):
        self.host = parse_api_host(host)
        if not ikey or not skey:
            raise DuoError('the Admin API integration key and secret key are required')
        self._ikey = str(ikey).strip()
        self._skey = str(skey).strip()
        self.transport = transport or urllib_transport
        self.now = now   # returns an RFC 2822 date string

    def __repr__(self):
        return 'DuoAdminClient(host={!r})'.format(self.host)

    def _date(self):
        return self.now() if self.now else email.utils.formatdate(usegmt=False)

    def request(self, path, params=None):
        """The decoded reply of a stat=OK GET: (response, metadata). Raises
        DuoRateLimited on 429/42901, DuoUnavailable on a 5xx or an unreachable
        Duo, and DuoError on anything else."""
        query = dict((k, v) for k, v in (params or {}).items() if v is not None)
        date = self._date()
        headers = {'Date': date, 'Host': self.host, 'Accept': 'application/json',
                   'Authorization': authorization(
                       self._ikey, self._skey,
                       canonical_string(date, 'GET', self.host, path, query, ''))}
        url = 'https://{}{}'.format(self.host, path)
        if query:
            url += '?' + canon_params(query)
        status, text, resp_headers = self.transport('GET', url, headers, '')
        logger.debug('Duo GET %s -> HTTP %s', path, status)
        try:
            payload = json.loads(text)
        except ValueError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        if status == 200 and payload.get('stat') == 'OK':
            response = payload.get('response')
            metadata = payload.get('metadata')
            if isinstance(response, dict) and metadata is None:
                metadata = response.get('metadata')
            return response, (metadata if isinstance(metadata, dict) else {})
        code = payload.get('code')
        detail = ' ({})'.format(payload['message_detail']) if payload.get('message_detail') else ''
        message = 'Duo Admin API GET {} -> HTTP {}{}: {}{}'.format(
            path, status, ' code {}'.format(code) if code else '',
            payload.get('message') or 'no message', detail)
        if status == 429 or str(code) == str(RATE_LIMIT_CODE):
            raise DuoRateLimited(message, status, code, _retry_after(resp_headers))
        if isinstance(status, int) and status >= 500:
            raise DuoUnavailable(message, status, code)
        raise DuoError(message, status, code)

    def log_page(self, path, mintime_ms, maxtime_ms, next_offset=None, limit=None):
        """One page of a v2 log endpoint, oldest first: (records, next_offset).
        sort=ts:asc is always sent - Duo documents no default order, and a
        window resumed from next_offset in descending order skips everything
        newer than its first page. Duo returns a next_offset on the last page
        that has records too (its documented example carries one with
        total_objects 1); only the call after that page comes back without
        one, so the caller must not read a next_offset as "more records"."""
        if int(mintime_ms) >= int(maxtime_ms):
            raise DuoError('Duo requires mintime < maxtime ({} >= {})'.format(mintime_ms, maxtime_ms))
        params = {'mintime': int(mintime_ms), 'maxtime': int(maxtime_ms),
                  'limit': int(limit or LOG_PAGE_LIMIT), 'sort': 'ts:asc'}
        if next_offset:
            params['next_offset'] = next_offset
        response, metadata = self.request(path, params)
        if isinstance(response, dict):
            records = response.get('authlogs')
            if records is None:
                records = response.get('items')
        else:
            records = response
        return list(records or []), normalize_next_offset(metadata.get('next_offset'))

    def users_page(self, offset=0, limit=None):
        """One page of /admin/v1/users: (users, next_offset, total_objects).
        next_offset is an int, or None on the last page."""
        response, metadata = self.request(USERS_PATH, {'limit': int(limit or USERS_PAGE_LIMIT),
                                                       'offset': int(offset)})
        next_offset = metadata.get('next_offset')
        try:
            next_offset = int(next_offset) if next_offset not in (None, '') else None
        except (TypeError, ValueError):
            next_offset = None
        total = metadata.get('total_objects')
        try:
            total = int(total) if total is not None else None
        except (TypeError, ValueError):
            total = None
        return list(response or []), next_offset, total
