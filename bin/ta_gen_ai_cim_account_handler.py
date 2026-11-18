#!/usr/bin/env python
# encoding=utf-8
"""
ta_gen_ai_cim_account_handler.py - REST handler for ta_gen_ai_cim_account.conf

restmap.conf [admin:ta_gen_ai_cim_account] / [admin_external:ta_gen_ai_cim_account]:

    /servicesNS/nobody/TA-gen_ai_cim/ta_gen_ai_cim_account/ta_gen_ai_cim_account[/<name>]

One stanza per account. auth_type picks what an account holds:

    basic               ServiceNow (or the `soar` account): username in the conf,
                        password in storage/passwords
    oauth_auth_code,    ServiceNow OAuth 2.0: client_id (and an optional username)
    oauth_client_creds  in the conf, client_secret (and an optional password)
                        in storage/passwords
    token               the `soar` account read by | genaiseedes: the automation
                        token, stored as `password` in storage/passwords
    duo_hmac            a Cisco Duo Admin API account (read by the Duo modular
                        input): url = https://api-<x>.duosecurity.com (or
                        duofederal.com), validated and normalized; client_id =
                        the integration key (ikey) in the conf; the secret key
                        (skey) ONLY in storage/passwords as `client_secret`

Secrets are never written to the conf, never logged, and never returned: list
answers a mask for a legacy plaintext secret and nothing else. Every secret lives
under realm ta_gen_ai_cim_account__<name>, credential name password|client_secret,
in the TA-gen_ai_cim app context (its ACL comes from metadata/default.meta).

Persistence uses the same documented endpoints the Configuration page has always
used (configs/conf-ta_gen_ai_cim_account, storage/passwords), with the caller's
session, so the caller's own permissions apply to every write.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import json
import logging
import os
import re
from urllib.parse import quote

import splunk
import splunk.admin as admin
import splunk.rest as rest

logger = logging.getLogger('ta_gen_ai_cim_account_handler')

APP_NAME = 'TA-gen_ai_cim'
CONF_NAME = 'ta_gen_ai_cim_account'
REALM_PREFIX = 'ta_gen_ai_cim_account__'
CONF_ENDPOINT = '/servicesNS/nobody/{}/configs/conf-{}'.format(APP_NAME, CONF_NAME)
PASSWORDS_ENDPOINT = '/servicesNS/nobody/{}/storage/passwords'.format(APP_NAME)

# Stanzas of the conf that are not accounts.
NON_ACCOUNT_STANZAS = ('default', 'asset_discovery')
ACCOUNT_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')

DUO_AUTH_TYPE = 'duo_hmac'
SNOW_AUTH_TYPES = ('basic', 'oauth_auth_code', 'oauth_client_creds')
AUTH_TYPES = SNOW_AUTH_TYPES + ('token', DUO_AUTH_TYPE)

# Same host rule as bin/ta_gen_ai_cim_duo_api.py API_HOST_RE (a test pins it).
DUO_API_HOST_RE = re.compile(r'^api-[a-z0-9]+\.(duosecurity|duofederal)\.com$')
DUO_IKEY_RE = re.compile(r'^[A-Za-z0-9]{16,64}$')
DUO_SKEY_RE = re.compile(r'^[\x21-\x7e]{20,128}$')
# Declared handler args a Cisco Duo account must not carry.
NON_DUO_ARGS = ('username', 'password')

SECRET_MASK = '********'
SECRET_FIELDS = ('password', 'client_secret')
# Never declared (nothing stores them, so splunkd rejects them before the
# handler runs), but masked in the reply too should one ever arrive:
# MConfigHandler.toXml() echoes every caller arg back to splunkd.
UNDECLARED_TOKEN_ARGS = ('access_token', 'refresh_token')
LISTED_FIELDS = ('url', 'auth_type', 'username', 'client_id')

DUO_URL_HELP = ('The API hostname must be the Duo Admin API hostname, for example '
                'api-XXXXXXXX.duosecurity.com or https://api-XXXXXXXX.duofederal.com '
                '(https only, no path, port or credentials).')


def normalize_duo_api_url(value):
    """'https://<host>' for a Duo Admin API hostname, or ValueError.

    Accepts the bare hostname (as the Duo Admin Panel shows it) or an https URL,
    either with at most a trailing slash. The input is never echoed: a secret
    pasted into the wrong field must not come back in an error message."""
    text = (value or '').strip()
    if not text:
        raise ValueError('The API hostname is required.')
    if '://' in text:
        # Parsed by hand, the same way config_config.js does, so the page and
        # the handler accept exactly the same strings (urlsplit lets an empty
        # port or query through).
        scheme, rest = text.split('://', 1)
        if scheme.lower() != 'https':
            raise ValueError('The Duo API hostname must use https.')
        authority, slash, path = rest.partition('/')
        if any(c in rest for c in '?#@') or ':' in authority or (slash + path) not in ('', '/'):
            raise ValueError(DUO_URL_HELP)
        host = authority.lower()
    else:
        host = text.lower()
        if host.endswith('/'):
            host = host[:-1]
    if not DUO_API_HOST_RE.match(host):
        raise ValueError(DUO_URL_HELP)
    return 'https://' + host


def validate_duo_ikey(value):
    """The integration key, stripped, or ValueError (never echoes the input)."""
    ikey = (value or '').strip()
    if not DUO_IKEY_RE.match(ikey):
        raise ValueError('The integration key must be 16-64 letters and digits '
                         '(Duo shows it as DIXXXXXXXXXXXXXXXXXX).')
    return ikey


def validate_duo_skey(value):
    """The secret key, stripped, or ValueError (never echoes the input)."""
    skey = (value or '').strip()
    if skey == SECRET_MASK or not DUO_SKEY_RE.match(skey):
        raise ValueError('The secret key must be 20-128 characters with no spaces.')
    return skey


def realm_for(account_name):
    return REALM_PREFIX + account_name


def _status(exc):
    return getattr(exc, 'statusCode', None)


class AccountHandler(admin.MConfigHandler):
    """EAI handler for the ServiceNow, SOAR and Cisco Duo accounts."""

    # ------------------------------------------------------------------ setup
    def setup(self):
        if self.requestedAction == admin.ACTION_CREATE:
            self.supportedArgs.addReqArg('url')
            self.supportedArgs.addReqArg('auth_type')
        if self.requestedAction in (admin.ACTION_CREATE, admin.ACTION_EDIT):
            # No redirect_url, access_token or refresh_token: the 1.x handler
            # declared them but never stored them, so a posted OAuth token was
            # dropped and then echoed unmasked in the reply. Undeclared,
            # splunkd rejects them with a clear error instead.
            optional = ['username', 'password', 'client_id', 'client_secret']
            if self.requestedAction == admin.ACTION_EDIT:
                optional = ['url', 'auth_type'] + optional
            for arg in optional:
                self.supportedArgs.addOptArg(arg)

    # ------------------------------------------------------------- REST layer
    def _rest(self, method, path, getargs=None, postargs=None):
        query = {'output_mode': 'json'}
        query.update(getargs or {})
        _response, content = rest.simpleRequest(
            path, sessionKey=self.getSessionKey(), getargs=query, postargs=postargs,
            method=method, raiseAllErrors=True)
        if isinstance(content, bytes):
            content = content.decode('utf-8', 'replace')
        return json.loads(content) if content else {}

    @staticmethod
    def _conf_path(name=None):
        return CONF_ENDPOINT + ('/' + quote(name, safe='') if name else '')

    @staticmethod
    def _secret_path(account_name=None, field=None):
        if account_name is None:
            return PASSWORDS_ENDPOINT
        credential = '{}:{}:'.format(realm_for(account_name), field)
        return PASSWORDS_ENDPOINT + '/' + quote(credential, safe='')

    def _conf_list(self):
        body = self._rest('GET', self._conf_path(), getargs={'count': 0})
        return [(e.get('name'), e.get('content') or {}) for e in body.get('entry', [])]

    def _conf_get(self, name):
        try:
            body = self._rest('GET', self._conf_path(name))
        except splunk.ResourceNotFound:
            return None
        entries = body.get('entry') or []
        return (entries[0].get('content') or {}) if entries else None

    def _store_secret(self, account_name, field, value):
        """Update the credential in place, or create it. Never deletes first, so a
        failed write cannot leave an account without its secret."""
        try:
            self._rest('POST', self._secret_path(account_name, field),
                       postargs={'password': value})
        except splunk.ResourceNotFound:
            self._rest('POST', self._secret_path(), postargs={
                'name': field, 'password': value, 'realm': realm_for(account_name)})
        logger.info('stored %s for account %s', field, account_name)

    def _delete_secret(self, account_name, field):
        try:
            self._rest('DELETE', self._secret_path(account_name, field))
        except splunk.ResourceNotFound:
            pass
        except Exception as exc:  # orphaned credential; logged without detail
            logger.warning('could not delete %s of account %s (%s, HTTP %s)',
                           field, account_name, type(exc).__name__, _status(exc))

    # ---------------------------------------------------------------- helpers
    def _arg(self, key):
        """First value of a caller arg; '' for an empty value, None when absent."""
        values = self.callerArgs.data.get(key)
        if not values:
            return None
        return values[0] if values[0] is not None else ''

    def _scrub_secrets(self):
        """MConfigHandler.toXml() serializes callerArgs back to splunkd with the
        reply; once a secret has been read, only a mask goes back."""
        for field in SECRET_FIELDS + UNDECLARED_TOKEN_ARGS:
            if field in self.callerArgs.data:
                self.callerArgs.data[field] = [SECRET_MASK]

    def _account_name(self, creating):
        name = (self.callerArgs.id or '').strip()
        if not name:
            raise admin.ArgValidationException('An account name is required.')
        if name in NON_ACCOUNT_STANZAS or name.startswith('_'):
            raise admin.ArgValidationException('"{}" is reserved and is not an account.'.format(name))
        if creating and not ACCOUNT_NAME_RE.match(name):
            raise admin.ArgValidationException(
                'An account name is 1-64 letters, digits, "_" or "-", starting with a letter or digit.')
        return name

    @staticmethod
    def _auth_type(value):
        auth_type = (value or '').strip().lower()
        if auth_type not in AUTH_TYPES:
            raise admin.ArgValidationException(
                'auth_type must be one of: {}.'.format(', '.join(AUTH_TYPES)))
        return auth_type

    def _duo_settings(self, creating):
        """(conf fields, [(secret field, value)]) for a duo_hmac create or edit."""
        extra = [k for k in NON_DUO_ARGS if self._arg(k) is not None]
        if extra:
            raise admin.ArgValidationException(
                'A Cisco Duo account takes only url, client_id and client_secret '
                '(not {}).'.format(', '.join(extra)))
        fields, secrets = {'auth_type': DUO_AUTH_TYPE}, []
        try:
            url = self._arg('url')
            if creating or url is not None:
                fields['url'] = normalize_duo_api_url(url)
            ikey = self._arg('client_id')
            if creating or ikey is not None:
                fields['client_id'] = validate_duo_ikey(ikey)
            skey = self._arg('client_secret')
            if creating or (skey and skey.strip() not in ('', SECRET_MASK)):
                secrets.append(('client_secret', validate_duo_skey(skey)))
        except ValueError as exc:
            raise admin.ArgValidationException(str(exc))
        return fields, secrets

    def _legacy_settings(self, auth_type, creating):
        """ServiceNow / soar settings, with the 1.x handler's semantics: a masked or
        empty secret leaves the stored one unchanged; client_id and client_secret
        belong to the OAuth types only."""
        fields, secrets = {}, []
        if creating or self._arg('auth_type') is not None:
            fields['auth_type'] = auth_type
        url = self._arg('url')
        if url is not None:
            if creating and not url.strip():
                raise admin.ArgValidationException('URL is required.')
            fields['url'] = url.strip()
        username = self._arg('username')
        if username is not None and (username.strip() or not creating):
            fields['username'] = username.strip()
        client_id = self._arg('client_id')
        if client_id is not None and auth_type.startswith('oauth_'):
            fields['client_id'] = client_id.strip()
        for field in SECRET_FIELDS:
            value = self._arg(field)
            if not value or value == SECRET_MASK:
                continue
            if field == 'client_secret' and not auth_type.startswith('oauth_'):
                continue
            secrets.append((field, value))
        return fields, secrets

    @staticmethod
    def _describe(confInfo, name, content):
        for key in LISTED_FIELDS:
            value = content.get(key)
            if key == 'auth_type':
                value = value or 'basic'
            confInfo[name].append(key, value or '')
        for key in SECRET_FIELDS:   # a mask for a legacy plaintext secret, never the value
            confInfo[name].append(key, SECRET_MASK if content.get(key) else '')

    @staticmethod
    def _rest_failure(exc, what):
        """An admin exception for a failed splunkd call; splunkd's own text is not
        passed through, so nothing a request carried can come back in it."""
        if isinstance(exc, admin.AdminManagerException):
            return exc
        if isinstance(exc, splunk.ResourceNotFound):
            return admin.NotFoundException('{}: not found.'.format(what))
        if isinstance(exc, splunk.AuthorizationFailed):
            return admin.PermissionsException('{}: permission denied.'.format(what))
        if _status(exc) == 409:
            return admin.AlreadyExistsException('{}: it already exists.'.format(what))
        logger.warning('%s failed (%s, HTTP %s)', what, type(exc).__name__, _status(exc))
        return admin.InternalException('{} failed (HTTP {}).'.format(what, _status(exc) or 'error'))

    # --------------------------------------------------------------- actions
    def handleList(self, confInfo):
        wanted = (self.callerArgs.id or '').strip()
        try:
            stanzas = self._conf_list()
        except Exception as exc:
            raise self._rest_failure(exc, 'Listing accounts')
        for name, content in stanzas:
            if not name or name in NON_ACCOUNT_STANZAS or name.startswith('_'):
                continue
            if wanted and name != wanted:
                continue
            self._describe(confInfo, name, content)
        if wanted and wanted not in confInfo:
            raise admin.NotFoundException('Account "{}" does not exist.'.format(wanted))

    def handleCreate(self, confInfo):
        name = self._account_name(creating=True)
        auth_type = self._auth_type(self._arg('auth_type'))
        try:
            if auth_type == DUO_AUTH_TYPE:
                fields, secrets = self._duo_settings(creating=True)
            else:
                fields, secrets = self._legacy_settings(auth_type, creating=True)
        finally:
            self._scrub_secrets()
        what = 'Creating account "{}"'.format(name)
        try:
            # setEntity-style "create" silently updates an existing stanza; refuse
            # instead, so a Duo account can never overwrite a ServiceNow one.
            if self._conf_get(name) is not None:
                raise admin.AlreadyExistsException(
                    'An account named "{}" already exists; choose another name.'.format(name))
            body = dict(fields)
            body['name'] = name
            self._rest('POST', self._conf_path(), postargs=body)
        except Exception as exc:
            raise self._rest_failure(exc, what)
        try:
            for field, value in secrets:
                self._store_secret(name, field, value)
        except Exception as exc:
            # Never leave an account behind without the secret it was created with.
            for field, _value in secrets:
                self._delete_secret(name, field)
            try:
                self._rest('DELETE', self._conf_path(name))
            except Exception:
                logger.warning('could not roll back account %s', name)
            raise self._rest_failure(exc, 'Storing the secret of account "{}"'.format(name))
        logger.info('created account %s (auth_type=%s)', name, auth_type)
        self.shouldAutoList = False
        self._describe(confInfo, name, fields)

    def handleEdit(self, confInfo):
        name = self._account_name(creating=False)
        what = 'Updating account "{}"'.format(name)
        try:
            current = self._conf_get(name)
        except Exception as exc:
            raise self._rest_failure(exc, what)
        if current is None:
            raise admin.NotFoundException('Account "{}" does not exist.'.format(name))
        current_type = (current.get('auth_type') or 'basic').strip().lower()
        requested = self._arg('auth_type')
        auth_type = self._auth_type(requested) if requested is not None else current_type
        if (current_type == DUO_AUTH_TYPE) != (auth_type == DUO_AUTH_TYPE):
            raise admin.ArgValidationException(
                'Account "{}" cannot switch between Cisco Duo and another auth type; '
                'delete it and create it again.'.format(name))
        try:
            if auth_type == DUO_AUTH_TYPE:
                fields, secrets = self._duo_settings(creating=False)
            else:
                fields, secrets = self._legacy_settings(auth_type, creating=False)
        finally:
            self._scrub_secrets()
        try:
            if fields:
                self._rest('POST', self._conf_path(name), postargs=fields)
            for field, value in secrets:
                self._store_secret(name, field, value)
        except Exception as exc:
            raise self._rest_failure(exc, what)
        logger.info('updated account %s (auth_type=%s)', name, auth_type)
        merged = dict(current)
        merged.update(fields)
        self.shouldAutoList = False
        self._describe(confInfo, name, merged)

    def handleRemove(self, confInfo):
        name = self._account_name(creating=False)
        try:
            self._rest('DELETE', self._conf_path(name))
        except Exception as exc:
            raise self._rest_failure(exc, 'Deleting account "{}"'.format(name))
        for field in SECRET_FIELDS:
            self._delete_secret(name, field)
        logger.info('deleted account %s', name)


# The 1.x class name, for anything that imported it.
ServiceNowAccountHandler = AccountHandler


def _setup_file_logging():
    """Best effort: $SPLUNK_HOME/var/log/splunk/ta_gen_ai_cim_account_handler.log."""
    if logger.handlers:
        return
    logger.setLevel(logging.INFO)
    try:
        from logging.handlers import RotatingFileHandler
        path = os.path.join(os.environ.get('SPLUNK_HOME', '/opt/splunk'), 'var', 'log', 'splunk',
                            'ta_gen_ai_cim_account_handler.log')
        handler = RotatingFileHandler(path, maxBytes=1024 * 1024, backupCount=2)
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s - %(message)s'))
        logger.addHandler(handler)
    except Exception:
        logger.addHandler(logging.NullHandler())


# splunkd runs the handler as a script (persistent mode included), as UCC's
# generated handlers assume; the guard keeps an import (the tests) inert.
if __name__ == '__main__':
    _setup_file_logging()
    admin.init(AccountHandler, admin.CONTEXT_APP_ONLY)
