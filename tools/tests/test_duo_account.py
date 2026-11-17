# encoding=utf-8
"""
Offline checks for the Cisco Duo Admin API account (auth_type duo_hmac,
TA-gen_ai_cim 1.9.0):

  * bin/ta_gen_ai_cim_account_handler.py validates the API hostname, keeps the
    integration key in the conf and the secret key ONLY in storage/passwords
    (realm ta_gen_ai_cim_account__<name>, name client_secret), never returns,
    logs or echoes the secret, and keeps the ServiceNow / soar semantics;
  * bin/sync_snow_asset.py get_snow_config picks a ServiceNow account only
    (contract decision 5): a duo_hmac stanza and a soar stanza that sort
    first are ignored;
  * appserver/static/config_config.js applies the same rules (run under node
    against the Python over the same vectors) and saves Duo accounts only
    through the account REST handler; configuration.xml carries the form.

The handler runs against an in-memory emulation of the two splunkd endpoints
it uses (configs/conf-ta_gen_ai_cim_account, storage/passwords), so no splunkd
is needed. Runs on Python 3.9 and 3.13:

    python3 -m unittest discover -s tools/tests -p 'test_duo_account.py' -v
"""

import importlib.util
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import xml.etree.ElementTree as ET
from urllib.parse import unquote

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
BIN = os.path.join(REPO, 'bin')
JS_PATH = os.path.join(REPO, 'appserver', 'static', 'config_config.js')
VIEW_PATH = os.path.join(REPO, 'default', 'data', 'ui', 'views', 'configuration.xml')
SPEC_PATH = os.path.join(REPO, 'default', 'ta_gen_ai_cim_account.conf.spec')

# Invented fixtures: no real tenant, key or instance.
DUO_HOST = 'api-fixture0.duosecurity.com'
IKEY = 'DIFIXTUREIKEY0000001'
SKEY = 'fixture-skey-not-real-000000000000000000'
SKEY2 = 'fixture-skey-not-real-111111111111111111'
SNOW_URL = 'https://fixture-instance.service-now.com'
CONF_BASE = '/servicesNS/nobody/TA-gen_ai_cim/configs/conf-ta_gen_ai_cim_account'
PW_BASE = '/servicesNS/nobody/TA-gen_ai_cim/storage/passwords'


# --------------------------------------------------------------------------
# Fake splunk.* modules (only what the handler touches)
# --------------------------------------------------------------------------
class RESTException(Exception):
    def __init__(self, statusCode, msg=None):
        Exception.__init__(self, msg)
        self.statusCode = statusCode


class ResourceNotFound(RESTException):
    def __init__(self, uri=''):
        RESTException.__init__(self, 404, 'not found: %s' % uri)


class AuthorizationFailed(RESTException):
    def __init__(self, uri=''):
        RESTException.__init__(self, 403, 'forbidden')


def _fake_admin():
    mod = types.ModuleType('splunk.admin')
    mod.ACTION_CREATE, mod.ACTION_LIST, mod.ACTION_EDIT, mod.ACTION_REMOVE = 1, 2, 4, 8
    mod.CONTEXT_APP_ONLY = 2

    class AdminManagerException(Exception):
        pass
    mod.AdminManagerException = AdminManagerException
    for exc in ('AlreadyExistsException', 'NotFoundException', 'ArgValidationException',
                'BadActionException', 'InternalException', 'PermissionsException'):
        setattr(mod, exc, type(exc, (AdminManagerException,), {}))

    class ArgSpecList(object):
        def __init__(self):
            self.required, self.optional = [], []

        def addReqArg(self, name):
            self.required.append(name)

        def addOptArg(self, name):
            self.optional.append(name)

    class CallerArgs(object):
        def __init__(self):
            self.id, self.data = None, {}

    class MConfigHandler(object):
        def __init__(self):
            self.callerArgs = CallerArgs()
            self.supportedArgs = ArgSpecList()
            self.requestedAction = 0
            self.shouldAutoList = True

        def getSessionKey(self):
            return 'fixture-session'

    mod.MConfigHandler = MConfigHandler
    mod.init = lambda handler, ctx: None
    return mod


class FakeSplunkd(object):
    """In-memory configs/conf-ta_gen_ai_cim_account + storage/passwords with the
    splunkd semantics the handler relies on: 409 on a duplicate create, 404 on
    a missing entity, update-in-place on POST to an entity."""

    def __init__(self):
        self.conf = {'default': {'auth_type': 'basic'},
                     'asset_discovery': {'ai_system_table': 'alm_ai_system_digital_asset'}}
        self.passwords = {}          # (realm, name) -> secret
        self.calls = []
        self.fail_password_create = False

    def request(self, path, sessionKey=None, getargs=None, postargs=None, method='GET',
                raiseAllErrors=False, **_ignored):
        assert sessionKey == 'fixture-session'
        assert (getargs or {}).get('output_mode') == 'json'
        self.calls.append((method, path, dict(postargs or {})))
        if path.startswith(CONF_BASE):
            return None, json.dumps(self._conf(method, unquote(path[len(CONF_BASE) + 1:]), postargs or {}))
        if path.startswith(PW_BASE):
            return None, json.dumps(self._pw(method, unquote(path[len(PW_BASE) + 1:]), postargs or {}))
        raise AssertionError('unexpected endpoint %s' % path)

    def _conf(self, method, name, post):
        if not name:
            if method == 'GET':
                return {'entry': [{'name': n, 'content': self._merged(n)} for n in sorted(self.conf)]}
            new = post['name']
            if new in self.conf:
                raise RESTException(409, 'exists')
            self.conf[new] = {k: v for k, v in post.items() if k != 'name'}
            return {'entry': [{'name': new, 'content': self._merged(new)}]}
        if name not in self.conf:
            raise ResourceNotFound(name)
        if method == 'GET':
            return {'entry': [{'name': name, 'content': self._merged(name)}]}
        if method == 'POST':
            self.conf[name].update(post)
            return {'entry': [{'name': name, 'content': self._merged(name)}]}
        del self.conf[name]
        return {'entry': []}

    def _merged(self, name):
        content = dict(self.conf.get('default', {}))
        content.update(self.conf[name])
        content['eai:acl'] = {'app': 'TA-gen_ai_cim'}
        return content

    def _pw(self, method, ident, post):
        if not ident:
            if self.fail_password_create:
                raise RESTException(500, 'boom')
            key = (post['realm'], post['name'])
            if key in self.passwords:
                raise RESTException(409, 'exists')
            self.passwords[key] = post['password']
            return {'entry': []}
        realm, name, _empty = ident.split(':')
        if (realm, name) not in self.passwords:
            raise ResourceNotFound(ident)
        if method == 'POST':
            self.passwords[(realm, name)] = post['password']
        elif method == 'DELETE':
            del self.passwords[(realm, name)]
        return {'entry': [{'name': ident, 'content': {'clear_password': self.passwords.get((realm, name))}}]}


def load_handler_module():
    """Import the handler against the fake splunk modules, then put sys.modules back."""
    splunk_pkg = types.ModuleType('splunk')
    splunk_pkg.RESTException = RESTException
    splunk_pkg.ResourceNotFound = ResourceNotFound
    splunk_pkg.AuthorizationFailed = AuthorizationFailed
    rest = types.ModuleType('splunk.rest')
    rest.simpleRequest = None   # bound per test
    admin = _fake_admin()
    splunk_pkg.admin, splunk_pkg.rest = admin, rest
    saved = {k: sys.modules.get(k) for k in ('splunk', 'splunk.admin', 'splunk.rest')}
    sys.modules.update({'splunk': splunk_pkg, 'splunk.admin': admin, 'splunk.rest': rest})
    try:
        spec = importlib.util.spec_from_file_location(
            'ta_gen_ai_cim_account_handler_under_test', os.path.join(BIN, 'ta_gen_ai_cim_account_handler.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
    return module


HANDLER = load_handler_module()
ADMIN = HANDLER.admin


class ConfInfo(dict):
    """Stands in for splunk.admin.ConfigInfo: confInfo[name].append(key, value)."""

    class Item(dict):
        def append(self, key, value):
            self[key] = value

    def __missing__(self, key):
        self[key] = ConfInfo.Item()
        return self[key]


ACTIONS = {'create': ('ACTION_CREATE', 'handleCreate'), 'edit': ('ACTION_EDIT', 'handleEdit'),
           'list': ('ACTION_LIST', 'handleList'), 'remove': ('ACTION_REMOVE', 'handleRemove')}


class HandlerCase(unittest.TestCase):

    def setUp(self):
        self.splunkd = FakeSplunkd()
        HANDLER.rest.simpleRequest = self.splunkd.request
        self.log = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log)
        HANDLER.logger.addHandler(self.log_handler)
        HANDLER.logger.setLevel(logging.DEBUG)

    def tearDown(self):
        HANDLER.logger.removeHandler(self.log_handler)
        # Whatever a test did, neither key may reach a log line.
        for secret in (IKEY, SKEY, SKEY2, 'fixture-snow-password', 'fixture-oauth-secret'):
            self.assertNotIn(secret, self.log.getvalue())

    def call(self, action, name=None, **args):
        """Drive one EAI action the way splunkd would: setup() first, a 400 for
        a missing required or an undeclared argument, then the handle*()."""
        constant, method = ACTIONS[action]
        handler = HANDLER.AccountHandler()
        handler.requestedAction = getattr(ADMIN, constant)
        handler.callerArgs.id = name
        handler.callerArgs.data = {k: [v] for k, v in args.items()}
        handler.setup()
        if action in ('create', 'edit'):
            declared = set(handler.supportedArgs.required + handler.supportedArgs.optional)
            self.assertEqual(set(args) - declared, set(), 'EAI would reject undeclared args')
            missing = set(handler.supportedArgs.required) - set(args)
            if missing:
                raise ADMIN.ArgValidationException('missing %s' % sorted(missing))
        info = ConfInfo()
        getattr(handler, method)(info)
        return handler, info

    def create_duo(self, name='duo', **overrides):
        args = dict(url=DUO_HOST, auth_type='duo_hmac', client_id=IKEY, client_secret=SKEY)
        args.update(overrides)
        return self.call('create', name, **args)

    def secret(self, account, field):
        return self.splunkd.passwords.get(('ta_gen_ai_cim_account__' + account, field))


class DuoAccountHandlerTests(HandlerCase):

    def test_create_keeps_the_skey_in_storage_passwords_only(self):
        handler, info = self.create_duo()
        self.assertEqual(self.splunkd.conf['duo'],
                         {'url': 'https://' + DUO_HOST, 'auth_type': 'duo_hmac', 'client_id': IKEY})
        self.assertEqual(self.secret('duo', 'client_secret'), SKEY)
        self.assertEqual(set(self.splunkd.passwords), {('ta_gen_ai_cim_account__duo', 'client_secret')})
        self.assertNotIn(SKEY, json.dumps(info))
        self.assertFalse(handler.shouldAutoList)
        # The stanza goes in before the secret, so a racing duplicate create
        # fails on the conf (409) before it can touch another account's secret.
        kinds = [(m, p.split('/')[-1] if p.startswith(PW_BASE) else 'conf') for m, p, _ in self.splunkd.calls
                 if m == 'POST']
        self.assertEqual(kinds[0], ('POST', 'conf'))

    def test_list_never_returns_the_skey(self):
        self.create_duo()
        _h, info = self.call('list')
        self.assertEqual(sorted(info), ['duo'])                 # default/asset_discovery are not accounts
        self.assertEqual(info['duo']['client_secret'], '')
        self.assertEqual(info['duo']['client_id'], IKEY)
        self.assertNotIn(SKEY, json.dumps(info))
        # A plaintext secret someone wrote into the conf comes back masked, never echoed.
        self.splunkd.conf['duo']['client_secret'] = SKEY
        _h, info = self.call('list', 'duo')
        self.assertEqual(info['duo']['client_secret'], '********')
        self.assertNotIn(SKEY, json.dumps(info))
        with self.assertRaises(ADMIN.NotFoundException):
            self.call('list', 'nope')

    def test_api_hostname_is_validated_and_normalized(self):
        good = {'api-fixture0.duosecurity.com': 'https://api-fixture0.duosecurity.com',
                ' API-Fixture0.DuoSecurity.com ': 'https://api-fixture0.duosecurity.com',
                'api-fixture0.duosecurity.com/': 'https://api-fixture0.duosecurity.com',
                'https://api-fixture0.duosecurity.com': 'https://api-fixture0.duosecurity.com',
                'HTTPS://api-fixture0.duofederal.com/': 'https://api-fixture0.duofederal.com'}
        for value, expected in good.items():
            self.assertEqual(HANDLER.normalize_duo_api_url(value), expected, value)
        bad = ['', 'http://api-fixture0.duosecurity.com', 'ftp://api-fixture0.duosecurity.com',
               'api-fixture0.duosecurity.com.evil.test', 'evil.test/api-fixture0.duosecurity.com',
               'https://api-fixture0.duosecurity.com:443', 'https://api-fixture0.duosecurity.com:',
               'https://api-fixture0.duosecurity.com/admin/v1', 'https://user@api-fixture0.duosecurity.com',
               'https://api-fixture0.duosecurity.com?x=1', 'https://api-fixture0.duosecurity.com#f',
               'https://api-fixture0.duosecurity.com?', 'api.duosecurity.com', 'api-.duosecurity.com',
               'admin-fixture0.duosecurity.com', 'api-fixture0.duo.com', 'https://' + SNOW_URL[8:], SKEY]
        for value in bad:
            with self.assertRaises(ValueError, msg=value) as ctx:
                HANDLER.normalize_duo_api_url(value)
            if value:
                self.assertNotIn(value.strip(), str(ctx.exception))   # never echoes the input

    def test_bad_hostname_or_keys_are_refused_without_echo(self):
        cases = [dict(url='http://' + DUO_HOST), dict(url='api-fixture0.example-duo.test'),
                 dict(client_id='DI SHORT'), dict(client_id=''), dict(client_secret='short'),
                 dict(client_secret='********'), dict(client_secret='has spaces ' * 4), dict(client_secret='')]
        for override in cases:
            with self.assertRaises(ADMIN.ArgValidationException, msg=override) as ctx:
                self.create_duo(**override)
            for value in override.values():
                if value and value != '********':
                    self.assertNotIn(value, str(ctx.exception))
        self.assertNotIn('duo', self.splunkd.conf)
        self.assertEqual(self.splunkd.passwords, {})

    def test_create_never_overwrites_an_existing_account(self):
        self.call('create', 'svc_splunk_integration', url=SNOW_URL, auth_type='basic',
                  username='dana.ortiz', password='fixture-snow-password')
        before_conf = dict(self.splunkd.conf['svc_splunk_integration'])
        before_pw = dict(self.splunkd.passwords)
        with self.assertRaises(ADMIN.AlreadyExistsException):
            self.create_duo('svc_splunk_integration')
        self.assertEqual(self.splunkd.conf['svc_splunk_integration'], before_conf)
        self.assertEqual(self.splunkd.passwords, before_pw)

    def test_edit_keeps_or_replaces_the_secret_in_place(self):
        self.create_duo()
        self.call('edit', 'duo', url='https://api-fixture1.duofederal.com', client_id=IKEY, client_secret='')
        self.assertEqual(self.splunkd.conf['duo']['url'], 'https://api-fixture1.duofederal.com')
        self.assertEqual(self.secret('duo', 'client_secret'), SKEY)
        self.call('edit', 'duo', client_secret='********')
        self.assertEqual(self.secret('duo', 'client_secret'), SKEY)
        self.splunkd.calls = []
        self.call('edit', 'duo', client_secret=SKEY2)
        self.assertEqual(self.secret('duo', 'client_secret'), SKEY2)
        self.assertNotIn('DELETE', [m for m, _p, _a in self.splunkd.calls])   # updated, never delete-then-create
        with self.assertRaises(ADMIN.ArgValidationException):
            self.call('edit', 'duo', url='https://api-fixture1.duosecurity.com/path')
        self.assertEqual(self.splunkd.conf['duo']['url'], 'https://api-fixture1.duofederal.com')
        with self.assertRaises(ADMIN.NotFoundException):
            self.call('edit', 'missing', client_secret=SKEY2)

    def test_no_switch_between_duo_and_other_auth_types(self):
        self.create_duo()
        self.call('create', 'svc_splunk_integration', url=SNOW_URL, auth_type='basic', username='dana.ortiz')
        with self.assertRaises(ADMIN.ArgValidationException):
            self.call('edit', 'duo', auth_type='basic')
        with self.assertRaises(ADMIN.ArgValidationException):
            self.call('edit', 'svc_splunk_integration', auth_type='duo_hmac', client_secret=SKEY)
        for foreign in ('username', 'password'):
            with self.assertRaises(ADMIN.ArgValidationException, msg=foreign):
                self.call('edit', 'duo', **{foreign: 'fixture-value'})
        self.assertEqual(self.splunkd.conf['duo']['auth_type'], 'duo_hmac')

    def test_oauth_token_args_are_not_declared(self):
        """Nothing stores redirect_url, access_token or refresh_token, so the
        handler no longer declares them and splunkd rejects them (a declared,
        unstored token used to be echoed unmasked in the reply)."""
        for action in (ADMIN.ACTION_CREATE, ADMIN.ACTION_EDIT):
            handler = HANDLER.AccountHandler()
            handler.requestedAction = action
            handler.setup()
            declared = set(handler.supportedArgs.required + handler.supportedArgs.optional)
            self.assertEqual(declared & {'redirect_url', 'access_token', 'refresh_token'}, set())
        self.assertEqual(HANDLER.NON_DUO_ARGS, ('username', 'password'))
        self.assertIsNone(self.secret('svc_splunk_integration', 'client_secret'))

    def test_remove_deletes_the_stanza_and_its_secrets(self):
        self.create_duo()
        self.create_duo('duo_second', client_secret=SKEY2)
        self.call('remove', 'duo')
        self.assertNotIn('duo', self.splunkd.conf)
        self.assertIsNone(self.secret('duo', 'client_secret'))
        self.assertEqual(self.secret('duo_second', 'client_secret'), SKEY2)
        with self.assertRaises(ADMIN.NotFoundException):
            self.call('remove', 'duo')

    def test_a_failed_secret_write_rolls_the_account_back(self):
        self.splunkd.fail_password_create = True
        with self.assertRaises(ADMIN.InternalException) as ctx:
            self.create_duo()
        self.assertNotIn('duo', self.splunkd.conf)
        self.assertNotIn(SKEY, str(ctx.exception))

    def test_names_and_auth_types_are_checked(self):
        for name in ('default', 'asset_discovery', '_hidden', 'bad name', '-dash', 'x' * 65, ''):
            with self.assertRaises(ADMIN.ArgValidationException, msg=name):
                self.create_duo(name)
        with self.assertRaises(ADMIN.ArgValidationException):
            self.call('create', 'weird', url=SNOW_URL, auth_type='kerberos')
        with self.assertRaises(ADMIN.ArgValidationException):
            self.call('create', 'nourl', auth_type='duo_hmac', client_id=IKEY, client_secret=SKEY)

    def test_setup_declares_the_duo_fields(self):
        handler = HANDLER.AccountHandler()
        handler.requestedAction = ADMIN.ACTION_CREATE
        handler.setup()
        self.assertEqual(handler.supportedArgs.required, ['url', 'auth_type'])
        self.assertTrue({'client_id', 'client_secret'} <= set(handler.supportedArgs.optional))
        handler = HANDLER.AccountHandler()
        handler.requestedAction = ADMIN.ACTION_EDIT
        handler.setup()
        self.assertEqual(handler.supportedArgs.required, [])
        self.assertTrue({'url', 'auth_type', 'client_id', 'client_secret'} <= set(handler.supportedArgs.optional))

    def test_module_import_is_inert_and_guarded(self):
        with io.open(os.path.join(BIN, 'ta_gen_ai_cim_account_handler.py'), encoding='utf-8') as handle:
            source = handle.read()
        self.assertIn("if __name__ == '__main__':\n    _setup_file_logging()\n    admin.init(", source)
        self.assertRegex(source, r"(?m)^logger = logging\.getLogger\(")   # module-level (R-PY-001)


class LegacyAccountHandlerTests(HandlerCase):
    """ServiceNow and soar accounts keep the 1.x handler's behaviour."""

    def test_servicenow_basic(self):
        self.call('create', 'servicenow', url=SNOW_URL, auth_type='basic',
                  username='dana.ortiz', password='fixture-snow-password')
        self.assertEqual(self.splunkd.conf['servicenow'],
                         {'url': SNOW_URL, 'auth_type': 'basic', 'username': 'dana.ortiz'})
        self.assertEqual(self.secret('servicenow', 'password'), 'fixture-snow-password')
        self.call('edit', 'servicenow', url=SNOW_URL, auth_type='basic', username='dana.ortiz',
                  password='********')
        self.assertEqual(self.secret('servicenow', 'password'), 'fixture-snow-password')
        self.call('edit', 'servicenow', password='fixture-snow-password-2')
        self.assertEqual(self.secret('servicenow', 'password'), 'fixture-snow-password-2')
        _h, info = self.call('list', 'servicenow')
        self.assertEqual(info['servicenow']['password'], '')

    def test_servicenow_oauth(self):
        self.call('create', 'snow_oauth', url=SNOW_URL, auth_type='oauth_client_creds',
                  client_id='fixture-client', client_secret='fixture-oauth-secret')
        self.assertEqual(self.splunkd.conf['snow_oauth']['client_id'], 'fixture-client')
        self.assertNotIn('client_secret', self.splunkd.conf['snow_oauth'])
        self.assertEqual(self.secret('snow_oauth', 'client_secret'), 'fixture-oauth-secret')

    def test_soar_token_is_stored_as_the_password(self):
        self.call('create', 'soar', url='https://soar.corp.test', auth_type='token',
                  password='fixture-snow-password')
        self.assertEqual(self.splunkd.conf['soar'], {'url': 'https://soar.corp.test', 'auth_type': 'token'})
        self.assertEqual(self.secret('soar', 'password'), 'fixture-snow-password')


class RealEaiRoundTripTests(unittest.TestCase):
    """Under Splunk's Python (`splunk cmd python3.13 -m unittest ...`), run the
    handler through the real splunk.admin serialization: the reply XML that
    goes back to splunkd must not carry the secret either (toXml echoes
    callerArgs). Skipped where the splunk package is not importable."""

    def setUp(self):
        try:
            import splunk.admin as real_admin   # noqa: F401  (Splunk's Python only)
            import splunk.rest as real_rest
        except ImportError:
            self.skipTest('needs Splunk\'s bundled Python (splunk cmd python3.13)')
        import splunk as real_splunk
        self.admin, self.rest, self.splunk = real_admin, real_rest, real_splunk
        spec = importlib.util.spec_from_file_location(
            'ta_gen_ai_cim_account_handler_real', os.path.join(BIN, 'ta_gen_ai_cim_account_handler.py'))
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.fake = FakeSplunkd()
        self.saved = real_rest.simpleRequest

        def simple_request(path, **kwargs):
            try:
                return self.fake.request(path, **kwargs)
            except ResourceNotFound:
                raise real_splunk.ResourceNotFound(path)
            except RESTException as exc:
                raise real_splunk.RESTException(exc.statusCode, 'fixture')
        real_rest.simpleRequest = simple_request

    def tearDown(self):
        self.rest.simpleRequest = self.saved

    def eai(self, action, ident, setup=False, **args):
        items = ''.join('<item name="%s">%s</item>' % (k, v) for k, v in args.items())
        request = ('<eai>%s<eai_settings><requestedAction>%d</requestedAction><maxCount>0</maxCount>'
                   '<posOffset>0</posOffset></eai_settings><callerArgs><id>%s</id><args>%s</args>'
                   '</callerArgs><sessionKey>fixture-session</sessionKey></eai>') % (
                       '<setup/>' if setup else '', action, ident, items)
        return self.admin.init_persistent(self.module.AccountHandler, self.admin.CONTEXT_APP_ONLY,
                                          request.encode('utf-8')).decode('utf-8')

    def test_setup_reply_declares_no_oauth_token_args(self):
        """splunkd validates caller args against this setup reply, so an
        undeclared token is rejected before the handler ever sees it."""
        for action in (self.admin.ACTION_CREATE, self.admin.ACTION_EDIT):
            declared = set(re.findall(r'<arg name="([^"]+)"', self.eai(action, 'x', setup=True)))
            self.assertTrue({'client_id', 'client_secret', 'password'} <= declared, declared)
            self.assertEqual(declared & {'redirect_url', 'access_token', 'refresh_token'}, set())

    def test_servicenow_create_never_echoes_oauth_tokens(self):
        """Even if a token arg got through, the reply masks it like a secret."""
        tokens = ('fixture-access-token-value', 'fixture-refresh-token-value')
        reply = self.eai(self.admin.ACTION_CREATE, 'snow', url=SNOW_URL,
                         auth_type='basic', username='dana.ortiz', password='fixture-snow-password',
                         access_token=tokens[0], refresh_token=tokens[1])
        self.assertIn('<item name="snow">', reply)
        for secret in tokens + ('fixture-snow-password',):
            self.assertNotIn(secret, reply)
        self.assertEqual(self.fake.passwords[('ta_gen_ai_cim_account__snow', 'password')], 'fixture-snow-password')
        for call in self.fake.calls:
            self.assertNotIn(tokens[0], json.dumps(call))
            self.assertNotIn(tokens[1], json.dumps(call))

    def test_reply_xml_never_carries_the_secret(self):
        reply = self.eai(self.admin.ACTION_CREATE, 'duo', url=DUO_HOST, auth_type='duo_hmac',
                         client_id=IKEY, client_secret=SKEY)
        self.assertIn('<item name="duo">', reply)
        self.assertNotIn(SKEY, reply)
        self.assertEqual(self.fake.passwords[('ta_gen_ai_cim_account__duo', 'client_secret')], SKEY)
        reply = self.eai(self.admin.ACTION_EDIT, 'duo', client_secret=SKEY2)
        self.assertNotIn(SKEY2, reply)
        reply = self.eai(self.admin.ACTION_LIST, '')
        self.assertIn('name="duo"', reply)
        self.assertNotIn(SKEY2, reply)
        reply = self.eai(self.admin.ACTION_CREATE, 'duo2', url='http://' + DUO_HOST, auth_type='duo_hmac',
                         client_id=IKEY, client_secret=SKEY)
        self.assertIn('ArgValidationException', reply)
        self.assertNotIn(SKEY, reply)


# --------------------------------------------------------------------------
# get_snow_config account selection (contract decision 5)
# --------------------------------------------------------------------------
def load_sync_module():
    """Import bin/sync_snow_asset.py with its file log pointed at a scratch dir."""
    home = tempfile.mkdtemp(prefix='duo-account-test-')
    os.makedirs(os.path.join(home, 'var', 'log', 'splunk'))
    saved_home = os.environ.get('SPLUNK_HOME')
    os.environ['SPLUNK_HOME'] = home
    try:
        spec = importlib.util.spec_from_file_location('sync_snow_asset_under_test',
                                                      os.path.join(BIN, 'sync_snow_asset.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        if saved_home is None:
            os.environ.pop('SPLUNK_HOME', None)
        else:
            os.environ['SPLUNK_HOME'] = saved_home
    for handler in list(module.logger.handlers):   # release the scratch file
        module.logger.removeHandler(handler)
        handler.close()
    module.logger.addHandler(logging.NullHandler())
    shutil.rmtree(home, ignore_errors=True)
    return module


SYNC = load_sync_module()


class Stanza(object):
    def __init__(self, name, **content):
        self.name, self.content = name, content


class Credential(object):
    def __init__(self, realm, name, secret):
        self.name = '{}:{}:'.format(realm, name)
        self.content = {'realm': realm, 'username': name, 'clear_password': secret}


class Service(object):
    def __init__(self, stanzas, credentials):
        self.confs = {'ta_gen_ai_cim_account': stanzas}
        self.storage_passwords = credentials


# (stanza name, settings) -> is a ServiceNow account? Shared with the JS parity test.
CLASSIFY_VECTORS = [
    ('svc_splunk_integration', {'url': SNOW_URL, 'auth_type': 'basic'}, True),
    ('servicenow', {'url': 'fixture-instance.servicenow.com'}, True),
    ('duo', {'url': 'https://' + DUO_HOST, 'auth_type': 'duo_hmac', 'client_id': IKEY}, False),
    ('duo_prod', {'url': 'https://' + DUO_HOST, 'auth_type': 'DUO_HMAC'}, False),
    ('soar', {'url': 'https://soar.corp.test', 'auth_type': 'token'}, False),
    ('soar', {'url': 'https://soar.corp.test', 'auth_type': 'basic'}, False),
    ('SOAR', {'url': 'https://soar.corp.test'}, False),
    ('duo', {'url': 'https://mfa.corp.test', 'auth_type': 'basic'}, False),
    ('mfa', {'url': DUO_HOST}, False),
    ('snow_duo_typo', {'url': SNOW_URL, 'auth_type': 'duo_hmac'}, False),
    ('soar', {'url': SNOW_URL, 'auth_type': 'basic'}, True),
    ('custom_snow', {'url': 'https://snow.corp.test', 'auth_type': 'oauth_client_creds'}, True),
    ('custom_token', {'url': 'https://snow.corp.test', 'auth_type': 'token'}, False),
    ('lookalike', {'url': 'https://fixture-instance.service-now.com.evil.test', 'auth_type': 'token'}, False),
    ('lookalike2', {'url': 'https://evilservice-now.com', 'auth_type': 'token'}, False),
    ('userinfo', {'url': 'https://fixture-instance.service-now.com@evil.test', 'auth_type': 'token'}, False),
    ('default', {'url': SNOW_URL}, False),
    ('asset_discovery', {}, False),
    ('_internal', {'url': SNOW_URL}, False),
    ('noauth', {}, True),
]

# Stanza lists -> the account get_snow_config uses.
SELECT_VECTORS = [
    ([('duo', {'url': 'https://' + DUO_HOST, 'auth_type': 'duo_hmac'}),
      ('soar', {'url': 'https://soar.corp.test', 'auth_type': 'basic'}),
      ('svc_splunk_integration', {'url': SNOW_URL, 'auth_type': 'basic'})], 'svc_splunk_integration'),
    ([('a_custom', {'url': 'https://snow.corp.test', 'auth_type': 'basic'}),
      ('zz_snow', {'url': SNOW_URL, 'auth_type': 'basic'})], 'zz_snow'),
    ([('zz_custom', {'url': 'https://snow.corp.test', 'auth_type': 'basic'}),
      ('duo', {'url': 'https://' + DUO_HOST, 'auth_type': 'duo_hmac'})], 'zz_custom'),
    ([('duo', {'url': 'https://' + DUO_HOST, 'auth_type': 'duo_hmac'}),
      ('soar', {'url': 'https://soar.corp.test', 'auth_type': 'token'})], None),
    ([('b_snow', {'url': SNOW_URL}), ('a_snow', {'url': SNOW_URL})], 'a_snow'),
    ([], None),
]


class SnowAccountSelectionTests(unittest.TestCase):

    def test_classification(self):
        for name, content, expected in CLASSIFY_VECTORS:
            self.assertEqual(SYNC.is_servicenow_account(name, content), expected, (name, content))

    def test_selection(self):
        for stanzas, expected in SELECT_VECTORS:
            picked = SYNC.select_snow_account([Stanza(n, **c) for n, c in stanzas])
            self.assertEqual(picked.name if picked else None, expected, stanzas)

    def test_duo_and_soar_sorting_first_are_ignored(self):
        stanzas = [Stanza('default', auth_type='basic'),
                   Stanza('duo', url='https://' + DUO_HOST, auth_type='duo_hmac', client_id=IKEY),
                   Stanza('soar', url='https://soar.corp.test', auth_type='basic', username='soar-bot'),
                   Stanza('asset_discovery', ai_system_table='alm_ai_system_digital_asset'),
                   Stanza('svc_splunk_integration', url=SNOW_URL, auth_type='basic', username='dana.ortiz')]
        credentials = [Credential('ta_gen_ai_cim_account__duo', 'client_secret', SKEY),
                       Credential('ta_gen_ai_cim_account__soar', 'password', 'fixture-soar-password'),
                       Credential('ta_gen_ai_cim_account__svc_splunk_integration', 'password',
                                  'fixture-snow-password')]
        config = SYNC.get_snow_config(None, service=Service(stanzas, credentials))
        self.assertTrue(config['configured'], config)
        self.assertEqual((config['url'], config['username'], config['password']),
                         (SNOW_URL, 'dana.ortiz', 'fixture-snow-password'))
        self.assertEqual(config['instance'], 'fixture-instance')
        self.assertNotIn(SKEY, json.dumps(config))
        self.assertNotIn('fixture-soar-password', json.dumps(config))

    def test_only_non_servicenow_accounts_means_not_configured(self):
        stanzas = [Stanza('duo', url='https://' + DUO_HOST, auth_type='duo_hmac', client_id=IKEY),
                   Stanza('soar', url='https://soar.corp.test', auth_type='token')]
        credentials = [Credential('ta_gen_ai_cim_account__duo', 'client_secret', SKEY)]
        config = SYNC.get_snow_config(None, service=Service(stanzas, credentials))
        self.assertFalse(config['configured'])
        self.assertIn('No ServiceNow account configured', config['error'])
        self.assertNotIn(SKEY, json.dumps(config))

    def test_duo_host_rules_agree_everywhere(self):
        patterns = {'handler': HANDLER.DUO_API_HOST_RE.pattern, 'sync_snow_asset': SYNC._DUO_API_HOST_RE.pattern}
        canonical = os.path.join(REPO, 'soar_apps', 'pseudoco_identity', 'pseudoco_identity_duo.py')
        with io.open(canonical, encoding='utf-8') as handle:
            patterns['soar canonical'] = re.search(r"API_HOST_RE = re\.compile\(r'([^']+)'\)", handle.read()).group(1)
        client = os.path.join(BIN, 'ta_gen_ai_cim_duo_api.py')
        if os.path.exists(client):
            spec = importlib.util.spec_from_file_location('duo_api_under_test', client)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            patterns['bin client'] = module.API_HOST_RE.pattern
            # The input must accept exactly what the handler stores.
            for value in ('api-fixture0.duosecurity.com', 'https://API-fixture0.duofederal.com/'):
                stored = HANDLER.normalize_duo_api_url(value)
                self.assertEqual(module.parse_api_host(stored), stored[len('https://'):])
        self.assertEqual(len(set(patterns.values())), 1, patterns)


# --------------------------------------------------------------------------
# Configuration page: the JS rules, the Duo form, the handler-only save path
# --------------------------------------------------------------------------
def read(path):
    with io.open(path, encoding='utf-8') as handle:
        return handle.read()


def function_body(source, name):
    """The source of `function <name>(...) {...}` by brace matching."""
    start = source.index('function {}('.format(name))
    depth, i = 0, source.index('{', start)
    while True:
        depth += {'{': 1, '}': -1}.get(source[i], 0)
        if depth == 0:
            return source[start:i + 1]
        i += 1


URL_VECTORS = ['api-fixture0.duosecurity.com', ' API-Fixture0.DuoSecurity.com ', 'api-fixture0.duosecurity.com/',
               'https://api-fixture0.duosecurity.com', 'HTTPS://api-fixture0.duofederal.com/', '',
               'http://api-fixture0.duosecurity.com', 'https://api-fixture0.duosecurity.com:443',
               'https://api-fixture0.duosecurity.com:', 'https://api-fixture0.duosecurity.com?',
               'https://api-fixture0.duosecurity.com/x', 'https://u@api-fixture0.duosecurity.com',
               'api-fixture0.duosecurity.com.evil.test', 'api-fixture0.duosecurity.com//', SNOW_URL]
IKEY_VECTORS = [IKEY, ' ' + IKEY + ' ', 'DI SHORT', '', 'DI' + 'X' * 70, 'di0123456789abcdef']
SKEY_VECTORS = [SKEY, ' ' + SKEY + '\n', '********', 'short', 'has spaces ' * 4, '', 'x' * 129]


class ConfigurationPageTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = read(JS_PATH)
        cls.view = read(VIEW_PATH)

    def python_results(self):
        def outcome(func, value):
            try:
                return {'value': func(value)}
            except ValueError as exc:
                return {'error': str(exc)}
        return {
            'classify': [SYNC.is_servicenow_account(n, c) for n, c, _e in CLASSIFY_VECTORS],
            'select': [getattr(SYNC.select_snow_account([Stanza(n, **c) for n, c in s]), 'name', None)
                       for s, _e in SELECT_VECTORS],
            'url': [outcome(HANDLER.normalize_duo_api_url, v) for v in URL_VECTORS],
            'ikey': [outcome(HANDLER.validate_duo_ikey, v) for v in IKEY_VECTORS],
            'skey': [outcome(HANDLER.validate_duo_skey, v) for v in SKEY_VECTORS],
        }

    def test_js_rules_match_the_python(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('node is not installed')
        block = self.js[self.js.index('// BEGIN account-rules'):self.js.index('// END account-rules')]
        script = block + '\n' + """
var V = %s;
function wrap(r) { return r.error !== undefined ? {error: r.error} : {value: r.url !== undefined ? r.url : r.value}; }
console.log(JSON.stringify({
  classify: V.classify.map(function (v) { return isServiceNowAccount(v[0], v[1]); }),
  select: V.select.map(function (s) {
    return selectServiceNowAccount(s.map(function (p) {
      var a = {name: p[0]}; for (var k in p[1]) { a[k] = p[1][k]; } return a; }));
  }),
  url: V.url.map(function (v) { return wrap(normalizeDuoApiUrl(v)); }),
  ikey: V.ikey.map(function (v) { return wrap(validateDuoIkey(v)); }),
  skey: V.skey.map(function (v) { return wrap(validateDuoSkey(v)); })
}));
""" % json.dumps({'classify': [[n, c] for n, c, _e in CLASSIFY_VECTORS],
                  'select': [s for s, _e in SELECT_VECTORS],
                  'url': URL_VECTORS, 'ikey': IKEY_VECTORS, 'skey': SKEY_VECTORS})
        work = tempfile.mkdtemp(prefix='duo-account-js-')
        try:
            path = os.path.join(work, 'rules.js')
            with io.open(path, 'w', encoding='utf-8') as handle:
                handle.write(script)
            out = subprocess.run([node, path], check=True, stdout=subprocess.PIPE, timeout=60).stdout
        finally:
            shutil.rmtree(work, ignore_errors=True)
        js_results = json.loads(out.decode('utf-8'))
        py_results = self.python_results()
        for key in py_results:
            self.assertEqual(js_results[key], py_results[key], key)
        self.assertEqual(py_results['classify'], [e for _n, _c, e in CLASSIFY_VECTORS])

    def test_js_parses(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('node is not installed')
        subprocess.run([node, '--check', JS_PATH], check=True, timeout=60)

    def test_js_sends_this_splunk_webs_csrf_token(self):
        # Cookies are scoped by host, not port: a browser that has used two
        # Splunk instances on one host holds a splunkweb_csrf_token_<port> for
        # each. Taking the first one failed CSRF validation (401), and Splunk
        # Web then reloaded the page without saving the account (found live on
        # 2026-11-16, on the first save from the Cisco Duo tab).
        getter = function_body(self.js, 'getCSRFToken')
        self.assertIn('pickCsrfToken(document.cookie', getter)
        self.assertIn('MRSPARKLE_PORT_NUMBER', getter)
        self.assertIn('window.location.port', getter)
        node = shutil.which('node')
        if not node:
            self.skipTest('node is not installed')
        vectors = [
            ['splunkweb_csrf_token_8000=other; x=1; splunkweb_csrf_token_8002=mine', ['8002'], 'mine'],
            ['splunkweb_csrf_token_8000=other; splunkweb_csrf_token_8002=mine', [None, '', 8002], 'mine'],
            ['splunkweb_csrf_token_8000=other; splunkweb_csrf_token_8002=mine', ['8443', '8000'], 'other'],
            ['splunkweb_csrf_token_8000=other; splunkweb_csrf_token_8002=mine', ['9999'], 'other'],
            ['splunkweb_csrf_token_8000=other; splunkweb_csrf_token_8002=mine', [], 'other'],
            ['splunkweb_csrf_token_8002=a%2Bb%3D', ['8002'], 'a+b='],
            ['splunkweb_csrf_token_8002; session_id_8002=s', ['8002'], ''],
            ['', ['8002'], ''],
        ]
        block = self.js[self.js.index('// BEGIN account-rules'):self.js.index('// END account-rules')]
        script = block + '\nvar V = %s;\nconsole.log(JSON.stringify(V.map(function (v) { return pickCsrfToken(v[0], v[1]); })));\n' % (
            json.dumps([[c, p] for c, p, _e in vectors]))
        work = tempfile.mkdtemp(prefix='duo-account-js-')
        try:
            path = os.path.join(work, 'csrf.js')
            with io.open(path, 'w', encoding='utf-8') as handle:
                handle.write(script)
            out = subprocess.run([node, path], check=True, stdout=subprocess.PIPE, timeout=60).stdout
        finally:
            shutil.rmtree(work, ignore_errors=True)
        self.assertEqual(json.loads(out.decode('utf-8')), [e for _c, _p, e in vectors])

    def test_duo_writes_go_only_through_the_handler(self):
        self.assertIn("'/ta_gen_ai_cim_account/ta_gen_ai_cim_account';", self.js)
        self.assertIn("var HANDLER_ENDPOINT = localePrefix + '/splunkd/__raw/servicesNS/nobody/' + APP_NAME + "
                      "'/ta_gen_ai_cim_account/ta_gen_ai_cim_account';", self.js)
        for name in ('saveDuoAccount', 'deleteDuoAccount'):
            body = function_body(self.js, name)
            self.assertIn('HANDLER_ENDPOINT', body, name)
            for forbidden in ('CONF_ENDPOINT', 'PASSWORDS_ENDPOINT', 'storage/passwords', 'storePassword'):
                self.assertNotIn(forbidden, body, name)
            self.assertNotRegex(body, r'console\.log\([^)]*\b(data|secret|skey)\b', name)
        save = function_body(self.js, 'saveDuoAccount')
        self.assertIn("auth_type: 'duo_hmac'", save)
        self.assertIn('client_secret', save)
        # The SNOW create no longer turns a 409 into an update of someone else's stanza.
        self.assertNotIn('updateAccount();\n                    } else {', function_body(self.js, 'saveAccount'))

    def test_view_carries_the_duo_form(self):
        root = ET.fromstring(self.view)                    # well-formed
        html = root.find('.//html').text
        self.assertIn('data-tab="duo">Cisco Duo (Admin API)</button>', html)
        self.assertIn('id="tab-duo"', html)
        self.assertRegex(html, r'<input type="password" id="duo-secret-key"[^>]*autocomplete="new-password"')
        for field in ('duo-account-name', 'duo-api-hostname', 'duo-integration-key'):
            self.assertRegex(html, r'<input type="text" id="%s"' % field)
        ids = set(re.findall(r'id="([^"]+)"', html))
        self.assertEqual(len(re.findall(r'id="([^"]+)"', html)), len(ids), 'duplicate ids')
        duo_js = ''.join(function_body(self.js, f) for f in
                         ('renderDuoAccountsTable', 'clearDuoForm', 'openDuoModal', 'saveDuoAccount',
                          'deleteDuoAccount', 'showDuoError', 'renderAccountsTable'))
        referenced = set(re.findall(r"\$\('#([A-Za-z0-9_-]+)'\)", duo_js))
        self.assertEqual(referenced - ids, set())

    def test_spec_documents_duo_and_keeps_secrets_out(self):
        spec = read(SPEC_PATH)
        for text in ('duo_hmac', 'https://api-<id>.duosecurity.com', 'ta_gen_ai_cim_account__<name>',
                     'Compatible with: Splunk Enterprise 9.0+, Splunk Cloud'):
            self.assertIn(text, spec)
        keys = re.findall(r'(?m)^([A-Za-z_]+)\s*=', spec)
        self.assertNotIn('client_secret', keys)
        self.assertNotIn('password', keys)
        self.assertIn('client_id', keys)


if __name__ == '__main__':
    unittest.main()
