# encoding=utf-8
"""
fake_splunk_rest.py - a loopback HTTP stand-in for one Splunk Cloud stack: the
splunkd REST endpoints and the ACS index endpoints that
tools/show_postdeploy.py --duo / --duo-teardown use. Dev only.

What makes a careless client fail a test:
  * the account endpoint IS the shipped handler
    (bin/ta_gen_ai_cim_account_handler.py, loaded the way test_duo_account.py
    loads it), so a wrong argument, a bad key or a duplicate create is refused
    exactly as on a stack, and the secret key lands in the handler's own
    storage/passwords emulation;
  * a new input is checked by the input's own parse_params (interval floor,
    never gen_ai_log), as validate_input does;
  * ACS lists only 30 indexes (as ACS does by default) and index duo is never
    among them, creation is asynchronous (404 until `acs_ready_after` reads),
    and creating an index that exists answers 409; a missing index answers 404
    with ACS's own code 404-index-not-found, a delete is asynchronous too when
    `acs_delete_removes` is off (accepted, and the index stays listed);
  * the KV store collection of the input checkpoints takes a new document (the
    pending-delete marker) and answers 409 for a key that exists; the roles can
    be listed; `serve(tls=(cert, key))` serves the same stack over TLS;
  * storage/passwords answers a GET with the clear password, as splunkd does;
    `echo_secret=True` makes a failed account write echo its whole request
    body, and every request is recorded with its raw body and headers;
  * the saved searches are the SHIPPED stanzas (default/savedsearches.conf):
    search text, cron, dispatch times and realtime_schedule of the lookup
    search and of every rule the tool knows, so a check of a rule's schedule
    is a check of what ships, never of a value invented here;
  * a one-shot search is answered only for the texts the tool is meant to
    send, each recorded with its time range: the two tstats counts, a rule's
    own search text followed by "| stats count by <id>" (answered from
    `judged`), and the risk-index search for a rule (answered from `raised`).

All data is invented: persona-style names, RFC 5737 addresses, no real tenant.
"""

import base64
import http.server
import json
import os
import re
import sys
import threading
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
for _path in (os.path.join(REPO, 'bin'), os.path.join(REPO, 'tools'), os.path.join(REPO, 'tools', 'tests')):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import ta_gen_ai_cim_duo_input as duo_input  # noqa: E402
import test_duo_account as acct  # noqa: E402  (the handler under its fake splunk modules)
from test_lab5_conf import read_conf  # noqa: E402

APP = 'TA-gen_ai_cim'
STACK = 'fixture-stack'
ADMIN_USER, ADMIN_PASSWORD = 'admin', 'fixture-admin-password'
ACS_TOKEN = 'fixture-acs-token'
DUO_RULE = 'AI Governance - Duo Authentication Fraud or Denial Burst - Rule'
CHAIN_RULE = 'AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule'
LOOKUP_GEN = 'GenAI - Identity - Duo Identity Lookup Gen'
SAVED = (LOOKUP_GEN, DUO_RULE, CHAIN_RULE)
AUTH_ST, USER_ST = 'ta_gen_ai_cim:duo:authentication', 'ta_gen_ai_cim:duo:user'
# What splunkd answers as JSON booleans, whatever the conf file spells.
BOOLEAN_KEYS = ('disabled', 'realtime_schedule', 'is_scheduled')


def one_line(spl):
    return ' '.join(str(spl).split())


def shipped_saved_searches(names=SAVED):
    """{name: content} of the shipped stanzas, as splunkd would answer for a
    freshly installed TA: the search text, the schedule and the dispatch times
    are read from default/savedsearches.conf, never typed here."""
    conf, saved = read_conf('savedsearches.conf'), {}
    for name in names:
        stanza = conf[name]
        content = dict((key, value) for key, value in stanza.items()
                       if key in ('search', 'cron_schedule', 'realtime_schedule', 'allow_skew')
                       or key.startswith('dispatch.'))
        content['disabled'] = stanza.get('disabled') == '1'
        content['is_scheduled'] = stanza.get('enableSched') == '1'
        content['realtime_schedule'] = stanza.get('realtime_schedule', '1') == '1'
        saved[name] = content
    return saved


class Reply(Exception):
    def __init__(self, status, body):
        Exception.__init__(self, status)
        self.status, self.body = status, body


def entry(name, content):
    return {'entry': [{'name': name, 'content': content}]}


class FakeStack(object):

    def __init__(self):
        self.apps = {APP: '1.9.0', 'Splunk_SA_CIM': '8.5.0'}
        self.schemes = {'ta_gen_ai_cim_duo'}
        self.indexes = {'risk', 'notable'}         # what splunkd knows (an ES stack)
        self.acs_indexes = {}                      # name -> {'searchableDays': n}
        self.acs_pending = {}                      # name -> reads left before it exists
        self.acs_ready_after = 2
        self.acs_new = {}
        self.acs_delete_removes = True
        self.acs_event_count = None                # None: what `events` adds up to
        self.account_store = acct.FakeSplunkd()    # conf + storage/passwords, used by the real handler
        self.inputs = {}
        self.saved = shipped_saved_searches()      # the shipped stanzas, all disabled
        self.roles = {'splunker': {'srchIndexesAllowed': ['main', 'gen_ai_log'], 'srchIndexesDefault': ['main'],
                                   'imported_srchIndexesAllowed': []}}
        self.macros = {('Splunk_SA_CIM', 'cim_Authentication_indexes'): '()'}
        self.conf_inputs = {}
        self.kv = {}                               # collection -> {key: doc}
        self.lookup_files = set()
        self.events = {}                           # sourcetype -> count, in index duo
        self.datamodel_events = None               # None: the authentication count
        self.judged = {}                           # rule -> ids its own search yields in one pass
        self.raised = {}                           # rule -> ids on its risk events (None: an event with no id)
        self.searches = []                         # every one-shot search: search, earliest, latest, app
        self.echo_secret = False
        self.fail = {}                             # (method, path suffix) -> (status, text)
        self.requests = []                         # dicts: service, method, path, query, form, raw, headers

    # -- convenience for tests ------------------------------------------------
    def writes(self):
        """Every request that changes state (a one-shot search is a read)."""
        return [(r['method'], r['path']) for r in self.requests
                if r['method'] != 'GET' and not r['path'].endswith('/search/jobs')]

    def secret(self, account='duo'):
        return self.account_store.passwords.get(('ta_gen_ai_cim_account__' + account, 'client_secret'))

    def state(self):
        return json.dumps({'indexes': sorted(self.indexes), 'acs': self.acs_indexes, 'pending': self.acs_pending,
                           'conf': self.account_store.conf,
                           'pw': sorted(map(str, self.account_store.passwords.items())),
                           'inputs': self.inputs, 'saved': self.saved, 'roles': self.roles, 'kv': self.kv,
                           'files': sorted(self.lookup_files)}, sort_keys=True)

    def add_index(self, days=90):
        self.acs_indexes['duo'] = {'searchableDays': days}
        self.indexes.add('duo')

    # -- account endpoint: the shipped handler --------------------------------
    def _account(self, method, name, form):
        action = {'GET': 'list', 'DELETE': 'remove'}.get(method) or ('edit' if name else 'create')
        if action == 'create':
            form = dict(form)
            name = form.pop('name', None)
        constant, func = acct.ACTIONS[action]
        acct.HANDLER.rest.simpleRequest = self.account_store.request
        handler = acct.HANDLER.AccountHandler()
        handler.requestedAction = getattr(acct.ADMIN, constant)
        handler.callerArgs.id = name
        handler.callerArgs.data = dict((k, [v]) for k, v in form.items())
        handler.setup()
        admin = acct.ADMIN
        try:
            if action in ('create', 'edit'):
                declared = set(handler.supportedArgs.required + handler.supportedArgs.optional)
                extra = sorted(set(form) - declared)
                if extra:
                    raise admin.ArgValidationException(
                        'Argument "{}" is not supported by this handler.'.format(extra[0]))
                missing = sorted(set(handler.supportedArgs.required) - set(form))
                if missing:
                    raise admin.ArgValidationException('The following required arguments are missing: {}.'.format(
                        ', '.join(missing)))
            info = acct.ConfInfo()
            getattr(handler, func)(info)
        except admin.ArgValidationException as exc:
            raise Reply(400, {'messages': [{'type': 'ERROR', 'text': str(exc)}]})
        except admin.AlreadyExistsException as exc:
            raise Reply(409, {'messages': [{'type': 'ERROR', 'text': str(exc)}]})
        except admin.NotFoundException as exc:
            raise Reply(404, {'messages': [{'type': 'ERROR', 'text': str(exc)}]})
        except admin.AdminManagerException as exc:
            raise Reply(500, {'messages': [{'type': 'ERROR', 'text': str(exc)}]})
        return {'entry': [{'name': key, 'content': dict(value)} for key, value in info.items()]}

    # -- splunkd --------------------------------------------------------------
    def splunkd(self, method, app, rel, form, raw):
        parts = [urllib.parse.unquote(p) for p in rel.split('/')]
        head = '/'.join(parts[:2])
        if head == 'server/info':
            return entry('server-info', {'version': '10.4.3'})
        if head == 'apps/local':
            if parts[2] not in self.apps:
                raise Reply(404, {})
            return entry(parts[2], {'version': self.apps[parts[2]]})
        if head == 'data/modular-inputs':
            if parts[2] not in self.schemes:
                raise Reply(404, {})
            return entry(parts[2], {})
        if head == 'data/indexes':
            if parts[2] not in self.indexes:
                raise Reply(404, {})
            return entry(parts[2], {})
        if head == 'ta_gen_ai_cim_account/ta_gen_ai_cim_account':
            if method == 'POST' and self.echo_secret:
                raise Reply(500, {'messages': [{'type': 'ERROR', 'text': 'In handler: ' + raw}]})
            return self._account(method, parts[2] if len(parts) > 2 else None, form)
        if head == 'storage/passwords':
            realm, name, _ = parts[2].split(':')
            store = self.account_store.passwords
            if (realm, name) not in store:
                raise Reply(404, {})
            clear = store[(realm, name)]
            if method == 'DELETE':
                del store[(realm, name)]
            return entry(parts[2], {'clear_password': clear})
        if head == 'authorization/roles':
            if len(parts) == 2:
                return {'entry': [{'name': name, 'content': dict(role)} for name, role in sorted(self.roles.items())]}
            role = self.roles.get(parts[2])
            if role is None:
                raise Reply(404, {})
            if method == 'POST':
                for key in ('srchIndexesAllowed', 'srchIndexesDefault'):
                    if key in form:
                        value = form[key] if isinstance(form[key], list) else [form[key]]
                        role[key] = [v for v in value if v != '']
            return entry(parts[2], dict(role))
        if head == 'configs/conf-macros':
            if (app, parts[2]) not in self.macros:
                raise Reply(404, {})
            return entry(parts[2], {'definition': self.macros[(app, parts[2])]})
        if head == 'configs/conf-inputs':
            if parts[2] not in self.conf_inputs:
                raise Reply(404, {})
            return entry(parts[2], self.conf_inputs[parts[2]])
        if head == 'saved/searches':
            search = self.saved.get(parts[2])
            if search is None:
                raise Reply(404, {})
            if method == 'POST':
                unknown = sorted(set(form) - {'disabled'})
                if unknown:
                    raise Reply(400, {'messages': [{'type': 'ERROR', 'text': 'this fake edits only disabled'}]})
                if 'disabled' in form:
                    search['disabled'] = form['disabled'] in ('1', 'true')
            return entry(parts[2], dict(search))
        if head == 'data/inputs' and parts[2] == 'ta_gen_ai_cim_duo':
            return self._inputs(method, parts[3:], form)
        if head == 'storage/collections' and parts[2] == 'data':
            docs = self.kv.get(parts[3], {})
            if len(parts) < 5:
                # A new document, as JSON with its own _key (the pending-delete marker).
                if method != 'POST' or not isinstance(form, dict) or not form.get('_key'):
                    raise Reply(400, {'messages': [{'type': 'ERROR', 'text': 'this fake only inserts a keyed '
                                                                             'document into a collection'}]})
                if form['_key'] in docs:
                    raise Reply(409, {'messages': [{'type': 'ERROR', 'text': 'A document with the same key '
                                                                             'already exists.'}]})
                self.kv.setdefault(parts[3], docs)[form['_key']] = dict(form)
                return {'_key': form['_key']}
            if parts[4] not in docs:
                raise Reply(404, {})
            if method == 'DELETE':
                del docs[parts[4]]
                return {}
            return docs[parts[4]]
        if head == 'data/lookup-table-files':
            if parts[2] not in self.lookup_files:
                raise Reply(404, {})
            if method == 'DELETE':
                self.lookup_files.discard(parts[2])
            return entry(parts[2], {})
        if head == 'search/jobs' and method == 'POST':
            return self._search(form, app)
        raise Reply(404, {'messages': [{'type': 'ERROR', 'text': 'fake has no ' + rel}]})

    def _inputs(self, method, rest, form):
        if not rest:
            if method == 'GET':
                return {'entry': [{'name': n, 'content': dict(c)} for n, c in sorted(self.inputs.items())]}
            name = form.get('name')
            if not name or name in self.inputs:
                raise Reply(409 if name else 400, {'messages': [{'type': 'ERROR', 'text': 'exists or unnamed'}]})
            fields = dict((k, v) for k, v in form.items() if k != 'name')
            try:
                duo_input.parse_params(fields, check_interval=True)      # as validate_input does
            except ValueError as exc:
                raise Reply(400, {'messages': [{'type': 'ERROR', 'text': str(exc)}]})
            self.inputs[name] = dict({'lag_seconds': '180', 'disabled': False}, **fields)
            return entry(name, dict(self.inputs[name]))
        name = rest[0]
        if name not in self.inputs:
            raise Reply(404, {})
        if len(rest) > 1:
            self.inputs[name]['disabled'] = rest[1] == 'disable'
        elif method == 'DELETE':
            del self.inputs[name]
            return {'entry': []}
        elif method == 'POST':
            try:       # the strict reading: validate_input sees only what the edit posted
                duo_input.parse_params(form, check_interval=True)
            except ValueError as exc:
                raise Reply(400, {'messages': [{'type': 'ERROR', 'text': str(exc)}]})
            self.inputs[name] = dict(self.inputs[name], **form)
        return entry(name, dict(self.inputs[name]))

    def _search(self, form, app=None):
        spl = form.get('search', '')
        self.searches.append({'search': spl, 'earliest': form.get('earliest_time'),
                              'latest': form.get('latest_time'), 'app': app})
        if form.get('exec_mode') != 'oneshot' or form.get('count') != '0':
            raise Reply(400, {'messages': [{'type': 'ERROR', 'text': 'fake runs one-shot searches only'}]})
        # The rule's own search, dispatched ad hoc: its text exactly, then the id count.
        for name in (DUO_RULE, CHAIN_RULE):
            own = 'search ' + self.saved[name]['search'].strip()       # character for character
            m = re.match(r'^ \| stats count by (\w+)$', spl[len(own):]) if spl.startswith(own) else None
            if m:
                if app != APP:
                    raise Reply(400, {'messages': [{'type': 'FATAL', 'text': 'The search specifies a macro '
                                                    'that cannot be found (not run in the app).'}]})
                return {'results': [{m.group(1): ident, 'count': '1'} for ident in self.judged.get(name, [])]}
        m = re.match(r'^search index=risk search_name="([^"]+)" \| eval (\w+)=coalesce\(\2, "([^"]*)"\) '
                     r'\| stats count by \2$', spl)
        if m:
            if 'risk' not in self.indexes:
                return {'results': []}
            rows = {}
            for ident in self.raised.get(m.group(1), []):
                key = m.group(3) if ident is None else ident
                rows[key] = rows.get(key, 0) + 1
            return {'results': [{m.group(2): key, 'count': str(n)} for key, n in sorted(rows.items())]}
        if not spl.startswith('| tstats') or 'index=duo' not in spl:
            raise Reply(400, {'messages': [{'type': 'ERROR', 'text': 'unexpected search'}]})
        if 'from datamodel=Authentication.Authentication' in spl:
            if ('Splunk_SA_CIM', 'cim_Authentication_indexes') not in self.macros:
                raise Reply(400, {'messages': [{'type': 'FATAL', 'text': 'Data model Authentication not found'}]})
            count = self.events.get(AUTH_ST, 0) if self.datamodel_events is None else self.datamodel_events
            return {'results': [{'count': str(count)}]}
        if 'by sourcetype' in spl:
            return {'results': [{'sourcetype': st, 'count': str(n)} for st, n in sorted(self.events.items()) if n]}
        raise Reply(400, {'messages': [{'type': 'ERROR', 'text': 'unexpected search'}]})

    # -- ACS ------------------------------------------------------------------
    def acs(self, method, rel, body):
        if rel == 'indexes':
            if method == 'GET':        # the first 30 of an ES stack; never the one a client is after
                return 200, [{'name': 'es_index_%02d' % i, 'datatype': 'event', 'searchableDays': 90}
                             for i in range(30)]
            name = body.get('name')
            if name in self.acs_indexes or name in self.acs_pending:
                return 409, {'code': '409-object-already-exists', 'message': name}
            self.acs_pending[name] = self.acs_ready_after
            self.acs_new = {'searchableDays': body.get('searchableDays', 90)}
            return 202, dict(body)
        name = urllib.parse.unquote(rel.split('/', 1)[1])
        if method == 'GET':
            if name in self.acs_pending:
                self.acs_pending[name] -= 1
                if self.acs_pending[name] <= 0:
                    del self.acs_pending[name]
                    self.acs_indexes[name] = dict(self.acs_new)
                    self.indexes.add(name)
            if name not in self.acs_indexes:
                return 404, {'code': '404-index-not-found', 'message': name + ' index not found'}
            total = sum(self.events.values()) if self.acs_event_count is None else self.acs_event_count
            return 200, dict(self.acs_indexes[name], name=name, datatype='event', totalEventCount=str(total))
        if method == 'DELETE':
            if name not in self.acs_indexes:
                return 404, {'code': '404-index-not-found', 'message': name + ' index not found'}
            if self.acs_delete_removes:
                del self.acs_indexes[name]
                self.indexes.discard(name)
                self.events = {}
            return 202, {}
        return 405, {}

    # -- HTTP -----------------------------------------------------------------
    def serve(self, tls=None):
        """Start serving on a loopback port. tls=(certificate file, key file)
        serves it over TLS; ssl.SSLError (an OSError) is raised from here where
        this Python cannot wrap a listening socket."""
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):

            def _run(self, method):
                parts = urllib.parse.urlsplit(self.path)
                raw = self.rfile.read(int(self.headers.get('Content-Length') or 0)).decode('utf-8')
                headers = dict(self.headers.items())
                record = {'method': method, 'path': parts.path, 'query': parts.query, 'raw': raw,
                          'headers': headers, 'form': {}}
                fake.requests.append(record)
                for (m, suffix), reply in fake.fail.items():
                    if m == method and parts.path.endswith(suffix):
                        return self._send(reply[0], reply[1])
                try:
                    if parts.path.startswith('/{}/adminconfig/v2/'.format(STACK)):
                        record['service'] = 'acs'
                        if headers.get('Authorization') != 'Bearer ' + ACS_TOKEN:
                            return self._send(401, {'code': '401-unauthorized'})
                        body = json.loads(raw) if raw else {}
                        record['form'] = body
                        status, reply = fake.acs(method, parts.path.split('/adminconfig/v2/', 1)[1], body)
                        return self._send(status, reply)
                    record['service'] = 'splunkd'
                    wanted = 'Basic ' + base64.b64encode('{}:{}'.format(ADMIN_USER, ADMIN_PASSWORD).encode()).decode()
                    if headers.get('Authorization') != wanted:
                        return self._send(401, {'messages': [{'type': 'ERROR', 'text': 'Unauthorized'}]})
                    if 'output_mode=json' not in parts.query:
                        return self._send(400, {'messages': [{'type': 'ERROR', 'text': 'output_mode=json expected'}]})
                    if headers.get('Content-Type', '').startswith('application/json'):
                        form = json.loads(raw) if raw else {}
                    else:
                        form = dict((k, v[0] if len(v) == 1 else v)
                                    for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items())
                    record['form'] = form
                    segs = parts.path.split('/')
                    if segs[1] == 'servicesNS':
                        app, rel = segs[3], '/'.join(segs[4:])
                    elif segs[1] == 'services':
                        app, rel = None, '/'.join(segs[2:])
                    else:
                        raise Reply(404, {})
                    return self._send(201 if (method == 'POST' and rel.count('/') == 1 and 'name' in form) else 200,
                                      fake.splunkd(method, app, rel, form, raw))
                except Reply as reply:
                    return self._send(reply.status, reply.body)

            def _send(self, status, body):
                data = (body if isinstance(body, str) else json.dumps(body)).encode('utf-8')
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._run('GET')

            def do_POST(self):
                self._run('POST')

            def do_DELETE(self):
                self._run('DELETE')

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        if tls:
            import ssl
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*tls)
            try:
                server.socket = context.wrap_socket(server.socket, server_side=True)
            except Exception:
                server.server_close()
                raise
        threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True).start()
        return server
