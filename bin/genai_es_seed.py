# encoding=utf-8
"""
genai_es_seed.py - shared core for seeding Splunk Enterprise Security (Mission
Control) with everything TA-gen_ai_cim cannot ship as conf, and for binding the
response plan's Containment tasks to the simulated identity-provider app on
the paired Splunk SOAR.

Used by two callers with different transports:

  * bin/genaiseedes.py  - the `| genaiseedes` custom command, run by the
    shipped, enabled, run_on_startup search "GenAI - ES - Seed Response Plan and
    SOAR Binding". splunkd is reached with the search's session key; SOAR is
    reached through Mission Control's own pairing proxy
    (/servicesNS/nobody/missioncontrol/v1/soar/...), so no SOAR credential is
    stored in this TA. An optional SOAR account (ta_gen_ai_cim_account.conf
    stanza `soar`) additionally allows installing the simulator app itself,
    which the proxy has no route for.
  * tools/show_postdeploy.py - dev-only Splunk Show post-deploy, which talks to
    splunkd with basic auth and to SOAR directly with a password or token.

Everything written is a TA-owned record: the response plan
(`mc_response_templates` _key ai_incident_response_plan), the investigation type
(`mc_incident_types` _key "ai security incident"), the findings queue (`queues`
_key ai_findings_queue) and, on SOAR, the asset `medadvice_idp` of the
"MedAdvice Identity Provider" app. Writes are idempotent (update-then-create),
and the plan write is merge-preserving: any actions[]/playbooks[] a task already
carries on the live record survive a re-run unless a soar_binding replaces them.

No event data is read. Nothing here logs prompt or response content.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import base64
import io
import json
import os
import ssl
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

APP_NAME = 'TA-gen_ai_cim'
INVESTIGATION_TYPE = 'ai security incident'          # lowercase is mandatory
QUEUE_TITLE = 'AI Findings'
PRIMARY_DETECTION = 'AI Governance - Prompt Injection Attack Correlation - Rule'
SOAR_APP_NAME = 'MedAdvice Identity Provider'
SOAR_ASSET_NAME = 'medadvice_idp'
SOAR_ASSET_RECORD = {
    'name': SOAR_ASSET_NAME,
    'product_vendor': 'MedAdvice',
    'product_name': SOAR_APP_NAME,
    'description': ('Simulated MedAdvice identity provider for the GenAI workshop '
                    '(TA-gen_ai_cim). Every action succeeds without contacting a '
                    'directory; every result carries simulated=true.'),
    'configuration': {'mode': 'simulate', 'directory_name': 'medadvice.example.com'},
    'tags': ['genai', 'workshop', 'simulated'],
}
IDP_APP_TYPES = ('identity management',)
MC_NS = '/servicesNS/nobody/missioncontrol'

_HERE = os.path.dirname(os.path.abspath(__file__))
APP_ROOT = os.path.dirname(_HERE)
RESPONSE_PLAN_PATH = os.path.join(APP_ROOT, 'default', 'data', 'response_plans',
                                  'ai_incident_response_plan.json')
# Top level, deliberately outside default/, so the folder can be lifted out of
# a checkout and uploaded to SOAR on its own. It still ships inside the TA
# tarball, which is what lets build_soar_app_tgz() package it in memory when
# install_simulator is on.
SOAR_APP_SRC = os.path.join(APP_ROOT, 'soar_apps', 'medadvice_idp')

# JavaScript encodeURIComponent() leaves these unescaped; Python's quote() never
# escapes alphanumerics or -_.~ . Together they make the output byte-identical
# to what the ES UI writes (observed: 'Identification%20(Detection%20and%20Analysis)').
_URI_COMPONENT_SAFE = "!~*'()"


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

class Reporter(object):
    """Per-step status rows: ('OK'|'SKIP'|'FAIL', step, detail)."""

    def __init__(self, echo=None):
        self.rows = []
        self.echo = echo

    def _add(self, status, step, detail):
        self.rows.append((status, step, detail))
        if self.echo:
            self.echo('  [{:>4}] {}{}'.format(status, step, ' - ' + detail if detail else ''))

    def ok(self, step, detail=''):
        self._add('OK', step, detail)

    def skip(self, step, detail=''):
        self._add('SKIP', step, detail)

    def fail(self, step, detail=''):
        self._add('FAIL', step, detail)

    def failures(self):
        return sum(1 for status, _, _ in self.rows if status == 'FAIL')


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def http_request(ctx, url, method='GET', data=None, headers=None, timeout=60):
    """urllib wrapper: returns (status_code, body_text); never raises."""
    headers = dict(headers or {})
    body = None
    if data is not None:
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data, doseq=True).encode('utf-8')
            headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        else:
            body = data if isinstance(data, bytes) else data.encode('utf-8')
    req = urllib.request.Request(url, data=body, method=method)
    for key, value in headers.items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode('utf-8', 'replace')
    except Exception as exc:  # network / TLS
        return 0, str(exc)


def _ssl_context(verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class Splunkd(object):
    """splunkd REST on :8089 with either a session key or basic auth.

    call() returns (code, text); every URL gets output_mode=json. dry_run turns
    non-GET calls into printed no-ops that return (200, '{}').
    """

    def __init__(self, mgmt_uri, session_key=None, username=None, password=None,
                 verify=False, dry_run=False, echo=None):
        self.mgmt = mgmt_uri.rstrip('/')
        self.session_key = session_key
        self.username = username
        self.password = password
        self.dry_run = dry_run
        self.echo = echo
        self.ctx = _ssl_context(verify)

    def _headers(self, json_body=False):
        if self.session_key:
            headers = {'Authorization': 'Splunk {}'.format(self.session_key)}
        else:
            cred = '{}:{}'.format(self.username, self.password).encode('utf-8')
            headers = {'Authorization': 'Basic ' + base64.b64encode(cred).decode('ascii')}
        if json_body:
            headers['Content-Type'] = 'application/json'
        return headers

    def call(self, path, method='GET', data=None, json_body=None, timeout=60):
        url = '{}{}'.format(self.mgmt, path)
        url = '{}{}output_mode=json'.format(url, '&' if '?' in url else '?')
        if self.dry_run and method != 'GET':
            if self.echo:
                shown = json.dumps(json_body if json_body is not None else data)[:300]
                self.echo('       DRY-RUN {} {}\n       DRY-RUN body: {}'.format(method, url, shown))
            return 200, '{}'
        if json_body is not None:
            return http_request(self.ctx, url, method, data=json.dumps(json_body).encode('utf-8'),
                                headers=self._headers(json_body=True), timeout=timeout)
        return http_request(self.ctx, url, method, data=data, headers=self._headers(),
                            timeout=timeout)

    def get_json(self, path, timeout=60):
        code, text = self.call(path, timeout=timeout)
        if code != 200:
            return code, None
        try:
            return code, json.loads(text)
        except ValueError:
            return code, None


# ---------------------------------------------------------------------------
# SOAR transports
# ---------------------------------------------------------------------------

class SoarViaEsProxy(object):
    """SOAR through Mission Control's pairing proxy - no SOAR credential needed.

    Routes used (missioncontrol/bin/soar.py): GET app, GET app/:id, GET asset,
    POST asset, GET app_action is NOT proxied (resolved via app/:id's action
    list instead), POST action_run. There is no app-install route, so
    install_app() returns None and the caller reports that the app must be
    installed on SOAR by other means (the `soar` account, the SOAR UI, or
    tools/show_postdeploy.py).
    """

    name = 'ES pairing proxy'
    can_install = False

    def __init__(self, splunkd):
        self.splunkd = splunkd
        self.dry_run = splunkd.dry_run
        self._paired = None

    def _get(self, route, params=None):
        query = '?' + urllib.parse.urlencode(params) if params else ''
        code, text = self.splunkd.call('{}/v1/soar/{}{}'.format(MC_NS, route.lstrip('/'), query),
                                       timeout=90)
        try:
            data = json.loads(text) if text else None
        except ValueError:
            data = text
        return code, data

    def paired(self):
        if self._paired is None:
            code, data = self._get('version')
            self._paired = code == 200 and isinstance(data, dict) and bool(data.get('version'))
            self.version = data.get('version') if self._paired else None
        return self._paired

    @staticmethod
    def _rows(data):
        if isinstance(data, dict):
            if isinstance(data.get('data'), list):
                return data['data']
            if isinstance(data.get('payload'), dict) and isinstance(data['payload'].get('data'), list):
                return data['payload']['data']
        return []

    def find_one(self, resource, name):
        code, data = self._get(resource, {'_filter_name': json.dumps(name), 'page_size': 10})
        for item in self._rows(data):
            if item.get('name') == name:
                return item
        return None

    def app_actions(self, app_id):
        code, data = self._get('app/{}'.format(app_id))
        if code != 200 or not isinstance(data, dict):
            return {}
        record = data.get('payload', data)
        actions = {}
        for item in record.get('_pretty_actions') or []:
            actions[item.get('name')] = {'action': item.get('name'), 'type': item.get('type', 'generic')}
        return actions

    def create_asset(self, record, app):
        payload = dict(record)
        if app.get('id'):
            payload['app'] = app['id']
        code, text = self.splunkd.call('{}/v1/soar/asset'.format(MC_NS), 'POST', json_body=payload,
                                       timeout=120)
        if self.dry_run:
            return {'id': None, 'name': record['name'], 'app': app.get('id')}, None
        try:
            data = json.loads(text)
        except ValueError:
            data = {}
        if code == 200 and isinstance(data, dict) and (data.get('success') or data.get('id')):
            return self.find_one('asset', record['name']) or {'id': data.get('id'),
                                                              'name': record['name']}, None
        return None, 'HTTP {} {}'.format(code, str(text)[:200])

    def install_app(self, tgz_bytes):
        return None

    def list_all(self, resource):
        code, data = self._get(resource, {'page_size': 500})
        return self._rows(data) if code == 200 else None


class SoarDirect(object):
    """SOAR over its own REST API - basic auth or ph-auth-token. TLS verified."""

    name = 'SOAR REST'
    can_install = True

    def __init__(self, url, username=None, password=None, token=None,
                 dry_run=False, echo=None, verify=True):
        self.base = url.rstrip('/')
        self.username = username
        self.password = password
        self.token = token
        self.dry_run = dry_run
        self.echo = echo
        self.ctx = _ssl_context(verify)
        self.version = None

    def _headers(self, json_body=False):
        headers = {'Accept': 'application/json'}
        if self.token:
            headers['ph-auth-token'] = self.token
        else:
            cred = '{}:{}'.format(self.username, self.password).encode('utf-8')
            headers['Authorization'] = 'Basic ' + base64.b64encode(cred).decode('ascii')
        if json_body:
            headers['Content-Type'] = 'application/json'
        return headers

    @staticmethod
    def _parse(code, text):
        try:
            return code, json.loads(text)
        except ValueError:
            return code, text

    def get(self, path, timeout=90):
        return self._parse(*http_request(self.ctx, self.base + path, 'GET',
                                         headers=self._headers(), timeout=timeout))

    def post(self, path, payload, timeout=240, quiet=False):
        if self.dry_run:
            if self.echo:
                shown = json.dumps(payload)
                if len(shown) > 300:
                    shown = shown[:300] + '... ({} bytes)'.format(len(json.dumps(payload)))
                self.echo('       DRY-RUN POST {}{}'.format(self.base, path))
                if not quiet:
                    self.echo('       DRY-RUN body: {}'.format(shown))
            return 200, {'success': True, 'id': None, 'dry_run': True}
        body = json.dumps(payload).encode('utf-8')
        return self._parse(*http_request(self.ctx, self.base + path, 'POST', data=body,
                                         headers=self._headers(json_body=True), timeout=timeout))

    def paired(self):
        code, data = self.get('/rest/version')
        ok = code == 200 and isinstance(data, dict)
        self.version = data.get('version') if ok else None
        return ok

    def find_one(self, resource, name):
        query = urllib.parse.urlencode({'_filter_name': json.dumps(name), 'page_size': 10})
        code, data = self.get('/rest/{}?{}'.format(resource, query))
        if code != 200 or not isinstance(data, dict):
            return None
        for item in data.get('data') or []:
            if item.get('name') == name:
                return item
        return None

    def app_actions(self, app_id):
        query = urllib.parse.urlencode({'_filter_app': app_id, 'page_size': 200})
        code, data = self.get('/rest/app_action?{}'.format(query))
        if code != 200 or not isinstance(data, dict):
            return {}
        return dict((item.get('action'), item) for item in data.get('data') or [])

    def create_asset(self, record, app):
        payload = dict(record)
        if app.get('id'):
            payload['app'] = app['id']
        code, data = self.post('/rest/asset', payload)
        if self.dry_run:
            return {'id': None, 'name': record['name'], 'app': app.get('id')}, None
        if code == 200 and isinstance(data, dict) and data.get('success'):
            return self.find_one('asset', record['name']) or {'id': data.get('id'),
                                                              'name': record['name']}, None
        return None, 'HTTP {} {}'.format(code, str(data)[:200])

    def list_all(self, resource):
        code, data = self.get('/rest/{}?page_size=500'.format(resource))
        if code != 200 or not isinstance(data, dict):
            return None
        return data.get('data') or []

    def install_app(self, tgz_bytes):
        payload = {'app': base64.b64encode(tgz_bytes).decode('ascii')}
        code, data = self.post('/rest/app', payload, quiet=True)
        if code == 200 and isinstance(data, dict) and data.get('success'):
            return data
        return {'failed': True, 'message': 'HTTP {} {}'.format(code, str(data)[:200])}

    def wait_action_run(self, run_id, timeout=90):
        deadline = time.time() + timeout
        record = {}
        while time.time() < deadline:
            code, record = self.get('/rest/action_run/{}'.format(run_id))
            if code == 200 and isinstance(record, dict) and \
                    record.get('status') not in ('running', 'pending', None, ''):
                return record
            time.sleep(3)
        return record if isinstance(record, dict) else {'status': 'timeout'}


# ---------------------------------------------------------------------------
# SOAR app package
# ---------------------------------------------------------------------------

def build_soar_app_tgz(src_dir=SOAR_APP_SRC):
    """Package the shipped simulator source into the tarball SOAR's
    POST /rest/app accepts (top-level directory = the app directory)."""
    buf = io.BytesIO()
    top = os.path.basename(src_dir.rstrip('/'))
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        # The top-level directory member is added explicitly. tools/soar/build.sh
        # produces one via tar(1), and that archive shape is the one verified to
        # install on SOAR Cloud 8.6 - so the in-product installer must not
        # produce a subtly different archive (tests assert the two match).
        tar.add(src_dir, arcname=top, recursive=False)
        for root, dirs, files in os.walk(src_dir):
            dirs[:] = sorted(d for d in dirs if d != '__pycache__')
            for name in sorted(files):
                if name.endswith(('.pyc', '.DS_Store')):
                    continue
                full = os.path.join(root, name)
                arcname = os.path.join(top, os.path.relpath(full, src_dir))
                tar.add(full, arcname=arcname, recursive=False)
    return buf.getvalue()


def soar_app_manifest_version(src_dir=SOAR_APP_SRC):
    try:
        with io.open(os.path.join(src_dir, os.path.basename(src_dir) + '.json'),
                     encoding='utf-8') as handle:
            return json.load(handle).get('app_version')
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Plan encoding + KV helpers
# ---------------------------------------------------------------------------

def encode_plan(obj):
    """URL-encode every string value (never keys); drop _comment* keys."""
    if isinstance(obj, dict):
        return dict((k, encode_plan(v)) for k, v in obj.items() if not k.startswith('_comment'))
    if isinstance(obj, list):
        return [encode_plan(v) for v in obj]
    if isinstance(obj, str):
        return urllib.parse.quote(obj, safe=_URI_COMPONENT_SAFE)
    return obj


def decode_plan(obj):
    """Inverse of encode_plan() for values read back from KV."""
    if isinstance(obj, dict):
        return dict((k, decode_plan(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return [decode_plan(v) for v in obj]
    if isinstance(obj, str):
        return urllib.parse.unquote(obj)
    return obj


def kv_path(collection, key=None):
    base = '{}/storage/collections/data/{}'.format(MC_NS, collection)
    return '{}/{}'.format(base, urllib.parse.quote(key, safe='')) if key else base


def kv_get(splunkd, collection, key):
    code, data = splunkd.get_json(kv_path(collection, key))
    return data if code == 200 and isinstance(data, dict) else None


def kv_upsert(splunkd, rep, collection, key, record, label):
    """Update-then-create so re-runs stay idempotent."""
    if splunkd.dry_run:
        splunkd.call(kv_path(collection, key), 'POST', json_body=record)
        rep.ok(label, 'dry-run')
        return True
    code, text = splunkd.call(kv_path(collection, key), 'POST', json_body=record)
    if code in (200, 201):
        rep.ok(label, 'updated existing record')
        return True
    code, text = splunkd.call(kv_path(collection), 'POST', json_body=record)
    if code in (200, 201):
        rep.ok(label, 'created')
        return True
    rep.fail(label, 'HTTP {} {}'.format(code, text[:200]))
    return False


# ---------------------------------------------------------------------------
# Response plan: binding + merge-preserve
# ---------------------------------------------------------------------------

def iter_tasks(plan):
    for phase in plan.get('phases') or []:
        for task in phase.get('tasks') or []:
            yield phase, task


def resolve_soar_binding(soar, binding, rep, label):
    """One suggestions.soar_binding entry -> Mission Control Action record, or
    None (reported) when the app, asset or action is not on that tenant."""
    app = soar.find_one('app', binding.get('app_name', ''))
    if not app:
        rep.fail(label, 'SOAR app "{}" not installed'.format(binding.get('app_name')))
        return None
    asset = soar.find_one('asset', binding.get('asset_name', ''))
    if not asset or (asset.get('app') not in (None, app.get('id'))):
        rep.fail(label, 'SOAR asset "{}" missing or not an asset of "{}"'.format(
            binding.get('asset_name'), app.get('name')))
        return None
    actions = soar.app_actions(app['id']) if app.get('id') is not None else {}
    action = actions.get(binding.get('action'))
    if actions and not action:
        rep.fail(label, 'action "{}" not offered by "{}"'.format(
            binding.get('action'), app.get('name')))
        return None
    # last_job_id null is what the missioncontrol Action model accepts for a
    # never-run action (a string is rejected). parameters mirrors SOAR's
    # action_run targets[].parameters[]: a list of one dict.
    return {
        'last_job_id': None,
        'name': binding.get('name') or '{} ({})'.format(binding.get('action'), app['name']),
        'description': binding.get('description', ''),
        'action': binding['action'],
        'type': binding.get('type') or (action or {}).get('type') or 'generic',
        'app_id': app['id'],
        'asset': asset['id'],
        'parameters': list(binding.get('parameters') or [{}]),
    }


def bind_soar_actions(plan, soar, rep):
    """Resolve suggestions.soar_binding[] into suggestions.actions[]; always
    strip soar_binding (it is not a Mission Control field). Returns
    (bound, dropped)."""
    bound = dropped = 0
    for phase, task in iter_tasks(plan):
        suggestions = task.get('suggestions')
        if not isinstance(suggestions, dict):
            continue
        bindings = suggestions.pop('soar_binding', None) or []
        for binding in bindings:
            label = 'bind "{}" -> {}'.format(task.get('name', '?')[:40], binding.get('action'))
            if soar is None:
                dropped += 1
                continue
            record = resolve_soar_binding(soar, binding, rep, label)
            if record:
                suggestions.setdefault('actions', []).append(record)
                bound += 1
            else:
                dropped += 1
    return bound, dropped


def preserve_live_actions(plan, live):
    """Carry actions[]/playbooks[] from the live record into every seed task
    that has none, matched on (phase name, task name). Keeps a UI-attached
    action alive across re-runs. Returns the number of tasks that inherited."""
    if not isinstance(live, dict):
        return 0
    live = decode_plan(live)
    existing = {}
    for phase, task in iter_tasks(live):
        existing[(phase.get('name'), task.get('name'))] = task.get('suggestions') or {}
    inherited = 0
    for phase, task in iter_tasks(plan):
        old = existing.get((phase.get('name'), task.get('name')))
        if not old:
            continue
        suggestions = task.setdefault('suggestions',
                                      {'searches': [], 'actions': [], 'playbooks': []})
        took = False
        for key in ('actions', 'playbooks'):
            if not suggestions.get(key) and old.get(key):
                suggestions[key] = old[key]
                took = True
        inherited += 1 if took else 0
    return inherited


def load_plan(path=RESPONSE_PLAN_PATH):
    with io.open(path, encoding='utf-8') as handle:
        plan = json.load(handle)
    plan.pop('_comment', None)
    return plan


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def step_response_plan(splunkd, rep, soar=None, plan_path=RESPONSE_PLAN_PATH,
                       label='response plan'):
    """Upsert the plan into mc_response_templates with SOAR bindings resolved
    (when a SOAR transport is given) or preserved from the live record."""
    if not os.path.exists(plan_path):
        rep.fail(label, 'asset missing: {}'.format(plan_path))
        return None
    plan = load_plan(plan_path)
    live = kv_get(splunkd, 'mc_response_templates', plan['_key'])
    bound, dropped = bind_soar_actions(plan, soar, rep)
    inherited = preserve_live_actions(plan, live) if dropped else 0

    now = int(time.time())
    if isinstance(live, dict) and live.get('create_time'):
        plan['create_time'] = live['create_time']
    plan.setdefault('create_time', now)
    plan['update_time'] = now

    encoded = encode_plan(plan)
    encoded['_key'] = plan['_key']          # the record address is never encoded
    ok = kv_upsert(splunkd, rep, 'mc_response_templates', plan['_key'], encoded,
                   '{} "{}"'.format(label, plan.get('name')))
    if ok:
        if bound:
            rep.ok('{} SOAR actions'.format(label), 'bound {} action(s) from soar_binding'.format(bound))
        elif dropped:
            rep.skip('{} SOAR actions'.format(label),
                     '{} binding(s) not resolved; {} task(s) kept the actions already on '
                     'the live record'.format(dropped, inherited))
    return plan.get('template_id')


def step_investigation_type(splunkd, rep, template_id, label='investigation type'):
    if not template_id:
        rep.skip(label, 'no template_id from the response plan step')
        return
    live = kv_get(splunkd, 'mc_incident_types', INVESTIGATION_TYPE) or {}
    ids = list(live.get('response_template_ids') or [])
    if template_id not in ids:
        ids.insert(0, template_id)      # first listed = default plan for the type
    record = {
        '_key': INVESTIGATION_TYPE,
        'description': live.get('description') or
        'GenAI/LLM security incidents surfaced by Cisco AI Defense.',
        'response_template_ids': ids,   # an ARRAY - incident_types_cleanup.py iterates it
        'create_time': live.get('create_time') or int(time.time()),
        'update_time': int(time.time()),
    }
    kv_upsert(splunkd, rep, 'mc_incident_types', INVESTIGATION_TYPE, record,
              '{} "{}"'.format(label, INVESTIGATION_TYPE))


def step_queue(splunkd, rep, label='queue'):
    live = kv_get(splunkd, 'queues', 'ai_findings_queue') or {}
    record = {
        '_key': 'ai_findings_queue',
        'id': 'ai_findings_queue',
        'title': QUEUE_TITLE,
        'description': 'Findings from Cisco AI Defense / GenAI governance detections.',
        'rule_string': 'search_name="AI Governance*"',
        'allow_override': True,
        'priority': 1,
        'create_time': live.get('create_time') or int(time.time()),
        'update_time': int(time.time()),
    }
    kv_upsert(splunkd, rep, 'queues', 'ai_findings_queue', record,
              '{} "{}"'.format(label, QUEUE_TITLE))


def step_soar_simulator(soar, rep, install=False, tgz_bytes=None, label='SOAR simulator'):
    """Ensure the simulator app (optionally installing it) and its asset exist.
    Returns (app, asset); either may be None."""
    if soar is None:
        rep.skip(label, 'no SOAR transport')
        return None, None
    if not soar.paired():
        rep.skip(label, 'SOAR not reachable/paired via {}'.format(soar.name))
        return None, None
    app = soar.find_one('app', SOAR_APP_NAME)
    wanted = soar_app_manifest_version()
    if app and (not install or not wanted or app.get('app_version') == wanted):
        rep.ok('{} app'.format(label), 'installed (id {}, v{})'.format(
            app.get('id'), app.get('app_version')))
    elif install and soar.can_install:
        tgz_bytes = tgz_bytes or build_soar_app_tgz()
        result = soar.install_app(tgz_bytes)
        if soar.dry_run:
            rep.ok('{} app'.format(label), 'dry-run - would {} v{}'.format(
                'update' if app else 'install', wanted))
            app = app or {'id': None, 'name': SOAR_APP_NAME, 'app_version': wanted}
        elif result and not result.get('failed'):
            app = soar.find_one('app', SOAR_APP_NAME) or {'id': result.get('id'), 'name': SOAR_APP_NAME}
            rep.ok('{} app'.format(label), '{} (id {}, v{})'.format(
                'updated' if app.get('app_version') == wanted and result.get('id') and wanted else 'installed',
                app.get('id'), app.get('app_version', wanted)))
        else:
            rep.fail('{} app'.format(label), (result or {}).get('message', 'install failed'))
            return app, None
    elif install:
        rep.skip('{} app'.format(label),
                 'not installed; {} cannot install apps - configure the `soar` account '
                 'in ta_gen_ai_cim_account.conf, upload soar_apps/medadvice_idp.tgz '
                 'in the SOAR UI, or run tools/show_postdeploy.py'.format(soar.name))
        return None, None
    else:
        rep.skip('{} app'.format(label),
                 'not installed on the paired SOAR (install_soar_simulator is off)')
        return None, None

    asset = soar.find_one('asset', SOAR_ASSET_NAME)
    if asset:
        rep.ok('{} asset'.format(label), 'exists (id {})'.format(asset.get('id')))
    else:
        asset, error = soar.create_asset(SOAR_ASSET_RECORD, app)
        if asset:
            rep.ok('{} asset'.format(label), 'created (id {})'.format(asset.get('id')))
        else:
            rep.fail('{} asset'.format(label), error or 'create failed')
    return app, asset


def step_competing_idp_assets(soar, rep, label='competing identity assets'):
    """READ-ONLY list of other identity-management assets the Guided Response
    agent could pick; exclude them in ES (Security AI Assistant settings ->
    Guided Response connectors), never by editing the assets: POST
    /rest/asset/<id> re-saves the whole asset and ignores `disabled`."""
    if soar is None or not soar.paired():
        rep.skip(label, 'no SOAR')
        return []
    lister = getattr(soar, 'list_all', None)
    app_rows = lister('app') if lister else None
    asset_rows = lister('asset') if lister else None
    if not app_rows or asset_rows is None:
        rep.skip(label, 'could not list apps/assets')
        return []
    idp_apps = dict((a['id'], a) for a in app_rows
                    if a.get('type') in IDP_APP_TYPES and a.get('name') != SOAR_APP_NAME)
    rows = []
    for asset in asset_rows:
        app = idp_apps.get(asset.get('app'))
        if app:
            mock = (asset.get('configuration') or {}).get('mock_app')
            rows.append('{} ({}{})'.format(asset.get('name'), app.get('name'), ', mock' if mock else ''))
    if rows:
        rep.ok(label, '{} - deselect them under ES Security AI Assistant settings -> '
                      'Guided Response connectors'.format(', '.join(rows)))
    else:
        rep.ok(label, 'none besides {}'.format(SOAR_APP_NAME))
    return rows


def triage_agent_available(splunkd):
    """(available, detail): ai_triage_enabled is a no-op unless the
    entitlement flag allow_ai_triage (mc_sa_spl_context) is true."""
    code, data = splunkd.get_json('{}/configs/conf-mc_sa_spl_context/settings'.format(MC_NS))
    if code != 200 or not data:
        return None, 'could not read mc_sa_spl_context (HTTP {})'.format(code)
    try:
        raw = data['entry'][0]['content'].get('allow_ai_triage')
    except (KeyError, IndexError, TypeError):
        return None, 'could not parse mc_sa_spl_context'
    return str(raw).strip().lower() in ('1', 'true', 'yes', 'on'), 'allow_ai_triage = {}'.format(raw)


def step_triage_agent(splunkd, rep, label='triage agent'):
    available, detail = triage_agent_available(splunkd)
    if not available:
        rep.skip(label, '{} - needs ES 8.6 Premier + Platform 10.1+ + AWS Cloud + '
                        'paired SOAR'.format(detail))
        return
    base = '{}/configs/conf-es_ai_settings'.format(MC_NS)
    code, text = splunkd.call('{}/settings'.format(base), 'POST',
                              {'ai_triage_enabled': '1', 'is_ai_assistant_active': '1'})
    if code in (200, 201):
        rep.ok('{} ai_triage_enabled'.format(label), '1')
    else:
        rep.fail('{} ai_triage_enabled'.format(label), 'HTTP {} {}'.format(code, text[:160]))
    # Key format is "<search name>+<app name>" (triage_agent_utils.py:93).
    enabled = json.dumps({'{}+{}'.format(PRIMARY_DETECTION, APP_NAME): None})
    code, text = splunkd.call('{}/ai_triage_detections'.format(base), 'POST', {'enabled': enabled})
    if code in (200, 201):
        rep.ok('{} detection allowlist'.format(label), PRIMARY_DETECTION)
    else:
        rep.fail('{} detection allowlist'.format(label), 'HTTP {} {}'.format(code, text[:160]))


def step_verify_plan_actions(splunkd, rep, label='verify plan actions'):
    live = kv_get(splunkd, 'mc_response_templates', 'ai_incident_response_plan')
    if not live:
        rep.fail(label, 'live record not readable')
        return []
    live = decode_plan(live)
    names = [task.get('name') for _, task in iter_tasks(live)
             if (task.get('suggestions') or {}).get('actions')]
    if names:
        rep.ok(label, '{} task(s) carry SOAR actions: {}'.format(len(names), '; '.join(names)[:120]))
    else:
        rep.skip(label, 'no task carries a SOAR action yet')
    return names


def seed(splunkd, rep, soar=None, install_simulator=False, enable_triage=False,
         plan_path=RESPONSE_PLAN_PATH):
    """The whole in-product sequence, in dependency order. Returns template_id."""
    app = asset = None
    if soar is not None:
        app, asset = step_soar_simulator(soar, rep, install=install_simulator)
        step_competing_idp_assets(soar, rep)
    binder = soar if (app and asset) else None
    template_id = step_response_plan(splunkd, rep, binder, plan_path)
    step_investigation_type(splunkd, rep, template_id)
    step_queue(splunkd, rep)
    if enable_triage:
        step_triage_agent(splunkd, rep)
    else:
        rep.skip('triage agent', 'enable_triage_agent is off')
    step_verify_plan_actions(splunkd, rep)
    return template_id
