#!/usr/bin/env python3
# encoding=utf-8
"""
show_postdeploy.py - Configure a Splunk Show / Splunk Cloud stack for the
Cisco AI Defense -> ES agentic SOC demo.

Dev-only tooling. package.sh excludes tools/, so this never ships inside the
TA tarball. Install TA-gen_ai_cim first, then run this.

Does everything the TA tarball structurally cannot:
  1. create the gen_ai_log index                 (Cloud apps cannot ship indexes.conf)
  2. create a HEC token for DemoBot              (and print it)
  3. enable the three AI Governance detections   (the primary correlation rule
                                                  ships enabled as of v1.6.2; the
                                                  other two ship disabled)
  4. seed the AI Incident Response Plan          (missioncontrol namespace)
  5. create an investigation type bound to it    (makes the plan auto-apply)
  6. create the AI findings queue                (missioncontrol namespace)
  7. turn the Triage agent on for those rules    (missioncontrol namespace)
  8. tune demo timing                            (incl. an ES-owned search)
  9. verify and report
 10. install the simulated "MedAdvice Identity     (paired SOAR, optional)
     Provider" SOAR app from tools/soar/
 11. configure its asset "medadvice_idp"           (paired SOAR, optional)
 12. list competing identity assets (read-only)    (paired SOAR, optional)
 13. smoke-test the app on a scratch container     (paired SOAR, opt-in flag)

The SOAR steps run first when SOAR credentials are supplied, so that step 4 can
translate each task's suggestions.soar_binding[] into real suggestions.actions[]
(app/asset ids are tenant-specific and resolved at run time). Without SOAR
credentials the binding is dropped and any actions/playbooks already on the live
record are preserved per task, so an action attached in the ES UI survives a
re-run.

Idempotent: re-running updates in place rather than duplicating.

Usage:
    export SPLUNK_ADMIN_PASSWORD='...'
    export SOAR_PASSWORD='...'            # or SOAR_AUTH_TOKEN
    python3 show_postdeploy.py --stack https://esp-shw-xxxx.splunkcloud.com \\
        [--acs-token <token>] [--username admin] [--keep-risk-timing] \\
        [--soar-url https://sor-xxxx.soar.splunkcloud.com] [--soar-username u] \\
        [--soar-app-tgz tools/soar/dist/medadvice_idp.tgz] [--soar-smoke-test] \\
        [--soar-only] [--dry-run]

Steps 1-2 need ACS (Splunk Cloud only). Supply --acs-token, or pass
--skip-acs and create the index and HEC token by hand. Steps 3-9 use the
splunkd REST API on :8089. Steps 10-13 use the SOAR REST API (basic auth or
ph-auth-token) and are skipped without --soar-url plus a credential;
--soar-only runs nothing else (no --stack needed).

VERIFICATION STATUS: steps 3, 4 and 8 use endpoints confirmed against a live ES
8.6 stack. Steps 5, 6 and 7 were corrected against the missioncontrol source of
truth - the Python data models and REST handlers, not collections.conf, which
only declares scalar types and omits nested objects. Steps 1 and 2 are built
from Splunk's documented ACS API and were NOT executed end-to-end. Step 7 is a
no-op without the Triage agent entitlement and now reports SKIP rather than a
misleading OK. Steps 10-13 were executed end-to-end against a SOAR Cloud 8.6.0
tenant paired with ES 8.6 (see the README changelog). The task-action record
shape written by step 4 was validated against the missioncontrol Action model.
Run with --dry-run first and read the per-step report.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import argparse
import base64
import io
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
import urllib.error


HERE = os.path.dirname(os.path.abspath(__file__))
APP_ROOT = os.path.dirname(HERE)
RESPONSE_PLAN_PATH = os.path.join(
    APP_ROOT, 'default', 'data', 'response_plans', 'ai_incident_response_plan.json')

INDEX_NAME = 'gen_ai_log'
HEC_TOKEN_NAME = 'demobot-ai-defense'
HEC_SOURCETYPE = 'gen_ai:json'
QUEUE_TITLE = 'AI Findings'
APP_NAME = 'TA-gen_ai_cim'

# LOWERCASE IS MANDATORY. missioncontrol/bin/blueridge/incident_types.py
# validate_incident_type() rejects any uppercase character: "Role API is
# case-insensitive, while the collection API is not. This causes chaos. The only
# practical solution is to only allow lowercase names." Spaces are legal (they
# are not in SPECIAL_CHARACTERS); the limit is 100 characters. This string must
# match action.notable.param.investigation_type in default/savedsearches.conf
# exactly, or the response plan will not attach to the investigation.
INVESTIGATION_TYPE = 'ai security incident'

# The demo centrepiece. Ships enabled as of TA v1.6.2 (re-POSTing disabled=0 is
# idempotent, so this step stays). Triage is enabled for this one; the other two
# are enabled here so the analyst queue has corroborating findings.
PRIMARY_DETECTION = 'AI Governance - Prompt Injection Attack Correlation - Rule'
DETECTIONS = [
    PRIMARY_DETECTION,
    'AI Governance - Prompt Injection Attempt Detected - Rule',
    'AI Governance - Prompt Injection Detected (GenAI Judge) - Rule',
]

# Demo timing. See the "Demo timing" section of the integration doc for why
# each of these matters; the suppression reset is the one that silently breaks
# repeat runs if skipped.
DEMO_TIMING = {
    'cron_schedule': '*/1 * * * *',
    'dispatch.earliest_time': '-15m',
    'dispatch.latest_time': 'now',
    'alert.suppress': '0',
}

# Owned by SA-ThreatIntelligence, not by this TA - conf layering cannot reach
# it, which is the whole reason this script exists.
RISK_RULE = 'Risk - 24 Hour Risk Threshold Exceeded - Rule'
RISK_RULE_APP = 'SA-ThreatIntelligence'
RISK_RULE_TIMING = {
    'cron_schedule': '*/1 * * * *',
    'dispatch.latest_time': 'now',
}

# The simulated identity provider SOAR app (tools/soar/). Its actions are what
# the response plan's Containment tasks bind to and what the ES Guided Response
# agent runs; every result it returns carries "simulated": true.
SOAR_APP_NAME = 'MedAdvice Identity Provider'
SOAR_ASSET_NAME = 'medadvice_idp'
SOAR_APP_TGZ = os.path.join(HERE, 'soar', 'dist', 'medadvice_idp.tgz')
SOAR_APP_MANIFEST = os.path.join(HERE, 'soar', 'medadvice_idp', 'medadvice_idp.json')
SOAR_ASSET_RECORD = {
    'name': SOAR_ASSET_NAME,
    'product_vendor': 'MedAdvice',
    'product_name': SOAR_APP_NAME,
    'description': ('Simulated MedAdvice identity provider for the GenAI workshop '
                    '(TA-gen_ai_cim tools/soar). Every action succeeds without '
                    'contacting a directory; every result carries simulated=true.'),
    'configuration': {'mode': 'simulate', 'directory_name': 'medadvice.example.com'},
    'tags': ['genai', 'workshop', 'simulated'],
}
# Step 12 lists the other identity-management assets on the tenant so the
# operator can deselect them in ES (Security AI Assistant settings -> Guided
# Response connectors). It is deliberately READ-ONLY: POST /rest/asset/<id>
# re-saves the whole asset (absent fields fall back to defaults - concurrency
# limit, boolean config such as the demo mock_app flag - and masked secrets are
# re-stored) and it ignores `disabled` entirely, so there is no safe way to
# switch an asset off over REST.
IDP_APP_TYPES = ('identity management',)
SMOKE_TEST_USER = 't.nguyen'


class Reporter(object):
    """Per-step status so a partial run is legible rather than a stack trace."""

    def __init__(self):
        self.rows = []

    def ok(self, step, detail=''):
        self.rows.append(('OK', step, detail))
        print('  [ OK ] {}{}'.format(step, ' - ' + detail if detail else ''))

    def skip(self, step, detail=''):
        self.rows.append(('SKIP', step, detail))
        print('  [SKIP] {}{}'.format(step, ' - ' + detail if detail else ''))

    def fail(self, step, detail=''):
        self.rows.append(('FAIL', step, detail))
        print('  [FAIL] {}{}'.format(step, ' - ' + detail if detail else ''))

    def summary(self):
        counts = {}
        for status, _, _ in self.rows:
            counts[status] = counts.get(status, 0) + 1
        print('\n' + '=' * 72)
        print('SUMMARY: {} ok, {} skipped, {} failed'.format(
            counts.get('OK', 0), counts.get('SKIP', 0), counts.get('FAIL', 0)))
        for status, step, detail in self.rows:
            if status != 'OK':
                print('  {}: {}{}'.format(status, step, ' - ' + detail if detail else ''))
        print('=' * 72)
        return counts.get('FAIL', 0)


def _http_request(ctx, url, method='GET', data=None, headers=None, timeout=60):
    """Shared urllib wrapper: returns (status_code, body_text); never raises."""
    headers = dict(headers or {})
    body = None
    if data is not None:
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data, doseq=True).encode('utf-8')
            headers.setdefault('Content-Type',
                               'application/x-www-form-urlencoded')
        else:
            body = data if isinstance(data, bytes) else data.encode('utf-8')
    req = urllib.request.Request(url, data=body, method=method)
    for key, value in headers.items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            raw = resp.read().decode('utf-8', 'replace')
            return resp.getcode(), raw
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode('utf-8', 'replace')
    except Exception as exc:
        return 0, str(exc)


class SoarClient(object):
    """Splunk SOAR REST client - basic auth or ph-auth-token, JSON in and out.

    TLS verification stays ON: SOAR Cloud presents a publicly rooted certificate.
    Every call returns (status_code, parsed_json_or_text).
    """

    def __init__(self, url, username=None, password=None, token=None,
                 dry_run=False):
        self.base = url.rstrip('/')
        self.username = username
        self.password = password
        self.token = token
        self.dry_run = dry_run
        self.ctx = ssl.create_default_context()

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
        return self._parse(*_http_request(self.ctx, self.base + path, 'GET',
                                          headers=self._headers(), timeout=timeout))

    def post(self, path, payload, timeout=240, quiet=False):
        if self.dry_run:
            shown = json.dumps(payload)
            if len(shown) > 300:
                shown = shown[:300] + '... ({} bytes)'.format(len(json.dumps(payload)))
            print('       DRY-RUN POST {}{}'.format(self.base, path))
            if not quiet:
                print('       DRY-RUN body: {}'.format(shown))
            return 200, {'success': True, 'id': None, 'dry_run': True}
        body = json.dumps(payload).encode('utf-8')
        return self._parse(*_http_request(self.ctx, self.base + path, 'POST', data=body,
                                          headers=self._headers(json_body=True),
                                          timeout=timeout))

    def find_one(self, resource, name):
        """First record of /rest/<resource> whose name equals `name`, else None."""
        query = urllib.parse.urlencode({'_filter_name': json.dumps(name),
                                        'page_size': 10})
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

    def wait_action_run(self, run_id, timeout=90):
        """Poll an action_run until it leaves running/pending. Returns the record."""
        deadline = time.time() + timeout
        record = {}
        while time.time() < deadline:
            code, record = self.get('/rest/action_run/{}'.format(run_id))
            if code == 200 and isinstance(record, dict) and \
                    record.get('status') not in ('running', 'pending', None, ''):
                return record
            time.sleep(3)
        return record if isinstance(record, dict) else {'status': 'timeout'}


class Client(object):
    def __init__(self, stack, username, password, acs_token=None,
                 insecure=True, dry_run=False):
        self.stack = stack.rstrip('/')
        host = urllib.parse.urlparse(self.stack).netloc or self.stack
        self.host = host.split(':')[0]
        self.mgmt = 'https://{}:8089'.format(self.host)
        self.acs = 'https://admin.splunk.com'
        # ACS addresses a stack by name, not by hostname.
        self.stack_name = self.host.split('.')[0]
        self.username = username
        self.password = password
        self.acs_token = acs_token
        self.dry_run = dry_run
        self.ctx = ssl.create_default_context()
        if insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def _request(self, url, method='GET', data=None, headers=None, timeout=60):
        return _http_request(self.ctx, url, method=method, data=data,
                             headers=headers, timeout=timeout)

    # --- splunkd REST (:8089) -------------------------------------------

    def splunkd(self, path, method='GET', data=None, timeout=60):
        url = '{}{}'.format(self.mgmt, path)
        sep = '&' if '?' in url else '?'
        url = '{}{}output_mode=json'.format(url, sep)
        cred = '{}:{}'.format(self.username, self.password).encode('utf-8')
        headers = {'Authorization': 'Basic ' + base64.b64encode(cred).decode('ascii')}
        if self.dry_run and method != 'GET':
            print('       DRY-RUN {} {}'.format(method, url))
            if data:
                print('       DRY-RUN body: {}'.format(
                    json.dumps(data)[:300] if isinstance(data, dict) else str(data)[:300]))
            return 200, '{}'
        return self._request(url, method=method, data=data, headers=headers,
                             timeout=timeout)

    # --- ACS (admin.splunk.com) -----------------------------------------

    def acs_call(self, path, method='GET', data=None, timeout=120):
        if not self.acs_token:
            return None, 'no ACS token supplied'
        url = '{}/{}/adminconfig/v2{}'.format(self.acs, self.stack_name, path)
        headers = {
            'Authorization': 'Bearer {}'.format(self.acs_token),
            'Content-Type': 'application/json',
        }
        payload = json.dumps(data).encode('utf-8') if data is not None else None
        if self.dry_run and method != 'GET':
            print('       DRY-RUN {} {}'.format(method, url))
            print('       DRY-RUN body: {}'.format(json.dumps(data)))
            return 200, '{}'
        return self._request(url, method=method, data=payload, headers=headers,
                             timeout=timeout)


# JavaScript encodeURIComponent() leaves these unescaped, and Python's quote()
# already never escapes alphanumerics or -_.~ . Adding the rest makes our output
# byte-identical to what the ES UI writes - the observed live value was
# 'Identification%20(Detection%20and%20Analysis)', with parens left literal.
_URI_COMPONENT_SAFE = "!~*'()"


def encode_plan(obj):
    """URL-encode every string in the response plan.

    Mission Control stores plan name/description and phase/task strings
    percent-encoded. The asset on disk is plain text so it stays reviewable in
    git; encoding happens here, on write. Keys are never encoded, only values,
    and bools/numbers pass through untouched so the collection's declared types
    (is_default bool, version number, phases.order number) still validate.
    """
    if isinstance(obj, dict):
        return dict((k, encode_plan(v)) for k, v in obj.items()
                    if not k.startswith('_comment'))
    if isinstance(obj, list):
        return [encode_plan(v) for v in obj]
    if isinstance(obj, str):
        return urllib.parse.quote(obj, safe=_URI_COMPONENT_SAFE)
    return obj


def decode_plan(obj):
    """Inverse of encode_plan(): percent-decode every string in a live record so
    values copied from KV back into the plain-text plan are not double-encoded
    when encode_plan() runs on the merged result."""
    if isinstance(obj, dict):
        return dict((k, decode_plan(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return [decode_plan(v) for v in obj]
    if isinstance(obj, str):
        return urllib.parse.unquote(obj)
    return obj


def kv_get(client, collection, key):
    """Read one KV record (already-decoded JSON) or None."""
    code, text = client.splunkd(kv_path(collection, key))
    if code != 200:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def kv_path(collection, key=None):
    base = '/servicesNS/nobody/missioncontrol/storage/collections/data/{}'.format(
        collection)
    return '{}/{}'.format(base, urllib.parse.quote(key, safe='')) if key else base


def kv_upsert(client, rep, collection, key, record, label):
    """Create-or-update a KV record. POST to .../<key> updates; POST to the
    collection creates. Try the update first so re-runs stay idempotent."""
    body = json.dumps(record).encode('utf-8')
    url = '{}{}?output_mode=json'.format(client.mgmt, kv_path(collection, key))
    cred = '{}:{}'.format(client.username, client.password).encode('utf-8')
    headers = {
        'Authorization': 'Basic ' + base64.b64encode(cred).decode('ascii'),
        'Content-Type': 'application/json',
    }
    if client.dry_run:
        print('       DRY-RUN POST {}'.format(url))
        rep.ok(label, 'dry-run')
        return True

    code, text = client._request(url, method='POST', data=body, headers=headers)
    if code in (200, 201):
        rep.ok(label, 'updated existing record')
        return True

    # Not present yet - create it.
    create_url = '{}{}?output_mode=json'.format(client.mgmt, kv_path(collection))
    code, text = client._request(create_url, method='POST', data=body,
                                 headers=headers)
    if code in (200, 201):
        rep.ok(label, 'created')
        return True
    rep.fail(label, 'HTTP {} {}'.format(code, text[:200]))
    return False


# --- steps ---------------------------------------------------------------

def step_index(client, rep, skip_acs):
    if skip_acs:
        rep.skip('1. index {}'.format(INDEX_NAME),
                 'ACS skipped - create the index manually')
        return
    code, text = client.acs_call('/indexes', 'GET')
    if code is None:
        rep.skip('1. index {}'.format(INDEX_NAME), text)
        return
    if code == 200 and INDEX_NAME in text:
        rep.ok('1. index {}'.format(INDEX_NAME), 'already exists')
        return
    code, text = client.acs_call('/indexes', 'POST', {
        'name': INDEX_NAME,
        'datatype': 'event',
        'searchableDays': 90,
    })
    if code in (200, 201, 202):
        rep.ok('1. index {}'.format(INDEX_NAME), 'created (may take ~minutes)')
    else:
        rep.fail('1. index {}'.format(INDEX_NAME),
                 'HTTP {} {}'.format(code, str(text)[:200]))


def step_hec(client, rep, skip_acs, out):
    if skip_acs:
        rep.skip('2. HEC token', 'ACS skipped - create the token manually')
        return
    code, text = client.acs_call('/inputs/http-event-collectors', 'GET')
    if code is None:
        rep.skip('2. HEC token', text)
        return
    if code == 200 and HEC_TOKEN_NAME in text:
        try:
            for item in json.loads(text).get('http-event-collectors', []):
                spec = item.get('spec', item)
                if spec.get('name') == HEC_TOKEN_NAME:
                    out['hec_token'] = spec.get('token')
        except Exception:
            pass
        rep.ok('2. HEC token', 'already exists ({})'.format(HEC_TOKEN_NAME))
        return
    code, text = client.acs_call('/inputs/http-event-collectors', 'POST', {
        'name': HEC_TOKEN_NAME,
        'defaultIndex': INDEX_NAME,
        'defaultSourcetype': HEC_SOURCETYPE,
        'allowedIndexes': [INDEX_NAME],
        'disabled': False,
    })
    if code in (200, 201, 202):
        try:
            out['hec_token'] = json.loads(text).get('token')
        except Exception:
            pass
        rep.ok('2. HEC token', 'created ({})'.format(HEC_TOKEN_NAME))
    else:
        rep.fail('2. HEC token', 'HTTP {} {}'.format(code, str(text)[:200]))


def step_enable_detections(client, rep):
    for name in DETECTIONS:
        path = '/servicesNS/nobody/TA-gen_ai_cim/saved/searches/{}'.format(
            urllib.parse.quote(name, safe=''))
        code, text = client.splunkd(path, 'POST', {'disabled': '0'})
        label = '3. enable "{}"'.format(name[:52])
        if code in (200, 201):
            rep.ok(label)
        elif code == 404:
            rep.fail(label, 'not found - is TA-gen_ai_cim installed?')
        else:
            rep.fail(label, 'HTTP {} {}'.format(code, text[:160]))


def _iter_tasks(plan):
    for phase in plan.get('phases') or []:
        for task in phase.get('tasks') or []:
            yield phase, task


def resolve_soar_binding(soar, binding, rep, label):
    """Turn one suggestions.soar_binding entry into a Mission Control Action
    record ({last_job_id, name, description, action, type, app_id, asset,
    parameters}) using the paired SOAR's ids. Returns None (and reports) when
    the app, asset or action is not on that tenant."""
    app = soar.find_one('app', binding.get('app_name', ''))
    if not app:
        rep.fail(label, 'SOAR app "{}" not installed'.format(binding.get('app_name')))
        return None
    asset = soar.find_one('asset', binding.get('asset_name', ''))
    if not asset or asset.get('app') != app.get('id'):
        rep.fail(label, 'SOAR asset "{}" missing or not an asset of "{}"'.format(
            binding.get('asset_name'), app.get('name')))
        return None
    actions = soar.app_actions(app['id'])
    action = actions.get(binding.get('action'))
    if not action:
        rep.fail(label, 'action "{}" not offered by "{}"'.format(
            binding.get('action'), app.get('name')))
        return None
    # last_job_id null is what the missioncontrol Action model accepts for a
    # never-run action (validated against response_template.py; a string is
    # rejected). parameters is a list of one dict, mirroring SOAR's
    # action_run targets[].parameters[].
    return {
        'last_job_id': None,
        'name': binding.get('name') or '{} ({})'.format(binding.get('action'), app['name']),
        'description': binding.get('description', ''),
        'action': binding['action'],
        'type': binding.get('type') or action.get('type') or 'generic',
        'app_id': app['id'],
        'asset': asset['id'],
        'parameters': list(binding.get('parameters') or [{}]),
    }


def bind_soar_actions(plan, soar, rep):
    """Resolve every task's suggestions.soar_binding[] into suggestions.actions[].
    The soar_binding key is always stripped - it is not a Mission Control field.
    Returns (bound, dropped)."""
    bound = dropped = 0
    for phase, task in _iter_tasks(plan):
        suggestions = task.get('suggestions')
        if not isinstance(suggestions, dict):
            continue
        bindings = suggestions.pop('soar_binding', None) or []
        for binding in bindings:
            label = '4. bind "{}" -> {}'.format(task.get('name', '?')[:40],
                                               binding.get('action'))
            if soar is None:
                dropped += 1
                continue
            record = resolve_soar_binding(soar, binding, rep, label)
            if record:
                suggestions.setdefault('actions', []).append(record)
                bound += 1
    return bound, dropped


def preserve_live_actions(plan, live):
    """Carry actions[]/playbooks[] from the live KV record into the seed for
    every task the seed leaves empty, matched on (phase name, task name). This is
    what keeps an action attached in the ES UI alive across a re-run without
    SOAR credentials. Returns the number of tasks that inherited something."""
    if not isinstance(live, dict):
        return 0
    live = decode_plan(live)
    existing = {}
    for phase, task in _iter_tasks(live):
        existing[(phase.get('name'), task.get('name'))] = task.get('suggestions') or {}
    inherited = 0
    for phase, task in _iter_tasks(plan):
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


def step_response_plan(client, rep, soar=None):
    if not os.path.exists(RESPONSE_PLAN_PATH):
        rep.fail('4. response plan', 'asset missing: {}'.format(RESPONSE_PLAN_PATH))
        return None
    with io.open(RESPONSE_PLAN_PATH, encoding='utf-8') as handle:
        plan = json.load(handle)
    plan.pop('_comment', None)

    bound, dropped = bind_soar_actions(plan, soar, rep)
    inherited = 0
    if dropped:
        # No SOAR credentials: keep whatever the live record already carries.
        inherited = preserve_live_actions(
            plan, kv_get(client, 'mc_response_templates', plan['_key']))

    now = int(time.time())
    plan.setdefault('create_time', now)
    plan['update_time'] = now

    encoded = encode_plan(plan)
    # _key must stay literal - it is the record address, not a value.
    encoded['_key'] = plan['_key']
    ok = kv_upsert(client, rep, 'mc_response_templates', plan['_key'], encoded,
                   '4. response plan "AI Incident Response Plan"')
    if ok:
        if bound:
            rep.ok('4. SOAR actions on tasks', 'bound {} action(s) from soar_binding'.format(bound))
        elif dropped:
            rep.skip('4. SOAR actions on tasks',
                     'no SOAR credentials - {} binding(s) dropped, {} task(s) kept '
                     'the actions already on the live record'.format(dropped, inherited))
    return plan.get('template_id')


def step_investigation_type(client, rep, template_id):
    """mc_incident_types keys on the type name and carries
    response_template_ids - that association is what makes the plan auto-apply
    to every new investigation of this type."""
    if not template_id:
        rep.skip('5. investigation type', 'no template_id from step 4')
        return
    record = {
        '_key': INVESTIGATION_TYPE,
        'description': 'GenAI/LLM security incidents surfaced by Cisco AI Defense.',
        # An ARRAY, not a scalar. incident_types_handler.py documents the field
        # as <array> and incident_types_cleanup.py iterates it with `in` and a
        # list comprehension - a bare string would match on substrings and be
        # rewritten into a character list on cleanup.
        'response_template_ids': [template_id],
        'create_time': int(time.time()),
        'update_time': int(time.time()),
    }
    kv_upsert(client, rep, 'mc_incident_types', INVESTIGATION_TYPE, record,
              '5. investigation type "{}"'.format(INVESTIGATION_TYPE))


def step_queue(client, rep):
    record = {
        '_key': 'ai_findings_queue',
        'id': 'ai_findings_queue',
        'title': QUEUE_TITLE,
        'description': 'Findings from Cisco AI Defense / GenAI governance detections.',
        'rule_string': 'search_name="AI Governance*"',
        'allow_override': True,
        'priority': 1,
        'create_time': int(time.time()),
        'update_time': int(time.time()),
    }
    kv_upsert(client, rep, 'queues', 'ai_findings_queue', record,
              '6. queue "{}"'.format(QUEUE_TITLE))


# --- SOAR steps (10-13) ----------------------------------------------------

def _manifest_version():
    try:
        with io.open(SOAR_APP_MANIFEST, encoding='utf-8') as handle:
            return json.load(handle).get('app_version')
    except (OSError, ValueError):
        return None


def step_soar_app(soar, rep, tgz_path):
    """Install or update the simulated IdP app from the built tarball."""
    label = '10. SOAR app "{}"'.format(SOAR_APP_NAME)
    app = soar.find_one('app', SOAR_APP_NAME)
    wanted = _manifest_version()
    if app and (not tgz_path or not wanted or app.get('app_version') == wanted):
        rep.ok(label, 'already installed (id {}, v{})'.format(
            app.get('id'), app.get('app_version')))
        return app
    if not tgz_path or not os.path.exists(tgz_path):
        rep.skip(label, 'not installed and no tarball found - run tools/soar/build.sh '
                        'or pass --soar-app-tgz')
        return app
    verb = 'updated' if app else 'installed'
    with open(tgz_path, 'rb') as handle:
        payload = {'app': base64.b64encode(handle.read()).decode('ascii')}
    code, data = soar.post('/rest/app', payload, quiet=True)
    if soar.dry_run:
        rep.ok(label, 'dry-run - would have {} from {}'.format(
            verb, os.path.basename(tgz_path)))
        return app or {'id': None, 'name': SOAR_APP_NAME, 'app_version': wanted}
    if code == 200 and isinstance(data, dict) and data.get('success'):
        app = soar.find_one('app', SOAR_APP_NAME) or {'id': data.get('id'), 'name': SOAR_APP_NAME}
        rep.ok(label, '{} (id {}, v{})'.format(verb, app.get('id'),
                                                 app.get('app_version', wanted)))
        return app
    rep.fail(label, 'HTTP {} {}'.format(code, str(data)[:200]))
    return app


def step_soar_asset(soar, rep, app):
    """Create (or re-enable) the medadvice_idp asset and test connectivity."""
    label = '11. SOAR asset "{}"'.format(SOAR_ASSET_NAME)
    if not app:
        rep.skip(label, 'app not available')
        return None
    asset = soar.find_one('asset', SOAR_ASSET_NAME)
    if asset is None:
        record = dict(SOAR_ASSET_RECORD)
        if app.get('id'):
            record['app'] = app['id']
        code, data = soar.post('/rest/asset', record)
        if soar.dry_run:
            rep.ok(label, 'dry-run - would create')
            return {'id': None, 'name': SOAR_ASSET_NAME, 'app': app.get('id')}
        if code == 200 and isinstance(data, dict) and data.get('success'):
            asset = soar.find_one('asset', SOAR_ASSET_NAME) or {'id': data.get('id'),
                                                              'name': SOAR_ASSET_NAME}
            rep.ok(label, 'created (id {})'.format(asset.get('id')))
        else:
            rep.fail(label, 'HTTP {} {}'.format(code, str(data)[:200]))
            return None
    else:
        rep.ok(label, 'exists (id {})'.format(asset.get('id')))
    return asset


def step_soar_competing_idp_assets(soar, rep):
    """READ-ONLY: list the other identity-management assets the Guided Response
    agent could pick instead of the simulator. On the ES8 demo tenant these are
    demo-mock Okta / Azure AD / AD LDAP assets that answer 'No data found' for
    the MedAdvice personas. Exclude them in ES, not here: Configure -> All
    configurations -> Security AI Assistant settings -> Guided Response
    connectors. (See IDP_APP_TYPES for why this step never writes.)"""
    label = '12. competing identity assets'
    code, apps = soar.get('/rest/app?page_size=500')
    if code != 200 or not isinstance(apps, dict):
        rep.skip(label, 'could not list apps (HTTP {})'.format(code))
        return
    idp_apps = dict((a['id'], a) for a in apps.get('data') or []
                    if a.get('type') in IDP_APP_TYPES and a.get('name') != SOAR_APP_NAME)
    code, assets = soar.get('/rest/asset?page_size=500')
    if code != 200 or not isinstance(assets, dict):
        rep.skip(label, 'could not list assets (HTTP {})'.format(code))
        return
    rows = []
    for asset in assets.get('data') or []:
        app = idp_apps.get(asset.get('app'))
        if app:
            mock = (asset.get('configuration') or {}).get('mock_app')
            rows.append('{} ({}{})'.format(asset.get('name'), app.get('name'),
                                           ', mock' if mock else ''))
    if rows:
        rep.ok(label, '{} - deselect them under ES Security AI Assistant settings '
                      '-> Guided Response connectors'.format(', '.join(rows)))
    else:
        rep.ok(label, 'none besides {}'.format(SOAR_APP_NAME))


def soar_run_action(soar, container_id, app, asset, action_name, action_type, params):
    payload = {
        'action': action_name,
        'type': action_type,
        'name': 'show_postdeploy smoke test: {}'.format(action_name),
        'container_id': container_id,
        'run_automation': False,
        'targets': [{'assets': [asset['name']], 'app_id': app['id'],
                     'parameters': [params]}],
    }
    code, data = soar.post('/rest/action_run', payload)
    if code != 200 or not isinstance(data, dict) or not data.get('success'):
        return None, 'HTTP {} {}'.format(code, str(data)[:200])
    record = soar.wait_action_run(data.get('action_run_id') or data.get('id'))
    return record, record.get('message') or record.get('status')


def step_soar_smoke_test(soar, rep, app, asset):
    """Run test connectivity, get user and disable user for t.nguyen on a scratch
    container, then close it. Proves the app answers before the workshop does."""
    label = '13. SOAR smoke test'
    if soar.dry_run:
        rep.ok(label, 'dry-run - would run test connectivity / get user / disable user '
                      'for {} on a scratch container'.format(SMOKE_TEST_USER))
        return
    if not (app and asset and asset.get('id') and app.get('id')):
        rep.skip(label, 'app/asset not available')
        return
    code, data = soar.post('/rest/container', {
        'name': 'MedAdvice IdP smoke test {}'.format(time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())),
        'label': 'events',
        'severity': 'low',
        'description': ('Scratch container created by tools/show_postdeploy.py to verify '
                        'the simulated MedAdvice identity provider. Safe to delete.'),
        'tags': ['genai', 'workshop', 'smoke-test'],
    })
    if code != 200 or not isinstance(data, dict) or not data.get('id'):
        rep.fail(label, 'could not create scratch container: HTTP {} {}'.format(
            code, str(data)[:160]))
        return
    container_id = data['id']
    actions = soar.app_actions(app['id'])
    runs = (
        ('test connectivity', {}),
        ('get user', {'username': SMOKE_TEST_USER}),
        ('disable user', {'username': SMOKE_TEST_USER,
                          'reason': 'show_postdeploy smoke test'}),
    )
    for action_name, params in runs:
        row = '13. {} {}'.format(action_name, params.get('username', '')).rstrip()
        action_type = (actions.get(action_name) or {}).get('type') or 'generic'
        record, message = soar_run_action(soar, container_id, app, asset,
                                          action_name, action_type, params)
        if record and record.get('status') == 'success':
            rep.ok(row, str(message)[:120])
        else:
            rep.fail(row, str(message)[:200])
    soar.post('/rest/container/{}'.format(container_id),
              {'status': 'closed'}, quiet=True)
    rep.ok(label, 'scratch container {} closed'.format(container_id))


TRIAGE_REQUIREMENTS = ('requires ES 8.6 Premier + Splunk Platform 10.1+ + AWS '
                       'Cloud + a paired SOAR instance')


def triage_agent_available(client):
    """Is the Triage agent actually able to run on this stack?

    ai_triage_enabled is a no-op unless allow_ai_triage is true - see
    missioncontrol/README/es_ai_settings.conf.spec ("ai_triage_enabled is only
    effective if allow_ai_triage is true"). allow_ai_triage is not admin-facing;
    it is entitlement-gated and ships false. Without this check the POSTs below
    return 200 on any stack and the step reports a green OK that means nothing.

    Returns (available, detail).
    """
    code, text = client.splunkd(
        '/servicesNS/nobody/missioncontrol/configs/conf-mc_sa_spl_context/settings',
        'GET')
    if code != 200:
        return None, 'could not read mc_sa_spl_context (HTTP {})'.format(code)
    try:
        content = json.loads(text)['entry'][0]['content']
    except (ValueError, KeyError, IndexError):
        return None, 'could not parse mc_sa_spl_context'
    raw = content.get('allow_ai_triage')
    allowed = str(raw).strip().lower() in ('1', 'true', 'yes', 'on')
    return allowed, 'allow_ai_triage = {}'.format(raw)


def step_triage_agent(client, rep):
    available, detail = triage_agent_available(client)
    if available is False:
        rep.skip('7. triage agent',
                 '{} on this stack - {}. Detections and the response plan are '
                 'still seeded; the agent lights up when the entitlement is '
                 'present.'.format(detail, TRIAGE_REQUIREMENTS))
        return
    if available is None:
        rep.skip('7. triage agent',
                 '{} - cannot confirm entitlement; {}'.format(detail, TRIAGE_REQUIREMENTS))
        return

    base = '/servicesNS/nobody/missioncontrol/configs/conf-es_ai_settings'
    code, text = client.splunkd('{}/settings'.format(base), 'POST', {
        'ai_triage_enabled': '1',
        'is_ai_assistant_active': '1',
    })
    if code in (200, 201):
        rep.ok('7. ai_triage_enabled = 1')
    else:
        rep.fail('7. ai_triage_enabled', 'HTTP {} {}'.format(code, text[:160]))

    # Value is a JSON dict of detection key -> null (JSON has no set type).
    # The KEY IS "<search name>+<app name>", not the bare search name -
    # missioncontrol/bin/blueridge/utils/triage_agent_utils.py:93 builds
    # f"{modaction.search_name}+{modaction.search_app_name}" and tests membership
    # against this list. A bare name never matches and the agent silently skips
    # every finding.
    enabled = json.dumps({'{}+{}'.format(PRIMARY_DETECTION, APP_NAME): None})
    code, text = client.splunkd('{}/ai_triage_detections'.format(base), 'POST',
                                {'enabled': enabled})
    if code in (200, 201):
        rep.ok('7. triage enabled for primary detection')
    else:
        rep.fail('7. ai_triage_detections',
                 'HTTP {} {}'.format(code, text[:160]))


def step_timing(client, rep, tune_risk_rule):
    path = '/servicesNS/nobody/TA-gen_ai_cim/saved/searches/{}'.format(
        urllib.parse.quote(PRIMARY_DETECTION, safe=''))
    code, text = client.splunkd(path, 'POST', DEMO_TIMING)
    if code in (200, 201):
        rep.ok('8. demo timing on primary detection',
               'cron */1, earliest -15m, suppression OFF')
    else:
        rep.fail('8. demo timing', 'HTTP {} {}'.format(code, text[:160]))

    if not tune_risk_rule:
        rep.skip('8. risk rule timing',
                 '--keep-risk-timing set; expect a 10+ minute lag to the Finding')
        return
    risk_path = '/servicesNS/nobody/{}/saved/searches/{}'.format(
        RISK_RULE_APP, urllib.parse.quote(RISK_RULE, safe=''))
    code, text = client.splunkd(risk_path, 'POST', RISK_RULE_TIMING)
    if code in (200, 201):
        rep.ok('8. risk rule timing', 'latest=now, cron */1 (was -10m@m, */5)')
    elif code == 404:
        rep.skip('8. risk rule timing', '{} not found'.format(RISK_RULE))
    else:
        rep.fail('8. risk rule timing', 'HTTP {} {}'.format(code, text[:160]))


def step_verify_plan_actions(client, rep):
    live = kv_get(client, 'mc_response_templates', 'ai_incident_response_plan')
    if not live:
        rep.fail('9. verify plan actions', 'live record not readable')
        return
    live = decode_plan(live)
    with_actions = [task.get('name') for _, task in _iter_tasks(live)
                    if (task.get('suggestions') or {}).get('actions')]
    if with_actions:
        rep.ok('9. verify plan actions', '{} task(s) carry SOAR actions: {}'.format(
            len(with_actions), '; '.join(with_actions)[:120]))
    else:
        rep.skip('9. verify plan actions',
                 'no task carries a SOAR action yet - supply SOAR credentials or '
                 'attach one in the ES response plan editor')


def step_verify(client, rep, out):
    step_verify_plan_actions(client, rep)
    code, text = client.splunkd(
        '/servicesNS/nobody/missioncontrol/configs/conf-es_ai_settings/settings')
    if code == 200 and '"ai_triage_enabled"' in text:
        try:
            content = json.loads(text)['entry'][0]['content']
            value = str(content.get('ai_triage_enabled'))
            if value in ('1', 'true', 'True'):
                rep.ok('9. verify ai_triage_enabled', value)
            else:
                rep.fail('9. verify ai_triage_enabled', 'is {}'.format(value))
        except Exception as exc:
            rep.fail('9. verify ai_triage_enabled', str(exc))
    else:
        rep.fail('9. verify ai_triage_enabled', 'HTTP {}'.format(code))

    path = '/servicesNS/nobody/TA-gen_ai_cim/saved/searches/{}'.format(
        urllib.parse.quote(PRIMARY_DETECTION, safe=''))
    code, text = client.splunkd(path)
    if code == 200:
        try:
            content = json.loads(text)['entry'][0]['content']
            disabled = content.get('disabled')
            suppress = str(content.get('alert.suppress'))
            cron = content.get('cron_schedule')
            if disabled in (False, 0, '0'):
                rep.ok('9. verify primary detection',
                       'enabled, cron={}, suppress={}'.format(cron, suppress))
            else:
                rep.fail('9. verify primary detection', 'still disabled')
            if suppress not in ('0', 'False', 'false'):
                rep.fail('9. verify suppression',
                         'still ON - repeat demo runs will produce nothing')
        except Exception as exc:
            rep.fail('9. verify primary detection', str(exc))
    else:
        rep.fail('9. verify primary detection', 'HTTP {}'.format(code))


def main():
    parser = argparse.ArgumentParser(
        description='Configure a Splunk Show stack for the AI Defense demo.')
    parser.add_argument('--stack',
                        help='Stack URL, e.g. https://esp-shw-xxx.splunkcloud.com '
                             '(required unless --soar-only)')
    parser.add_argument('--username', default='admin')
    parser.add_argument('--password',
                        default=os.environ.get('SPLUNK_ADMIN_PASSWORD'),
                        help='Defaults to $SPLUNK_ADMIN_PASSWORD')
    parser.add_argument('--acs-token', default=os.environ.get('SPLUNK_ACS_TOKEN'),
                        help='Defaults to $SPLUNK_ACS_TOKEN')
    parser.add_argument('--skip-acs', action='store_true',
                        help='Skip index and HEC creation (do them by hand)')
    parser.add_argument('--keep-risk-timing', action='store_true',
                        help='Leave the ES risk rule alone (keeps its 10m lag)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Print writes without making them')
    soar_group = parser.add_argument_group('paired SOAR (steps 10-13, optional)')
    soar_group.add_argument('--soar-url', default=os.environ.get('SOAR_URL'),
                            help='SOAR base URL; defaults to $SOAR_URL')
    soar_group.add_argument('--soar-username',
                            default=os.environ.get('SOAR_USERNAME', 'soar_local_admin'))
    soar_group.add_argument('--soar-password', default=os.environ.get('SOAR_PASSWORD'),
                            help='Defaults to $SOAR_PASSWORD')
    soar_group.add_argument('--soar-token', default=os.environ.get('SOAR_AUTH_TOKEN'),
                            help='ph-auth-token; defaults to $SOAR_AUTH_TOKEN')
    soar_group.add_argument('--soar-app-tgz',
                            default=SOAR_APP_TGZ if os.path.exists(SOAR_APP_TGZ) else None,
                            help='Built app package (default: tools/soar/dist/medadvice_idp.tgz '
                                 'when present; build with tools/soar/build.sh)')
    soar_group.add_argument('--soar-smoke-test', action='store_true',
                            help='Run test connectivity / get user / disable user for '
                                 '{} on a scratch container'.format(SMOKE_TEST_USER))
    soar_group.add_argument('--soar-only', action='store_true',
                            help='Run only the SOAR steps (no --stack needed)')
    soar_group.add_argument('--skip-soar', action='store_true',
                            help='Skip the SOAR steps even if credentials are set')
    args = parser.parse_args()

    soar_wanted = bool(args.soar_url) and not args.skip_soar
    soar_cred = bool(args.soar_token or args.soar_password)
    if args.soar_only and not (args.soar_url and soar_cred):
        print('ERROR: --soar-only needs --soar-url and $SOAR_PASSWORD / $SOAR_AUTH_TOKEN.',
              file=sys.stderr)
        return 2
    if not args.soar_only:
        if not args.stack:
            print('ERROR: --stack is required (or pass --soar-only).', file=sys.stderr)
            return 2
        if not args.password:
            print('ERROR: no password. Set $SPLUNK_ADMIN_PASSWORD or pass --password.',
                  file=sys.stderr)
            return 2

    rep = Reporter()
    out = {}
    print('Mode    : {}'.format('DRY RUN' if args.dry_run else 'apply'))

    # --- SOAR first, so step 4 can bind task actions to real ids -----------
    soar = None
    soar_app = soar_asset = None
    if soar_wanted and soar_cred:
        soar = SoarClient(args.soar_url, args.soar_username, args.soar_password,
                          token=args.soar_token, dry_run=args.dry_run)
        code, data = soar.get('/rest/version')
        if code != 200 or not isinstance(data, dict):
            print('ERROR: cannot reach SOAR {} (HTTP {}): {}'.format(
                soar.base, code, str(data)[:200]), file=sys.stderr)
            return 2
        print('SOAR    : {} (v{})'.format(soar.base, data.get('version')))
        print('-' * 72)
        soar_app = step_soar_app(soar, rep, args.soar_app_tgz)
        soar_asset = step_soar_asset(soar, rep, soar_app)
        step_soar_competing_idp_assets(soar, rep)
        if args.soar_smoke_test:
            step_soar_smoke_test(soar, rep, soar_app, soar_asset)
        else:
            rep.skip('13. SOAR smoke test', 'pass --soar-smoke-test to run it')
    elif soar_wanted:
        print('WARNING: --soar-url given without $SOAR_PASSWORD / $SOAR_AUTH_TOKEN - '
              'SOAR steps skipped.', file=sys.stderr)
        rep.skip('10-13. SOAR steps', 'no SOAR credential')
    else:
        rep.skip('10-13. SOAR steps', 'no --soar-url; response plan keeps the actions '
                                      'already on the live record')

    if args.soar_only:
        failures = rep.summary()
        return 1 if failures else 0

    skip_acs = args.skip_acs or not args.acs_token
    client = Client(args.stack, args.username, args.password,
                    acs_token=args.acs_token, dry_run=args.dry_run)

    print('Stack   : {}'.format(client.host))
    print('Mgmt    : {}'.format(client.mgmt))
    print('ACS     : {}'.format('skipped' if skip_acs else client.stack_name))
    print('-' * 72)

    code, text = client.splunkd('/services/server/info')
    if code != 200:
        print('ERROR: cannot reach {} (HTTP {}): {}'.format(
            client.mgmt, code, text[:200]), file=sys.stderr)
        return 2
    try:
        version = json.loads(text)['entry'][0]['content'].get('version')
        print('Connected to Splunk {}\n'.format(version))
    except Exception:
        print('Connected.\n')

    step_index(client, rep, skip_acs)
    step_hec(client, rep, skip_acs, out)
    step_enable_detections(client, rep)
    template_id = step_response_plan(client, rep, soar)
    step_investigation_type(client, rep, template_id)
    step_queue(client, rep)
    step_triage_agent(client, rep)
    step_timing(client, rep, not args.keep_risk_timing)
    step_verify(client, rep, out)

    failures = rep.summary()

    if out.get('hec_token'):
        print('\nPoint DemoBot at:')
        print('  URL   : https://http-inputs-{}.splunkcloud.com/services/collector/event'
              .format(client.stack_name))
        print('  Token : {}'.format(out['hec_token']))
        print('  Index : {}   Sourcetype: {}'.format(INDEX_NAME, HEC_SOURCETYPE))
        print('\n  Use /services/collector/event with an explicit "time" - NOT /raw.')
    elif not skip_acs:
        print('\nNo HEC token returned; create one manually and point DemoBot at it.')

    print('\nDemo loop: spray -> detection fires within 60s -> Finding -> '
          'triage dispatch polls every 30s.\nExpect roughly 60-90 seconds '
          'end to end, not 30.')

    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
