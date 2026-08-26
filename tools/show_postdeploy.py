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

Idempotent: re-running updates in place rather than duplicating.

Usage:
    export SPLUNK_ADMIN_PASSWORD='...'
    python3 show_postdeploy.py --stack https://esp-shw-xxxx.splunkcloud.com \\
        [--acs-token <token>] [--username admin] [--skip-timing] [--dry-run]

Steps 1-2 need ACS (Splunk Cloud only). Supply --acs-token, or pass
--skip-acs and create the index and HEC token by hand. Steps 3-9 use the
splunkd REST API on :8089.

VERIFICATION STATUS: steps 3, 4 and 8 use endpoints confirmed against a live ES
8.6 stack. Steps 5, 6 and 7 were corrected against the missioncontrol source of
truth - the Python data models and REST handlers, not collections.conf, which
only declares scalar types and omits nested objects. Steps 1 and 2 are built
from Splunk's documented ACS API and were NOT executed end-to-end. Step 7 is a
no-op without the Triage agent entitlement and now reports SKIP rather than a
misleading OK. Run with --dry-run first and read the per-step report.

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
            with urllib.request.urlopen(req, context=self.ctx, timeout=timeout) as resp:
                raw = resp.read().decode('utf-8', 'replace')
                return resp.getcode(), raw
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode('utf-8', 'replace')
        except Exception as exc:
            return 0, str(exc)

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


def step_response_plan(client, rep):
    if not os.path.exists(RESPONSE_PLAN_PATH):
        rep.fail('4. response plan', 'asset missing: {}'.format(RESPONSE_PLAN_PATH))
        return None
    with io.open(RESPONSE_PLAN_PATH, encoding='utf-8') as handle:
        plan = json.load(handle)
    plan.pop('_comment', None)

    now = int(time.time())
    plan.setdefault('create_time', now)
    plan['update_time'] = now

    encoded = encode_plan(plan)
    # _key must stay literal - it is the record address, not a value.
    encoded['_key'] = plan['_key']
    kv_upsert(client, rep, 'mc_response_templates', plan['_key'], encoded,
              '4. response plan "AI Incident Response Plan"')
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


def step_verify(client, rep, out):
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
    parser.add_argument('--stack', required=True,
                        help='Stack URL, e.g. https://esp-shw-xxx.splunkcloud.com')
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
    args = parser.parse_args()

    if not args.password:
        print('ERROR: no password. Set $SPLUNK_ADMIN_PASSWORD or pass --password.',
              file=sys.stderr)
        return 2

    skip_acs = args.skip_acs or not args.acs_token

    client = Client(args.stack, args.username, args.password,
                    acs_token=args.acs_token, dry_run=args.dry_run)
    rep = Reporter()
    out = {}

    print('Stack   : {}'.format(client.host))
    print('Mgmt    : {}'.format(client.mgmt))
    print('ACS     : {}'.format('skipped' if skip_acs else client.stack_name))
    print('Mode    : {}'.format('DRY RUN' if args.dry_run else 'apply'))
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
    template_id = step_response_plan(client, rep)
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
