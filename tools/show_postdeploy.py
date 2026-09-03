#!/usr/bin/env python3
# encoding=utf-8
"""
show_postdeploy.py - Configure a Splunk Show / Splunk Cloud stack for the
Cisco AI Defense -> ES agentic SOC demo.

Dev-only tooling. package.sh excludes tools/, so this never ships inside the
TA tarball. Install TA-gen_ai_cim first, then run this.

The TA seeds Mission Control on its own: the shipped search "GenAI - ES - Seed
Response Plan and SOAR Binding" runs `| genaiseedes` hourly and on startup.
This script exists for the demo-specific extras and for doing the same seeding
immediately, from the outside, with explicit credentials:

  1. create the gen_ai_log index                 (Cloud apps cannot ship indexes.conf)
  2. create a HEC token for DemoBot              (and print it)
  3. enable the three AI Governance detections   (the primary correlation rule
                                                  ships enabled as of v1.6.2; the
                                                  other two ship disabled)
  4. seed the AI Incident Response Plan          (missioncontrol namespace; SOAR
                                                  task actions bound when SOAR
                                                  credentials are given)
  5. create an investigation type bound to it    (makes the plan auto-apply)
  6. create the AI findings queue                (missioncontrol namespace)
  7. turn the Triage agent on for those rules    (missioncontrol namespace)
  8. tune demo timing                            (incl. an ES-owned search)
  9. verify and report
 10. install the simulated "MedAdvice Identity     (paired SOAR, needs SOAR creds)
     Provider" SOAR app from soar_apps
 11. configure its asset "medadvice_idp"           (paired SOAR)
 12. list competing identity assets (read-only)    (paired SOAR)
 13. smoke-test the app on a scratch container     (paired SOAR, opt-in flag)

Steps 4-7 and 10-12 are the same code the TA runs in-product
(bin/genai_es_seed.py); this script only supplies the transports. SOAR steps run
first so that step 4 can translate each task's suggestions.soar_binding[] into
real suggestions.actions[] (app/asset ids are tenant-specific). Without SOAR
credentials the binding is dropped and any actions/playbooks already on the live
record are preserved per task.

Idempotent: re-running updates in place rather than duplicating.

Usage:
    export SPLUNK_ADMIN_PASSWORD='...'
    export SOAR_PASSWORD='...'            # or SOAR_AUTH_TOKEN
    python3 show_postdeploy.py --stack https://esp-shw-xxxx.splunkcloud.com \\
        [--acs-token <token>] [--username admin] [--keep-risk-timing] \\
        [--soar-url https://sor-xxxx.soar.splunkcloud.com] [--soar-username u] \\
        [--soar-app-tgz soar_apps/medadvice_idp.tgz] [--soar-smoke-test] \\
        [--soar-only] [--skip-triage] [--dry-run]

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
no-op without the Triage agent entitlement and reports SKIP rather than a
misleading OK. Steps 10-13 were executed end-to-end against a SOAR Cloud 8.6.0
tenant paired with ES 8.6 (2026-09-03). The task-action record shape written by
step 4 was validated against the missioncontrol Action model. Run with
--dry-run first and read the per-step report.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import argparse
import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
APP_ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(APP_ROOT, 'bin'))

import genai_es_seed as seed  # noqa: E402  (shared with the | genaiseedes command)

INDEX_NAME = 'gen_ai_log'
HEC_TOKEN_NAME = 'demobot-ai-defense'
HEC_SOURCETYPE = 'gen_ai:json'
APP_NAME = seed.APP_NAME
PRIMARY_DETECTION = seed.PRIMARY_DETECTION
DETECTIONS = [
    PRIMARY_DETECTION,
    'AI Governance - Prompt Injection Attempt Detected - Rule',
    'AI Governance - Prompt Injection Detected (GenAI Judge) - Rule',
]
# The committed, ready-to-upload package. Optional: the seeding core packages
# soar_apps/medadvice_idp/ in memory when this file is absent.
SOAR_APP_TGZ = os.path.join(APP_ROOT, 'soar_apps', 'medadvice_idp.tgz')
SMOKE_TEST_USER = 't.nguyen'

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


def summary(rep):
    counts = {}
    for status, _, _ in rep.rows:
        counts[status] = counts.get(status, 0) + 1
    print('\n' + '=' * 72)
    print('SUMMARY: {} ok, {} skipped, {} failed'.format(
        counts.get('OK', 0), counts.get('SKIP', 0), counts.get('FAIL', 0)))
    for status, step, detail in rep.rows:
        if status != 'OK':
            print('  {}: {}{}'.format(status, step, ' - ' + detail if detail else ''))
    print('=' * 72)
    return counts.get('FAIL', 0)


class AcsClient(object):
    """Admin Config Service - addresses a stack by name, Bearer token."""

    def __init__(self, stack_name, token, dry_run=False):
        self.stack_name = stack_name
        self.token = token
        self.dry_run = dry_run
        self.base = 'https://admin.splunk.com'
        self.ctx = seed._ssl_context(True)

    def call(self, path, method='GET', data=None, timeout=120):
        if not self.token:
            return None, 'no ACS token supplied'
        url = '{}/{}/adminconfig/v2{}'.format(self.base, self.stack_name, path)
        headers = {'Authorization': 'Bearer {}'.format(self.token),
                   'Content-Type': 'application/json'}
        payload = json.dumps(data).encode('utf-8') if data is not None else None
        if self.dry_run and method != 'GET':
            print('       DRY-RUN {} {}'.format(method, url))
            print('       DRY-RUN body: {}'.format(json.dumps(data)))
            return 200, '{}'
        return seed.http_request(self.ctx, url, method=method, data=payload,
                                 headers=headers, timeout=timeout)


# --- Splunk-only steps -------------------------------------------------------

def step_index(acs, rep, skip_acs):
    label = '1. index {}'.format(INDEX_NAME)
    if skip_acs:
        rep.skip(label, 'ACS skipped - create the index manually')
        return
    code, text = acs.call('/indexes', 'GET')
    if code is None:
        rep.skip(label, text)
        return
    if code == 200 and INDEX_NAME in text:
        rep.ok(label, 'already exists')
        return
    code, text = acs.call('/indexes', 'POST', {
        'name': INDEX_NAME, 'datatype': 'event', 'searchableDays': 90})
    if code in (200, 201, 202):
        rep.ok(label, 'created (may take ~minutes)')
    else:
        rep.fail(label, 'HTTP {} {}'.format(code, str(text)[:200]))


def step_hec(acs, rep, skip_acs, out):
    label = '2. HEC token'
    if skip_acs:
        rep.skip(label, 'ACS skipped - create the token manually')
        return
    code, text = acs.call('/inputs/http-event-collectors', 'GET')
    if code is None:
        rep.skip(label, text)
        return
    if code == 200 and HEC_TOKEN_NAME in text:
        try:
            for item in json.loads(text).get('http-event-collectors', []):
                spec = item.get('spec', item)
                if spec.get('name') == HEC_TOKEN_NAME:
                    out['hec_token'] = spec.get('token')
        except Exception:
            pass
        rep.ok(label, 'already exists ({})'.format(HEC_TOKEN_NAME))
        return
    code, text = acs.call('/inputs/http-event-collectors', 'POST', {
        'name': HEC_TOKEN_NAME, 'defaultIndex': INDEX_NAME,
        'defaultSourcetype': HEC_SOURCETYPE, 'allowedIndexes': [INDEX_NAME],
        'disabled': False})
    if code in (200, 201, 202):
        try:
            out['hec_token'] = json.loads(text).get('token')
        except Exception:
            pass
        rep.ok(label, 'created ({})'.format(HEC_TOKEN_NAME))
    else:
        rep.fail(label, 'HTTP {} {}'.format(code, str(text)[:200]))


def saved_search_path(app, name):
    return '/servicesNS/nobody/{}/saved/searches/{}'.format(app, urllib.parse.quote(name, safe=''))


def step_enable_detections(splunkd, rep):
    for name in DETECTIONS:
        code, text = splunkd.call(saved_search_path(APP_NAME, name), 'POST', {'disabled': '0'})
        label = '3. enable "{}"'.format(name[:52])
        if code in (200, 201):
            rep.ok(label)
        elif code == 404:
            rep.fail(label, 'not found - is TA-gen_ai_cim installed?')
        else:
            rep.fail(label, 'HTTP {} {}'.format(code, text[:160]))


def step_timing(splunkd, rep, tune_risk_rule):
    code, text = splunkd.call(saved_search_path(APP_NAME, PRIMARY_DETECTION), 'POST', DEMO_TIMING)
    if code in (200, 201):
        rep.ok('8. demo timing on primary detection', 'cron */1, earliest -15m, suppression OFF')
    else:
        rep.fail('8. demo timing', 'HTTP {} {}'.format(code, text[:160]))
    if not tune_risk_rule:
        rep.skip('8. risk rule timing', '--keep-risk-timing set; expect a 10+ minute lag to the Finding')
        return
    code, text = splunkd.call(saved_search_path(RISK_RULE_APP, RISK_RULE), 'POST', RISK_RULE_TIMING)
    if code in (200, 201):
        rep.ok('8. risk rule timing', 'latest=now, cron */1 (was -10m@m, */5)')
    elif code == 404:
        rep.skip('8. risk rule timing', '{} not found'.format(RISK_RULE))
    else:
        rep.fail('8. risk rule timing', 'HTTP {} {}'.format(code, text[:160]))


def step_verify(splunkd, rep):
    seed.step_verify_plan_actions(splunkd, rep, label='9. verify plan actions')
    code, data = splunkd.get_json('{}/configs/conf-es_ai_settings/settings'.format(seed.MC_NS))
    if code == 200 and data:
        try:
            value = str(data['entry'][0]['content'].get('ai_triage_enabled'))
            if value in ('1', 'true', 'True'):
                rep.ok('9. verify ai_triage_enabled', value)
            else:
                rep.skip('9. verify ai_triage_enabled', 'is {} (entitlement or --skip-triage)'.format(value))
        except Exception as exc:
            rep.fail('9. verify ai_triage_enabled', str(exc))
    else:
        rep.fail('9. verify ai_triage_enabled', 'HTTP {}'.format(code))
    code, data = splunkd.get_json(saved_search_path(APP_NAME, PRIMARY_DETECTION))
    if code == 200 and data:
        try:
            content = data['entry'][0]['content']
            disabled = content.get('disabled')
            suppress = str(content.get('alert.suppress'))
            cron = content.get('cron_schedule')
            if disabled in (False, 0, '0'):
                rep.ok('9. verify primary detection', 'enabled, cron={}, suppress={}'.format(cron, suppress))
            else:
                rep.fail('9. verify primary detection', 'still disabled')
            if suppress not in ('0', 'False', 'false'):
                rep.fail('9. verify suppression', 'still ON - repeat demo runs will produce nothing')
        except Exception as exc:
            rep.fail('9. verify primary detection', str(exc))
    else:
        rep.fail('9. verify primary detection', 'HTTP {}'.format(code))


# --- SOAR-only extras --------------------------------------------------------

def soar_run_action(soar, container_id, app, asset, action_name, action_type, params):
    payload = {
        'action': action_name, 'type': action_type,
        'name': 'show_postdeploy smoke test: {}'.format(action_name),
        'container_id': container_id, 'run_automation': False,
        'targets': [{'assets': [asset['name']], 'app_id': app['id'], 'parameters': [params]}],
    }
    code, data = soar.post('/rest/action_run', payload)
    if code != 200 or not isinstance(data, dict) or not data.get('success'):
        return None, 'HTTP {} {}'.format(code, str(data)[:200])
    record = soar.wait_action_run(data.get('action_run_id') or data.get('id'))
    return record, record.get('message') or record.get('status')


def step_soar_smoke_test(soar, rep, app, asset):
    """test connectivity / get user / disable user for t.nguyen on a scratch
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
        'label': 'events', 'severity': 'low',
        'description': ('Scratch container created by tools/show_postdeploy.py to verify '
                        'the simulated MedAdvice identity provider. Safe to delete.'),
        'tags': ['genai', 'workshop', 'smoke-test'],
    })
    if code != 200 or not isinstance(data, dict) or not data.get('id'):
        rep.fail(label, 'could not create scratch container: HTTP {} {}'.format(code, str(data)[:160]))
        return
    container_id = data['id']
    actions = soar.app_actions(app['id'])
    for action_name, params in (('test connectivity', {}),
                                ('get user', {'username': SMOKE_TEST_USER}),
                                ('disable user', {'username': SMOKE_TEST_USER,
                                                  'reason': 'show_postdeploy smoke test'})):
        row = '13. {} {}'.format(action_name, params.get('username', '')).rstrip()
        action_type = (actions.get(action_name) or {}).get('type') or 'generic'
        record, message = soar_run_action(soar, container_id, app, asset, action_name, action_type, params)
        if record and record.get('status') == 'success':
            rep.ok(row, str(message)[:120])
        else:
            rep.fail(row, str(message)[:200])
    soar.post('/rest/container/{}'.format(container_id), {'status': 'closed'}, quiet=True)
    rep.ok(label, 'scratch container {} closed'.format(container_id))


def main():
    parser = argparse.ArgumentParser(description='Configure a Splunk Show stack for the AI Defense demo.')
    parser.add_argument('--stack', help='Stack URL, e.g. https://esp-shw-xxx.splunkcloud.com '
                                        '(required unless --soar-only)')
    parser.add_argument('--username', default='admin')
    parser.add_argument('--password', default=os.environ.get('SPLUNK_ADMIN_PASSWORD'),
                        help='Defaults to $SPLUNK_ADMIN_PASSWORD')
    parser.add_argument('--acs-token', default=os.environ.get('SPLUNK_ACS_TOKEN'),
                        help='Defaults to $SPLUNK_ACS_TOKEN')
    parser.add_argument('--skip-acs', action='store_true', help='Skip index and HEC creation')
    parser.add_argument('--keep-risk-timing', action='store_true',
                        help='Leave the ES risk rule alone (keeps its 10m lag)')
    parser.add_argument('--skip-triage', action='store_true',
                        help='Do not turn on ES AI triage for the primary detection')
    parser.add_argument('--dry-run', action='store_true', help='Print writes without making them')
    group = parser.add_argument_group('paired SOAR (steps 10-13, optional)')
    group.add_argument('--soar-url', default=os.environ.get('SOAR_URL'), help='Defaults to $SOAR_URL')
    group.add_argument('--soar-username', default=os.environ.get('SOAR_USERNAME', 'soar_local_admin'))
    group.add_argument('--soar-password', default=os.environ.get('SOAR_PASSWORD'),
                       help='Defaults to $SOAR_PASSWORD')
    group.add_argument('--soar-token', default=os.environ.get('SOAR_AUTH_TOKEN'),
                       help='ph-auth-token; defaults to $SOAR_AUTH_TOKEN')
    group.add_argument('--soar-app-tgz', default=SOAR_APP_TGZ if os.path.exists(SOAR_APP_TGZ) else None,
                       help='Built app package (default: soar_apps/medadvice_idp.tgz when '
                            'present; otherwise the shipped source is packaged in memory)')
    group.add_argument('--soar-smoke-test', action='store_true',
                       help='Run test connectivity / get user / disable user for {} on a scratch '
                            'container'.format(SMOKE_TEST_USER))
    group.add_argument('--soar-only', action='store_true', help='Run only the SOAR steps')
    group.add_argument('--skip-soar', action='store_true', help='Skip the SOAR steps')
    args = parser.parse_args()

    soar_wanted = bool(args.soar_url) and not args.skip_soar
    soar_cred = bool(args.soar_token or args.soar_password)
    if args.soar_only and not (args.soar_url and soar_cred):
        print('ERROR: --soar-only needs --soar-url and $SOAR_PASSWORD / $SOAR_AUTH_TOKEN.', file=sys.stderr)
        return 2
    if not args.soar_only:
        if not args.stack:
            print('ERROR: --stack is required (or pass --soar-only).', file=sys.stderr)
            return 2
        if not args.password:
            print('ERROR: no password. Set $SPLUNK_ADMIN_PASSWORD or pass --password.', file=sys.stderr)
            return 2

    rep = seed.Reporter(echo=print)
    out = {}
    print('Mode    : {}'.format('DRY RUN' if args.dry_run else 'apply'))

    # --- SOAR first, so step 4 can bind task actions to real ids -----------
    soar = soar_app = soar_asset = None
    if soar_wanted and soar_cred:
        soar = seed.SoarDirect(args.soar_url, args.soar_username, args.soar_password,
                               token=args.soar_token, dry_run=args.dry_run, echo=print)
        if not soar.paired():
            print('ERROR: cannot reach SOAR {}'.format(soar.base), file=sys.stderr)
            return 2
        print('SOAR    : {} (v{})'.format(soar.base, soar.version))
        print('-' * 72)
        tgz = None
        if args.soar_app_tgz and os.path.exists(args.soar_app_tgz):
            with open(args.soar_app_tgz, 'rb') as handle:
                tgz = handle.read()
        soar_app, soar_asset = seed.step_soar_simulator(soar, rep, install=True, tgz_bytes=tgz,
                                                        label='10-11. SOAR simulator')
        seed.step_competing_idp_assets(soar, rep, label='12. competing identity assets')
        if args.soar_smoke_test:
            step_soar_smoke_test(soar, rep, soar_app, soar_asset)
        else:
            rep.skip('13. SOAR smoke test', 'pass --soar-smoke-test to run it')
    elif soar_wanted:
        print('WARNING: --soar-url given without $SOAR_PASSWORD / $SOAR_AUTH_TOKEN - SOAR steps skipped.',
              file=sys.stderr)
        rep.skip('10-13. SOAR steps', 'no SOAR credential')
    else:
        rep.skip('10-13. SOAR steps', 'no --soar-url; response plan keeps the actions already on the live record')

    if args.soar_only:
        return 1 if summary(rep) else 0

    host = (urllib.parse.urlparse(args.stack.rstrip('/')).netloc or args.stack).split(':')[0]
    stack_name = host.split('.')[0]
    splunkd = seed.Splunkd('https://{}:8089'.format(host), username=args.username,
                           password=args.password, verify=False, dry_run=args.dry_run, echo=print)
    skip_acs = args.skip_acs or not args.acs_token
    acs = AcsClient(stack_name, args.acs_token, dry_run=args.dry_run)

    print('Stack   : {}'.format(host))
    print('Mgmt    : {}'.format(splunkd.mgmt))
    print('ACS     : {}'.format('skipped' if skip_acs else stack_name))
    print('-' * 72)

    code, data = splunkd.get_json('/services/server/info')
    if code != 200:
        print('ERROR: cannot reach {} (HTTP {})'.format(splunkd.mgmt, code), file=sys.stderr)
        return 2
    try:
        print('Connected to Splunk {}\n'.format(data['entry'][0]['content'].get('version')))
    except Exception:
        print('Connected.\n')

    step_index(acs, rep, skip_acs)
    step_hec(acs, rep, skip_acs, out)
    step_enable_detections(splunkd, rep)
    binder = soar if (soar_app and soar_asset) else None
    template_id = seed.step_response_plan(splunkd, rep, binder, label='4. response plan')
    seed.step_investigation_type(splunkd, rep, template_id, label='5. investigation type')
    seed.step_queue(splunkd, rep, label='6. queue')
    if args.skip_triage:
        rep.skip('7. triage agent', '--skip-triage set')
    else:
        seed.step_triage_agent(splunkd, rep, label='7. triage agent')
    step_timing(splunkd, rep, not args.keep_risk_timing)
    step_verify(splunkd, rep)

    failures = summary(rep)

    if out.get('hec_token'):
        print('\nPoint DemoBot at:')
        print('  URL   : https://http-inputs-{}.splunkcloud.com/services/collector/event'.format(stack_name))
        print('  Token : {}'.format(out['hec_token']))
        print('  Index : {}   Sourcetype: {}'.format(INDEX_NAME, HEC_SOURCETYPE))
        print('\n  Use /services/collector/event with an explicit "time" - NOT /raw.')
    elif not skip_acs:
        print('\nNo HEC token returned; create one manually and point DemoBot at it.')

    print('\nDemo loop: spray -> detection fires within 60s -> Finding -> '
          'triage dispatch polls every 30s.\nExpect roughly 60-90 seconds end to end, not 30.')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
