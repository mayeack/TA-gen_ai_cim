# encoding=utf-8
"""
lab5_steps.py - the AI Trust Lab 5 ("Verify: Cisco Identity Intelligence")
steps behind `tools/show_postdeploy.py --lab5` and `--lab5-teardown`. One run
per room stack. Dev-only (tools/ never ships in the TA package).

--lab5, in order:
  L1  index cisco_identity_intelligence (ACS)       where the CII webhook lands
  L2  HEC token cisco-identity-intelligence (ACS)    for the setup tool's labelled
                                                     backfill; only its last 4
                                                     characters are ever printed
  L3  Cisco Security Cloud app version floor        3.7.3 (3.x) / 4.1.3 (4.x)
  L4  enable the Lab 5 rule, the persona identity    in TA-gen_ai_cim's local/
      input and seed_identity_response_plan          on the stack, through REST
  L5  CII index in the triage roles' default         and searchable by splunker
      indexes
  L6  install/upgrade both SOAR apps                 MedAdvice Identity Provider
                                                     (1.1.0 refuses Lab 5
                                                     identities) and PseudoCo
                                                     Identity
  L7  upsert the pseudoco_identity asset            Duo Admin API keys from the
                                                     environment only, never argv
  L8  smoke test: get user <victim>                  read-only; never disables
  L9  seed + bind the Compromised Identity Response
      Plan, then verify it read-only

--lab5-teardown reverses L4 and L7 (the asset and its Duo secret are deleted)
and lists what only a person can do: delete the Security Cloud CII input (which
unregisters the webhook) and revoke the stack's CII API client.

The CII input itself is created in the Cisco Security Cloud app's UI (Webhook
method, checks assigned to MFA Flood, Impossible Travel and Duo Sign In Threat
Detected) BEFORE the takeover: CII webhooks announce only newly failing users.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import fnmatch
import io
import json
import os
import re
import tarfile
import time
import urllib.parse

import genai_es_seed as seed

CII_INDEX = 'cisco_identity_intelligence'
CII_HEC_TOKEN_NAME = 'cisco-identity-intelligence'
LAB5_DETECTION = seed.LAB5_DETECTION
PERSONA_INPUT = 'identity_manager://pseudoco_identity_personas'
SECURITY_CLOUD_APPS = ('CiscoSecurityCloud',)
SECURITY_CLOUD_FLOORS = {3: (3, 7, 3), 4: (4, 1, 3)}
TRIAGE_ROLES = ('admin', 'ess_admin', 'ess_analyst')
PARTICIPANT_ROLE = 'splunker'
IDENTITY_APP_SRC = os.path.join(seed.APP_ROOT, 'soar_apps', 'pseudoco_identity')
IDENTITY_APP_TGZ = os.path.join(seed.APP_ROOT, 'soar_apps', 'pseudoco_identity.tgz')
# The Duo Admin API application "PseudoCo Identity Ops" (Grant resource read +
# write). Read from the environment only, so the secret never reaches argv,
# shell history or this script's output.
ENV_DUO_HOST = 'DUO_IDENTITY_OPS_API_HOST'
ENV_DUO_IKEY = 'DUO_IDENTITY_OPS_IKEY'
ENV_DUO_SKEY = 'DUO_IDENTITY_OPS_SKEY'
PERSONA_RE = re.compile(r'^[a-z][a-z0-9]*(\.[a-z0-9]+)+$')


def last4(secret):
    return '...' + secret[-4:] if secret and len(secret) > 8 else '(hidden)'


def version_tuple(text):
    parts = re.findall(r'\d+', str(text or ''))[:3]
    return tuple(int(p) for p in parts) + (0,) * (3 - len(parts)) if parts else None


def write_out(path, data):
    """0600 JSON for lab5_setup / lab5_instance; secrets go here, not stdout."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write('\n')
    os.chmod(path, 0o600)


# --- Splunk side --------------------------------------------------------------

def step_cii_index(acs, rep, skip_acs):
    label = 'L1. index {}'.format(CII_INDEX)
    if skip_acs:
        rep.skip(label, 'ACS skipped - create the index manually')
        return
    code, text = acs.call('/indexes', 'GET')
    if code is None:
        rep.skip(label, text)
    elif code == 200 and '"{}"'.format(CII_INDEX) in text:
        rep.ok(label, 'already exists')
    else:
        code, text = acs.call('/indexes', 'POST', {'name': CII_INDEX, 'datatype': 'event',
                                                   'searchableDays': 30})
        if code in (200, 201, 202):
            rep.ok(label, 'created (may take ~minutes)')
        else:
            rep.fail(label, 'HTTP {} {}'.format(code, str(text)[:200]))


def step_cii_hec(acs, rep, skip_acs, out):
    label = 'L2. HEC token {}'.format(CII_HEC_TOKEN_NAME)
    if skip_acs:
        rep.skip(label, 'ACS skipped')
        return
    code, text = acs.call('/inputs/http-event-collectors', 'GET')
    if code is None:
        rep.skip(label, text)
        return
    token = None
    if code == 200 and CII_HEC_TOKEN_NAME in text:
        try:
            for item in json.loads(text).get('http-event-collectors', []):
                spec = item.get('spec', item)
                if spec.get('name') == CII_HEC_TOKEN_NAME:
                    token = item.get('token') or spec.get('token')
        except ValueError:
            pass
        rep.ok(label, 'already exists ({})'.format(last4(token)))
    else:
        code, text = acs.call('/inputs/http-event-collectors', 'POST', {
            'name': CII_HEC_TOKEN_NAME, 'defaultIndex': CII_INDEX,
            'allowedIndexes': [CII_INDEX], 'disabled': False})
        if code not in (200, 201, 202):
            rep.fail(label, 'HTTP {} {}'.format(code, str(text)[:200]))
            return
        try:
            body = json.loads(text)
            token = body.get('token') or (body.get('http-event-collector') or {}).get('token')
        except ValueError:
            pass
        rep.ok(label, 'created ({})'.format(last4(token)))
    if token:
        out['cii_hec_token'] = token
        out['cii_index'] = CII_INDEX


def step_security_cloud_floor(splunkd, rep):
    label = 'L3. Cisco Security Cloud app version floor'
    for name in SECURITY_CLOUD_APPS:
        code, data = splunkd.get_json('/services/apps/local/{}'.format(name))
        if code != 200 or not data:
            continue
        try:
            version = data['entry'][0]['content'].get('version')
        except (KeyError, IndexError, TypeError):
            version = None
        got = version_tuple(version)
        floor = SECURITY_CLOUD_FLOORS.get(got[0]) if got else None
        if got and floor and got >= floor:
            rep.ok(label, '{} {} (floor {})'.format(name, version, '.'.join(map(str, floor))))
        else:
            rep.fail(label, '{} {} is below the floor 3.7.3 (3.x) / 4.1.3 (4.x) for the Identity '
                            'Intelligence input'.format(name, version))
        return
    rep.fail(label, 'Cisco Security Cloud app not installed - install 3.7.3+ (3.x) or 4.1.3+ (4.x), then '
                    'create its Identity Intelligence input (Webhook) into index {}'.format(CII_INDEX))


def _post(splunkd, rep, label, path, body):
    code, text = splunkd.call(path, 'POST', body)
    if code in (200, 201):
        rep.ok(label, ', '.join('{}={}'.format(k, v) for k, v in body.items()))
    elif code == 404:
        rep.fail(label, 'not found - is TA-gen_ai_cim 1.8.0+ installed?')
    else:
        rep.fail(label, 'HTTP {} {}'.format(code, text[:160]))


def step_lab5_switches(splunkd, rep, on=True, prefix='L4'):
    """The Lab 5 rule, the persona identity input and the identity-plan seed
    switch, all written into TA-gen_ai_cim's local/ on the stack."""
    app = seed.APP_NAME
    _post(splunkd, rep, '{}. {} Lab 5 rule'.format(prefix, 'enable' if on else 'disable'),
          '/servicesNS/nobody/{}/saved/searches/{}'.format(app, urllib.parse.quote(LAB5_DETECTION, safe='')),
          {'disabled': '0' if on else '1'})
    _post(splunkd, rep, '{}. {} persona identity input'.format(prefix, 'enable' if on else 'disable'),
          '/servicesNS/nobody/{}/configs/conf-inputs/{}'.format(app, urllib.parse.quote(PERSONA_INPUT, safe='')),
          {'disabled': '0' if on else '1'})
    _post(splunkd, rep, '{}. seed_identity_response_plan'.format(prefix),
          '/servicesNS/nobody/{}/configs/conf-ta_gen_ai_cim_es/es_integration'.format(app),
          {'seed_identity_response_plan': 'true' if on else 'false'})


def _as_list(value):
    if not value:
        return []
    return [value] if isinstance(value, str) else list(value)


def step_lab5_roles(splunkd, rep):
    """CII index into the triage roles' default indexes (search access must
    already be there) and into splunker's allowed + default indexes, so
    attendees can open the evidence from the finding."""
    for role in TRIAGE_ROLES + (PARTICIPANT_ROLE,):
        label = 'L5. {} indexes for {}'.format(CII_INDEX, role)
        path = '/services/authorization/roles/{}'.format(urllib.parse.quote(role, safe=''))
        code, data = splunkd.get_json(path)
        if code == 404:
            rep.skip(label, 'role not present on this stack')
            continue
        try:
            content = data['entry'][0]['content']
        except (TypeError, KeyError, IndexError):
            rep.fail(label, 'HTTP {} - could not read the role'.format(code))
            continue
        defaults = _as_list(content.get('srchIndexesDefault'))
        allowed = _as_list(content.get('srchIndexesAllowed'))
        reach = allowed + _as_list(content.get('imported_srchIndexesAllowed'))
        body = {}
        if role == PARTICIPANT_ROLE and not any(fnmatch.fnmatchcase(CII_INDEX, p) for p in reach):
            body['srchIndexesAllowed'] = allowed + [CII_INDEX]
        elif role != PARTICIPANT_ROLE and not any(fnmatch.fnmatchcase(CII_INDEX, p) for p in reach):
            rep.fail(label, '{} is not in srchIndexesAllowed; grant search access first'.format(CII_INDEX))
            continue
        if CII_INDEX not in defaults:
            body['srchIndexesDefault'] = defaults + [CII_INDEX]
        if not body:
            rep.ok(label, 'already searchable by default')
            continue
        code, text = splunkd.call(path, 'POST', body)
        if code in (200, 201):
            rep.ok(label, 'added to {}'.format(' and '.join(sorted(body))))
        else:
            rep.fail(label, 'HTTP {} {}'.format(code, text[:160]))


# --- SOAR side ----------------------------------------------------------------

def identity_app_version():
    return seed.soar_app_manifest_version(IDENTITY_APP_SRC)


def step_identity_app(soar, rep, label='L6. SOAR app PseudoCo Identity'):
    wanted = identity_app_version()
    app = soar.find_one('app', seed.IDENTITY_SOAR_APP_NAME)
    if app and app.get('app_version') == wanted:
        rep.ok(label, 'installed (id {}, v{})'.format(app.get('id'), wanted))
        return app
    if os.path.exists(IDENTITY_APP_TGZ):
        with open(IDENTITY_APP_TGZ, 'rb') as handle:
            tgz = handle.read()
    else:
        tgz = seed.build_soar_app_tgz(IDENTITY_APP_SRC)
    result = soar.install_app(tgz)
    if soar.dry_run:
        rep.ok(label, 'dry-run - would {} v{}'.format('update' if app else 'install', wanted))
        return app or {'id': None, 'name': seed.IDENTITY_SOAR_APP_NAME, 'app_version': wanted}
    if result and not result.get('failed'):
        app = soar.find_one('app', seed.IDENTITY_SOAR_APP_NAME) or {'id': result.get('id')}
        rep.ok(label, 'installed v{} (id {})'.format(wanted, app.get('id')))
        return app
    rep.fail(label, (result or {}).get('message', 'install failed'))
    return None


def duo_credentials(env=None):
    env = os.environ if env is None else env
    host, ikey, skey = (env.get(ENV_DUO_HOST, '').strip(), env.get(ENV_DUO_IKEY, '').strip(),
                        env.get(ENV_DUO_SKEY, '').strip())
    missing = [name for name, value in ((ENV_DUO_HOST, host), (ENV_DUO_IKEY, ikey),
                                        (ENV_DUO_SKEY, skey)) if not value]
    return (host, ikey, skey), missing


def identity_asset_record(app, victim, room, creds):
    host, ikey, skey = creds
    return {
        'name': seed.IDENTITY_SOAR_ASSET_NAME,
        'product_vendor': 'PseudoCo',
        'product_name': seed.IDENTITY_SOAR_APP_NAME,
        'app': app.get('id'),
        'description': ('AI Trust Lab 5 containment (TA-gen_ai_cim): disables the room victim {} in '
                        'Duo. NOT simulated. Created by show_postdeploy.py --lab5; deleted by '
                        '--lab5-teardown.').format(victim),
        'configuration': {'api_host': host, 'ikey': ikey, 'skey': skey,
                          'victim_username': victim, 'room': room or ''},
        'tags': ['genai', 'workshop', 'lab5'],
    }


def step_identity_asset(soar, rep, app, victim, room, creds, label='L7. SOAR asset pseudoco_identity'):
    """Create or re-save the asset. The body carries the Duo secret, so it is
    posted quietly (a dry run prints the URL, never the body)."""
    record = identity_asset_record(app or {}, victim, room, creds)
    existing = soar.find_one('asset', seed.IDENTITY_SOAR_ASSET_NAME)
    path = '/rest/asset/{}'.format(existing['id']) if existing else '/rest/asset'
    code, data = soar.post(path, record, quiet=True)
    if soar.dry_run:
        rep.ok(label, 'dry-run - would {} it (victim {}, key {})'.format(
            'update' if existing else 'create', victim, last4(creds[2])))
        return existing or {'id': None, 'name': seed.IDENTITY_SOAR_ASSET_NAME}
    if code == 200 and isinstance(data, dict) and (data.get('success') or data.get('id')):
        asset = soar.find_one('asset', seed.IDENTITY_SOAR_ASSET_NAME)
        rep.ok(label, '{} (id {}, victim {}, key {})'.format(
            'updated' if existing else 'created', (asset or {}).get('id'), victim, last4(creds[2])))
        return asset
    rep.fail(label, 'HTTP {} {}'.format(code, str(data)[:160]))
    return None


def step_identity_smoke(soar, rep, app, asset, victim, run_action, label='L8. smoke test'):
    """get user for the victim on a scratch container. Read-only: it proves the
    asset's host, keys and victim without disabling anyone."""
    if soar.dry_run:
        rep.ok(label, 'dry-run - would run get user {} on a scratch container'.format(victim))
        return
    if not (app and asset and app.get('id') and asset.get('id')):
        rep.skip(label, 'app/asset not available')
        return
    code, data = soar.post('/rest/container', {
        'name': 'PseudoCo Identity smoke test {}'.format(time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())),
        'label': 'events', 'severity': 'low', 'tags': ['genai', 'workshop', 'lab5', 'smoke-test'],
        'description': 'Scratch container from tools/show_postdeploy.py --lab5 (read-only get user). Safe to delete.'})
    if code != 200 or not isinstance(data, dict) or not data.get('id'):
        rep.fail(label, 'could not create scratch container: HTTP {} {}'.format(code, str(data)[:160]))
        return
    record, message = run_action(soar, data['id'], app, asset, 'get user', 'investigate',
                                 {'username': victim})
    if record and record.get('status') == 'success':
        rep.ok('{} get user {}'.format(label, victim), str(message)[:120])
    else:
        rep.fail('{} get user {}'.format(label, victim), str(message)[:200])
    soar.post('/rest/container/{}'.format(data['id']), {'status': 'closed'}, quiet=True)


def step_identity_plan(splunkd, rep, soar):
    seed.step_identity_plan(splunkd, rep, soar, label='L9. identity response plan')
    seed.step_verify_plan_actions(splunkd, rep, label='L9. verify identity plan actions',
                                  key=seed.IDENTITY_PLAN_KEY)


def step_delete_identity_asset(soar, rep, label='T2. delete SOAR asset pseudoco_identity'):
    if soar is None:
        rep.skip(label, 'no SOAR credentials - delete the asset (and its Duo secret) in the SOAR UI')
        return
    asset = soar.find_one('asset', seed.IDENTITY_SOAR_ASSET_NAME)
    if not asset:
        rep.ok(label, 'not present')
        return
    if soar.dry_run:
        rep.ok(label, 'dry-run - would delete asset id {}'.format(asset.get('id')))
        return
    code, text = seed.http_request(soar.ctx, '{}/rest/asset/{}'.format(soar.base, asset['id']), 'DELETE',
                                   headers=soar._headers())
    if code == 200:
        rep.ok(label, 'deleted id {}'.format(asset.get('id')))
    else:
        rep.fail(label, 'HTTP {} {}'.format(code, str(text)[:160]))


def validate_victim(victim):
    """The victim must look like a persona and never be a participant account."""
    victim = (victim or '').strip().lower()
    if victim.startswith('l5-'):
        return None, 'a participant account (l5-*) is never a victim'
    if not PERSONA_RE.match(victim):
        return None, 'expected a persona username such as avery.kim'
    return victim, None
