# encoding=utf-8
"""
Offline tests for bin/genai_es_seed.py - the seeding core shared by the
`| genaiseedes` command and tools/show_postdeploy.py.

Fake splunkd and SOAR transports stand in for the network, so the tests cover
the logic that matters: soar_binding resolution into Mission Control Action
records, stripping of the soar_binding key, merge-preserve of live actions
without double-encoding, investigation-type array handling, the simulator
install/asset sequence, and the in-memory SOAR app package.

    /opt/splunk104/bin/splunk cmd python3.13 -m unittest discover -s tools/soar/tests -v
"""

import io
import json
import os
import re
import subprocess
import sys
import tarfile
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, os.path.join(REPO, 'bin'))

import genai_es_seed as seed  # noqa: E402


class FakeSplunkd(object):
    """Records KV writes; serves a canned live record."""

    def __init__(self, live=None, dry_run=False):
        self.live = dict(live or {})
        self.writes = []
        self.dry_run = dry_run
        self.mgmt = 'https://fake:8089'

    def call(self, path, method='GET', data=None, json_body=None, timeout=60):
        if method == 'GET':
            for key, record in self.live.items():
                if path.endswith(urllib.parse.quote(key, safe='')):
                    return 200, json.dumps(record)
            return 404, '{}'
        self.writes.append((path, method, json_body if json_body is not None else data))
        if isinstance(json_body, dict) and json_body.get('_key'):
            self.live[json_body['_key']] = json_body   # write-through, like KV store
        return 200, '{}'

    def get_json(self, path, timeout=60):
        code, text = self.call(path)
        return code, (json.loads(text) if code == 200 else None)


class FakeSoar(object):
    name = 'fake SOAR'
    can_install = True

    def __init__(self, apps=None, assets=None, dry_run=False):
        self.apps = list(apps or [])
        self.assets = list(assets or [])
        self.dry_run = dry_run
        self.installed = []
        self.version = '8.6.0'

    def paired(self):
        return True

    def find_one(self, resource, name):
        for item in (self.apps if resource == 'app' else self.assets):
            if item.get('name') == name:
                return item
        return None

    def app_actions(self, app_id):
        return {'disable user': {'type': 'contain'}, 'clear user sessions': {'type': 'contain'},
                'get user': {'type': 'investigate'}}

    def list_all(self, resource):
        return list(self.apps if resource == 'app' else self.assets)

    def create_asset(self, record, app):
        asset = {'id': 34, 'name': record['name'], 'app': app.get('id')}
        self.assets.append(asset)
        return asset, None

    def install_app(self, tgz_bytes):
        self.installed.append(tgz_bytes)
        self.apps.append({'id': 198, 'name': seed.SOAR_APP_NAME,
                          'app_version': seed.soar_app_manifest_version()})
        return {'success': True, 'id': 198}


def containment(plan):
    return [ph for ph in plan['phases'] if ph['name'] == 'Containment'][0]['tasks']


class BindingTests(unittest.TestCase):

    def setUp(self):
        self.plan = seed.load_plan()

    def test_seed_carries_two_bindings_on_containment_tasks(self):
        tasks = containment(self.plan)
        self.assertEqual(tasks[0]['name'], "Inactivate the offending identity's account")
        self.assertTrue(tasks[0]['is_note_required'])
        self.assertEqual(tasks[0]['suggestions']['soar_binding'][0]['action'], 'disable user')
        self.assertEqual(tasks[1]['suggestions']['soar_binding'][0]['action'], 'clear user sessions')

    def test_bind_resolves_ids_and_strips_binding(self):
        soar = FakeSoar(apps=[{'id': 198, 'name': seed.SOAR_APP_NAME, 'app_version': '1.0.0'}],
                        assets=[{'id': 34, 'name': seed.SOAR_ASSET_NAME, 'app': 198}])
        rep = seed.Reporter()
        bound, dropped = seed.bind_soar_actions(self.plan, soar, rep)
        self.assertEqual((bound, dropped), (2, 0))
        action = containment(self.plan)[0]['suggestions']['actions'][0]
        self.assertEqual(action['app_id'], 198)
        self.assertEqual(action['asset'], 34)
        self.assertEqual(action['type'], 'contain')
        self.assertIsNone(action['last_job_id'])
        self.assertEqual(action['parameters'][0]['username'], '$user$')
        self.assertNotIn('soar_binding', json.dumps(self.plan))

    def test_bind_without_soar_drops_and_preserve_keeps_live_actions(self):
        rep = seed.Reporter()
        bound, dropped = seed.bind_soar_actions(self.plan, None, rep)
        self.assertEqual((bound, dropped), (0, 2))
        live = seed.encode_plan(json.loads(json.dumps(self.plan)))
        ui_action = seed.encode_plan({
            'last_job_id': None, 'name': 'UI added: disable user (MedAdvice)',
            'description': 'x (y)', 'action': 'disable user', 'type': 'contain',
            'app_id': 198, 'asset': 34, 'parameters': [{'username': 't.nguyen'}]})
        live['phases'][1]['tasks'][0]['suggestions']['actions'] = [ui_action]
        self.assertEqual(seed.preserve_live_actions(self.plan, live), 1)
        merged = containment(self.plan)[0]['suggestions']['actions'][0]
        self.assertEqual(merged['name'], 'UI added: disable user (MedAdvice)')
        encoded = seed.encode_plan(self.plan)
        self.assertEqual(encoded['phases'][1]['tasks'][0]['suggestions']['actions'][0]['name'],
                         urllib.parse.quote('UI added: disable user (MedAdvice)',
                                            safe=seed._URI_COMPONENT_SAFE))

    def test_bind_reports_missing_app(self):
        rep = seed.Reporter()
        bound, dropped = seed.bind_soar_actions(self.plan, FakeSoar(), rep)
        self.assertEqual((bound, dropped), (0, 2))
        self.assertEqual(rep.failures(), 2)


class CommittedPackageTests(unittest.TestCase):
    """The tarball committed at soar_apps/medadvice_idp.tgz is what an operator
    uploads to SOAR by hand, so it must not drift from the shipped source."""

    TGZ = os.path.join(REPO, 'soar_apps', 'medadvice_idp.tgz')

    def test_committed_tarball_exists_and_matches_the_source(self):
        self.assertTrue(os.path.exists(self.TGZ),
                        'run bash tools/soar/build.sh')
        with tarfile.open(self.TGZ, 'r:gz') as tar:
            names = tar.getnames()
            manifest = json.loads(
                tar.extractfile('medadvice_idp/medadvice_idp.json').read().decode('utf-8'))
        self.assertIn('medadvice_idp/medadvice_idp_connector.py', names)
        self.assertIn('medadvice_idp/medadvice_idp_consts.py', names)
        self.assertFalse([n for n in names if '__pycache__' in n or n.endswith('.pyc')])
        self.assertEqual(manifest['app_version'], seed.soar_app_manifest_version(),
                         'committed tarball is stale; rerun bash tools/soar/build.sh')
        self.assertEqual(manifest['name'], seed.SOAR_APP_NAME)

    def test_in_memory_package_matches_the_committed_member_list(self):
        def members(fh_or_path, **kw):
            with tarfile.open(fh_or_path, 'r:gz', **kw) as tar:
                return sorted((m.name.rstrip('/'), m.isdir()) for m in tar.getmembers())
        committed = members(self.TGZ)
        in_memory = members(None, fileobj=io.BytesIO(seed.build_soar_app_tgz()))
        self.assertEqual(committed, in_memory,
                         'the in-product packager and tools/soar/build.sh must produce '
                         'the same archive shape - only build.sh has been verified to '
                         'install on SOAR')
        self.assertIn(('medadvice_idp', True), in_memory)


class StepTests(unittest.TestCase):

    def test_response_plan_step_writes_encoded_record_with_key(self):
        splunkd = FakeSplunkd()
        rep = seed.Reporter()
        template_id = seed.step_response_plan(splunkd, rep, None)
        self.assertEqual(template_id, 'b7c3f1a2-5d84-4e97-a1c6-3f9e02d47b58')
        path, method, body = splunkd.writes[0]
        self.assertIn('mc_response_templates', path)
        self.assertEqual(body['_key'], 'ai_incident_response_plan')
        self.assertEqual(body['phases'][0]['name'], 'Identification%20(Detection%20and%20Analysis)')
        self.assertNotIn('soar_binding', json.dumps(body))
        self.assertNotIn('_comment', body)

    def test_investigation_type_keeps_existing_ids_and_puts_ours_first(self):
        splunkd = FakeSplunkd(live={'ai security incident': {
            '_key': 'ai security incident', 'response_template_ids': ['other'],
            'create_time': 1, 'description': 'custom'}})
        rep = seed.Reporter()
        seed.step_investigation_type(splunkd, rep, 'tmpl')
        body = splunkd.writes[0][2]
        self.assertEqual(body['response_template_ids'], ['tmpl', 'other'])
        self.assertEqual(body['description'], 'custom')
        self.assertEqual(body['create_time'], 1)

    def test_queue_step(self):
        splunkd = FakeSplunkd()
        rep = seed.Reporter()
        seed.step_queue(splunkd, rep)
        self.assertEqual(splunkd.writes[0][2]['_key'], 'ai_findings_queue')

    def test_simulator_install_then_asset(self):
        soar = FakeSoar()
        rep = seed.Reporter()
        app, asset = seed.step_soar_simulator(soar, rep, install=True)
        self.assertEqual(app['id'], 198)
        self.assertEqual(asset['name'], seed.SOAR_ASSET_NAME)
        self.assertEqual(len(soar.installed), 1)
        with tarfile.open(fileobj=io.BytesIO(soar.installed[0]), mode='r:gz') as tar:
            names = tar.getnames()
        self.assertIn('medadvice_idp/medadvice_idp.json', names)
        self.assertIn('medadvice_idp/medadvice_idp_connector.py', names)
        self.assertFalse(any('__pycache__' in n for n in names))

    def test_simulator_not_installed_and_install_off_skips(self):
        soar = FakeSoar()
        rep = seed.Reporter()
        app, asset = seed.step_soar_simulator(soar, rep, install=False)
        self.assertIsNone(app)
        self.assertEqual(rep.rows[0][0], 'SKIP')

    def test_full_seed_binds_when_simulator_present(self):
        soar = FakeSoar(apps=[{'id': 198, 'name': seed.SOAR_APP_NAME, 'app_version': '1.0.0'}])
        splunkd = FakeSplunkd()
        rep = seed.Reporter()
        seed.seed(splunkd, rep, soar=soar, install_simulator=False, enable_triage=False)
        self.assertEqual(rep.failures(), 0, rep.rows)
        plan_write = [w for w in splunkd.writes if 'mc_response_templates' in w[0]][0][2]
        actions = plan_write['phases'][1]['tasks'][0]['suggestions']['actions']
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]['asset'], 34)


MISSIONCONTROL = os.path.join(os.environ.get('SPLUNK_HOME', '/opt/splunk104'), 'etc', 'apps', 'missioncontrol')


@unittest.skipUnless(os.path.isdir(os.path.join(MISSIONCONTROL, 'lib', 'rule_engine')),
                     'missioncontrol (ES) is not installed beside this TA')
class QueueRuleTests(unittest.TestCase):
    """The queue rule is Mission Control rule_engine syntax, not SPL. The
    SPL-style 'search_name="AI Governance*"' seeded up to 1.7.0 was a syntax
    error logged on every finding. Validated with missioncontrol's own engine
    and UI builder, in a subprocess so its lib/ never shadows this TA's splunklib."""

    def run_mc(self, code):
        out = subprocess.run([sys.executable, '-c', code], cwd=MISSIONCONTROL,
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_rule_string_parses_and_routes_only_ai_governance(self):
        # The finding at queue-assignment time: notable params (rule_title with
        # literal $tokens$) plus the result row, and no search_name yet.
        conf = open(os.path.join(REPO, 'default', 'savedsearches.conf'), encoding='utf-8').read()
        titles = [t for t in re.findall(r'^action\.notable\.param\.rule_title = (.*)$', conf, re.M)
                  if t.startswith('GenAI Prompt Injection')]
        self.assertEqual(len(titles), 3, titles)
        other = 'Risk Threshold Exceeded For $risk_object_type$=$risk_object$'
        result = self.run_mc(
            "import sys, json; sys.path[:0] = ['lib', 'bin']; import rule_engine; "
            "r = rule_engine.Rule({!r}); "
            "print(json.dumps([r.matches({{'rule_title': t}}) for t in {!r}]))".format(
                seed.QUEUE_RULE_STRING, titles + [other]))
        self.assertEqual(result, [True, True, True, False])

    def test_rule_string_is_what_the_es_ui_builds_from_rules(self):
        built = self.run_mc(
            "import sys, json; sys.path[:0] = ['lib', 'bin']; "
            "from blueridge.data_models.models.queues import Queues; "
            "print(json.dumps(Queues.build_rule_string({!r})))".format(seed.QUEUE_RULES))
        self.assertEqual(built, seed.QUEUE_RULE_STRING)

    def test_queue_record_carries_rules_as_a_json_string_when_routing(self):
        splunkd, rep = FakeSplunkd(), seed.Reporter()
        seed.step_queue(splunkd, rep, route=True)
        record = splunkd.live['ai_findings_queue']
        self.assertEqual(json.loads(record['rules']), seed.QUEUE_RULES)
        self.assertEqual(record['rule_string'], seed.QUEUE_RULE_STRING)

    def test_routing_is_off_by_default(self):
        # Findings must stay in the Analyst Queue unless routing is opted into:
        # rule_executor skips an empty rule_string.
        splunkd, rep = FakeSplunkd(), seed.Reporter()
        seed.step_queue(splunkd, rep)
        record = splunkd.live['ai_findings_queue']
        self.assertEqual((record['rule_string'], json.loads(record['rules'])), ('', []))
        self.assertIn(('SKIP', 'queue routing'), [(s, step) for s, step, _ in rep.rows])


if __name__ == '__main__':
    unittest.main()
