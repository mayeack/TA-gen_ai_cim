# encoding=utf-8
"""
Offline checks for the AI Trust Lab 5 configuration in TA-gen_ai_cim 1.8.0:
the compromised-identity rule (TA-1), the prompt-injection correlation's
identity-gate exclusion (TA-2), the normalization (TA-7), the plan (TA-3) and
the navigation (TA-8). Live behaviour is covered by test_lab5_spl.py.

    python3 -m unittest discover -s tools/tests -v
"""

import io
import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
LAB5_RULE = 'AI Governance - Compromised Identity AI Attack Correlation - Rule'
LAB4_RULE = 'AI Governance - Prompt Injection Attack Correlation - Rule'


def read_conf(name):
    """{stanza: {key: value}} with backslash line continuations joined."""
    stanzas, current, key = {}, None, None
    with io.open(os.path.join(REPO, 'default', name), encoding='utf-8') as handle:
        lines = handle.read().split('\n')
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        m = re.match(r'^\[(.*)\]\s*$', line)
        if m:
            current = stanzas.setdefault(m.group(1), {})
            continue
        if '=' not in line or current is None:
            continue
        key, value = line.split('=', 1)
        value = value.strip()
        while value.endswith('\\') and i < len(lines):
            value = value[:-1] + '\n' + lines[i].strip()
            i += 1
        current[key.strip()] = value
    return stanzas


class Lab5RuleTests(unittest.TestCase):

    def setUp(self):
        self.rule = read_conf('savedsearches.conf')[LAB5_RULE]

    def test_ships_disabled_and_throttled_like_lab4(self):
        r = self.rule
        self.assertEqual(r['disabled'], '1')
        self.assertEqual((r['alert.suppress'], r['alert.suppress.fields'], r['alert.suppress.period']),
                         ('1', 'user', '600s'))
        self.assertEqual(r['cron_schedule'], '*/1 * * * *')
        self.assertIn('lastAiBlockTime>=relative_time(now(), "-5m")', r['search'])

    def test_windows_and_signals(self):
        s = self.rule['search']
        self.assertTrue(s.startswith('| multisearch'))
        self.assertIn('earliest=-24h `genai_identity_ai_events` gen_ai.policy.blocked="true" '
                      'gen_ai.guardrail.ids="cisco_ai_defense"', s)
        self.assertIn('earliest=-7d `genai_cii_failed_checks`', s)
        self.assertIn('`genai_identity_ai_attack_join`', s)
        self.assertEqual(self.rule['dispatch.earliest_time'], '-7d')

    def test_finding_and_risk_are_on_the_user_only(self):
        r = self.rule
        self.assertEqual(r['action.notable.param.rule_title'], 'GenAI Compromised Identity: $user$')
        self.assertEqual(json.loads(r['action.notable.param._entities']),
                         [{'risk_object_field': 'user', 'risk_object_type': 'user', 'risk_score': 100}])
        self.assertEqual(json.loads(r['action.risk.param._risk']), json.loads(r['action.notable.param._entities']))
        self.assertNotRegex(r['search'], r'risk_object')
        self.assertNotIn('action.notable.param.investigation_type', r)

    def test_annotations(self):
        ann = json.loads(self.rule['action.correlationsearch.annotations'])
        self.assertEqual(ann['mitre_attack'], ['T1078', 'T1621'])
        self.assertEqual(ann['atlas'], ['AML.T0012', 'AML.T0051'])

    def test_next_steps_name_pseudoco_identity_and_provenance(self):
        steps = json.loads(self.rule['action.notable.param.next_steps'])['data']
        self.assertIn('PseudoCo Identity -> disable user', steps)
        self.assertIn('backfill (lab5-setup)', steps)
        self.assertIn('$cii_provenance$', self.rule['action.notable.param.rule_description'])

    def test_no_raw_content(self):
        for key in ('search', 'action.notable.param.rule_description', 'action.risk.param._risk_message'):
            self.assertNotRegex(self.rule[key], r'input_messages|output_messages|gen_ai\.input|gen_ai\.output')


class MacroTests(unittest.TestCase):

    def setUp(self):
        self.macros = read_conf('macros.conf')

    def test_lab5_macros_exist_and_declare_iseval(self):
        for name in ('genai_cii_index', 'genai_cii_events', 'genai_cii_extract', 'genai_cii_failed_checks',
                     'genai_cii_failed_check_rows', 'genai_identity_join_key(1)', 'genai_identity_ai_events',
                     'genai_identity_participant_filter', 'genai_identity_ai_attack_join',
                     'genai_identity_ai_attack_filter'):
            self.assertIn(name, self.macros)
            self.assertEqual(self.macros[name]['iseval'], '0', name)

    def test_participants_never_join(self):
        self.assertEqual(self.macros['genai_identity_participant_filter']['definition'],
                         'search NOT identity_user="l5-*"')
        self.assertIn('`genai_identity_participant_filter`',
                      self.macros['genai_identity_ai_attack_join']['definition'])

    def test_webhook_test_events_are_dropped_and_backfill_is_accepted(self):
        rows = self.macros['genai_cii_failed_check_rows']['definition']
        self.assertIn('cii_event_type=="FAILED_CHECK"', rows)
        extract = self.macros['genai_cii_extract']['definition']
        for needle in ('detail.login', 'detail.checkId', 'detail.userTrustLevel', '"backfill (lab5-setup)"',
                       'cii_body_source=="lab5-setup"', '"synthetic test event"', '"CII webhook"'):
            self.assertIn(needle, extract)


class Lab4ExclusionTests(unittest.TestCase):

    def test_identity_gate_blocks_are_dropped_right_after_the_base_search(self):
        lines = read_conf('savedsearches.conf')[LAB4_RULE]['search'].split('\n')
        self.assertEqual(lines[0].strip(), 'index=gen_ai_log `exclude_scoring_sourcetypes`')
        self.assertEqual(lines[1].strip(),
                         '| where isnull(mvfind(\'gen_ai.guardrail.ids\', "^cisco_identity_intelligence$"))')

    def test_enabled_exceptions_unchanged(self):
        enabled = sorted(n for n, s in read_conf('savedsearches.conf').items() if s.get('disabled') == '0')
        self.assertEqual(enabled, ['AI Governance - Prompt Injection Attack Correlation - Rule',
                                   'GenAI - ES - Seed Response Plan and SOAR Binding',
                                   'GenAI - Tokenomics - Seed Token Cost Pricing'])


class NormalizationTests(unittest.TestCase):

    def test_audit_and_identity_fields(self):
        props = read_conf('props.conf')['gen_ai:json']
        self.assertIn("isnotnull(audit_id), 'gen_ai.audit.action_raw'", props['EVAL-gen_ai.audit.action'])
        self.assertIn('"identity_signin_success", "success"', props['EVAL-action'])
        self.assertIn('"duo"', props['EVAL-authentication_service'])
        for key in ('EVAL-gen_ai.identity.verified', 'EVAL-gen_ai.identity.override',
                    'FIELDALIAS-genai_identity_check', 'EVAL-gen_ai.identity.risk.failing_checks'):
            self.assertIn(key, props)
        self.assertIn("'identity_risk.failing_checks{}'", props['EVAL-gen_ai.identity.risk.failing_checks'])

    def test_eventtypes_and_tags(self):
        et = read_conf('eventtypes.conf')
        tags = read_conf('tags.conf')
        self.assertIn('identity_signin_success', et['gen_ai_identity_authentication']['search'])
        self.assertEqual(tags['eventtype=gen_ai_identity_authentication']['authentication'], 'enabled')
        self.assertIn('cisco_identity_intelligence', et['gen_ai_identity_block']['search'])


class PlanAndNavTests(unittest.TestCase):

    def test_identity_plan(self):
        with io.open(os.path.join(REPO, 'default', 'data', 'response_plans',
                                  'compromised_identity_response_plan.json'), encoding='utf-8') as handle:
            plan = json.load(handle)
        self.assertEqual(plan['_key'], 'compromised_identity_response_plan')
        self.assertIsInstance(plan['origin'], dict)
        bindings = [b for ph in plan['phases'] for t in ph['tasks']
                    for b in (t.get('suggestions') or {}).get('soar_binding', [])]
        self.assertEqual([(b['app_name'], b['asset_name'], b['action']) for b in bindings],
                         [('PseudoCo Identity', 'pseudoco_identity', 'disable user')])

    def test_switch_ships_off(self):
        es = read_conf('ta_gen_ai_cim_es.conf')['es_integration']
        self.assertEqual(es['seed_identity_response_plan'], 'false')

    def test_nav_has_home_default_and_the_dashboard(self):
        with io.open(os.path.join(REPO, 'default', 'data', 'ui', 'nav', 'default.xml'), encoding='utf-8') as handle:
            nav = handle.read()
        self.assertIn('<view name="TA-gen_ai_cim_home" default=\'true\'', nav)
        self.assertIn('<view name="compromised_identity"', nav)
        self.assertEqual(nav.count("default='true'"), 1)


if __name__ == '__main__':
    unittest.main()
