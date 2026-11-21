# encoding=utf-8
"""
Offline checks for the AI Trust Lab 5 configuration in TA-gen_ai_cim 1.8.0:
the compromised-identity rule (TA-1), the prompt-injection correlation's
identity-gate exclusion (TA-2), the normalization (TA-7), the plan (TA-3),
the navigation (TA-8) and the gaps the Lab 5 dry run of 2026-11-06 found
(H1 flat identity fields, H2 version floor, H4 takeover checks, M1 check IDs).
Also, since 1.9.0, the menu, the home dashboard (one numbered card per
dashboard, re-flowed for cards 05 and 06) and the Duo Identity Feed view,
including that every macro and rule the view names exists and that the identity
source it reads is the one default/inputs.conf names in its commented example
(that source does not ship as a stanza: R-INP-002). The Identity Activity view
behind card 06 has its own file, test_identity_activity.py.
Live behaviour is covered by test_lab5_spl.py.

    python3 -m unittest discover -s tools/tests -v
"""

import io
import json
import os
import re
import sys
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
LAB5_RULE = 'AI Governance - Compromised Identity AI Attack Correlation - Rule'
LAB4_RULE = 'AI Governance - Prompt Injection Attack Correlation - Rule'
DUO_RULE = 'AI Governance - Duo Authentication Fraud or Denial Burst - Rule'
DUO_VIEW = 'ta_gen_ai_cim_duo_identity'
IDENTITY_VIEW = 'ta_gen_ai_cim_identity_activity'
DUO_IDENTITY_SOURCE = 'ta_gen_ai_cim_duo_identities'
VIEWS = os.path.join(REPO, 'default', 'data', 'ui', 'views')
NAV = os.path.join(REPO, 'default', 'data', 'ui', 'nav', 'default.xml')
# The menu's Dashboards collection, in order; the home has one card per entry.
DASHBOARDS = [('ai_governance_overview', 'AI Governance Overview'), ('tokenomics', 'Tokenomics'),
              ('prompt_injection_detection', 'Prompt Injection Detection'),
              ('compromised_identity', 'Compromised Identity'), (DUO_VIEW, 'Duo Identity Feed'),
              (IDENTITY_VIEW, 'Identity Activity')]
# Home card number -> the KPI label beside it.
HOME_KPIS = {'01': 'GenAI events, last 24h', '02': 'tokens, last 24h', '03': 'policy blocks, last 24h',
             '04': 'CII failed checks, last 7d', '05': 'Duo authentications, last 24h',
             '06': 'identities active, last 24h'}
# The home scoreboard, exactly as it was before cards 05 and 06: (tile title, query).
SCOREBOARD = [
    ('GenAI events', 'index=gen_ai_log `exclude_scoring_sourcetypes` | stats count as v'),
    ('Users', 'index=gen_ai_log `exclude_scoring_sourcetypes` | stats dc(user) as v'),
    ('Policy blocks', 'index=gen_ai_log `exclude_scoring_sourcetypes` gen_ai.policy.blocked="true" | stats count as v'),
    ('Safety violations',
     'index=gen_ai_log `exclude_scoring_sourcetypes` gen_ai.safety.violated="true" | stats count as v'),
    ('PII detections', 'index=gen_ai_log `exclude_scoring_sourcetypes` gen_ai.pii.detected="true" | stats count as v'),
]
# CII's check IDs (listCheckMetadata, 2026-11-06), and the ones that count as
# takeover evidence: the same two the Identity Risk Gate refuses a turn for.
CII_CHECK_CATALOGUE = ('mfa-flood', 'impossible-travel', 'duo-sign-in-threat-detected', 'is-bypass-code-used',
                       'is-weak-mfa-used', 'user-account-locked-out')
TAKEOVER_CHECKS = ('mfa-flood', 'impossible-travel')
# PseudoCo Assistant backend/services/identity_gate.py BLOCKING_CHECKS (the
# letters-only names the gate matches on), main 98e21b1. Change it together
# with the gate and genai_cii_takeover_check_ids.
GATE_BLOCKING_CHECKS = ('mfaflood', 'impossibletravel')
# Per gen_ai.identity.risk.* EVAL, the names it must read in this order: the
# flat fields PseudoCo Assistant 4.23.0 writes, then the nested pre-release
# draft names as a fallback.
IDENTITY_FLAT_FIRST = {
    'EVAL-gen_ai.identity.risk.verdict': ('coalesce(identity_risk,', "'identity_risk.verdict'"),
    'EVAL-gen_ai.identity.risk.reasons': ("'identity_risk_reasons{}'", 'isnotnull(identity_risk_reasons)',
                                          "'identity_risk.reasons{}'"),
    'EVAL-gen_ai.identity.risk.failing_checks': ("'identity_failing_checks{}'", 'isnotnull(identity_failing_checks)',
                                                 "'identity_risk.failing_checks{}'"),
    'EVAL-gen_ai.identity.risk.trust_level': ('coalesce(identity_trust_level,', "'identity_risk.trust_level'"),
    'EVAL-gen_ai.identity.risk.duo_status': ('coalesce(identity_duo_status,', "'identity_risk.duo_status'"),
}


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


def commented_stanza(name, stanza):
    """The commented example of [stanza] in default/<name>, as the lines an owner
    copies ('[stanza]', then each 'key = value'), without the leading '#' and
    indentation. It ends at the first line that is not a commented setting. None
    when the conf holds no such example; a stanza that ships live is not one."""
    with io.open(os.path.join(REPO, 'default', name), encoding='utf-8') as handle:
        lines = handle.read().split('\n')
    header = re.compile(r'^#\s*\[%s\]\s*$' % re.escape(stanza))
    for i, line in enumerate(lines):
        if not header.match(line):
            continue
        example = ['[%s]' % stanza]
        for follow in lines[i + 1:]:
            m = re.match(r'^#\s*([A-Za-z_][\w.-]*)\s*=\s*(.*?)\s*$', follow)
            if not m:
                break
            example.append('%s = %s' % m.groups())
        return example
    return None


def studio(name):
    """(root element, definition) of a Dashboard Studio view in default/."""
    root = ET.parse(os.path.join(VIEWS, name + '.xml')).getroot()
    return root, json.loads(root.find('definition').text)


def nav_collection(label):
    """[(view name, label)] of one nav collection, in menu order."""
    root = ET.parse(NAV).getroot()
    collection = [c for c in root.iter('collection') if c.get('label') == label]
    return [(v.get('name'), v.get('label')) for v in collection[0].iter('view')] if collection else []


def positions(definition):
    return {b['item']: b['position'] for b in definition['layout']['structure']}


def inside(inner, outer):
    return (inner['x'] >= outer['x'] and inner['y'] >= outer['y'] and
            inner['x'] + inner['w'] <= outer['x'] + outer['w'] and
            inner['y'] + inner['h'] <= outer['y'] + outer['h'])


def overlap(a, b):
    return not (a['x'] + a['w'] <= b['x'] or b['x'] + b['w'] <= a['x'] or
                a['y'] + a['h'] <= b['y'] or b['y'] + b['h'] <= a['y'])


class StudioLayoutMixin(object):
    """Wiring and geometry every absolute-layout Studio view in the TA must satisfy."""

    def assert_wired(self, definition):
        viz, ds = definition['visualizations'], definition['dataSources']
        placed = [b['item'] for b in definition['layout']['structure']]
        self.assertEqual(len(placed), len(set(placed)), 'a block is placed twice')
        self.assertEqual(set(placed), set(viz), 'every visualization is placed, nothing undefined is')
        used = set()
        for name, v in viz.items():
            for ref in (v.get('dataSources') or {}).values():
                self.assertIn(ref, ds, name)
                used.add(ref)
        for name, control in (definition.get('inputs') or {}).items():
            for ref in (control.get('dataSources') or {}).values():
                self.assertIn(ref, ds, name)
                used.add(ref)
        for name, source in ds.items():
            if source['type'] == 'ds.chain':
                self.assertEqual(ds[source['options']['extend']]['type'], 'ds.search', name)
                used.add(source['options']['extend'])
        self.assertEqual(used, set(ds), 'every data source feeds a panel, an input or a chain')

    def assert_on_canvas(self, definition):
        options = definition['layout']['options']
        for item, p in positions(definition).items():
            self.assertTrue(p['x'] >= 0 and p['y'] >= 0, item)
            self.assertLessEqual(p['x'] + p['w'], options['width'], item)
            self.assertLessEqual(p['y'] + p['h'], options['height'], item)

    def assert_no_overlap(self, definition, items):
        pos = positions(definition)
        for i, a in enumerate(items):
            for b in items[i + 1:]:
                self.assertFalse(overlap(pos[a], pos[b]), (a, b))

    def assert_draw_order(self, definition):
        """An absolute layout draws layout.structure in order, later blocks on top,
        and the card rectangles are opaque (fillOpacity 1): a rectangle placed
        after something it overlaps hides it, with every other test still green."""
        viz, pos = definition['visualizations'], positions(definition)
        order = [b['item'] for b in definition['layout']['structure']]
        cards = [v for v in order if viz[v]['type'] == 'splunk.rectangle']
        self.assertTrue(cards, 'the view has no card rectangle')
        for card in cards:
            self.assertEqual(viz[card]['options'].get('fillOpacity'), 1, card)
            for earlier in order[:order.index(card)]:
                if viz[earlier]['type'] != 'splunk.rectangle':
                    self.assertFalse(overlap(pos[earlier], pos[card]),
                                     '%s is drawn over %s, which comes before it' % (card, earlier))


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
        self.assertIn('earliest=-24h `genai_identity_ai_events` gen_ai.identity.verified="true" \n'
                      '| `genai_cii_gate_failed_check_rows`', s)
        self.assertIn('`genai_identity_ai_attack_join`', s)
        self.assertEqual(self.rule['dispatch.earliest_time'], '-7d')

    def test_fresh_cii_evidence_also_fires_and_overrides_are_critical(self):
        s = self.rule['search']
        self.assertIn('| where lastAiBlockTime>=relative_time(now(), "-5m") '
                      'OR lastCiiTime>=relative_time(now(), "-5m")', s)
        self.assertIn('identity_overrides>0 AND abs(lastAiBlockTime-lastOverrideTime)<=600, "critical"', s)
        self.assertIn('isnotnull(mvfind(cii_trust_levels, "^UNTRUSTED$")), "critical"', s)

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
                     'genai_cii_failed_check_rows', 'genai_cii_takeover_check_ids', 'genai_cii_takeover_checks',
                     'genai_cii_gate_failed_check_rows', 'genai_identity_join_key(1)',
                     'genai_identity_ai_events', 'genai_identity_participant_filter',
                     'genai_identity_ai_attack_join', 'genai_identity_ai_attack_filter'):
            self.assertIn(name, self.macros)
            self.assertEqual(self.macros[name]['iseval'], '0', name)

    def test_only_takeover_checks_count(self):
        """H4: a bypass-code or weak-MFA failure, which every persona gets after a
        handout code, never reaches the join; only the takeover checks do."""
        ids = self.macros['genai_cii_takeover_check_ids']['definition']
        self.assertEqual(sorted(re.findall(r'"([^"]+)"', ids)), sorted(TAKEOVER_CHECKS))
        self.assertEqual(self.macros['genai_cii_takeover_checks']['definition'],
                         'search cii_check_id IN (`genai_cii_takeover_check_ids`)')
        rows = [line.strip() for line in self.macros['genai_cii_failed_check_rows']['definition'].split('\n')]
        self.assertEqual(rows[1:], ['| `genai_cii_takeover_checks`',
                                    '| eval identity_user=`genai_identity_join_key(cii_login)`'])

    def test_takeover_checks_match_the_identity_gate(self):
        """D1 (2026-11-16): the TA counts the same CII checks PseudoCo Assistant's
        Identity Risk Gate refuses a turn for. Compared as letters and digits, the
        way the gate itself matches check names."""
        squash = lambda name: re.sub(r'[^a-z0-9]', '', name.lower())  # noqa: E731
        self.assertEqual(sorted(squash(c) for c in TAKEOVER_CHECKS), sorted(GATE_BLOCKING_CHECKS))
        self.assertNotIn('duo-sign-in-threat-detected',
                         self.macros['genai_cii_takeover_check_ids']['definition'])

    def test_gate_lookup_rows_count_takeover_checks_and_untrusted(self):
        """Backlog row 3: the app's own signed-in events are CII evidence, one row
        per takeover check, plus an UNTRUSTED trust level; names normalized."""
        rows = self.macros['genai_cii_gate_failed_check_rows']['definition']
        for needle in ("'gen_ai.identity.risk.failing_checks'", "'gen_ai.identity.risk.trust_level'",
                       '"trust-level-untrusted"', '| mvexpand cii_check_id',
                       '| search cii_check_id IN (`genai_cii_takeover_check_ids`, "trust-level-untrusted")',
                       'identity_user=`genai_identity_join_key(user)`',
                       'cii_provenance="PseudoCo Assistant gate lookup"'):
            self.assertIn(needle, rows)
        self.assertIn('lower(replace(trim(', rows)
        self.assertIn('max(eval(if(signal=="identity_gate" AND gate_override==1, _time, null()))) as lastOverrideTime',
                      self.macros['genai_identity_ai_attack_join']['definition'])

    def test_rule_and_dashboard_read_cii_through_the_filter(self):
        """The rule and the dashboard reach CII only through genai_cii_failed_checks
        (which applies genai_cii_takeover_checks), never the raw index or events."""
        self.assertIn('`genai_cii_failed_check_rows`', self.macros['genai_cii_failed_checks']['definition'])
        rule = read_conf('savedsearches.conf')[LAB5_RULE]['search']
        with io.open(os.path.join(REPO, 'default', 'data', 'ui', 'views', 'compromised_identity.xml'),
                     encoding='utf-8') as handle:
            dashboard = handle.read()
        for name, text in (('rule', rule), ('dashboard', dashboard)):
            self.assertIn('`genai_cii_failed_checks`', text, name)
            self.assertNotIn('genai_cii_events', text, name)
            self.assertNotIn('genai_cii_index', text, name)

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


def view_data_sources(name):
    """{data source id: query} of a Dashboard Studio view in default/data/ui/views."""
    with io.open(os.path.join(REPO, 'default', 'data', 'ui', 'views', name + '.xml'), encoding='utf-8') as handle:
        text = handle.read()
    definition = json.loads(re.search(r'<definition><!\[CDATA\[(.*?)\]\]></definition>', text, re.S).group(1))
    return {key: ds.get('options', {}).get('query', '') for key, ds in definition['dataSources'].items()}


class CompromisedIdentityDashboardTests(unittest.TestCase):
    """The dashboard counts CII evidence the way the Lab 5 rule does: the CII
    webhook OR PseudoCo Assistant's gate lookup on signed-in turns (backlog
    row 3). Before 2026-11-17 it read the webhook only, so with no CII
    notification target its CII tile, CII table and join stayed at 0 while the
    rule fired from the gate lookup."""

    WEBHOOK = '[ search `genai_cii_failed_checks` ]'
    GATE = ('[ search `genai_identity_ai_events` gen_ai.identity.verified="true" host="$instance_filter$" '
            '| `genai_cii_gate_failed_check_rows` ]')

    def setUp(self):
        self.ds = view_data_sources('compromised_identity')

    @staticmethod
    def branches(search):
        """The multisearch branches in front of the join, with the rule's own
        earliest= windows removed and whitespace collapsed."""
        body = search.split('| multisearch', 1)[1].split('| `genai_identity_ai_attack_join`', 1)[0]
        return re.sub(r'\s+', ' ', re.sub(r'earliest=-\S+\s+', '', body)).strip()

    def test_join_is_the_rule_without_its_windows(self):
        """The join is the detection minus its time windows and freshness limit:
        the same four branches, the gate-lookup branch included."""
        rule = read_conf('savedsearches.conf')[LAB5_RULE]['search']
        self.assertEqual(self.branches(self.ds['ds_join']), self.branches(rule))
        self.assertIn('`genai_cii_gate_failed_check_rows` | eval signal="cii_failed_check" ]', self.ds['ds_join'])

    def test_cii_tile_and_table_read_the_webhook_and_the_gate_lookup(self):
        for key in ('ds_kpi_cii', 'ds_cii'):
            query = self.ds[key]
            self.assertTrue(query.startswith('| multisearch ' + self.WEBHOOK + ' ' + self.GATE), key)
            self.assertIn('| search identity_user="$user_filter$"', query, key)

    def test_one_flagged_user_counts_once_however_many_turns(self):
        """Every event of every signed-in turn repeats the user's failing checks,
        so the tile counts distinct user/check pairs and the table gives one row
        per user, check and source with the number of observations."""
        self.assertIn('| eval cii_pair=identity_user.":".cii_check_id | stats dc(cii_pair) as count',
                      self.ds['ds_kpi_cii'])
        self.assertIn('count as observations', self.ds['ds_cii'])
        self.assertIn('by identity_user, cii_check_id, cii_provenance', self.ds['ds_cii'])

    def test_home_card_counts_the_same_evidence(self):
        query = view_data_sources('TA-gen_ai_cim_home')['ds_card_04']
        self.assertTrue(query.startswith('| multisearch ' + self.WEBHOOK + ' [ search `genai_identity_ai_events` '
                                         'gen_ai.identity.verified="true" | `genai_cii_gate_failed_check_rows` ]'))
        self.assertTrue(query.endswith('| eval cii_pair=identity_user.":".cii_check_id | stats dc(cii_pair) as v'))


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

    def test_identity_risk_reads_the_flat_fields_first(self):
        """H1: 4.23.0 writes identity_duo_status, identity_failing_checks, ... as flat
        fields; the nested identity_risk.* names are read only after them."""
        props = read_conf('props.conf')['gen_ai:json']
        for key, names in IDENTITY_FLAT_FIRST.items():
            positions = [props[key].find(name) for name in names]
            self.assertNotIn(-1, positions, (key, names))
            self.assertEqual(positions, sorted(positions), key)

    def test_eventtypes_and_tags(self):
        et = read_conf('eventtypes.conf')
        tags = read_conf('tags.conf')
        self.assertIn('identity_signin_success', et['gen_ai_identity_authentication']['search'])
        self.assertEqual(tags['eventtype=gen_ai_identity_authentication']['authentication'], 'enabled')
        self.assertIn('cisco_identity_intelligence', et['gen_ai_identity_block']['search'])


class DryRunRegressionTests(unittest.TestCase):
    """Gaps the Lab 5 dry run of 2026-11-06 found in the docs and samples."""

    def test_version_floor_is_4_23(self):
        """H2: the Identity Risk Gate ships in PseudoCo Assistant 4.23.0; 4.22.0 has none.
        The README's version history may still say 4.22.0, so only its Lab 5 section is read."""
        texts = {}
        for path in ('tools/lab5-identity-runbook.md', 'tools/lab5-identity-runbook.html', 'README.md',
                     'default/props.conf', 'default/eventtypes.conf', 'default/savedsearches.conf'):
            with io.open(os.path.join(REPO, *path.split('/')), encoding='utf-8') as handle:
                texts[path] = handle.read()
        readme = texts['README.md']
        texts['README.md'] = readme[readme.index('## AI Trust Lab 5'):readme.index('## Version History')]
        for path, text in texts.items():
            self.assertNotRegex(text, r'Assistant(?:\s|#)+4\.22', path)

    def test_scratch_samples_use_the_app_shape_and_real_check_ids(self):
        """H1, M1: the scratch end-to-end samples carry the identity fields the way
        4.23.0 writes them (flat, never an identity_risk object) and only CII's
        real check IDs, including is-bypass-code-used on a trusted persona."""
        sys.path.insert(0, HERE)
        import lab5_scratch_e2e
        checks, flat = {}, 0
        for _sourcetype, _offset, ev in lab5_scratch_e2e.events():
            self.assertNotIsInstance(ev.get('identity_risk'), dict, ev)
            flat += 'identity_duo_status' in ev
            if 'detail' in ev:
                checks.setdefault(ev['detail']['checkId'], set()).add(ev['detail']['login'].split('@')[0])
        self.assertGreater(flat, 0)
        self.assertLessEqual(set(checks), set(CII_CHECK_CATALOGUE))
        self.assertIn('marcus.bell', checks['is-bypass-code-used'])


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
        with io.open(NAV, encoding='utf-8') as handle:
            nav = handle.read()
        self.assertIn('<view name="TA-gen_ai_cim_home" default=\'true\'', nav)
        self.assertIn('<view name="compromised_identity"', nav)
        self.assertIn('<view name="%s" label="Duo Identity Feed" />' % DUO_VIEW, nav)
        self.assertIn('<view name="%s" label="Duo Identity Feed" />\n'
                      '    <view name="%s" label="Identity Activity" />' % (DUO_VIEW, IDENTITY_VIEW), nav)
        self.assertEqual(nav.count("default='true'"), 1)

    def test_hidden_views_are_kept_but_not_shown(self):
        nav = ET.parse(NAV).getroot()
        shown = [v.get('name') for v in nav.iter('view')]
        self.assertEqual(shown, ['TA-gen_ai_cim_home', 'ai_governance_overview', 'tokenomics',
                                 'prompt_injection_detection', 'compromised_identity', DUO_VIEW,
                                 IDENTITY_VIEW, 'reports', 'alerts'])
        for name in ('configuration', 'genai_scoring_config', 'ai_asset_discovery', 'pii_detection'):
            root = ET.parse(os.path.join(VIEWS, name + '.xml')).getroot()
            self.assertEqual(root.get('isVisible'), 'false', name)
        with io.open(os.path.join(VIEWS, 'TA-gen_ai_cim_home.xml'), encoding='utf-8') as handle:
            home = handle.read()
        self.assertNotIn('/ai_asset_discovery', home)
        self.assertNotIn('/pii_detection', home)

    def test_dashboards_menu_order(self):
        self.assertEqual(nav_collection('Dashboards'), DASHBOARDS)
        for name, _label in DASHBOARDS:
            self.assertTrue(os.path.isfile(os.path.join(VIEWS, name + '.xml')), name)


class HomeDashboardTests(StudioLayoutMixin, unittest.TestCase):
    """The home: one numbered card per menu dashboard with one live KPI, then the
    unchanged five-tile scoreboard, re-flowed for cards 05 and 06 on the same 130 px pitch."""

    def setUp(self):
        self.root, self.d = studio('TA-gen_ai_cim_home')
        self.viz, self.ds = self.d['visualizations'], self.d['dataSources']
        self.cards = sorted(re.match(r'^viz_md_(\d\d)$', v).group(1) for v in self.viz if re.match(r'^viz_md_\d\d$', v))

    def test_studio_absolute_dark(self):
        self.assertEqual((self.root.get('version'), self.root.get('theme')), ('2', 'dark'))
        self.assertEqual(self.d['layout']['type'], 'absolute')
        self.assertEqual(self.d['layout']['options']['width'], 1440)

    def test_one_numbered_card_per_menu_dashboard_in_menu_order(self):
        self.assertEqual(self.cards, ['%02d' % (i + 1) for i in range(len(DASHBOARDS))])
        for number, (view, title) in zip(self.cards, DASHBOARDS):
            md = self.viz['viz_md_' + number]['options']['markdown']
            heading, purpose, link = md.split('\n')
            self.assertEqual(heading, '## %s %s' % (number, title))
            self.assertTrue(purpose.strip() and len(purpose) <= 110, (number, purpose))
            self.assertEqual(link, '[Open %s](/app/TA-gen_ai_cim/%s)' % (title, view))

    def test_each_card_has_one_live_kpi(self):
        for number in self.cards:
            count = self.viz['viz_count_' + number]
            self.assertEqual(count['type'], 'splunk.singlevalue', number)
            self.assertEqual(count['options']['underLabel'], HOME_KPIS[number], number)
            source = self.ds[count['dataSources']['primary']]
            self.assertEqual(count['dataSources']['primary'], 'ds_card_' + number)
            window = {'last 24h': '-24h', 'last 7d': '-7d'}[HOME_KPIS[number].rsplit(', ', 1)[1]]
            self.assertEqual(source['options']['queryParameters'], {'earliest': window, 'latest': 'now'}, number)
            # A tile must show 0, not ###, on an empty window: a bare sum() or max()
            # returns no row there, so the last stats is a count/dc, or carries a
            # count beside it and fills the null (card 02 did not until v1.9.0).
            self.assertRegex(source['options']['query'],
                             r'\| stats (count|dc\([^)]*\)) as v$'
                             r'|\| stats count as rows, \w+\([^)]*\) as v \| fillnull value=0 v \| fields v$', number)

    def test_duo_card_counts_duo_authentications_through_the_macro(self):
        query = self.ds['ds_card_05']['options']['query']
        self.assertTrue(query.startswith('`genai_duo_auth_events`'), query)
        self.assertNotRegex(query, r'\bindex\s*=|\bsourcetype\s*=')

    def test_identity_card_counts_identities_active_in_either_feed(self):
        """Card 06: distinct identity join keys with a Duo sign-in or a verified AI
        turn, each feed through its macro and both keyed by genai_identity_join_key.
        A verified turn is the view's own definition (genai_identity_verified_turn),
        read through genai_identity_activity_events like every panel of the view."""
        query = self.ds['ds_card_06']['options']['query']
        self.assertTrue(query.startswith('| multisearch [ search `genai_duo_auth_events` '
                                         '| search event_type="authentication" '), query)
        self.assertIn('[ search `genai_identity_activity_events` | where `genai_identity_verified_turn` ', query)
        self.assertEqual(query.count('| eval identity_key=`genai_identity_join_key(user)` ]'), 2)
        self.assertTrue(query.endswith('| stats dc(identity_key) as v'), query)
        self.assertNotRegex(query, r'\bindex\s*=|\bsourcetype\s*=|\|\s*rest\b')
        for macro in ('genai_identity_activity_events', 'genai_identity_verified_turn', 'genai_identity_ai_events',
                      'genai_identity_join_key(1)', 'genai_duo_auth_events'):
            self.assertIn(macro, read_conf('macros.conf'))

    def test_scoreboard_is_unchanged(self):
        tiles = sorted(v for v in self.viz if re.match(r'^viz_score_\d$', v))
        self.assertEqual([(self.viz[t]['title'], self.ds[self.viz[t]['dataSources']['primary']]['options']['query'])
                          for t in tiles], SCOREBOARD)
        self.assertTrue(self.viz['viz_score_title']['options']['markdown'].startswith('## Scoreboard, last 24h'))

    def test_layout_reflows_cleanly(self):
        self.assert_wired(self.d)
        self.assert_on_canvas(self.d)
        self.assert_draw_order(self.d)
        pos = positions(self.d)
        for i, number in enumerate(self.cards):
            self.assertEqual(pos['viz_rect_' + number], {'x': 0, 'y': 110 + 130 * i, 'w': 1440, 'h': 120}, number)
            for part in ('viz_md_', 'viz_count_'):
                self.assertTrue(inside(pos[part + number], pos['viz_rect_' + number]), part + number)
            # The card's text and its KPI sit side by side, never one over the other.
            self.assertFalse(overlap(pos['viz_md_' + number], pos['viz_count_' + number]), number)
            self.assertEqual(self.viz['viz_count_' + number]['options']['backgroundColor'],
                             self.viz['viz_rect_' + number]['options']['fillColor'], number)
        tiles = sorted(v for v in self.viz if re.match(r'^viz_score_\d$', v))
        top_level = ['viz_header'] + ['viz_rect_' + n for n in self.cards] + ['viz_score_title'] + tiles
        self.assert_no_overlap(self.d, top_level)
        last_card = pos['viz_rect_' + self.cards[-1]]
        self.assertGreaterEqual(pos['viz_score_title']['y'], last_card['y'] + last_card['h'])
        title = pos['viz_score_title']
        self.assertEqual({pos[t]['y'] for t in tiles}, {title['y'] + 80})
        bottom = max(pos[t]['y'] + pos[t]['h'] for t in tiles)
        self.assertTrue(0 <= self.d['layout']['options']['height'] - bottom <= 40, bottom)


class DuoIdentityViewTests(StudioLayoutMixin, unittest.TestCase):
    """The Duo Identity Feed view (1.9.0): Studio, absolute, dark like the home, and
    reading Duo data only through the contract macros."""

    def setUp(self):
        self.root, self.d = studio(DUO_VIEW)
        self.viz, self.ds = self.d['visualizations'], self.d['dataSources']
        self.queries = {name: s['options']['query'] for name, s in self.ds.items()}
        self.spl = '\n'.join(self.queries.values())

    def test_studio_absolute_dark_like_the_home(self):
        _root, home = studio('TA-gen_ai_cim_home')
        self.assertEqual((self.root.get('version'), self.root.get('theme')), ('2', 'dark'))
        self.assertEqual(self.root.find('label').text, 'Duo Identity Feed')
        self.assertEqual(self.d['title'], 'Duo Identity Feed')
        self.assertEqual(self.d['layout']['type'], 'absolute')
        for key in ('width', 'backgroundColor', 'showTitleAndDescription'):
            self.assertEqual(self.d['layout']['options'][key], home['layout']['options'][key], key)
        cards = [v for v in self.viz.values() if v['type'] == 'splunk.rectangle']
        self.assertTrue(cards)
        for card in cards:
            self.assertEqual(card['options'], home['visualizations']['viz_rect_01']['options'])

    def test_layout(self):
        self.assert_wired(self.d)
        self.assert_on_canvas(self.d)
        self.assert_draw_order(self.d)
        pos = positions(self.d)
        kpis = sorted(v for v in self.viz if v.startswith('viz_kpi_'))
        rects = sorted(v for v in self.viz if v.startswith('viz_rect_'))
        self.assertEqual(len(kpis), 6)
        self.assert_no_overlap(self.d, ['viz_header'] + kpis + rects)
        panels = [v for v in self.viz if v not in kpis + rects + ['viz_header']]
        self.assertEqual(len(panels), len(rects))
        for panel in panels:
            hosts = [r for r in rects if inside(pos[panel], pos[r])]
            self.assertEqual(len(hosts), 1, panel)
            self.assertEqual(self.viz[panel]['options']['backgroundColor'], 'transparent', panel)

    def test_every_panel_is_titled_and_every_kpi_says_its_window(self):
        for name, v in self.viz.items():
            if v['type'] in ('splunk.table', 'splunk.column'):
                self.assertTrue(v.get('title'), name)
        windows = {'ds_auth': '-24h', 'ds_risk': '-7d'}
        for name, v in self.viz.items():
            if not name.startswith('viz_kpi_'):
                continue
            label = v['options']['underLabel']
            source = self.ds[v['dataSources']['primary']]
            base = source['options']['extend'] if source['type'] == 'ds.chain' else v['dataSources']['primary']
            if base in windows:
                self.assertTrue(label.endswith({'-24h': 'last 24h', '-7d': 'last 7d'}[windows[base]]), label)
                self.assertEqual(self.ds[base]['options']['queryParameters']['earliest'], windows[base])

    def test_duo_data_only_through_the_contract_macros(self):
        for macro in ('`genai_duo_auth_events`', '`genai_duo_activity_events`', '`genai_duo_user_events`'):
            self.assertIn(macro, self.spl)
        self.assertNotRegex(self.spl, r'\bindex\s*=|\bsourcetype\s*=|ta_gen_ai_cim:duo:')
        _root, home = studio('TA-gen_ai_cim_home')
        for query in list(self.queries.values()) + [home['dataSources']['ds_card_05']['options']['query']]:
            # Filters follow a macro as "| search", never as bare appended terms; inside
            # tstats the macro is the whole WHERE clause.
            for m in re.finditer(r'`genai_duo_\w+`', query):
                self.assertRegex(query[m.end():], r'^($|\n| \|| by )', query)

    def test_checkpoint_lag_comes_from_the_events_not_rest(self):
        """Per input instance (source = the input stanza) over the whole window, with
        tstats on the event macros: never | rest and never the checkpoint collection."""
        lag = self.queries['ds_lag']
        self.assertNotRegex(self.spl, r'\|\s*rest\b|ta_gen_ai_cim_duo_checkpoint|storage/collections')
        for macro, endpoint in (('genai_duo_auth_events', 'authentication'),
                                ('genai_duo_activity_events', 'activity'), ('genai_duo_user_events', 'users')):
            self.assertIn('tstats count as events, max(_time) as newest, max(_indextime) as indexed '
                          'where `%s` by source' % macro, lag)
            self.assertIn('endpoint="%s"' % endpoint, lag)
        self.assertIn('lag_minutes=round((now()-newest)/60, 1)', lag)
        self.assertIn('| where isnotnull(source) OR instances==0', lag)

    def test_tstats_macros_expand_to_pipe_free_terms(self):
        """A macro inside a tstats WHERE must stay index/sourcetype terms (its doc says
        so); a pipe in it, or in a macro it nests, would break the lag panel."""
        macros = read_conf('macros.conf')
        names = re.findall(r'where `(genai_duo_\w+)`', self.spl)
        self.assertEqual(len(names), 3)
        for name in names:
            definition = (macros.get(name) or {}).get('definition')
            self.assertTrue(definition, 'default/macros.conf lacks %s' % name)
            for inner in re.findall(r'`(genai_duo_\w+)`', definition):
                definition = definition.replace('`%s`' % inner, macros[inner]['definition'])
            self.assertNotIn('|', definition, name)
            self.assertNotIn('`', definition, name)

    def test_authentications_by_action_and_denied_fraud_by_user(self):
        self.assertIn('| stats count by _time, action, duo_result, duo_reason', self.queries['ds_auth'])
        self.assertEqual(self.ds['ds_auth_by_action']['options']['extend'], 'ds_auth')
        self.assertIn('timechart span=1h sum(count) by action', self.queries['ds_auth_by_action'])
        by_user = self.queries['ds_denied_by_user']
        self.assertIn('result="denied" OR result="fraud" OR reason="user_marked_fraud"', by_user)
        self.assertIn('by duo_user', by_user)
        self.assertEqual(self.ds['ds_denied_by_user']['options']['queryParameters']['earliest'], '-24h')
        # The user shown is the identity join key, never the raw Duo username: on a
        # tenant whose usernames are email addresses that would print an address.
        self.assertIn("duo_login=coalesce(user, 'user.name'), "
                      'duo_user=coalesce(`genai_identity_join_key(duo_login)`, "unknown")', by_user)
        self.assertEqual(by_user.count('duo_user='), 1)
        self.assertIn('identity join key', self.viz['viz_denied_by_user']['description'])

    def test_newest_complete_snapshot_is_judged_like_the_lookup_gen(self):
        """Complete = event count equals snapshot_total, newest by _time, over the lookup
        gen's own window: the KPI is the snapshot that search would write."""
        snapshots = self.queries['ds_snapshots']
        self.assertIn('max(_time) as taken, count as users, max(snapshot_total) as snapshot_total by snapshot_id',
                      snapshots)
        self.assertIn('complete=if(users==snapshot_total, "complete", "incomplete")', snapshots)
        self.assertIn('| where complete=="complete"\n| head 1', self.queries['ds_kpi_snapshot'])
        gen = read_conf('savedsearches.conf').get('GenAI - Identity - Duo Identity Lookup Gen')
        self.assertIsNotNone(gen, 'default/savedsearches.conf has no Duo identity lookup gen')
        self.assertIn('snapshot_events==snapshot_expected', gen['search'])
        window = self.ds['ds_snapshots']['options']['queryParameters']['earliest']
        self.assertEqual(window, gen['dispatch.earliest_time'])
        self.assertTrue(self.viz['viz_snapshots']['title'].endswith('last %s' % window.lstrip('-')))

    def test_merged_identities_are_the_duo_source_rows(self):
        merged = self.queries['ds_merged']
        self.assertTrue(merged.startswith('| inputlookup identity_lookup_expanded\n'), merged)
        self.assertIn('mvfind(\'_sources\', "^%s$")' % DUO_IDENTITY_SOURCE, merged)
        # _sources holds identity_manager stanza names; the stanza's category is a
        # label only (SA-IdentityManagement inputs.conf.spec) and never reaches the rows.
        # The Duo source does not ship as a stanza (R-INP-002): its name and category
        # are the ones in the commented example an owner copies into local/.
        stanza = 'identity_manager://' + DUO_IDENTITY_SOURCE
        self.assertNotIn(stanza, read_conf('inputs.conf'))
        example = commented_stanza('inputs.conf', stanza)
        self.assertIsNotNone(example, 'default/inputs.conf has no commented example of [%s]' % stanza)
        source = dict(line.split(' = ', 1) for line in example[1:])
        self.assertEqual(source.get('category'), 'Cisco Duo users')
        self.assertIn('(source: %s)' % source['category'], self.viz['viz_merged']['title'])
        self.assertIn('the identity source an admin adds under that name', self.viz['viz_merged']['description'])
        # No email address on the dashboard: the lookup's email column is not read,
        # and the first key (a Duo username, which may be one) is shown as the join key.
        self.assertTrue(merged.endswith('| table first_key, keys, category, watchlist, other_sources'), merged)
        self.assertIn('first_key=coalesce(mvindex(normalized_identity, 0), mvindex(identity, 0)), '
                      'first_key=`genai_identity_join_key(first_key)`, ', merged)
        self.assertIn('local part only', self.viz['viz_merged']['description'])

    def test_users_with_duo_risk_read_the_duo_rule(self):
        risk = self.queries['ds_risk']
        self.assertIn('from datamodel=Risk.All_Risk where source="%s"' % DUO_RULE, risk)
        self.assertTrue(DUO_RULE in read_conf('savedsearches.conf'),
                        'default/savedsearches.conf has no [%s]' % DUO_RULE)

    def test_duo_risk_counts_risk_events_and_findings_apart(self):
        """On ES 8 the Risk data model reads the notable index as well as the risk
        index, so a rule that writes a risk event and raises a finding is two rows.
        They are counted in two columns; risk_score stays the total, as in ES."""
        risk = self.queries['ds_risk']
        self.assertIn(' by All_Risk.risk_object, index\n| rename All_Risk.risk_object as user, index as risk_index\n',
                      risk)
        self.assertIn('sum(eval(if(risk_index=="notable", 0, n))) as risk_events, '
                      'sum(eval(if(risk_index=="notable", n, 0))) as findings, sum(risk_score) as risk_score', risk)
        self.assertTrue(risk.endswith('| table user, risk_events, findings, risk_score, base_scores, last_risk'), risk)
        description = self.viz['viz_risk']['description']
        for needle in ('rows in the risk index', 'rows in the notable index', 'counts its score twice',
                       'Needs Enterprise Security'):
            self.assertIn(needle, description)

    def test_every_macro_the_dashboards_name_exists(self):
        _root, home = studio('TA-gen_ai_cim_home')
        text = self.spl + '\n'.join(s['options']['query'] for s in home['dataSources'].values())
        macros = read_conf('macros.conf')
        names = sorted(set(re.findall(r'`(genai_duo_\w+)`', text)))
        self.assertTrue(names)
        missing = [name for name in names if name not in macros]
        self.assertEqual(missing, [], 'default/macros.conf lacks these macros')
        for name in names:
            self.assertIn('iseval', macros[name], name)

    def test_no_secret_phone_or_email_fields(self):
        """No secret, and no content the dashboards must not show: a phone number, an
        email address or a person's name (the users snapshot carries all three)."""
        self.assertNotRegex(self.spl.lower(),
                            r'ikey|skey|client_secret|phone|token|password|email|realname|firstname|lastname')
        text = json.dumps(self.viz).lower()
        self.assertNotRegex(text, r'[\w.+-]+@[\w-]+\.[\w.-]+')
        # Every table that names a user names the identity join key.
        for name in ('ds_denied_by_user', 'ds_merged'):
            self.assertIn('`genai_identity_join_key(', self.queries[name], name)

    def test_spl_is_balanced(self):
        """splunkd is not running here, so catch typos statically: quotes, backticks,
        parentheses and subsearch brackets balance in every query of both dashboards."""
        _root, home = studio('TA-gen_ai_cim_home')
        queries = list(self.queries.items()) + [(n, s['options']['query']) for n, s in home['dataSources'].items()]
        for name, query in queries:
            self.assertEqual(query.count('"') % 2, 0, name)
            self.assertEqual(query.count('`') % 2, 0, name)
            bare = re.sub(r'"[^"]*"', '""', query)
            self.assertEqual(bare.count("'") % 2, 0, name)
            depth = {'(': 0, '[': 0}
            for ch in bare:
                if ch in '([':
                    depth[ch] += 1
                elif ch in ')]':
                    depth['(' if ch == ')' else '['] -= 1
                    self.assertGreaterEqual(min(depth.values()), 0, name)
            self.assertEqual(depth, {'(': 0, '[': 0}, name)


if __name__ == '__main__':
    unittest.main()
