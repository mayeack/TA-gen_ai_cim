# encoding=utf-8
"""
Offline checks for the Cisco Duo content in TA-gen_ai_cim 1.9.0: the three
TA-owned sourcetypes (CIM Authentication / Change mapping), the eventtypes and
tags, the five genai_duo_* macros, the identity lookup definition, the
identity lookup gen and the Duo user-risk rule. Pins the ship-off defaults,
the names every part of the build shares, and the absence of any cisco:duo:*
props. Also R-INP-002: an ES identity or asset source ships in
default/inputs.conf only together with its lookup file, so the Duo identity
source (whose CSV is generated at runtime) ships as a commented example only,
identical to the stanza the README prints. Live behaviour is covered by
test_duo_spl.py.

    python3 -m unittest discover -s tools/tests -v
"""

import fnmatch
import io
import json
import os
import re
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
from test_lab5_conf import commented_stanza, read_conf  # noqa: E402

SOURCETYPES = ('ta_gen_ai_cim:duo:authentication', 'ta_gen_ai_cim:duo:activity', 'ta_gen_ai_cim:duo:user')
MACROS = ('genai_duo_index', 'genai_duo_auth_events', 'genai_duo_activity_events', 'genai_duo_user_events',
          'genai_duo_identity_scope')
EVENTTYPES = {
    'ta_gen_ai_cim_duo_authentication':
        ('sourcetype="ta_gen_ai_cim:duo:authentication" event_type="authentication"', {'authentication'}),
    'ta_gen_ai_cim_duo_enrollment':
        ('sourcetype="ta_gen_ai_cim:duo:authentication" event_type="enrollment"', {'change', 'account'}),
    'ta_gen_ai_cim_duo_admin_login':
        ('sourcetype="ta_gen_ai_cim:duo:activity" action.name="admin_login*"', {'authentication', 'privileged'}),
    'ta_gen_ai_cim_duo_activity':
        ('sourcetype="ta_gen_ai_cim:duo:activity" NOT action.name="admin_login*"', {'change'}),
}
LOOKUP = 'ta_gen_ai_cim_duo_identities'
# The ES identity source an owner adds once the lookup has rows. It does not
# ship as a stanza: default/inputs.conf and the README carry exactly this text.
DUO_IDENTITY_STANZA = [
    '[identity_manager://ta_gen_ai_cim_duo_identities]',
    'target = identity',
    'url = lookup://ta_gen_ai_cim_duo_identities',
    'category = Cisco Duo users',
    'description = Cisco Duo users from the Duo Admin API users snapshot (ta_gen_ai_cim:duo:user)',
    'disabled = false',
]
# The identity and asset sources that do ship: each one's CSV is tracked and packaged.
SHIPPED_IDENTITY_SOURCES = ('medadvice_identities', 'medadvice_assets', 'pseudoco_identity_personas')
LOOKUP_GEN = 'GenAI - Identity - Duo Identity Lookup Gen'
RULE = 'AI Governance - Duo Authentication Fraud or Denial Burst - Rule'
IDENTITY_COLUMNS = ['identity', 'nick', 'first', 'last', 'email', 'managedBy', 'priority', 'bunit', 'category',
                    'watchlist', 'startDate', 'endDate']
CIM_CONSTANTS = {'EVAL-vendor_product': '"Cisco Duo"', 'EVAL-vendor': '"Cisco"', 'EVAL-product': '"Duo"'}
# The sourcetypes PseudoCo Assistant's own Duo sign-in records use (gen_ai:json
# through the audit gate, demobot:audit on the Mac destination).
PSEUDOCO_SIGNIN_SOURCETYPES = ('gen_ai:json', 'demobot:audit', 'medadvice3:json', 'toyapp:json')
INDEX_TIME_KEY = re.compile(r'^(TIME_|MAX_TIMESTAMP|TZ$|DATETIME_CONFIG|LINE_BREAKER|SHOULD_LINEMERGE|BREAK_ONLY|'
                            r'MUST_BREAK|TRUNCATE|INDEXED_EXTRACTIONS|TIMESTAMP_FIELDS|TRANSFORMS-|SEDCMD-|'
                            r'CHARSET|NO_BINARY_CHECK|EVENT_BREAKER|ANNOTATE_PUNCT|rename$)')


def raw_text(*parts):
    with io.open(os.path.join(REPO, *parts), encoding='utf-8') as handle:
        return handle.read()


def one_line(spl):
    return re.sub(r'\s+', ' ', spl)


def uncommented(text):
    """The comment lines of a conf text as one line, '#' and indentation removed."""
    return one_line(' '.join(line.lstrip('#').strip() for line in text.split('\n') if line.startswith('#')))


def readme_stanza(stanza):
    """The README's fenced example of [stanza], as lines without indentation."""
    lines = raw_text('README.md').split('\n')
    starts = [i for i, line in enumerate(lines) if line.strip() == '[%s]' % stanza]
    if len(starts) != 1:
        return None
    example = []
    for line in lines[starts[0]:]:
        if line.strip().startswith('```'):
            return example
        example.append(line.strip())
    return None


def path_runs(rel):
    """Every run of whole path components of a repo path, which is what an
    unanchored tar or git pattern is matched against: for 'lookups/x.csv' that
    is 'lookups', 'lookups/x.csv' and 'x.csv' (a matched directory takes its
    contents with it)."""
    parts = rel.split('/')
    return ['/'.join(parts[i:j]) for i in range(len(parts)) for j in range(i + 1, len(parts) + 1)]


def package_exclude_for(rel):
    """The package.sh --exclude pattern that keeps repo path `rel` out of the
    tarball, or None. It over-matches if anything, which is the safe side: it
    can fail a file that would ship, never pass one that would not."""
    for pattern in re.findall(r"--exclude='([^']+)'", raw_text('package.sh')):
        if any(fnmatch.fnmatchcase(run, pattern.rstrip('/')) for run in path_runs(rel)):
            return pattern
    return None


def gitignore_rule_for(rel):
    """The .gitignore line that ignores repo path `rel`, or None (same matching)."""
    for line in raw_text('.gitignore').split('\n'):
        pattern = line.strip()
        if not pattern or pattern.startswith(('#', '!')):
            continue
        if any(fnmatch.fnmatchcase(run, pattern.strip('/')) for run in path_runs(rel)):
            return pattern
    return None


def identity_source_problems(stanza, keys):
    """Why an [identity_manager://...] stanza may not ship in default/inputs.conf
    (R-INP-002); [] when its url names a lookup definition whose file ships."""
    url = keys.get('url', '')
    definition = url[len('lookup://'):] if url.startswith('lookup://') else ''
    if not definition:
        return ['[%s]: url %r is not lookup://<definition>' % (stanza, url)]
    filename = (read_conf('transforms.conf').get(definition) or {}).get('filename')
    if not filename:
        return ['[%s]: default/transforms.conf has no [%s] with a filename' % (stanza, definition)]
    rel = 'lookups/' + filename
    problems = []
    if not os.path.isfile(os.path.join(REPO, 'lookups', filename)):
        problems.append('%s does not exist' % rel)
    excluded, ignored = package_exclude_for(rel), gitignore_rule_for(rel)
    if excluded:
        problems.append('package.sh excludes %s (%s)' % (rel, excluded))
    if ignored:
        problems.append('.gitignore ignores %s (%s)' % (rel, ignored))
    return ['[%s]: %s' % (stanza, problem) for problem in problems]


class DuoNameTests(unittest.TestCase):

    def test_sourcetype_stanzas_are_json(self):
        props = read_conf('props.conf')
        for st in SOURCETYPES:
            self.assertIn(st, props)
            self.assertEqual(props[st]['KV_MODE'], 'json', st)

    def test_no_cisco_duo_props_eventtypes_or_tags(self):
        """Security Cloud owns cisco:duo:*; the TA maps only its own sourcetypes."""
        for name in ('props.conf', 'eventtypes.conf', 'tags.conf', 'transforms.conf'):
            stanzas = read_conf(name)
            for stanza, keys in stanzas.items():
                self.assertNotRegex(stanza.lower(), r'cisco:duo', (name, stanza))
                for key, value in keys.items():
                    self.assertNotRegex(value.lower(), r'sourcetype\s*=\s*"?cisco:duo', (name, stanza, key))
        for name in MACROS:
            self.assertNotIn('cisco:duo', read_conf('macros.conf')[name]['definition'], name)

    def test_eventtypes_and_tags(self):
        et, tags = read_conf('eventtypes.conf'), read_conf('tags.conf')
        for name, (search, want_tags) in EVENTTYPES.items():
            self.assertEqual(et[name]['search'], search, name)
            self.assertNotRegex(search, r'\bindex\s*=', name)
            got = {t for t, v in tags['eventtype=' + name].items() if v == 'enabled'}
            self.assertEqual(got, want_tags, name)

    def test_five_macros_are_documented_and_declare_iseval(self):
        macros = read_conf('macros.conf')
        text = raw_text('default', 'macros.conf')
        for name in MACROS:
            self.assertIn(name, macros)
            self.assertEqual(macros[name]['iseval'], '0', name)
            head = text[:text.index('[%s]' % name)].rstrip().split('\n')
            block = '\n'.join(head[-25:])
            self.assertIn('# ' + name, block, name)
            self.assertIn('# Usage:', block, name)
        self.assertEqual(sorted(n for n in macros if n.startswith('genai_duo_')), sorted(MACROS))

    def test_macro_definitions(self):
        macros = read_conf('macros.conf')
        self.assertEqual(macros['genai_duo_index']['definition'], 'index=duo')
        for name, st in (('genai_duo_auth_events', SOURCETYPES[0]), ('genai_duo_activity_events', SOURCETYPES[1]),
                         ('genai_duo_user_events', SOURCETYPES[2])):
            self.assertEqual(macros[name]['definition'], '`genai_duo_index` sourcetype="%s"' % st, name)
        self.assertNotIn('gen_ai_log', ' '.join(macros[n]['definition'] for n in MACROS))

    def test_identity_lookup_definition(self):
        lookup = read_conf('transforms.conf')[LOOKUP]
        self.assertEqual(lookup, {'filename': LOOKUP + '.csv', 'case_sensitive_match': 'false'})

    def test_saved_search_names_follow_the_conventions(self):
        searches = read_conf('savedsearches.conf')
        self.assertIn(LOOKUP_GEN, searches)
        self.assertIn(RULE, searches)
        self.assertRegex(LOOKUP_GEN, r'^GenAI - [^-]+ - .+$')
        self.assertTrue(RULE.startswith('AI Governance - ') and RULE.endswith(' - Rule'))


class DuoShipOffTests(unittest.TestCase):

    def test_new_saved_searches_ship_disabled(self):
        searches = read_conf('savedsearches.conf')
        for name in (LOOKUP_GEN, RULE):
            self.assertEqual(searches[name]['disabled'], '1', name)
            self.assertNotIn('run_on_startup', searches[name], name)

    def test_enabled_exceptions_unchanged(self):
        enabled = sorted(n for n, s in read_conf('savedsearches.conf').items() if s.get('disabled') == '0')
        self.assertEqual(enabled, ['AI Governance - Prompt Injection Attack Correlation - Rule',
                                   'GenAI - ES - Seed Response Plan and SOAR Binding',
                                   'GenAI - Tokenomics - Seed Token Cost Pricing'])

    def test_identity_source_does_not_ship_as_a_stanza(self):
        """Not even disabled: its CSV is generated at runtime, and ES logs an ERROR
        every 5 minutes for a source whose file is missing (R-INP-002). It ships as
        a commented example an owner copies into local/, every line a comment."""
        stanza = 'identity_manager://' + LOOKUP
        self.assertNotIn(stanza, read_conf('inputs.conf'))
        text = raw_text('default', 'inputs.conf')
        named = [line for line in text.split('\n') if '[%s]' % stanza in line]
        self.assertEqual(len(named), 1, named)
        self.assertTrue(named[0].startswith('#'), named[0])
        block = text[text.index('# Cisco Duo users (v1.9.0).'):text.index('#' * 79 + '\n# CISCO DUO MODULAR INPUT')]
        self.assertEqual([line for line in block.split('\n') if line.strip() and not line.startswith('#')], [])
        example = commented_stanza('inputs.conf', stanza)
        self.assertEqual(example, DUO_IDENTITY_STANZA)
        source = dict(line.split(' = ', 1) for line in example[1:])
        self.assertEqual((source['target'], source['url'], source['category'], source['disabled']),
                         ('identity', 'lookup://' + LOOKUP, 'Cisco Duo users', 'false'))

    def test_no_duo_input_instance_in_default(self):
        for stanza, keys in read_conf('inputs.conf').items():
            self.assertFalse(stanza.startswith('ta_gen_ai_cim_duo://'), stanza)
            if stanza == 'ta_gen_ai_cim_duo':
                self.assertNotEqual(keys.get('disabled'), '0')

    def test_identity_csv_is_never_tracked_or_shipped(self):
        path = 'lookups/%s.csv' % LOOKUP
        self.assertIn(path, raw_text('.gitignore').split('\n'))
        self.assertTrue(re.search(r"--exclude='(lookups/)?%s\.csv'" % LOOKUP, raw_text('package.sh')),
                        'package.sh must exclude ' + path)
        try:
            tracked = subprocess.check_output(['git', '-C', REPO, 'ls-files', path]).decode().strip()
        except (OSError, subprocess.CalledProcessError):
            self.skipTest('git not available')
        self.assertEqual(tracked, '')


class ShippedIdentitySourceTests(unittest.TestCase):
    """R-INP-002: ES's identity manager (SA-IdentityManagement, every 300 s)
    checks the lookup file of EVERY identity_manager source, a disabled one
    included, and splunkd logs "ERROR PersistentScript ... Lookup table was not
    found" while the file is missing. So an identity or asset source ships in
    default/inputs.conf only together with its lookup file."""

    def setUp(self):
        self.sources = {stanza: keys for stanza, keys in read_conf('inputs.conf').items()
                        if stanza.startswith('identity_manager://')}

    def test_every_shipped_source_ships_its_lookup_file(self):
        """url = lookup://<definition>, the definition's filename exists under
        lookups/, and neither package.sh nor .gitignore keeps it out."""
        self.assertLessEqual({'identity_manager://' + name for name in SHIPPED_IDENTITY_SOURCES}, set(self.sources))
        for stanza, keys in sorted(self.sources.items()):
            self.assertIn(keys.get('target'), ('identity', 'asset'), stanza)
            self.assertEqual(identity_source_problems(stanza, keys), [], stanza)

    def test_the_duo_source_could_not_ship(self):
        """The check has teeth: the stanza 1.9.0 first shipped fails it, disabled or
        not, and whether or not this box has generated the CSV."""
        stanza = 'identity_manager://' + LOOKUP
        self.assertNotIn(stanza, self.sources)
        for disabled in ('true', 'false'):
            problems = identity_source_problems(stanza, {'target': 'identity', 'url': 'lookup://' + LOOKUP,
                                                         'disabled': disabled})
            self.assertIn('[%s]: package.sh excludes lookups/%s.csv (lookups/%s.csv)' % (stanza, LOOKUP, LOOKUP),
                          problems)
            self.assertIn('[%s]: .gitignore ignores lookups/%s.csv (lookups/%s.csv)' % (stanza, LOOKUP, LOOKUP),
                          problems)

    def test_a_source_must_name_a_lookup_definition_with_a_file(self):
        for keys in ({'target': 'identity'}, {'url': 'lookup://'}, {'url': 'https://corp.test/identities.csv'},
                     {'url': 'lookup://no_such_definition'}):
            self.assertEqual(len(identity_source_problems('identity_manager://x', keys)), 1, keys)

    def test_exclusion_matching(self):
        """The helpers match like tar and git: whole path components, a matched
        directory with its contents, and never a mere name prefix."""
        self.assertEqual(package_exclude_for('lookups/llm_pii_mixed_responses_200k.csv'),
                         'lookups/llm_pii_mixed_responses_200k.csv')
        self.assertEqual(package_exclude_for('local/inputs.conf'), 'local')
        self.assertEqual(package_exclude_for('bin/__pycache__/x.cpython-39.pyc'), '*.pyc')
        self.assertIsNone(package_exclude_for('.github/workflows/x.yml'))          # '.git' is not a prefix match
        self.assertEqual(gitignore_rule_for('lookups/pii_model_metadata.csv'), 'lookups/*_model_metadata.csv')
        self.assertEqual(gitignore_rule_for('local/inputs.conf'), 'local/')
        for name in SHIPPED_IDENTITY_SOURCES:
            rel = 'lookups/%s.csv' % name
            self.assertIsNone(package_exclude_for(rel), rel)
            self.assertIsNone(gitignore_rule_for(rel), rel)


class DuoPropsTests(unittest.TestCase):

    def setUp(self):
        props = read_conf('props.conf')
        self.auth, self.activity, self.user = (props[st] for st in SOURCETYPES)

    def test_search_time_only(self):
        """R-CONF-001: only search-time keys; _time comes from the input."""
        for st, stanza in zip(SOURCETYPES, (self.auth, self.activity, self.user)):
            for key in stanza:
                self.assertNotRegex(key, INDEX_TIME_KEY, (st, key))
                self.assertRegex(key, r'^(KV_MODE|FIELDALIAS-|EVAL-)', (st, key))

    def test_cim_constants(self):
        for st, stanza in zip(SOURCETYPES, (self.auth, self.activity, self.user)):
            for key, value in CIM_CONSTANTS.items():
                self.assertEqual(stanza[key], value, (st, key))
        self.assertEqual(self.auth['EVAL-authentication_service'], '"duo"')
        self.assertEqual(self.activity['EVAL-authentication_service'], '"duo"')

    def test_no_synthesized_user_agent(self):
        """Contract decision 7: Duo sends browser + version, never a user agent string."""
        for st, stanza in zip(SOURCETYPES, (self.auth, self.activity, self.user)):
            for key, value in stanza.items():
                self.assertNotRegex(key, r'user_agent', (st, key))
                self.assertNotRegex(value, r'\bAS\s+user_agent\b', (st, key))

    def test_auth_mapping(self):
        a = self.auth
        self.assertEqual(a['FIELDALIAS-duo_auth_user'], 'user.name AS user')
        self.assertEqual(a['FIELDALIAS-duo_auth_user_id'], 'user.key AS user_id')
        for key in ('EVAL-src', 'EVAL-src_ip'):
            self.assertEqual(a[key], 'if(in(lower(\'access_device.ip\'), "", "null"), null(), \'access_device.ip\')', key)
        self.assertEqual(a['FIELDALIAS-duo_auth_app'], 'application.name AS app application.name AS dest')
        self.assertEqual(a['FIELDALIAS-duo_auth_method'], 'factor AS authentication_method')
        self.assertEqual(a['FIELDALIAS-duo_auth_session'], 'trusted_session_uuid AS session_id')
        self.assertEqual(a['EVAL-signature_id'], 'if(in(lower(reason), "", "null"), result, coalesce(reason, result))')
        self.assertNotIn('txid', a['EVAL-signature_id'] + a['EVAL-signature'])
        action = one_line(a['EVAL-action'])
        for needle in ('"enrollment", "created"', '=="success", "success"', '=="fraud", "failure"',
                       '=="denied"', '=="error", "error"', '1=1, "unknown"'):
            self.assertIn(needle, action)
        # src_user is CIM's privilege-escalation field; auth_device is the 2FA phone.
        joined = ' '.join(list(a) + list(a.values()))
        self.assertNotIn('src_user', joined)
        self.assertNotIn('auth_device', joined)

    def test_enrollment_change_fields_are_gated(self):
        for key in ('EVAL-status', 'EVAL-object', 'EVAL-object_category', 'EVAL-change_type', 'EVAL-command'):
            self.assertTrue(self.auth[key].startswith('if(lower(event_type)=="enrollment"'), key)

    def test_activity_mapping(self):
        v = self.activity
        for key in ('EVAL-src', 'EVAL-src_ip'):
            self.assertEqual(v[key], 'if(in(lower(\'access_device.ip.address\'), "", "null"), null(), '
                                     '\'access_device.ip.address\')', key)
        self.assertEqual(v['FIELDALIAS-duo_activity_command'], 'action.name AS command action.name AS signature_id')
        self.assertEqual(v['FIELDALIAS-duo_activity_object'], 'target.name AS object target.key AS object_id')
        self.assertIn("'actor.name'", v['EVAL-src_user'])
        self.assertIn('"^admin_login"), null()', v['EVAL-src_user'])
        self.assertEqual(v['EVAL-change_type'], '"AAA"')

    def test_user_stanza_carries_no_contact_fields(self):
        self.assertEqual(self.user['FIELDALIAS-duo_user_user'], 'username AS user')
        text = ' '.join(list(self.user) + list(self.user.values())).lower()
        self.assertNotRegex(text, r'phone|token|webauthn|u2f|desktop')


class DuoRiskRuleTests(unittest.TestCase):

    def setUp(self):
        self.rule = read_conf('savedsearches.conf')[RULE]
        self.spl = one_line(self.rule['search'])

    def test_tstats_on_authentication_scoped_by_the_duo_macro(self):
        """Contract decision 3 / critique must_fix: Duo's own log only, never PseudoCo sign-ins."""
        self.assertTrue(self.spl.startswith('| tstats summariesonly=false allow_old_summaries=true count '
                                            'from datamodel=Authentication.Authentication where '
                                            '`genai_duo_auth_events` '), self.spl[:200])
        where = self.spl[:self.spl.index(' by _time')]
        self.assertNotIn('authentication_service', where)
        self.assertNotIn('vendor_product', self.spl)

    def test_auth_macro_is_a_pure_scope_for_tstats(self):
        """The rule embeds the macro in a tstats WHERE: index/sourcetype terms only, no
        pipe, and never one of PseudoCo Assistant's sign-in sourcetypes."""
        macros = read_conf('macros.conf')
        expanded = macros['genai_duo_auth_events']['definition'].replace(
            '`genai_duo_index`', macros['genai_duo_index']['definition'])
        self.assertNotIn('|', expanded)
        terms = re.findall(r'(\w+)=("[^"]*"|\S+)', expanded)
        self.assertEqual([t[0] for t in terms], ['index', 'sourcetype'])
        self.assertEqual(terms[1][1].strip('"'), SOURCETYPES[0])
        for st in PSEUDOCO_SIGNIN_SOURCETYPES:
            self.assertNotEqual(terms[1][1].strip('"'), st)

    def test_cim_authentication_model_has_no_vendor_product(self):
        """Why the scope is the sourcetype and not Authentication.vendor_product."""
        path = os.path.join(REPO, os.pardir, 'Splunk_SA_CIM', 'default', 'data', 'models', 'Authentication.json')
        if not os.path.exists(path):
            self.skipTest('Splunk_SA_CIM is not installed beside the TA')
        with io.open(path, encoding='utf-8') as handle:
            model = json.load(handle)
        fields = set()
        defaulted = set()
        for obj in model['objects']:
            fields.update(f['fieldName'] for f in obj.get('fields', []))
            for calc in obj.get('calculations', []):
                outputs = [f['fieldName'] for f in calc.get('outputFields', [])]
                fields.update(outputs)
                if obj['objectName'] == 'Authentication' and 'isnull(' in (calc.get('expression') or ''):
                    defaulted.update(outputs)
        self.assertIn('signature_id', fields)
        self.assertNotIn('vendor_product', fields)
        # The rule's tstats BY fields other than signature_id (which the TA's
        # props always derive from Duo's reason or result) are never null:
        # the model gives each a default, and tstats drops rows with a null BY field.
        self.assertLessEqual({'user', 'action', 'src', 'app'}, defaulted)

    def test_tstats_by_clause_is_in_the_documented_form(self):
        """tstats syntax is BY <field-list> [span=<timespan>]; a BY field that is
        null on a row drops the row, so the list holds no field the Duo feed can
        leave null (Authentication.result is a CIM 8.5 calculated field only)."""
        head = self.spl[:self.spl.index(' | rename "Authentication.*" as *')]
        self.assertTrue(head.endswith(' (Authentication.action="failure" OR '
                                      'Authentication.signature_id="user_marked_fraud") by _time, Authentication.user, '
                                      'Authentication.action, Authentication.signature_id, Authentication.src, '
                                      'Authentication.app span=1s'), head)
        self.assertNotIn('result', self.spl)
        self.assertNotIn('fillnull_value', head)
        props = read_conf('props.conf')['ta_gen_ai_cim:duo:authentication']
        self.assertIn('coalesce(reason, result)', props['EVAL-signature_id'])
        self.assertIn('lower(result)=="fraud", "failure"', one_line(props['EVAL-action']))

    def test_identity_key_then_participant_filter_then_scoring(self):
        s = self.spl
        positions = [s.index(n) for n in ('eval identity_user=`genai_identity_join_key(user)`',
                                          '`genai_identity_participant_filter`',
                                          'streamstats time_window=10m sum(failed_events) as failures_10m by identity_user',
                                          'by identity_user | where fraud_reports>0 OR max_failures_10m>=5')]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('eval fraud_events=if(lower(signature_id)=="user_marked_fraud", count, 0)', s)
        self.assertIn('| where isnotnull(identity_user) AND NOT in(identity_user, "", "unknown", "null") |', s)

    def test_risk_on_user_80_or_40_with_one_entity(self):
        r = self.rule
        risk = json.loads(r['action.risk.param._risk'])
        entities = json.loads(r['action.notable.param._entities'])
        self.assertEqual(risk, [{'risk_object_field': 'user', 'risk_object_type': 'user', 'risk_score': 40}])
        self.assertEqual(entities, risk)
        self.assertIn('eval risk_score=if(fraud_reports>0, 80, 40)', self.spl)
        self.assertNotRegex(self.spl, r'risk_object')
        self.assertTrue(self.spl.endswith('| eval user=identity_user, _time=lastTime | fields - identity_user'),
                        self.spl[-120:])
        self.assertEqual((r['action.notable'], r['action.risk']), ('1', '1'))
        self.assertNotIn('action.notable.param.investigation_type', r)

    def test_no_raw_content(self):
        """R-SEC-001: counts, reason codes, IPs and application names only."""
        for key in ('search', 'action.notable.param.rule_title', 'action.notable.param.rule_description',
                    'action.risk.param._risk_message', 'action.notable.param.nes_fields'):
            self.assertNotRegex(self.rule[key], r'input_messages|output_messages|gen_ai\.(input|output)|_raw\b'
                                                r'|explanation|isotimestamp|txid', key)

    def test_schedule_and_throttle(self):
        r = self.rule
        self.assertEqual((r['cron_schedule'], r['dispatch.earliest_time'], r['dispatch.latest_time']),
                         ('*/10 * * * *', '-30m@m', 'now'))
        self.assertEqual((r['alert.suppress'], r['alert.suppress.fields'], r['alert.suppress.period']),
                         ('1', 'user,signature', '1800s'))
        meta = json.loads(r['action.correlationsearch.metadata'])
        self.assertRegex(meta['detection_id'], r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
        json.loads(r['action.correlationsearch.annotations'])
        steps = json.loads(r['action.notable.param.next_steps'])
        self.assertEqual(steps['version'], 1)


class DuoLookupGenTests(unittest.TestCase):

    def setUp(self):
        self.search = read_conf('savedsearches.conf')[LOOKUP_GEN]
        self.spl = one_line(self.search['search'])

    def test_reads_the_user_feed_and_the_newest_complete_snapshot(self):
        s = self.spl
        self.assertTrue(s.startswith('`genai_duo_user_events` '), s[:80])
        self.assertIn('eventstats count as snapshot_events, max(snapshot_total) as snapshot_expected, '
                      'max(_time) as snapshot_time by snapshot_id', s)
        self.assertIn('where isnotnull(snapshot_id) AND snapshot_expected>0 AND snapshot_events==snapshot_expected', s)
        self.assertIn('eventstats max(snapshot_time) as newest_snapshot_time | where snapshot_time==newest_snapshot_time', s)

    def test_identity_value_is_username_email_aliases_lowercased(self):
        s = self.spl
        self.assertIn("eval _keys=mvappend(username, email, alias1, alias2, alias3, alias4, 'aliases{}')", s)
        self.assertIn("foreach aliases.* [ eval _keys=mvappend(_keys, '<<FIELD>>') ]", s)
        self.assertIn('eval _keys=mvmap(_keys, lower(trim(_keys)))', s)
        self.assertIn('eval identity_keys=mvdedup(mvfilter(_keys!="" AND _keys!="null"))', s)
        # JSON nulls arrive as the string "null"; a shared "null" key would merge every user.
        self.assertIn("foreach username email realname firstname lastname status is_enrolled created "
                      "alias1 alias2 alias3 alias4 [ eval <<FIELD>>=if(in(lower(trim('<<FIELD>>')), \"\", \"null\"), "
                      "null(), trim('<<FIELD>>')) ]", s)
        self.assertLess(s.index('| foreach username '), s.index('| eval _keys='))
        self.assertIn('identity=mvjoin(identity_keys, "|")', s)
        self.assertLess(s.index('`genai_duo_identity_scope`'), s.index('| table '))

    def test_writes_only_the_identity_columns(self):
        m = re.search(r'\| table ([^|]+) \| outputlookup override_if_empty=false create_empty=false '
                      + LOOKUP + r' \| stats count as identities$', self.spl)
        self.assertIsNotNone(m, self.spl[-300:])
        self.assertEqual([c.strip() for c in m.group(1).split(',')], IDENTITY_COLUMNS)
        self.assertNotRegex(self.spl.lower(), r'phone|token|webauthn|u2f|work_|cim_entity_zone|last_login')

    def test_columns_follow_the_identity_design(self):
        s = self.spl
        for needle in ('nick=username', 'bunit=coalesce(mvindex(_groups, 0), "cisco_duo")',
                       "_groups=mvsort(coalesce('groups{}.name', 'groups{}'))",
                       '"duo_status_" . _status', '"duo_enrolled", "duo_unenrolled"',
                       'watchlist=if(match(lower(status), "^(bypass|locked out)$"), "true", "false")',
                       'startDate=tonumber(created)', 'managedBy=""', 'priority=""', 'endDate=""'):
            self.assertIn(needle, s)

    def test_daily_disabled_and_reads_three_days(self):
        r = self.search
        self.assertRegex(r['cron_schedule'], r'^\d+ \d+ \* \* \*$')
        self.assertEqual((r['dispatch.earliest_time'], r['disabled']), ('-3d', '1'))

    def test_scope_excludes_participants_and_personas_by_key(self):
        scope = one_line(read_conf('macros.conf')['genai_duo_identity_scope']['definition'])
        self.assertTrue(scope.startswith('search NOT identity_keys="l5-*" NOT [| inputlookup pseudoco_identity_personas '),
                        scope)
        self.assertEqual(scope.count('eval identity_keys=split(lower(identity), "|") | mvexpand identity_keys'), 2)
        # A persona email key drops a row outright ...
        self.assertIn('| where like(identity_keys, "%@%") | dedup identity_keys | fields identity_keys] NOT ([', scope)
        # ... a bare persona short name only when the row has no Duo email.
        self.assertTrue(scope.endswith('| where identity_keys!="" AND NOT like(identity_keys, "%@%") '
                                       '| dedup identity_keys | fields identity_keys] AND NOT email=*)'), scope)
        # By key, never by email domain.
        self.assertNotRegex(scope, r'@[A-Za-z0-9]')
        self.assertNotIn('pseudocoassistant', scope.lower())


class DuoDocsTests(unittest.TestCase):
    """The enablement order and the identity-order facts the docs must keep."""

    def test_identity_source_is_added_only_once_its_file_has_rows(self):
        """README steps 5 to 7, in this order: lookup gen, a complete snapshot, one
        run by hand, a count above 0, THEN the identity source (local/inputs.conf or
        the ES 8.5 dialog), then the rule."""
        readme = one_line(raw_text('README.md'))
        steps = readme[readme.index('5. Enable *GenAI - Identity - Duo Identity Lookup Gen*'):]
        steps = steps[:steps.index('### How the input reads Duo')]
        needles = ('**not yet add the identity source**',
                   'run the lookup gen once by hand',
                   '`| inputlookup ta_gen_ai_cim_duo_identities | stats count` returns more than 0',
                   '6. Only then add the identity source.',
                   'The TA does not ship its stanza',
                   'checks the lookup file of every identity source every 5 minutes, a disabled source\'s included',
                   '`ERROR PersistentScript ... Lookup table was not found`',
                   'fail for every source',
                   'In `local/inputs.conf`, then restart Splunk or reload the inputs',
                   ' '.join(DUO_IDENTITY_STANZA),
                   '**Configure > All configurations**',
                   '**Data** section **Assets and identities**',
                   '**Identity lookups** tab',
                   '**New > New configuration**',
                   'choose the lookup definition `ta_gen_ai_cim_duo_identities` as the **Source**',
                   'give it the same **Name**',
                   'Do not add it on a stack where `genai_duo_identity_scope` leaves no rows',
                   '7. Enable the rule.')
        found = [steps.find(needle) for needle in needles]
        self.assertEqual([needle for needle, at in zip(needles, found) if at < 0], [])
        self.assertEqual(found, sorted(found))

    def test_inputs_conf_says_why_the_identity_source_does_not_ship(self):
        text = raw_text('default', 'inputs.conf')
        head = uncommented(text.split('\n[', 1)[0])
        self.assertIn('the Duo identity source does not ship; add it in local/', head)
        stanza = '[identity_manager://%s]' % LOOKUP
        comment = uncommented(text[text.index('# Cisco Duo users (v1.9.0).'):])
        comment = comment[:comment.index(stanza)]
        for needle in ('This identity source does NOT ship',
                       'checks the lookup file of EVERY identity_manager source, a disabled one included',
                       '"ERROR PersistentScript ... Lookup table was not found" to splunkd.log every 5 minutes',
                       'only once the file has rows', 'run the lookup gen once by hand',
                       '"| inputlookup ta_gen_ai_cim_duo_identities | stats count" returns more than 0',
                       'fails that search for EVERY source',
                       'Do not add it where genai_duo_identity_scope leaves no rows',
                       'copy the example into local/inputs.conf without the leading "#"',
                       'a restart or an inputs reload', 'dynamic_identity_spec = {"email_short": true}'):
            self.assertIn(needle, comment)

    def test_commented_example_matches_the_readme_stanza(self):
        """What an owner copies from default/inputs.conf and what the README prints
        are the same six lines, enabled."""
        stanza = 'identity_manager://' + LOOKUP
        example = commented_stanza('inputs.conf', stanza)
        self.assertEqual(example, DUO_IDENTITY_STANZA)
        self.assertEqual(readme_stanza(stanza), example)

    def test_no_doc_says_the_identity_source_ships_disabled(self):
        stale = re.compile(re.escape('identity_manager://' + LOOKUP)
                           + r'\]`?(\W{0,4}\(?ships?\W{0,3}`?disabled|\W{0,4}`?disabled = true|; both ship disabled)',
                           re.I)
        for path in (('README.md',), ('CLAUDE.md',), ('default', 'inputs.conf'), ('default', 'transforms.conf'),
                     ('default', 'savedsearches.conf'),
                     ('default', 'data', 'ui', 'views', 'ta_gen_ai_cim_duo_identity.xml')):
            text = one_line(raw_text(*path)).replace(' # ', ' ')
            self.assertIsNone(stale.search(text), path)
            self.assertNotIn('identity source and the rule all ship off', text, path)
        readme = one_line(raw_text('README.md'))
        self.assertIn('no input instance and no identity source ship', readme)
        self.assertIn('| **not shipped**: `default/inputs.conf` holds only a commented example;', readme)

    def test_canonical_key_is_the_username_not_the_first_sorted_key(self):
        """ES rejoins identity before its mvsort, so the source's pipe order holds."""
        for path in (('README.md',), ('CLAUDE.md',), ('default', 'savedsearches.conf'),
                     ('default', 'data', 'ui', 'views', 'ta_gen_ai_cim_duo_identity.xml')):
            text = one_line(raw_text(*path))
            self.assertNotRegex(text, r'(?i)first sorted', path)
            self.assertNotIn('A&I `email_short`', text, path)
        readme = one_line(raw_text('README.md'))
        self.assertIn('`dynamic_identity_spec = {"email_short": true}`', readme)
        self.assertIn('the canonical key (the first `normalized_identity` value, which UEBA reads) is the Duo '
                      'username', readme)


if __name__ == '__main__':
    unittest.main()
