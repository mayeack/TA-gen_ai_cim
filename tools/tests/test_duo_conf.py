# encoding=utf-8
"""
Offline checks for the Cisco Duo content in TA-gen_ai_cim 1.9.0: the three
TA-owned sourcetypes (CIM Authentication / Change mapping), the eventtypes and
tags, the five genai_duo_* macros, the identity lookup definition, the
identity lookup gen, the Duo user-risk rule and the joined rule (a Duo denial
burst, then an application sign-in, then a blocked AI turn). Pins the ship-off defaults,
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
CHAIN = 'AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule'
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


def commands(spl):
    """The top-level commands of a one-line search, in order: split at every
    pipe that is outside a subsearch and outside a quoted string. The first
    item is the base search with its subsearches."""
    out, depth, quoted, start = [], 0, False, 0
    for at, char in enumerate(spl):
        if char == '"' and (at == 0 or spl[at - 1] != '\\'):
            quoted = not quoted
        elif quoted:
            continue
        elif char == '[':
            depth += 1
        elif char == ']':
            depth -= 1
        elif char == '|' and depth == 0:
            out.append(spl[start:at].strip())
            start = at + 1
    out.append(spl[start:].strip())
    return out


def result_fields(spl):
    """The fields a search's result rows carry: what its last stats produces (its
    "as" names and its BY fields) and what the evals after it assign, minus
    what a later "fields -" removes. Enough for the two Duo rules, whose tails
    hold no macro; a rule that ends in a macro needs it expanded first."""
    cmds = commands(spl)
    last = max(i for i, cmd in enumerate(cmds) if cmd.startswith('stats '))
    fields = set(re.findall(r'\bas (\w+)', cmds[last]))
    fields.update(name.strip() for name in cmds[last].rsplit(' by ', 1)[1].split(','))
    for cmd in cmds[last + 1:]:
        if cmd.startswith('eval '):
            fields.update(re.findall(r'(?<![=!<>\w.\'"])(\w+)=(?!=)', cmd))
        elif cmd.startswith('fields - '):
            fields.difference_update(name.strip() for name in cmd[len('fields - '):].split(','))
    return fields


OUTBOUND_TOKEN_KEYS = ('action.notable.param.rule_title', 'action.notable.param.rule_description',
                       'action.notable.param.drilldown_name', 'action.notable.param.drilldown_search',
                       'action.risk.param._risk_message')


def unknown_tokens(rule, spl):
    """(key, token) for every $token$ of a finding's title, description, risk
    message and drill-down that names no field of the search's result. ES
    leaves such a token as it is, so the finding would read "$usr$" for ever
    (each event is judged once), or its drill-down would find nothing."""
    produced = result_fields(spl)
    return [(key, token) for key in OUTBOUND_TOKEN_KEYS for token in re.findall(r'\$(\w+)\$', rule[key])
            if token not in produced]


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
        self.assertIn(CHAIN, searches)
        self.assertRegex(LOOKUP_GEN, r'^GenAI - [^-]+ - .+$')
        for name in (RULE, CHAIN):
            self.assertTrue(name.startswith('AI Governance - ') and name.endswith(' - Rule'), name)
            self.assertEqual(searches[name]['action.correlationsearch.label'],
                             'GenAI - ' + name[len('AI Governance - '):-len(' - Rule')])


class DuoShipOffTests(unittest.TestCase):

    def test_new_saved_searches_ship_disabled(self):
        searches = read_conf('savedsearches.conf')
        for name in (LOOKUP_GEN, RULE, CHAIN):
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
    """The rule judges each Duo event once, by index time, and counts by event
    time (LR-07). Live behaviour: test_duo_spl.py (fixtures, dispatch, tiling)."""

    def setUp(self):
        self.rule = read_conf('savedsearches.conf')[RULE]
        self.spl = one_line(self.rule['search'])

    def test_reads_duo_events_through_the_macro_never_the_data_model(self):
        """Duo's own log only, never PseudoCo sign-ins; and no tstats on the CIM
        Authentication data model, whose accelerated summaries keep no index time."""
        base = '`genai_duo_auth_events` (action="failure" OR signature_id="user_marked_fraud") '
        self.assertTrue(self.spl.startswith(base + '[| makeresults | addinfo '), self.spl[:160])
        self.assertEqual(self.spl.count(base), 2)            # the base search and its context finder
        self.assertNotRegex(self.spl, r'\|\s*tstats\b|datamodel|Authentication\.')
        self.assertNotIn('authentication_service', self.spl)
        self.assertNotIn('vendor_product', self.spl)

    def test_auth_macro_is_a_pure_scope(self):
        """The rule puts more search terms and subsearches after the macro, twice:
        index/sourcetype terms only, no pipe, never a PseudoCo sign-in sourcetype."""
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
        """Why the scope is the sourcetype macro and not a vendor_product filter."""
        path = os.path.join(REPO, os.pardir, 'Splunk_SA_CIM', 'default', 'data', 'models', 'Authentication.json')
        if not os.path.exists(path):
            self.skipTest('Splunk_SA_CIM is not installed beside the TA')
        with io.open(path, encoding='utf-8') as handle:
            model = json.load(handle)
        fields = set()
        for obj in model['objects']:
            fields.update(f['fieldName'] for f in obj.get('fields', []))
            for calc in obj.get('calculations', []):
                fields.update(f['fieldName'] for f in calc.get('outputFields', []))
        self.assertIn('signature_id', fields)
        self.assertNotIn('vendor_product', fields)

    def test_time_range_is_one_index_time_slot(self):
        """The job's time range is the slot of INDEX time this run judges: one cron
        period wide, so runs tile, and continuous scheduling never skips one."""
        r = self.rule
        self.assertEqual((r['cron_schedule'], r['dispatch.earliest_time'], r['dispatch.latest_time']),
                         ('*/10 * * * *', '-12m@m', '-2m@m'))
        period = int(re.match(r'^\*/(\d+) \* \* \* \*$', r['cron_schedule']).group(1))
        back = [int(re.match(r'^-(\d+)m@m$', r[k]).group(1)) for k in ('dispatch.earliest_time', 'dispatch.latest_time')]
        self.assertEqual(back[0] - back[1], period)
        self.assertEqual(r['realtime_schedule'], '0')
        for key in ('dispatch.index_earliest', 'dispatch.index_latest'):
            self.assertNotIn(key, r)                         # they would hide the context events too
        # allow_skew only delays the dispatch; allow_data_time_skew would move the
        # slot off the cron tick by the skew, so consecutive slots would not tile.
        self.assertNotIn('allow_data_time_skew', r)
        self.assertEqual(r['allow_skew'], '5m')
        s = self.spl
        # A time range with no end (all time: info_max_time is "+Infinity") is judged
        # up to now. Unguarded, floor() of it is null and splunkd rejects the term.
        self.assertIn('[| makeresults | addinfo | eval search=if(isnum(info_max_time), "_index_latest=" . '
                      'tostring(floor(info_max_time)), "_index_latest=now") | fields search ]', s)
        self.assertIn('[| makeresults | addinfo | eval search="_index_earliest=" . tostring(floor(info_min_time)) '
                      '. if(isnum(info_max_time), " _index_latest=" . tostring(floor(info_max_time)), "") '
                      '| fields search ]', s)
        self.assertEqual(s.count('isnum(info_max_time)'), 2)
        self.assertEqual(s.count('floor(info_max_time)'), 2)     # never outside its guard
        self.assertIn('| append [| makeresults | addinfo | eval slot_earliest=floor(info_min_time) '
                      '| fields slot_earliest ] | eventstats max(slot_earliest) as slot_earliest '
                      '| where isnotnull(duo_event) | eval is_new=if(indexed>=slot_earliest, 1, 0),', s)
        # Every addinfo sits in a subsearch of its own. In the main pipeline it would
        # return the event-time range the base search was given inline (the context
        # subsearch writes earliest= and latest=), not the job's slot.
        self.assertEqual(s.count('addinfo'), 3)
        self.assertEqual(s.count('[| makeresults | addinfo '), 3)
        self.assertEqual([cmd for cmd in commands(s) if cmd.startswith('addinfo')], [])
        # No slot written as a literal, and no clock but the job's own time range.
        self.assertNotRegex(s, r'_index_(earliest|latest)=[-\d]')
        self.assertNotIn('now()', s)

    def test_the_pipeline_is_pinned_command_by_command(self):
        """A command slipped in between two pinned pieces (a filter on one Duo
        application, say), a misspelt command and the lines no other test names
        would all leave the rule dead with this file green. The digest in
        fixtures/duo_rule_proof.json (test_duo_spl.py) refuses any text its
        fixtures were not run against; this says which line moved."""
        s = self.spl
        self.assertEqual([cmd.split(' ', 1)[0] for cmd in commands(s)],
                         ['`genai_duo_auth_events`', 'eval', 'where', '`genai_identity_participant_filter`', 'eval',
                          'stats', 'append', 'eventstats', 'where', 'eval', 'eval', 'eval', 'sort', 'streamstats',
                          'eval', 'streamstats', 'streamstats', 'stats', 'eval', 'where', 'mvexpand', 'eval', 'eval',
                          'eval', 'eval', 'fields'])
        self.assertIn('| stats sum(is_failure) as failures, sum(is_fraud) as fraud_reports, '
                      'sum(old_fraud) as old_fraud_reports, max(failures_10m) as max_failures_10m, '
                      'max(old_failures_10m) as old_max_failures_10m, min(eval(', s)
        self.assertIn('as fraud_epoch, values(user) as duo_users, values(signature_id) as signature_ids, '
                      'values(src) as src, values(app) as app, min(_time) as firstTime, max(_time) as lastTime '
                      'by identity_user, burst_seq | eval judged=', s)
        self.assertIn('| mvexpand judged | eval src=mvfilter(NOT match(src, '
                      '"^(127\\.\\d+\\.\\d+\\.\\d+|::1|null|unknown|-)$")) '
                      '| eval risk_score=if(judged=="fraud", 80, 40), '
                      'signature=if(judged=="fraud", "Duo user marked fraud", "Duo authentication denial burst"), '
                      'severity=if(judged=="fraud", "high", "medium") | eval user=identity_user,', s)

    def test_every_token_of_the_finding_names_a_field_of_the_result(self):
        """ES leaves a token it cannot fill as it is, and every event is judged
        once: a mistyped token would stand in every finding of a backfill, and a
        mistyped $user$ empties the drill-down."""
        r = self.rule
        produced = result_fields(self.spl)
        self.assertEqual(unknown_tokens(r, self.spl), [])
        self.assertEqual(sorted(set(token for key in OUTBOUND_TOKEN_KEYS
                                    for token in re.findall(r'\$(\w+)\$', r[key]))),
                         ['app', 'burst_earliest', 'burst_latest', 'burst_time', 'duo_users', 'failures',
                          'fraud_reports', 'max_failures_10m', 'signature', 'signature_ids', 'src', 'user'])
        for key in ('action.notable.param.nes_fields', 'alert.suppress.fields'):
            self.assertEqual([name for name in r[key].split(',') if name not in produced], [], key)
        for entity in json.loads(r['action.risk.param._risk']) + json.loads(r['action.notable.param._entities']):
            self.assertIn(entity['risk_object_field'], produced)
        for names in json.loads(r['action.notable.param.extract_artifacts']).values():
            self.assertEqual([name for name in names if name not in produced], [])
        # The check has teeth: one renamed token is found, in the key that holds it.
        broken = dict(r, **{'action.notable.param.drilldown_search':
                            r['action.notable.param.drilldown_search'].replace('$user$', '$userx$')})
        self.assertEqual(unknown_tokens(broken, self.spl), [('action.notable.param.drilldown_search', 'userx')])
        self.assertNotIn('identity_user', produced)            # removed by the final fields -

    def test_context_is_read_by_event_time(self):
        """Around the slot's events, the failures are read by EVENT time whenever they
        were indexed; with nothing new the base search reads an empty second."""
        s = self.spl
        self.assertIn('[ search `genai_duo_auth_events` (action="failure" OR signature_id="user_marked_fraud") '
                      'earliest=-181d@d latest=now [| makeresults', s)
        self.assertIn('| stats count, min(_time) as oldest, max(_time) as newest | eval search=if(count>0, '
                      '"earliest=" . tostring(floor(oldest)-3600) . " latest=" . tostring(floor(newest)+601), '
                      '"earliest=1 latest=2") | fields search ]', s)

    def test_events_are_deduplicated_on_txid_keeping_the_first_indexed(self):
        self.assertIn('| eval duo_event=coalesce(txid, _bkt . ":" . _cd, _cd) | stats min(_indextime) as indexed, '
                      'min(_time) as _time, first(user) as user, first(action) as action, '
                      'first(signature_id) as signature_id, first(src) as src, first(app) as app '
                      'by identity_user, duo_event |', self.spl)

    def test_identity_key_then_participant_filter_then_judging(self):
        s = self.spl
        needles = ('eval identity_user=`genai_identity_join_key(user)`',
                   '| where isnotnull(identity_user) AND NOT in(identity_user, "", "unknown", "null") |',
                   '`genai_identity_participant_filter`',
                   'by identity_user, duo_event',
                   '| sort 0 _time | streamstats current=f last(_time) as prev_time by identity_user',
                   'eval opens_burst=if(isnull(prev_time) OR _time-prev_time>600, 1, 0)',
                   'streamstats sum(opens_burst) as burst_seq by identity_user',
                   'streamstats time_window=10m sum(is_failure) as failures_10m, sum(old_failure) as old_failures_10m '
                   'by identity_user',
                   'by identity_user, burst_seq | eval judged=',
                   '| where isnotnull(judged) | mvexpand judged |')
        positions = [s.index(n) for n in needles]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('eval old_failure=if(is_new==0, is_failure, 0), old_fraud=if(is_new==0, is_fraud, 0)', s)

    def test_a_fraud_report_is_never_one_of_the_failures(self):
        """The props map Duo's result fraud to action failure, so a fraud report would
        count twice: as a fraud report (80) and towards a burst (40). The two
        signatures are judged on disjoint events, so five fraud reports are one finding."""
        s = self.spl
        self.assertIn('| eval is_new=if(indexed>=slot_earliest, 1, 0), '
                      'is_fraud=if(lower(signature_id)=="user_marked_fraud", 1, 0) '
                      '| eval is_failure=if(action=="failure" AND is_fraud==0, 1, 0) '
                      '| eval old_failure=', s)
        self.assertNotIn('is_failure=if(action=="failure", 1, 0)', s)
        props = read_conf('props.conf')['ta_gen_ai_cim:duo:authentication']
        self.assertIn('lower(result)=="fraud", "failure"', one_line(props['EVAL-action']))
        self.assertIn('other failed Duo authentication(s)', self.rule['action.notable.param.rule_description'])
        self.assertIn('other failed Duo authentication(s)', self.rule['action.risk.param._risk_message'])

    def test_a_burst_is_judged_in_the_slot_that_takes_it_over_the_threshold(self):
        """Before the slot under 5 in 10 minutes, with it 5 or more; a fraud report
        when the slot holds the burst's first one. The two are judged apart."""
        self.assertIn('eval judged=mvappend(if(max_failures_10m>=5 AND old_max_failures_10m<5, "burst", null()), '
                      'if(fraud_reports>0 AND old_fraud_reports==0, "fraud", null()))', self.spl)

    def test_finding_is_dated_at_the_duo_event_and_named_per_burst(self):
        s = self.spl
        self.assertIn('min(eval(if(failures_10m>=5, _time, null()))) as burst_epoch, '
                      'min(eval(if(is_fraud==1, _time, null()))) as fraud_epoch', s)
        self.assertIn('eval user=identity_user, _time=if(judged=="fraud", fraud_epoch, burst_epoch) | eval '
                      'burst_id=user . ":" . judged . ":" . tostring(floor(_time)), '
                      'burst_time=strftime(_time, "%Y-%m-%d %H:%M:%S %Z"), '
                      'burst_earliest=floor(firstTime)-600, burst_latest=floor(lastTime)+601', s)
        r = self.rule
        self.assertIn('$burst_time$', r['action.notable.param.rule_description'])
        self.assertIn('$burst_time$', r['action.risk.param._risk_message'])
        # nes_fields are what ES pre-selects in its "Suppress Event" dialog: a
        # suppression that names one burst could never match another finding.
        self.assertEqual(r['action.notable.param.nes_fields'], 'user,duo_users,src,app,signature,signature_ids,'
                         'fraud_reports,failures,max_failures_10m,risk_score,severity')
        # ES stamps a finding with its creation time, so the drill-down names its own range.
        self.assertTrue(r['action.notable.param.drilldown_search'].startswith(
            '`genai_duo_auth_events` earliest=$burst_earliest$ latest=$burst_latest$ | '))

    def test_risk_on_user_80_or_40_with_one_entity(self):
        r = self.rule
        risk = json.loads(r['action.risk.param._risk'])
        entities = json.loads(r['action.notable.param._entities'])
        self.assertEqual(risk, [{'risk_object_field': 'user', 'risk_object_type': 'user', 'risk_score': 40}])
        self.assertEqual(entities, risk)
        self.assertIn('eval risk_score=if(judged=="fraud", 80, 40)', self.spl)
        self.assertNotRegex(self.spl, r'risk_object')
        self.assertTrue(self.spl.endswith('| fields - identity_user, burst_seq, judged, old_fraud_reports, '
                                          'old_max_failures_10m, burst_epoch, fraud_epoch'), self.spl[-140:])
        self.assertEqual((r['action.notable'], r['action.risk']), ('1', '1'))
        self.assertNotIn('action.notable.param.investigation_type', r)

    def test_no_raw_content(self):
        """R-SEC-001: counts, reason codes, IPs and application names only. Duo's
        txid is the de-duplication key inside the search and nowhere else."""
        outbound = ('action.notable.param.rule_title', 'action.notable.param.rule_description',
                    'action.risk.param._risk_message', 'action.notable.param.nes_fields',
                    'action.notable.param.drilldown_search')
        for key in outbound:
            self.assertNotRegex(self.rule[key], r'input_messages|output_messages|gen_ai\.(input|output)|_raw\b'
                                                r'|explanation|isotimestamp|txid|duo_event', key)
        self.assertNotRegex(self.rule['search'], r'input_messages|output_messages|gen_ai\.(input|output)|_raw\b'
                                                 r'|explanation|isotimestamp')
        self.assertEqual(self.spl.count('txid'), 1)
        self.assertIn('coalesce(txid, ', self.spl)
        self.assertIn(' by identity_user, burst_seq ', self.spl)   # the per-event rows end in a stats

    def test_suppression_is_per_burst_not_per_window(self):
        r = self.rule
        self.assertEqual((r['alert.suppress'], r['alert.suppress.fields'], r['alert.suppress.period']),
                         ('1', 'user,signature,burst_id', '86400s'))
        self.assertEqual(r['alert.digest_mode'], '1')
        for field in r['alert.suppress.fields'].split(','):
            self.assertRegex(self.spl, r'\b%s=' % field, field)      # the search sets every key
        meta = json.loads(r['action.correlationsearch.metadata'])
        self.assertRegex(meta['detection_id'], r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
        json.loads(r['action.correlationsearch.annotations'])
        steps = json.loads(r['action.notable.param.next_steps'])
        self.assertEqual(steps['version'], 1)

    def test_search_lines_are_indented(self):
        """The gate scripts end a stanza at a line that starts with "[": every
        continuation line of the search, its subsearches included, is indented."""
        text = raw_text('default', 'savedsearches.conf')
        body = text[text.index('[%s]\n' % RULE) + len(RULE) + 3:]
        body = body[:body.index('\n# --- Scheduling ---')]
        search = body[body.index('\nsearch = '):]
        lines = search.split('\n')[2:]
        self.assertGreater(len(lines), 30)
        for line in lines:
            self.assertTrue(line.startswith('    ') or line.startswith('| '), line)
        self.assertEqual(search.count('['), search.count(']'))
        self.assertEqual(len(re.findall(r'\n +\[', search)), 4)       # four subsearches, each on an indented line
        self.assertNotIn('\n[', search)


class DuoAiChainRuleTests(unittest.TestCase):
    """The joined rule (LR-06): for one identity, a Duo denial burst, then an
    application sign-in, then a blocked verified AI turn. Judged once by index
    time and correlated by event time, like the Duo rule (LR-07). Live
    behaviour: test_duo_spl.py (chain fixtures, dispatch, tiling)."""

    STEPS = ('(`genai_identity_activity_events` (gen_ai.audit.action="identity_signin_success" OR '
             '(gen_ai.operation.name="chat" gen_ai.policy.blocked="true")))')

    def setUp(self):
        self.searches = read_conf('savedsearches.conf')
        self.rule = self.searches[CHAIN]
        self.spl = one_line(self.rule['search'])

    def test_reads_both_feeds_through_the_contract_macros(self):
        """Duo's own log and the application's identity events, never a hard-coded
        index or sourcetype and never a data model (which keeps no index time)."""
        s = self.spl
        base = '((`genai_duo_auth_events` (action="failure" OR action="success")) OR ' + self.STEPS + ') '
        self.assertTrue(s.startswith(base + '[| makeresults | addinfo '), s[:200])
        # What is NEW is looked for among the three steps only: a successful Duo
        # authentication is read as context (the sign-in's own Duo record) and
        # never makes a run read anything.
        finder = '[ search ((`genai_duo_auth_events` action="failure") OR ' + self.STEPS + ') earliest=-181d@d latest=now '
        self.assertIn(finder, s)
        self.assertEqual(s.count('`genai_duo_auth_events`'), 2)
        self.assertEqual(s.count('`genai_identity_activity_events`'), 2)
        self.assertNotRegex(s, r'\|\s*tstats\b|datamodel|Authentication\.|\bindex\s*=|sourcetype\s*=')
        self.assertNotIn('authentication_service', s)
        macros = read_conf('macros.conf')
        for name in ('genai_duo_auth_events', 'genai_identity_activity_events', 'genai_identity_ai_events',
                     'exclude_scoring_sourcetypes'):
            # The rule wraps each in parentheses and puts terms after it: no pipe.
            self.assertNotIn('|', macros[name]['definition'], name)
        self.assertIn('`genai_identity_ai_events`', macros['genai_identity_activity_events']['definition'])

    def test_time_range_is_one_index_time_slot(self):
        """The Duo rule's contract (LR-07): the job's time range is the slot of
        INDEX time this run judges, exactly one cron period wide."""
        r = self.rule
        self.assertEqual((r['cron_schedule'], r['dispatch.earliest_time'], r['dispatch.latest_time']),
                         ('*/5 * * * *', '-7m@m', '-2m@m'))
        period = int(re.match(r'^\*/(\d+) \* \* \* \*$', r['cron_schedule']).group(1))
        back = [int(re.match(r'^-(\d+)m@m$', r[k]).group(1)) for k in ('dispatch.earliest_time', 'dispatch.latest_time')]
        self.assertEqual(back[0] - back[1], period)
        self.assertEqual(back[1], 2)                         # the same 2 minutes as the Duo rule
        self.assertEqual(r['realtime_schedule'], '0')
        for key in ('dispatch.index_earliest', 'dispatch.index_latest', 'allow_data_time_skew'):
            self.assertNotIn(key, r)
        self.assertEqual(r['allow_skew'], '5m')
        s = self.spl
        duo = one_line(self.searches[RULE]['search'])
        # The two index-time subsearches are the Duo rule's own, unbounded guard included.
        for sub in ('[| makeresults | addinfo | eval search=if(isnum(info_max_time), "_index_latest=" . '
                    'tostring(floor(info_max_time)), "_index_latest=now") | fields search ]',
                    '[| makeresults | addinfo | eval search="_index_earliest=" . tostring(floor(info_min_time)) '
                    '. if(isnum(info_max_time), " _index_latest=" . tostring(floor(info_max_time)), "") '
                    '| fields search ]'):
            self.assertIn(sub, s)
            self.assertIn(sub, duo)
        self.assertEqual(s.count('isnum(info_max_time)'), 2)
        self.assertEqual(s.count('floor(info_max_time)'), 2)
        # The slot's start is read where the Duo rule reads it: in an append
        # subsearch, after the rows are one per event. addinfo in the MAIN pipeline
        # returns the event-time range the base search was given inline (its finder
        # subsearch writes earliest= and latest=), not the job's slot. The first
        # build read it there: every row counted as new, the "before the slot" half
        # of the search never ran, and a chain was raised again by every later run
        # that indexed anything within 100 minutes of it. Its 25 fixtures could not
        # see that (makeresults rows carry no inline time range).
        slot = ('| append [| makeresults | addinfo | eval slot_earliest=floor(info_min_time) | fields slot_earliest ] '
                '| eventstats max(slot_earliest) as slot_earliest ')
        self.assertIn('by identity_user, chain_event ' + slot + '| where isnotnull(step) '
                      '| eval is_new=if(indexed>=slot_earliest, 1, 0),', s)
        self.assertIn(slot, duo)
        for text in (s, duo):
            self.assertEqual(text.count('addinfo'), 3)
            self.assertEqual(text.count('[| makeresults | addinfo '), 3)    # each in a subsearch of its own
            self.assertEqual(text.count('info_min_time'), 2)                # the finder's edge and the slot's
            self.assertEqual([cmd for cmd in commands(text) if cmd.startswith('addinfo')], [])
        self.assertNotRegex(s, r'_index_(earliest|latest)=[-\d]')
        self.assertNotIn('now()', s)

    def test_context_is_read_by_event_time_100_minutes_either_side(self):
        """10 minutes of failures + 30 to the sign-in + 60 to the blocked turn = 6,000 s,
        back from the oldest new event and forward from the newest."""
        self.assertIn('| stats count, min(_time) as oldest, max(_time) as newest | eval search=if(count>0, '
                      '"earliest=" . tostring(floor(oldest)-6000) . " latest=" . tostring(floor(newest)+6001), '
                      '"earliest=1 latest=2") | fields search ]', self.spl)
        self.assertEqual(600 + 1800 + 3600, 6000)

    def test_steps_are_classified_application_first(self):
        """The application's sign-in record also says action=success, and its sign-in
        failure record action=failure: the audit action is read first, so neither is
        ever taken for a Duo authentication. A blocked turn is a VERIFIED turn's one
        chat event; any other application event is no step."""
        self.assertIn('| eval step=case(\'gen_ai.audit.action\'=="identity_signin_success", "signin", '
                      'isnotnull(\'gen_ai.audit.action\'), null(), `genai_identity_verified_turn` AND '
                      '\'gen_ai.policy.blocked\'=="true", "blocked", isnotnull(\'gen_ai.operation.name\') OR '
                      'isnotnull(\'gen_ai.provider.name\'), null(), action=="failure", "failure", '
                      'action=="success", "duo_ok") | where isnotnull(step) |', self.spl)
        # A fraud report is a failure here (the props map it to action=failure): no exclusion.
        self.assertNotIn('user_marked_fraud', self.spl)
        self.assertNotIn('is_fraud', self.spl)
        verified = read_conf('macros.conf')['genai_identity_verified_turn']['definition']
        self.assertIn("'gen_ai.identity.verified'==\"true\"", verified)

    def test_sign_in_is_matched_to_duo_on_the_transaction_id(self):
        """The application's sign-in record carries details.duo_txid, equal to the txid
        of the Duo authentication: both land in one row, which is the exact match.
        The Duo record only describes the sign-in (signin_duo); it is never a step,
        never dates the row and never decides when the row was indexed."""
        s = self.spl
        self.assertIn('| eval chain_event=coalesce(txid, \'details.duo_txid\', mvindex(\'gen_ai.event.id\', 0), '
                      '_bkt . ":" . _cd), signin_duo=if(step=="duo_ok", coalesce(authentication_method, "unknown") '
                      '. " on " . coalesce(app, "unknown"), null()), step=nullif(step, "duo_ok"), '
                      'app=if(isnull(step), null(), app), own_time=if(isnull(step), null(), _time), '
                      'own_indexed=if(isnull(step), null(), _indextime) '
                      '| stats min(own_indexed) as indexed, min(own_time) as _time, first(step) as step, '
                      'first(app) as app, first(src) as src, first(signin_duo) as signin_duo, '
                      'values(gen_ai.guardrail.ids) as guardrails by identity_user, chain_event |', s)
        self.assertIn('signin_duo=coalesce(signin_duo, "none indexed")', s)
        self.assertIn('$signin_duo$', self.rule['action.notable.param.rule_description'])
        # It never gates the chain. Structurally: the four commands that name it are
        # the eval that makes it, the two stats that carry it and the eval that words
        # it; no where and no search does, and nothing else is ever derived from it.
        naming = [cmd for cmd in commands(s) if 'signin_duo' in cmd]
        self.assertEqual([cmd.split(' ', 1)[0] for cmd in naming], ['eval', 'stats', 'stats', 'eval'])
        self.assertEqual(s.count('signin_duo'), 7)
        self.assertEqual(s.count('first(signin_duo) as signin_duo'), 2)
        for cmd in commands(s):
            if cmd.split(' ', 1)[0] in ('where', 'search'):
                self.assertNotIn('signin_duo', cmd)
        self.assertIn('| where blocked_turns>0 AND already==0 | eval src=mvfilter(', s)
        self.assertEqual(s.count('duo_ok'), 3)

    def test_identity_key_then_participant_filter_then_the_three_windows(self):
        s = self.spl
        needles = ('eval identity_user=`genai_identity_join_key(user)`',
                   '| where isnotnull(identity_user) AND NOT in(identity_user, "", "unknown", "null") |',
                   '`genai_identity_participant_filter`',
                   'by identity_user, chain_event',
                   '| sort 0 _time | streamstats time_window=10m sum(is_failure) as failures_10m, '
                   'sum(old_failure) as old_failures_10m, values(failure_app) as apps_10m by identity_user',
                   'eval burst_at=if(is_failure==1 AND failures_10m>=5, _time, null()), '
                   'old_burst_at=if(old_failure==1 AND old_failures_10m>=5, _time, null()),',
                   '| streamstats time_window=30m last(burst_at) as burst_30m, last(old_burst_at) as old_burst_30m, '
                   'last(burst_n) as n_30m, last(burst_apps) as apps_30m by identity_user',
                   '| eval signin_at=if(step=="signin" AND isnotnull(burst_30m), _time, null()),',
                   '| streamstats last(signin_at) as chain_signin, last(old_signin_at) as old_chain_signin '
                   'by identity_user',
                   '| where isnotnull(signin_at) OR (step=="blocked" AND _time-chain_signin<=3600)',
                   'by identity_user, chain_signin | where blocked_turns>0 AND already==0')
        positions = [s.index(n) for n in needles]
        self.assertEqual(positions, sorted(positions))
        # The Duo rule's own threshold: 5 failures within 10 minutes.
        self.assertIn('failures_10m>=5', one_line(self.searches[RULE]['search']))

    def test_every_quantity_is_computed_before_and_with_the_slot(self):
        """A chain is raised in the run that indexes its last missing step, and a
        blocked turn that already completed a chain before the slot never raises
        another, even when a late sign-in record re-attributes it."""
        s = self.spl
        self.assertIn('eval old_failure=if(is_new==0, is_failure, 0), failure_app=if(is_failure==1, app, null())', s)
        self.assertIn('old_signin_at=if(step=="signin" AND is_new==0 AND isnotnull(old_burst_30m), _time, null())', s)
        self.assertIn('burst_n=if(isnotnull(burst_at), failures_10m, null()), '
                      'burst_apps=if(isnotnull(burst_at), mvjoin(apps_10m, ", "), null()) |', s)
        # "Already raised" is decided per chain, by the turn that completed one: an
        # old blocked turn within the hour of an old qualifying sign-in is a turn of
        # a chain that was complete before the slot (old_turn), and only the FIRST of
        # them completed it (old_turn_n == 1). A chain that holds such a turn was
        # raised before. A chain whose turns were merely later turns of another,
        # judged chain was not: the first build suppressed it (max over any old
        # turn), and so dropped a second chain whose burst is indexed last.
        self.assertIn('| eval turn=if(step=="blocked", 1, 0), turn_time=if(turn==1, _time, null()), '
                      'old_turn=if(turn==1 AND is_new==0 AND _time-old_chain_signin<=3600, 1, 0) '
                      '| streamstats sum(old_turn) as old_turn_n by identity_user, old_chain_signin '
                      '| stats min(turn_time) as _time, max(turn_time) as lastTime, sum(turn) as blocked_turns, '
                      'max(eval(if(old_turn==1 AND old_turn_n==1, 1, 0))) as already,', s)
        self.assertNotIn('max(already)', s)
        self.assertNotIn('max(old_turn)', s)

    def test_the_pipeline_is_pinned_command_by_command(self):
        """As for the Duo rule: which command moved, when the digest says one did."""
        self.assertEqual([cmd.split(' ', 1)[0] for cmd in commands(self.spl)],
                         ['((`genai_duo_auth_events`', 'eval', 'where', '`genai_identity_participant_filter`', 'eval',
                          'where', 'eval', 'stats', 'append', 'eventstats', 'where', 'eval', 'eval', 'sort',
                          'streamstats', 'eval', 'streamstats', 'eval', 'streamstats', 'where', 'eval', 'streamstats',
                          'stats', 'where', 'eval', 'eval', 'fields'])
        self.assertIn('| where blocked_turns>0 AND already==0 | eval src=mvfilter(NOT match(src, '
                      '"^(127\\.\\d+\\.\\d+\\.\\d+|::1|null|unknown|-)$")) '
                      '| eval user=identity_user, signature="GenAI Identity Takeover Chain", severity="high", ',
                      self.spl)
        self.assertIn('| eval is_new=if(indexed>=slot_earliest, 1, 0), is_failure=if(step=="failure", 1, 0) '
                      '| eval old_failure=', self.spl)

    def test_every_token_of_the_finding_names_a_field_of_the_result(self):
        r = self.rule
        produced = result_fields(self.spl)
        self.assertEqual(unknown_tokens(r, self.spl), [])
        self.assertEqual(sorted(set(token for key in OUTBOUND_TOKEN_KEYS
                                    for token in re.findall(r'\$(\w+)\$', r[key]))),
                         ['app', 'blocked_time', 'blocked_turns', 'burst_time', 'chain_earliest', 'chain_latest',
                          'duo_app', 'duo_failures_10m', 'guardrails', 'signin_duo', 'signin_time', 'src', 'user'])
        for key in ('action.notable.param.nes_fields', 'alert.suppress.fields'):
            self.assertEqual([name for name in r[key].split(',') if name not in produced], [], key)
        for entity in json.loads(r['action.risk.param._risk']) + json.loads(r['action.notable.param._entities']):
            self.assertIn(entity['risk_object_field'], produced)
        for names in json.loads(r['action.notable.param.extract_artifacts']).values():
            self.assertEqual([name for name in names if name not in produced], [])
        for token in ('guardrails', 'duo_app', 'user'):
            broken = dict(r, **{'action.risk.param._risk_message':
                                r['action.risk.param._risk_message'].replace('$%s$' % token, '$%sx$' % token)})
            self.assertEqual(unknown_tokens(broken, self.spl), [('action.risk.param._risk_message', token + 'x')]
                             if '$%s$' % token in r['action.risk.param._risk_message'] else [])

    def test_finding_is_dated_at_the_first_blocked_turn_and_named_per_sign_in(self):
        s = self.spl
        self.assertIn('first(burst_30m) as chain_burst, first(n_30m) as duo_failures_10m, first(apps_30m) as duo_app, '
                      'first(signin_duo) as signin_duo, values(guardrails) as guardrails, values(src) as src, '
                      'values(app) as app by identity_user, chain_signin', s)
        self.assertIn('chain_id=user . ":takeover:" . tostring(floor(chain_signin)), '
                      'burst_time=strftime(chain_burst, "%Y-%m-%d %H:%M:%S %Z"), '
                      'signin_time=strftime(chain_signin, "%Y-%m-%d %H:%M:%S %Z"), '
                      'blocked_time=strftime(_time, "%Y-%m-%d %H:%M:%S %Z"), '
                      'chain_earliest=floor(chain_burst)-600, chain_latest=floor(lastTime)+1', s)
        r = self.rule
        for token in ('$burst_time$', '$signin_time$', '$blocked_time$', '$duo_failures_10m$', '$blocked_turns$'):
            self.assertIn(token, r['action.notable.param.rule_description'], token)
            self.assertIn(token, r['action.risk.param._risk_message'], token)
        self.assertIn('the finding itself is dated when it was raised', r['action.notable.param.rule_description'])
        # ES stamps a finding with its creation time: the drill-down names its own
        # range, ahead of the two scopes so that it binds both.
        self.assertTrue(r['action.notable.param.drilldown_search'].startswith(
            'earliest=$chain_earliest$ latest=$chain_latest$ ((`genai_duo_auth_events`) OR '
            '(`genai_identity_activity_events`)) | '), r['action.notable.param.drilldown_search'][:140])
        # nes_fields only pre-select ES's "Suppress Event" dialog: nothing that names one chain.
        self.assertEqual(r['action.notable.param.nes_fields'], 'user,app,duo_app,guardrails,severity')

    def test_high_severity_risk_80_on_user_with_one_entity(self):
        r = self.rule
        risk = json.loads(r['action.risk.param._risk'])
        self.assertEqual(risk, [{'risk_object_field': 'user', 'risk_object_type': 'user', 'risk_score': 80}])
        self.assertEqual(json.loads(r['action.notable.param._entities']), risk)
        self.assertEqual((r['action.notable'], r['action.risk'], r['action.notable.param.severity'],
                          r['action.notable.param.security_domain']), ('1', '1', 'high', 'identity'))
        self.assertIn('severity="high"', self.spl)
        self.assertNotRegex(self.spl, r'risk_object|risk_score')
        self.assertTrue(self.spl.endswith('| fields - identity_user, already, chain_signin, chain_burst, lastTime'),
                        self.spl[-90:])
        self.assertNotIn('action.notable.param.investigation_type', r)
        self.assertEqual(r['action.notable.param.rule_title'], 'GenAI Identity Takeover Chain: $user$')
        self.assertEqual(r['action.summary_index._name'], 'notable')
        self.assertEqual((r['action.correlationsearch'], r['action.correlationsearch.enabled']), ('0', '1'))

    def test_conventions_of_the_ai_governance_rules(self):
        """Annotations, metadata and next steps as the other AI Governance rules carry them."""
        r = self.rule
        meta = json.loads(r['action.correlationsearch.metadata'])
        self.assertRegex(meta['detection_id'], r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
        ids = [json.loads(s['action.correlationsearch.metadata'])['detection_id']
               for s in self.searches.values() if 'action.correlationsearch.metadata' in s]
        self.assertEqual(len(ids), len(set(ids)), 'detection ids must be unique')
        notes = json.loads(r['action.correlationsearch.annotations'])
        self.assertEqual(notes['analytic_story'], ['GenAI Compromised Identity'])
        self.assertEqual(notes['mitre_attack'], ['T1110', 'T1621', 'T1078'])
        self.assertEqual(notes['atlas'], ['AML.T0012'])
        steps = json.loads(r['action.notable.param.next_steps'])
        self.assertEqual(steps['version'], 1)
        self.assertNotIn('[[action|', steps['data'])           # read-only: no adaptive response is offered
        self.assertEqual(json.loads(r['action.notable.param.extract_artifacts']),
                         {'asset': ['src'], 'identity': ['user']})
        self.assertEqual(r['is_visible'], 'false')

    def test_no_raw_content_and_no_transaction_id_outbound(self):
        """R-SEC-001: counts, times, guardrail ids, factor and application names only."""
        outbound = ('action.notable.param.rule_title', 'action.notable.param.rule_description',
                    'action.risk.param._risk_message', 'action.notable.param.nes_fields',
                    'action.notable.param.drilldown_search', 'action.notable.param.next_steps')
        for key in outbound:
            self.assertNotRegex(self.rule[key], r'input_messages|output_messages|gen_ai\.(input|output)|_raw\b'
                                                r'|explanation|isotimestamp|txid|chain_event|event\.id', key)
        self.assertNotRegex(self.rule['search'], r'input_messages|output_messages|gen_ai\.(input|output)|_raw\b'
                                                 r'|explanation|isotimestamp')
        # The transaction id and the event id are the de-duplication key and nothing else.
        self.assertEqual(self.spl.count('txid'), 2)
        self.assertEqual(self.spl.count('gen_ai.event.id'), 1)
        self.assertIn('coalesce(txid, \'details.duo_txid\', ', self.spl)
        self.assertIn(' by identity_user, chain_signin ', self.spl)   # the per-event rows end in a stats

    def test_suppression_is_per_chain(self):
        r = self.rule
        self.assertEqual((r['alert.suppress'], r['alert.suppress.fields'], r['alert.suppress.period']),
                         ('1', 'user,chain_id', '86400s'))
        self.assertEqual(r['alert.digest_mode'], '1')
        for field in r['alert.suppress.fields'].split(','):
            self.assertRegex(self.spl, r'\b%s=' % field, field)

    def test_search_lines_are_indented(self):
        """The gate scripts end a stanza at a line that starts with "["."""
        text = raw_text('default', 'savedsearches.conf')
        body = text[text.index('[%s]\n' % CHAIN) + len(CHAIN) + 3:]
        body = body[:body.index('\n# --- Scheduling ---')]
        search = body[body.index('\nsearch = '):]
        lines = search.split('\n')[2:]
        self.assertGreater(len(lines), 40)
        for line in lines:
            self.assertTrue(line.startswith('    ') or line.startswith('| '), line)
        self.assertEqual(search.count('['), search.count(']'))
        self.assertEqual(len(re.findall(r'\n +\[', search)), 4)       # four subsearches, each on an indented line
        self.assertNotIn('\n[', search)

    def test_ships_disabled_after_the_duo_rule(self):
        text = raw_text('default', 'savedsearches.conf')
        self.assertEqual(self.rule['disabled'], '1')
        self.assertNotIn('run_on_startup', self.rule)
        self.assertLess(text.index('[%s]' % RULE), text.index('[%s]' % CHAIN))
        self.assertLess(text.index('[%s]' % CHAIN), text.index('# IDENTITY - CISCO DUO IDENTITY SOURCE'))
        comment = uncommented(text[text.index('# Duo denial burst, then application sign-in, then blocked AI turn'):
                                   text.index('[%s]' % CHAIN)])
        for needle in ('review decision LR-06', 'a fraud report is a failure too',
                       'matched exactly, on Duo\'s transaction id', 'never decides whether the rule fires',
                       'reads "none indexed"', 'It needs BOTH feeds in this stack',
                       'sent again with their original time and event ids',
                       'the RISK EVENT keeps that time, the FINDING is dated when it is raised',
                       # What the review found and the stanza now says.
                       'read in an append subsearch as in the Duo rule',
                       'addinfo in the main pipeline returns the event-time range the finder subsearch wrote',
                       'What was raised before is decided per chain, by the turn that completed it',
                       'the second chain within the hour whose burst is indexed last',
                       'What the finding NAMES is what was indexed when it was raised',
                       'an open decision, not built',
                       'Ships disabled; enable it together with the Duo rule, before the Duo input.'):
            self.assertIn(needle, comment)
        duo_comment = uncommented(text[text.index('# Duo user risk (v1.9.0) - feeds ES Entity Risk Scoring'):
                                       text.index('[%s]' % RULE)])
        for needle in ('both ends of the range, and never index time the scheduled runs have judged',
                       'A failed run writes no status row to scheduler.log',
                       'never with addinfo in the main pipeline'):
            self.assertIn(needle, duo_comment)
        self.assertIn('(the same chain_id, time and risk)', self.rule['description'])
        self.assertIn('names an earlier burst within the 30 minutes', self.rule['description'])
        self.assertIn('the burst named (the nearest one indexed before the sign-in), its count and the Duo record '
                      'are what was indexed when this finding was raised',
                      self.rule['action.notable.param.rule_description'])


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

    def test_rule_timing_is_documented(self):
        """LR-07: index-time judging, the enablement order and the catch-up run."""
        readme = one_line(raw_text('README.md'))
        steps = readme[readme.index('4. Enable the rule first (step 7)'):readme.index('### How the input reads Duo')]
        needles = ('it has to be running when the first poll brings the history in',
                   '7. Enable the rule. Do it before step 4 where you can',
                   '### How the rule judges Duo events',
                   '**Once, by index time.**', 'from 12 to 2 minutes before the run',
                   'continuous scheduling (`realtime_schedule = 0`)',
                   '`dispatch.earliest_time` of this rule is therefore an edge of that slot, never how far back '
                   'it reads events',
                   '**Counted by event time.**', 'never as one of the 5 failures', 'raises both (40 and 80)',
                   '**The risk event is dated at the Duo event, the finding when it is raised.**',
                   'keeps the event time in `orig_time`',
                   'adds its score to "last 24 hours" risk at the moment of the backfill',
                   '**Suppressed per burst.**', '`burst_id` is `<user>:<burst|fraud>:<epoch of the event>`',
                   'de-duplicated on Duo\'s `txid`',
                   '**A run that fails loses its slot.**',
                   # A failed scheduled run writes no status row, and status=continued rows are
                   # deferrals: the first text's "status!=success" could not find a lost slot.
                   'writes no `status` row at all', 'the slots that have NO successful run',
                   'index=_internal sourcetype=scheduler status=success savedsearch_name="' + RULE + '"',
                   '| eval missed_slots=(scheduled_time-previous)/600-1 | where missed_slots>=1',
                   '(divide by 300 for the joined rule)', '(info=failed OR info=bad_request)',
                   'still logs `success` and is in neither', 'step D8',
                   'set `allow_data_time_skew`',
                   '### Judging history that is already indexed',
                   # The one-off range has BOTH ends: a range that also covers index time the
                   # scheduled runs judged raises their findings again once they are older than
                   # the 24-hour suppression.
                   'and only that index time', 'raises their findings a second time',
                   'drops a repeat for 24 hours and no longer', 'needs BOTH ends',
                   'the START of the first slot a scheduled run judged',
                   '`scheduled_time` minus 12 minutes (minus 7 for the joined rule)',
                   '| eval judge_from=0, judge_up_to=first_run-720',
                   '**A lost slot:** exactly its two edges',
                   'In Splunk Web (edit the search\'s time range) or in `local/`, set `dispatch.earliest_time` and '
                   '`dispatch.latest_time` to those two values', 'set them back to `-12m@m` and `-2m@m`',
                   'treat a `never raised` there as a lost slot')
        found = [steps.find(needle) for needle in needles]
        self.assertEqual([needle for needle, at in zip(needles, found) if at < 0], [])
        self.assertEqual(found, sorted(found))
        # Both searches the README prints are read-only and name the rule's own period and edges.
        blocks = [block.split('```', 1)[0] for block in raw_text('README.md').split('```spl\n')[1:]
                  if 'sourcetype=scheduler status=success' in block]
        self.assertEqual(len(blocks), 2)
        period = int(re.match(r'^\*/(\d+) ', read_conf('savedsearches.conf')[RULE]['cron_schedule']).group(1)) * 60
        earliest = int(re.match(r'^-(\d+)m@m$', read_conf('savedsearches.conf')[RULE]['dispatch.earliest_time']).group(1))
        self.assertIn('/{}-1'.format(period), blocks[0])
        self.assertIn('first_run-{}'.format(earliest * 60), blocks[1])
        for block in blocks:
            self.assertNotRegex(block, r'\|\s*(collect|outputlookup|delete|sendalert)\b')
        for path in (('README.md',), ('CLAUDE.md',), ('default', 'macros.conf'), ('default', 'savedsearches.conf')):
            text = one_line(raw_text(*path)).replace(' # ', ' ')
            for stale in ('throttled for 30 minutes', 'embeds it in a `tstats` WHERE clause',
                          'embeds it in a tstats WHERE clause', 'scopes `tstats` by the sourcetype',
                          'Runs every 10 minutes over the last 30', 'Throttled per user and signature for 30 minutes',
                          # Corrected in review: neither finds a lost slot, and the second repeats
                          # every finding older than the suppression.
                          'sourcetype=scheduler status!=success', 'to cover it (for example `-31d@m`)',
                          'Do it within 24 hours of the lost run',
                          # Corrected in review: a finding is dated when it is raised, and its
                          # own Risk.All_Risk row counts in "last 24 hours" risk at the backfill.
                          '**Dated at the Duo event.**', 'A risk event dated days back is outside',
                          'does not count in ES 24-hour risk thresholds',
                          'a burst with both raises both (40 and 80)'):
                self.assertNotIn(stale, text, (path, stale))
        claude = one_line(raw_text('CLAUDE.md'))
        for needle in ('**The rule judges by index time and counts by event time**',
                       # The contract other tools rely on (a setup check that read this key as an
                       # event-time reach would refuse every stack that runs the rule).
                       '**`dispatch.earliest_time` of this rule is an index-time slot edge, never an event-time '
                       'reach; the event-time reach is the `-181d@d` in the context subsearch.**',
                       'the risk event is dated at the Duo event; the finding, and its own row in `Risk.All_Risk` '
                       '(index notable, same score), when it is raised',
                       'A fraud report is a fraud report only, never one of the 5 failures',
                       '`tstats` on the raw index does honour `_index_earliest` and returns `_indextime`',
                       '`dispatch.index_*` or `allow_data_time_skew`'):
            self.assertIn(needle, claude)

    def test_joined_rule_is_documented(self):
        """LR-06: what the joined rule needs, how it matches Duo and what it cannot do."""
        readme = one_line(raw_text('README.md'))
        self.assertIn('| *' + CHAIN + '* | the takeover story as one high finding and user risk 80:', readme)
        self.assertIn('enable *AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule* at the same '
                      'time (*The joined rule* below)', readme)
        section = readme[readme.index('### The joined rule: Duo burst, sign-in, blocked AI turn'):
                         readme.index('### How the input reads Duo')]
        needles = ('5 or more failed Duo authentications within 10 minutes',
                   'here a fraud report counts as a failure',
                   'less than 30 minutes after a moment the failures stood at 5 or more',
                   'a blocked verified AI turn within 60 minutes of that sign-in',
                   'A burst that comes after the sign-in raises nothing.',
                   '**One finding per sign-in**', '`chain_id` is `<user>:takeover:<epoch of the sign-in>`',
                   'its burst is the step that is indexed last',
                   'a chain that holds the blocked turn that completed an earlier one',
                   '**Matched to Duo on the transaction id.**', '`details.duo_txid`',
                   'The match never decides whether the rule fires', '`none indexed`',
                   'A successful Duo authentication alone is never the sign-in step.',
                   '**Judged once by index time, correlated by event time**',
                   'from 7 to 2 minutes before the run', '100 minutes either side',
                   'the sign-in or the blocked turn as well',
                   'set them back to `-7m@m` and `-2m@m`',
                   '**Dated like the Duo rule.**', 'the finding is dated when it is raised',
                   '**What a finding names is what was indexed when it was raised.**',
                   'is the same from a live run and from a backfill', 'names the earlier burst',
                   'Nothing corrects the finding afterwards', 'an open decision and is not built',
                   '**It needs both feeds in the stack.**',
                   'sent again with their original time and event ids',
                   '**Limits.**', 'have not run on a schedule yet')
        found = [section.find(needle) for needle in needles]
        self.assertEqual([needle for needle, at in zip(needles, found) if at < 0], [])
        self.assertEqual(found, sorted(found))
        self.assertIn('- ADDED (review decision LR-06, 2026-11-17): *AI Governance - Duo Denial Burst to Blocked AI '
                      'Turn Correlation - Rule* (ships **disabled**)', readme)
        claude = one_line(raw_text('CLAUDE.md'))
        for needle in ('both Duo rules (the denial-burst rule and the joined rule, below) `disabled = 1`',
                       '**The joined rule** (LR-06, 2026-11-17)',
                       'its `dispatch.earliest_time` is a slot edge too, never a reach',
                       '**a fraud report is a failure here**',
                       '**The sign-in is matched to Duo exactly, and the match never gates the rule**',
                       'reads the audit action BEFORE Duo\'s `action`',
                       'Keep the search under 4,900 characters and every `chain:` fixture under 5,000',
                       # What the review of the first build found, kept as rules.
                       'read in an append subsearch exactly as in the Duo rule',
                       '**What was raised before is decided per chain, by the blocked turn that completed it**',
                       '**What a finding names is what was indexed when it was raised**',
                       'is an open decision of the owner\'s, not built',
                       '**The proof record**', 'Never edit the digest by hand to make the suite green',
                       '`SPLUNK_TEST_REQUIRED=1` makes every live test of `test_duo_spl.py` FAIL',
                       'a rule must never be its own oracle',
                       'never with `addinfo` in the main pipeline',
                       'never with `status!=success`',
                       'the Duo input backfills, the application\'s HEC feed does not'):
            self.assertIn(needle, claude)
        macros = uncommented(raw_text('default', 'macros.conf'))
        self.assertIn('"AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule" (LR-06) does the same '
                      'with the macro wrapped in parentheses', macros)

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
