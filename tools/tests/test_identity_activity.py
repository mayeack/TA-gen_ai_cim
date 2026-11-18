# encoding=utf-8
"""
Offline checks for the Identity Activity view (TA-gen_ai_cim 1.9.0,
default/data/ui/views/ta_gen_ai_cim_identity_activity.xml): per identity, what
Cisco Duo knows next to what the AI application saw. They pin what a reviewer
cannot see in a diff of one long JSON string:

  - the definition is valid Dashboard Studio JSON (no duplicate keys), absolute
    and dark, with the home's canvas colour and card rectangles;
  - every search reads events only through the contract macros, is bounded by
    the time input and honours the identity input, which is only ever compared
    as a field value;
  - every KPI returns a row on an empty window (a bare stats sum() returns a
    null and Studio draws ###);
  - no | rest, no join, no write, no "$" that is not a token, and no content
    field (prompt or response text, email, phone) reaches a panel;
  - the panels fed by Enterprise Security say so, and the Duo and application
    panels do not depend on it;
  - a verified AI turn is its one chat event (genai_identity_verified_turn),
    never every event that carries the identity flag;
  - a turn that only claims an identity's name (genai_identity_claimed_turn: what
    a prompt-injection spray writes) is counted beside the verified turns and
    apart from them, never creates a row and is never read as a sign-in;
  - one classification of a Duo outcome (genai_identity_duo_class) feeds the
    tiles, the overview and the timeline;
  - risk events and findings are counted apart (ES 8's Risk data model reads
    both the risk and the notable index);
  - the Duo sign-in to AI activity panel matches an application sign-in on
    Duo's transaction id and a verified turn on user and time, and says so.

    python3 -m unittest discover -s tools/tests -v

SIMULATIONS are makeresults rows run through the view's own text (a branch's
eval, a search's tail from a marker, the macros). Offline they are checked for
shape; SimulationLiveTests runs them on a real splunkd and compares the answer.

IdentityActivityLiveTests dispatches every data source, over an empty window
and over the default one, on a real splunkd (read-only searches). It needs a
Splunk where this branch's conf is visible from SPLUNK_TEST_APP and is skipped
otherwise, like test_duo_spl.py:

    SPLUNK_TEST_URL=https://localhost:8090 SPLUNK_TEST_USER=admin \\
    SPLUNK_TEST_PASSWORD=... python3 -m unittest tools.tests.test_identity_activity -v
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
sys.path.insert(0, HERE)
from test_lab5_conf import (NAV, VIEWS, StudioLayoutMixin, inside, nav_collection, overlap, positions,  # noqa: E402
                            read_conf, studio)

VIEW = 'ta_gen_ai_cim_identity_activity'
DUO_VIEW = 'ta_gen_ai_cim_duo_identity'
HOME = 'TA-gen_ai_cim_home'
ES_NOTE = 'Needs Enterprise Security'
# The only tokens the view uses, and the one form the identity token takes.
TOKENS = ('$time.earliest$', '$time.latest$', '$identity|s$')
IDENTITY_FILTER = '| search identity_key=$identity|s$'
# Where events may come from: the Duo feed and the AI application, by macro.
EVENT_MACROS = ('genai_duo_auth_events', 'genai_duo_user_events', 'genai_identity_activity_events',
                'genai_identity_claimed_events')
# The five macros behind the view (default/macros.conf, "IDENTITY ACTIVITY MACROS").
ACTIVITY_EVENTS = ('`genai_identity_ai_events` identity_* '
                   '(gen_ai.identity.verified="true" OR gen_ai.audit.action="identity_*")')
VERIFIED_TURN = ("(isnull('gen_ai.audit.action') AND 'gen_ai.identity.verified'==\"true\" AND "
                 "isnotnull('gen_ai.provider.name') AND 'gen_ai.operation.name'==\"chat\")")
CLAIMED_EVENTS = '`genai_identity_ai_events` gen_ai.operation.name="chat" NOT gen_ai.identity.verified="true"'
CLAIMED_TURN = ("(isnull('gen_ai.audit.action') AND isnotnull('gen_ai.provider.name') AND "
                "'gen_ai.operation.name'==\"chat\" AND coalesce('gen_ai.identity.verified', \"false\")!=\"true\" AND "
                "isnotnull(user))")
# The one label of a claimed turn on the timeline, and the only two searches that read one.
CLAIMED = 'AI turn claimed, not verified'
CLAIMED_SEARCHES = ('ds_overview', 'ds_timeline')
# Its colour on the timeline: pale, the lightest series of the chart. A saturated orange
# (#F1813F, between the red of a Duo failure and the yellow of a blocked turn) was the
# first choice; under simulated protanopia it measured a CIEDE2000 distance of 2.8 from
# the green of "Duo success", so a claimed turn could be read as a sign-in by colour.
# Lightness separates it in every vision mode (13.8 or more from every other series).
CLAIMED_COLOUR = '#FFEFBF'
DUO_CLASS = ('case(lower(result)=="fraud" OR lower(reason)=="user_marked_fraud", "fraud", lower(result)=="success", '
             '"success", lower(result)=="denied" OR lower(result)=="failure", "denied", true(), "other")')
# The detection that shares two of the view's macros (default/savedsearches.conf).
JOINED_RULE = 'AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule'
# The risk subsearches filter on the identity as well, one level in.
NESTED_FILTER = '    ' + IDENTITY_FILTER
# The Enterprise Security objects the view reads.
ES_SOURCES = ('datamodel=Risk.All_Risk', 'identity_lookup_expanded')
# KPI tile -> (label, the feed its number comes from).
KPIS = [('viz_kpi_duo_identities', 'identities with Duo sign-ins', 'Cisco Duo'),
        ('viz_kpi_duo_success', 'Duo sign-ins succeeded', 'Cisco Duo'),
        ('viz_kpi_duo_denied', 'Duo sign-ins denied or marked fraud', 'Cisco Duo'),
        ('viz_kpi_ai_identities', 'identities with verified AI turns', 'AI application'),
        ('viz_kpi_ai_blocked', 'verified AI turns blocked', 'AI application'),
        ('viz_kpi_risk', 'identities with ES user risk', ES_NOTE)]
# Panel -> (type, title), top to bottom.
PANELS = [('viz_overview', 'splunk.table', 'Identity overview'),
          ('viz_timeline', 'splunk.column', 'Activity timeline'),
          ('viz_duo_to_ai', 'splunk.table', 'Duo sign-in to AI activity'),
          ('viz_addresses', 'splunk.table', 'Source addresses by identity'),
          ('viz_risk', 'splunk.bar', 'Risk by detection')]
ES_PANELS = ['viz_kpi_risk', 'viz_overview', 'viz_timeline', 'viz_risk']
ACTIVITIES = ['Duo success', 'Duo failure', 'Duo other', 'application sign-in', 'AI turn allowed', 'AI turn blocked',
              CLAIMED, 'risk event', 'finding']
OVERVIEW_COLUMNS = ['identity_key', 'duo_status', 'duo_enrolled', 'duo_success', 'duo_denied', 'duo_fraud', 'duo_other',
                    'last_duo_signin', 'last_duo_factor', 'app_signins', 'ai_turns', 'ai_blocked', 'gate_verdicts',
                    'claimed_not_verified', 'claimed_blocked', 'risk_events', 'findings', 'risk_score', 'es_category']
DUO_TO_AI_COLUMNS = ['identity_key', 'duo_signin', 'duo_application', 'duo_factor', 'duo_result', 'duo_src',
                     'duo_denied_10m', 'app_event', 'app_time', 'app_src', 'seconds_apart', 'addresses_match',
                     'matched_on']
CONTENT_FIELDS = (r'input_messages|output_messages|gen_ai\.input|gen_ai\.output|system_instructions|explanation|'
                  r'_raw|email|phone|realname|firstname|lastname')
WRITES = r'\|\s*(outputlookup|outputcsv|collect|sendalert|sendemail|delete|tscollect|mcollect|map|script)\b'


def luminance(colour):
    """WCAG relative luminance of a #RRGGBB colour, 0 (black) to 1 (white)."""
    channels = [int(colour[i:i + 2], 16) / 255.0 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    dupes = sorted(set(k for k in keys if keys.count(k) > 1))
    if dupes:
        raise ValueError('duplicate JSON keys: %s' % ', '.join(dupes))
    return dict(pairs)


def raw_definition(name):
    """(root element, the definition's JSON text) of a view in default/."""
    root = ET.parse(os.path.join(VIEWS, name + '.xml')).getroot()
    return root, root.find('definition').text


def full_query(ds, name):
    """The SPL a data source runs: a chain's own query after its base search's."""
    source = ds[name]
    if source['type'] == 'ds.chain':
        return ds[source['options']['extend']]['options']['query'] + '\n' + source['options']['query']
    return source['options']['query']


def own_query(ds, name):
    return ds[name]['options']['query']


def resolve(query, identity='*'):
    """query with the identity token filled in the way Studio's |s filter does:
    wrapped in double quotes with every quote inside escaped. Backslashes are
    escaped here as well, so a test value is one SPL string whatever it holds."""
    quoted = '"%s"' % identity.replace('\\', '\\\\').replace('"', '\\"')
    return query.replace('$identity|s$', quoted)


def without_tokens(text):
    for token in TOKENS:
        text = text.replace(token, '')
    return text


def last_stats_guarantees_a_row(query):
    """True when a KPI query cannot come back empty or null: its last stats has
    no BY clause and is a bare count or dc (0 on no input), or it carries a count
    beside the sum and the null sum is then filled with 0."""
    lines = query.split('\n')
    at = [i for i, line in enumerate(lines) if line.startswith('| stats ')]
    if not at:
        return False
    stats, rest = lines[at[-1]], lines[at[-1] + 1:]
    if re.search(r'\bby\b', stats):
        return False
    if re.match(r'^\| stats (count|dc\(\w+\)) as v$', stats):
        return rest == []
    return (re.match(r'^\| stats count as rows, sum\(\w+\) as v$', stats) is not None and
            rest == ['| fillnull value=0 v', '| fields v'])


class ViewTestCase(StudioLayoutMixin, unittest.TestCase):

    def setUp(self):
        self.root, self.d = studio(VIEW)
        self.viz, self.ds = self.d['visualizations'], self.d['dataSources']
        self.searches = sorted(n for n, s in self.ds.items() if s['type'] == 'ds.search')
        self.chains = sorted(n for n, s in self.ds.items() if s['type'] == 'ds.chain')
        self.spl = '\n'.join(own_query(self.ds, n) for n in self.ds)

    def feeds(self, viz):
        """The full SPL behind a visualization."""
        return full_query(self.ds, self.viz[viz]['dataSources']['primary'])


class ViewShapeTests(ViewTestCase):
    """Studio v2, absolute, dark, with the home's canvas and cards."""

    def test_definition_is_valid_json_without_duplicate_keys(self):
        root, text = raw_definition(VIEW)
        definition = json.loads(text, object_pairs_hook=no_duplicate_keys)
        self.assertEqual(sorted(definition), ['dataSources', 'defaults', 'description', 'inputs', 'layout',
                                              'title', 'visualizations'])
        self.assertEqual(definition['title'], 'Identity Activity')
        self.assertEqual(root.find('label').text, 'Identity Activity')
        self.assertEqual(root.find('description').text, definition['description'])
        with self.assertRaises(ValueError):
            json.loads('{"a": 1, "a": 2}', object_pairs_hook=no_duplicate_keys)

    def test_studio_absolute_dark_like_the_home_and_the_duo_view(self):
        _root, home = studio(HOME)
        _root, duo = studio(DUO_VIEW)
        self.assertEqual((self.root.tag, self.root.get('version'), self.root.get('theme')),
                         ('dashboard', '2', 'dark'))
        self.assertEqual(self.d['layout']['type'], 'absolute')
        for key in ('width', 'backgroundColor', 'showTitleAndDescription'):
            self.assertEqual(self.d['layout']['options'][key], home['layout']['options'][key], key)
        cards = [v for v in self.viz.values() if v['type'] == 'splunk.rectangle']
        self.assertEqual(len(cards), len(PANELS))
        for card in cards:
            self.assertEqual(card['options'], home['visualizations']['viz_rect_01']['options'])
        # Type scale: the header and the tiles carry the same options as their siblings.
        header = dict(self.viz['viz_header']['options'], markdown='')
        self.assertEqual(header, dict(duo['visualizations']['viz_header']['options'], markdown=''))
        self.assertTrue(self.viz['viz_header']['options']['markdown'].startswith('## Identity Activity\n'))
        sibling = dict(duo['visualizations']['viz_kpi_auth']['options'], underLabel='')
        for name, _label, _feed in KPIS:
            tile = dict(self.viz[name]['options'], underLabel='', majorColor='#FFFFFF')
            self.assertEqual(tile, sibling, name)
        for name, kind, _title in PANELS:
            if kind == 'splunk.table':
                self.assertEqual(self.viz[name]['options']['headerVisibility'], 'fixed', name)

    def test_layout(self):
        self.assert_wired(self.d)
        self.assert_on_canvas(self.d)
        self.assert_draw_order(self.d)
        pos = positions(self.d)
        kpis = [name for name, _label, _feed in KPIS]
        rects = sorted(v for v in self.viz if v.startswith('viz_rect_'))
        self.assertEqual(sorted(v for v in self.viz if v.startswith('viz_kpi_')), sorted(kpis))
        self.assertEqual(len({(pos[k]['y'], pos[k]['w'], pos[k]['h']) for k in kpis}), 1)
        self.assertEqual([pos[k]['x'] for k in kpis], sorted(pos[k]['x'] for k in kpis))
        self.assert_no_overlap(self.d, ['viz_header'] + kpis + rects)
        panels = [name for name, _kind, _title in PANELS]
        self.assertEqual(sorted(panels + kpis + rects + ['viz_header']), sorted(self.viz))
        for panel in panels:
            hosts = [r for r in rects if inside(pos[panel], pos[r])]
            self.assertEqual(hosts, ['viz_rect_' + panel[len('viz_'):]], panel)
            self.assertEqual(self.viz[panel]['options']['backgroundColor'], 'transparent', panel)
        # The panels follow the order of the brief, top to bottom then left to right.
        order = sorted(panels, key=lambda p: (pos[p]['y'], pos[p]['x']))
        self.assertEqual(order, panels)
        bottom = max(p['y'] + p['h'] for p in pos.values())
        self.assertTrue(0 <= self.d['layout']['options']['height'] - bottom <= 40, bottom)

    def test_six_kpi_tiles_and_five_titled_panels(self):
        for name, label, feed in KPIS:
            tile = self.viz[name]
            self.assertEqual((tile['type'], tile['options']['underLabel'], tile['description']),
                             ('splunk.singlevalue', label, feed), name)
            self.assertTrue(tile['dataSources']['primary'].startswith('ds_kpi_'), name)
        for name, kind, title in PANELS:
            panel = self.viz[name]
            self.assertEqual((panel['type'], panel['title']), (kind, title), name)
            self.assertTrue(panel['description'].strip(), name)


class InputTests(ViewTestCase):
    """A time range (last 14 days) and an identity dropdown (All = *); every search honours both."""

    def test_inputs_have_defaults(self):
        inputs = self.d['inputs']
        self.assertEqual(self.d['layout']['globalInputs'], ['input_time', 'input_identity'])
        self.assertEqual(sorted(inputs), ['input_identity', 'input_time'])
        time = inputs['input_time']
        self.assertEqual((time['type'], time['options']), ('input.timerange',
                                                           {'token': 'time', 'defaultValue': '-14d@d,now'}))
        identity = inputs['input_identity']
        self.assertEqual(identity['type'], 'input.dropdown')
        self.assertEqual((identity['options']['token'], identity['options']['defaultValue']), ('identity', '*'))
        self.assertEqual(identity['context']['statics'], [['All identities'], ['*']])
        # The token also has a default of its own, so a search never sees it unset.
        self.assertEqual(self.d['defaults'], {'tokens': {'default': {'identity': {'value': '*'}}}})

    def test_every_token_used_has_a_default(self):
        used = set()
        for source in self.ds.values():
            text = source['options']['query'] + ' ' + json.dumps(source['options'].get('queryParameters', {}))
            used.update(re.findall(r'\$[^$\s]+\$', text))
        self.assertEqual(used, set(TOKENS))
        text = json.dumps(self.viz)
        self.assertEqual(re.findall(r'\$[^$\s]+\$', text), [], 'no token in a title, label or description')

    def test_no_dollar_sign_that_is_not_a_token(self):
        """Studio pairs any two "$" into a token, so a regex "$" anchor in a query
        that also holds a token silently swallows the SPL between them."""
        for name in self.ds:
            self.assertNotIn('$', without_tokens(own_query(self.ds, name)), name)

    def test_every_search_is_bounded_by_the_time_input(self):
        self.assertEqual(self.searches, ['ds_addresses', 'ds_base', 'ds_duo_to_ai', 'ds_overview', 'ds_risk',
                                         'ds_timeline'])
        for name in self.searches:
            self.assertEqual(self.ds[name]['options']['queryParameters'],
                             {'earliest': '$time.earliest$', 'latest': '$time.latest$'}, name)
        for name in self.chains:
            self.assertNotIn('queryParameters', self.ds[name]['options'], name)
            self.assertIn(self.ds[name]['options']['extend'], self.searches, name)
        self.assertNotRegex(self.spl, r'\b(earliest|latest|_index_earliest|_index_latest)\s*=')

    def test_only_the_sign_in_chain_re_runs_itself(self):
        """Duo's log reaches the index minutes after the application's own records
        (the input's lag plus its poll interval), so the sign-in chain re-runs every
        5 minutes and a fresh sign-in pairs up without a reload. Nothing else does."""
        for name, source in self.ds.items():
            extra = {k: v for k, v in source['options'].items() if k not in ('query', 'queryParameters', 'extend')}
            self.assertEqual(extra, {'refresh': '5m', 'refreshType': 'delay'} if name == 'ds_duo_to_ai' else {}, name)

    def test_every_panel_honours_the_identity_input(self):
        """Once in the main pipeline of every panel's search. The three searches that
        read Risk.All_Risk apply it inside that subsearch too, so one identity's risk
        is one identity's rows (append keeps only the first 50,000)."""
        for name, v in self.viz.items():
            if 'dataSources' not in v:
                continue
            lines = self.feeds(name).split('\n')
            self.assertEqual(lines.count(IDENTITY_FILTER), 1, name)
            self.assertEqual(lines.count(NESTED_FILTER), 1 if name in ES_PANELS else 0, name)
        # The dropdown's own feed cannot filter on the token it sets.
        self.assertNotIn('$identity', full_query(self.ds, 'ds_identities'))

    def test_identity_token_is_only_ever_compared_as_a_field_value(self):
        """Always "| search identity_key=<quoted value>": the |s filter quotes and
        escapes it, and it never lands in a macro argument or an eval. The only
        indented copy is the same comparison on the rows of a risk tstats."""
        self.assertEqual(self.spl.count('$identity'), self.spl.count(IDENTITY_FILTER))
        self.assertGreater(self.spl.count(IDENTITY_FILTER), 0)
        for name in self.ds:
            lines = own_query(self.ds, name).split('\n')
            for i, line in enumerate(lines):
                if '$identity' not in line:
                    continue
                self.assertIn(line, (IDENTITY_FILTER, NESTED_FILTER), name)
                if line == NESTED_FILTER:
                    opened = [j for j in range(i) if lines[j].startswith('    [')][-1]
                    self.assertTrue(lines[opened].startswith('    [| tstats '), (name, lines[opened][:40]))
                    self.assertIn('identity_key=`genai_identity_join_key(risk_object)`', lines[i - 1], name)
        self.assertEqual(resolve(IDENTITY_FILTER), '| search identity_key="*"')
        self.assertEqual(resolve(IDENTITY_FILTER, 'a"b\\c'), '| search identity_key="a\\"b\\\\c"')

    def test_identity_dropdown_lists_the_identities_of_either_feed_in_the_range(self):
        identity = self.d['inputs']['input_identity']
        self.assertEqual(identity['dataSources'], {'primary': 'ds_identities'})
        feed = self.ds['ds_identities']
        self.assertEqual((feed['type'], feed['options']['extend']), ('ds.chain', 'ds_base'))
        self.assertTrue(feed['options']['query'].endswith('| fields identity_key'))
        base = own_query(self.ds, 'ds_base')
        self.assertIn('`genai_duo_auth_events`', base)
        self.assertIn('`genai_identity_activity_events`', base)
        self.assertIn(' by identity_key', base)
        for key in ('label', 'value'):
            self.assertIn('seriesByName("identity_key")', identity['context'][key])
        self.assertEqual(identity['options']['items'], '>frame(label, value) | prepend(formattedStatics) | objects()')


class SearchRuleTests(ViewTestCase):
    """What every search of the view must and must not do."""

    def test_events_only_through_the_contract_macros(self):
        """Never a hard-coded index or sourcetype: the Duo feed through genai_duo_*,
        the AI application through genai_identity_activity_events (which reads
        genai_identity_ai_events), ES through the Risk data model and
        identity_lookup_expanded."""
        self.assertNotRegex(self.spl, r'\bindex\s*=|\bsourcetype\s*=|ta_gen_ai_cim:duo:|gen_ai_log|gen_ai:json')
        seen = set()
        for name in self.searches:
            query = own_query(self.ds, name)
            self.assertTrue(query.startswith('| multisearch\n'), name)
            for m in re.finditer(r'\[\s*(\|?)\s*(\w+)\s+(\S+)', query):
                piped, command, first = m.groups()
                if command == 'search' and not piped:
                    self.assertIn(first.strip('`'), EVENT_MACROS, (name, m.group(0)))
                    self.assertTrue(first.startswith('`') and first.endswith('`'), (name, m.group(0)))
                    seen.add(first.strip('`'))
                elif command == 'tstats' and piped:
                    tail = query[m.start():].split(']', 1)[0]
                    self.assertIn(' from datamodel=Risk.All_Risk where All_Risk.risk_object_type="user" by ', tail,
                                  name)
                else:
                    # The only other bracket is a foreach template, which reads no data.
                    self.assertEqual((piped, command), ('', 'eval'), (name, m.group(0)))
                    self.assertTrue(first.startswith('<<FIELD>>='), (name, m.group(0)))
        self.assertEqual(seen, set(EVENT_MACROS))
        # The application branch adds no terms of its own: the macro is the whole base search.
        self.assertEqual(self.spl.count('    [ search `genai_identity_activity_events`\n    | eval '),
                         self.spl.count('genai_identity_activity_events'))
        self.assertEqual(self.spl.count('    [ search `genai_identity_claimed_events`\n    | eval '),
                         self.spl.count('genai_identity_claimed_events'))
        for name in self.chains:
            self.assertNotIn('[', own_query(self.ds, name), 'a chain holds no subsearch: %s' % name)
        self.assertNotRegex(self.spl, r'\b(inputlookup|inputcsv|loadjob|savedsearch|makeresults|metadata|dbinspect)\b')
        self.assertEqual(self.spl.count('identity_lookup_expanded'), 1)

    def test_filters_follow_a_duo_macro_as_a_search_command(self):
        """Like the Duo Identity Feed view: a site may repoint a genai_duo_* macro, so
        nothing is appended to it as bare terms."""
        for name in self.ds:
            query = own_query(self.ds, name)
            for m in re.finditer(r'`genai_duo_\w+`', query):
                self.assertRegex(query[m.end():], r'^\n\s+\| ', name)
        self.assertEqual(self.spl.count('`genai_duo_auth_events`\n    | search event_type="authentication"\n'),
                         self.spl.count('`genai_duo_auth_events`'))

    def test_identity_key_is_always_the_join_key_macro(self):
        made = re.findall(r'\bidentity_key=(\S+?)[,\s\]]', self.spl.replace(IDENTITY_FILTER, ''))
        self.assertGreater(len(made), 10)
        self.assertEqual(set(made), {'`genai_identity_join_key(user)`', '`genai_identity_join_key(username)`',
                                     '`genai_identity_join_key(risk_object)`'})

    def test_every_macro_named_exists(self):
        macros = read_conf('macros.conf')
        names = sorted(set(re.findall(r'`(\w+)(?:\([^`]*\))?`', self.spl)))
        self.assertEqual(names, ['genai_duo_auth_events', 'genai_duo_user_events', 'genai_identity_activity_events',
                                 'genai_identity_claimed_events', 'genai_identity_claimed_turn',
                                 'genai_identity_duo_class', 'genai_identity_join_key',
                                 'genai_identity_verified_turn'])
        for name in names:
            stanza = name + '(1)' if name == 'genai_identity_join_key' else name
            self.assertIn(stanza, macros)
            self.assertEqual(macros[stanza].get('iseval'), '0', stanza)

    def test_no_rest_no_join_no_write(self):
        self.assertNotRegex(self.spl, r'\|\s*rest\b')
        self.assertNotRegex(self.spl, r'\|\s*(join|selfjoin|appendcols|transaction)\b')
        self.assertNotRegex(self.spl, WRITES)

    def test_no_content_field_reaches_a_panel(self):
        """No prompt or response text, email address or phone number: not in a
        search, and not in any text the view prints."""
        self.assertNotRegex(self.spl.lower(), CONTENT_FIELDS)
        text = json.dumps(self.viz).lower() + self.d['title'].lower() + self.d['description'].lower()
        self.assertNotRegex(text, r'[\w.+-]+@[\w-]+\.[\w.-]+')
        self.assertNotRegex(text, r'\b\d{1,3}(?:\.\d{1,3}){3}\b')

    def test_no_search_returns_raw_events(self):
        """Every search ends in an aggregate or in a table of named columns, so no
        event (and no field nobody named) reaches the browser."""
        tables = ('ds_overview', 'ds_duo_to_ai', 'ds_addresses')
        for name in self.searches:
            query = own_query(self.ds, name)
            if name in tables:
                lines = query.split('\n')
                self.assertTrue(lines[-2].startswith('| table identity_key, '), name)
                self.assertEqual(lines[-1], '| rename identity_key as identity', name)
            else:
                self.assertRegex(query, r'\n\| (stats|timechart|chart) ', name)
                self.assertNotRegex(query, r'\n\| (table|fields) \*', name)
        self.assertNotRegex(self.spl, r'\|\s*(table|fields)\s+\*')

    def test_spl_is_balanced(self):
        for name in self.ds:
            query = full_query(self.ds, name)
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


class KpiTests(ViewTestCase):
    """Six tiles; each one returns a row, and a number, on an empty window."""

    def kpi_sources(self):
        return [self.viz[name]['dataSources']['primary'] for name, _label, _feed in KPIS]

    def test_the_guard_rejects_what_studio_draws_as_hashes(self):
        """A bare stats sum() or max() over no rows gives a null (###), and a BY
        clause gives no row at all."""
        for bad in ('| stats sum(duo_success) as v', '| stats max(users) as v',
                    '| stats count as v by identity_key', '| stats count as rows, sum(x) as v',
                    '| stats count as rows, sum(x) as v\n| fields v', '| where x>0'):
            self.assertFalse(last_stats_guarantees_a_row(bad), bad)
        for good in ('| stats count as v', '| where x>0\n| stats dc(identity_key) as v',
                     '| stats count as rows, sum(x) as v\n| fillnull value=0 v\n| fields v'):
            self.assertTrue(last_stats_guarantees_a_row(good), good)

    def test_every_kpi_returns_a_row_on_an_empty_window(self):
        for name in self.kpi_sources():
            source = self.ds[name]
            self.assertEqual(source['type'], 'ds.chain', name)
            self.assertTrue(last_stats_guarantees_a_row(own_query(self.ds, name)), name)
        _root, home = studio(HOME)
        card = home['dataSources']['ds_card_06']['options']['query']
        self.assertTrue(last_stats_guarantees_a_row(card.replace(' | ', '\n| ')), card)

    def test_duo_and_application_kpis_chain_from_the_per_identity_base(self):
        base = own_query(self.ds, 'ds_base')
        for needle in ('count(eval(feed=="duo")) as duo_signins', 'count(eval(duo_class=="success")) as duo_success',
                       'count(eval(duo_class=="denied" OR duo_class=="fraud")) as duo_denied_fraud',
                       'sum(turn) as ai_turns', 'sum(eval(turn*blocked)) as ai_blocked by identity_key'):
            self.assertIn(needle, base)
        # The outcome of a Duo authentication and "a verified turn" are each one macro,
        # so the tiles cannot drift from the overview, the timeline or the sign-in chain.
        self.assertIn('feed="duo", identity_key=`genai_identity_join_key(user)`, '
                      'duo_class=`genai_identity_duo_class` ]', base)
        self.assertIn('turn=if(`genai_identity_verified_turn`, 1, 0), ', base)
        self.assertIn("blocked=if('gen_ai.policy.blocked'==\"true\", 1, 0)", base)
        want = {'ds_kpi_duo_identities': '| where duo_signins>0\n| stats count as v',
                'ds_kpi_duo_success': '| stats count as rows, sum(duo_success) as v',
                'ds_kpi_duo_denied': '| stats count as rows, sum(duo_denied_fraud) as v',
                'ds_kpi_ai_identities': '| where ai_turns>0\n| stats count as v',
                'ds_kpi_ai_blocked': '| stats count as rows, sum(ai_blocked) as v'}
        for name, tail in want.items():
            source = self.ds[name]
            self.assertEqual(source['options']['extend'], 'ds_base', name)
            self.assertTrue(source['options']['query'].startswith(IDENTITY_FILTER + '\n' + tail), name)

    def test_risk_kpi_counts_the_overview_rows_with_risk(self):
        source = self.ds['ds_kpi_risk']
        self.assertEqual(source['options'], {'extend': 'ds_overview',
                                             'query': '| where risk_events>0 OR findings>0\n| stats count as v'})

    def test_coloured_kpis_stay_white_at_zero(self):
        for name in ('viz_kpi_duo_denied', 'viz_kpi_ai_blocked', 'viz_kpi_risk'):
            tile = self.viz[name]
            self.assertEqual(tile['options']['majorColor'], '> majorValue | rangeValue(majorColorConfig)', name)
            self.assertEqual(tile['context']['majorColorConfig'][0], {'to': 1, 'value': '#FFFFFF'}, name)
            self.assertEqual(tile['context']['majorColorConfig'][1]['from'], 1, name)


class PanelTests(ViewTestCase):

    def test_overview_has_one_row_per_identity_seen_in_either_feed(self):
        query = own_query(self.ds, 'ds_overview')
        lines = query.split('\n')
        self.assertEqual(lines[-2], '| table ' + ', '.join(OVERVIEW_COLUMNS))
        self.assertIn(' by identity_key\n| eventstats count(duo_status) as snapshot_users\n'
                      '| where duo_signins>0 OR app_events>0\n' + IDENTITY_FILTER + '\n', query)
        # ES only enriches: a risk object that is in neither feed gets no row.
        self.assertLess(query.index('datamodel=Risk.All_Risk'), query.index('| where duo_signins>0 OR app_events>0'))
        self.assertIn('| lookup identity_lookup_expanded identity as identity_key OUTPUT category as es_category',
                      query)
        self.assertIn('latest(duo_factor) as last_duo_factor', query)
        self.assertIn('max(eval(if(feed=="duo", _time, null()))) as last_duo', query)
        self.assertIn('count(eval(app_action=="identity_signin_success")) as app_signins', query)
        # The gate's verdict is read from the turn's own event, like the turn itself.
        self.assertIn("turn=if(`genai_identity_verified_turn`, 1, 0), "
                      "blocked=if('gen_ai.policy.blocked'==\"true\", 1, 0), "
                      "gate=if(turn==1, coalesce('gen_ai.identity.risk.verdict', \"none\")", query)
        self.assertIn("'gen_ai.identity.check'==\"unavailable\"", query)
        self.assertEqual(self.viz['viz_overview']['dataSources'], {'primary': 'ds_overview'})

    def test_overview_counts_every_duo_outcome_once(self):
        """success + denied + fraud + other = every Duo sign-in: a result of failure
        counts as denied (the TA's CIM action for it is failure) and error or
        anything else has a column of its own, so no attempt is hidden."""
        query = own_query(self.ds, 'ds_overview')
        self.assertIn('duo_class=`genai_identity_duo_class`, duo_result=', query)
        for name in ('success', 'denied', 'fraud', 'other'):
            self.assertIn('count(eval(duo_class=="%s")) as duo_%s, ' % (name, name), query)
        self.assertEqual(read_conf('macros.conf')['genai_identity_duo_class']['definition'], DUO_CLASS)
        description = self.viz['viz_overview']['description']
        self.assertIn('duo_denied: Duo result denied or failure; duo_other: error or anything else', description)

    def test_overview_counts_risk_events_and_findings_apart(self):
        """ES 8's Risk data model reads (index=risk OR index=notable), so one firing of
        a rule that writes a risk event and raises a finding is two rows. They get a
        column each; risk_score stays the total of both, which is ES's entity risk.
        A detection that only raises a finding still shows (no filter on the index)."""
        query = own_query(self.ds, 'ds_overview')
        self.assertIn('count as n, sum(All_Risk.calculated_risk_score) as risk_score from datamodel=Risk.All_Risk '
                      'where All_Risk.risk_object_type="user" by All_Risk.risk_object, index\n'
                      '    | rename All_Risk.risk_object as risk_object, index as risk_index\n', query)
        self.assertIn('risk_events=if(risk_index=="notable", 0, n), findings=if(risk_index=="notable", n, 0)\n'
                      + NESTED_FILTER + '\n'
                      '    | stats sum(risk_events) as risk_events, sum(findings) as findings, '
                      'sum(risk_score) as risk_score by feed, identity_key\n'
                      '    | sort 0 -risk_score ]\n', query)
        self.assertIn('sum(risk_events) as risk_events, sum(findings) as findings, sum(risk_score) as risk_score '
                      'by identity_key\n', query)
        self.assertIn('| fillnull value=0 ai_turns, ai_blocked, claimed_not_verified, claimed_blocked, risk_events, '
                      'findings, risk_score\n', query)
        self.assertNotRegex(self.spl, r'risk_index\s*[!=]=\s*"risk"')
        description = self.viz['viz_overview']['description']
        for needle in ('risk_events: rows in the risk index', 'findings: rows in the notable index',
                       'risk_score: the total of both, as in ES entity risk'):
            self.assertIn(needle, description)

    def test_duo_account_state_is_the_newest_complete_snapshot_like_the_lookup_gen(self):
        """Complete = event count equals snapshot_total, newest by _time: the same
        test "GenAI - Identity - Duo Identity Lookup Gen" applies before it writes."""
        query = own_query(self.ds, 'ds_overview')
        gen = read_conf('savedsearches.conf')['GenAI - Identity - Duo Identity Lookup Gen']['search']
        for line in ('| eval snapshot_total=tonumber(snapshot_total)',
                     '| eventstats count as snapshot_events, max(snapshot_total) as snapshot_expected, '
                     'max(_time) as snapshot_time by snapshot_id',
                     '| where isnotnull(snapshot_id) AND snapshot_expected>0 AND snapshot_events==snapshot_expected',
                     '| eventstats max(snapshot_time) as newest_snapshot_time',
                     '| where snapshot_time==newest_snapshot_time', '| dedup user_id'):
            self.assertIn('\n    ' + line + '\n', query, line)
            self.assertIn(line, gen, line)
        self.assertIn('duo_status=lower(coalesce(status, "unknown"))', query)
        self.assertIn('duo_enrolled=if(lower(is_enrolled)=="true" OR is_enrolled=="1", "yes", "no")', query)
        self.assertIn('newest complete Duo users snapshot in the range', self.viz['viz_overview']['description'])
        # An identity with no account state says why: no complete snapshot fell in the
        # range at all, or one did and the identity is not a Duo user in it.
        self.assertIn('duo_status=coalesce(mvjoin(duo_status, ", "), '
                      'if(snapshot_users>0, "not in snapshot", "no snapshot in range"))', query)

    def test_timeline_stacks_the_six_activity_types(self):
        query = own_query(self.ds, 'ds_timeline')
        named = re.findall(r'"((?:Duo|application|AI|risk) [a-zA-Z, -]+|finding)"', query)
        self.assertEqual(sorted(set(named)), sorted(ACTIVITIES))
        chart = self.viz['viz_timeline']
        self.assertEqual(chart['options']['stackMode'], 'stacked')
        self.assertEqual(list(chart['options']['seriesColorsByField']), ACTIVITIES)
        self.assertEqual(len(set(chart['options']['seriesColorsByField'].values())), len(ACTIVITIES))
        self.assertTrue(query.endswith(IDENTITY_FILTER + '\n| timechart sum(n) by activity\n| fillnull value=0'))
        # Risk, and a claimed turn, count only for identities seen in a feed, like the overview.
        self.assertIn('| eventstats max(eval(if(activity=="risk event" OR activity=="finding" OR '
                      'activity=="%s", 0, 1))) as in_feed by identity_key\n| where in_feed==1\n' % CLAIMED, query)

    def test_timeline_uses_the_tiles_duo_classes_and_one_event_per_turn(self):
        query = own_query(self.ds, 'ds_timeline')
        # Duo failure is denied + fraud, exactly the tile; error and unknown are "Duo other".
        self.assertIn('duo_class=`genai_identity_duo_class`, activity=case(duo_class=="success", "Duo success", '
                      'duo_class=="other", "Duo other", true(), "Duo failure"), n=1 ]', query)
        # Positive matches only: an event that is neither a sign-in nor a turn's own
        # chat event (a tool call, a decision, an escalation record) gets no activity.
        self.assertIn('activity=case(\'gen_ai.audit.action\'=="identity_signin_success", "application sign-in", '
                      '`genai_identity_verified_turn` AND \'gen_ai.policy.blocked\'=="true", "AI turn blocked", '
                      '`genai_identity_verified_turn`, "AI turn allowed"), n=1 ]\n', query)
        self.assertIn(' ]\n| where isnotnull(activity)\n| bin _time span=5m\n', query)
        self.assertNotIn('NOT `genai_identity_verified_turn`', self.spl)

    def test_timeline_risk_is_split_filtered_and_bounded_inside_the_subsearch(self):
        """append keeps the first 50,000 rows of its subsearch. The risk rows are cut
        down before they leave it: one identity when one is chosen, hourly buckets
        once the range is over 2 days, newest first so a cap drops the oldest."""
        query = own_query(self.ds, 'ds_timeline')
        self.assertIn('by _time, All_Risk.risk_object, index span=5m\n'
                      '    | rename All_Risk.risk_object as risk_object, index as risk_index\n'
                      '    | eval identity_key=`genai_identity_join_key(risk_object)`, '
                      'activity=if(risk_index=="notable", "finding", "risk event")\n'
                      + NESTED_FILTER + '\n'
                      '    | addinfo\n'
                      '    | eval span=if(isnum(info_max_time) AND info_max_time-info_min_time<=172800, 300, 3600), '
                      '_time=floor(_time/span)*span\n'
                      '    | stats sum(n) as n by _time, identity_key, activity\n'
                      '    | sort 0 -_time ]\n', query)
        description = self.viz['viz_timeline']['description']
        for needle in ('risk event is a row in the risk index', 'finding is a row in the notable index',
                       'at most 50,000 bucket rows, newest first'):
            self.assertIn(needle, description)

    def test_duo_to_ai_matches_a_sign_in_on_duos_transaction_id(self):
        """The application's identity_signin_success record carries Duo's transaction
        id (details.duo_txid), and it equals the txid of the Duo authentication. The
        pair is made on that key whatever the clocks say: sorted next to each other
        and joined by a streamstats that resets on every key (bounded, no join)."""
        query = own_query(self.ds, 'ds_duo_to_ai')
        self.assertEqual(query.split('\n')[-2], '| table ' + ', '.join(DUO_TO_AI_COLUMNS))
        self.assertIn('kind="duo", ord=0, identity_key=`genai_identity_join_key(user)`, link=txid, '
                      'duo_class=`genai_identity_duo_class`, duo_time=_time, ', query)
        self.assertIn('kind=case(\'gen_ai.audit.action\'=="identity_signin_success", "signin", '
                      '`genai_identity_verified_turn`, "turn"), ord=if(kind=="signin", 1, 2), '
                      'identity_key=`genai_identity_join_key(user)`, '
                      'link=if(kind=="signin", \'details.duo_txid\', null()), ', query)
        self.assertIn('| sort 0 str(identity_key), str(link), ord\n'
                      '| streamstats reset_on_change=true last(duo_time) as id_time, ', query)
        self.assertIn(' as id_src by identity_key, link\n', query)
        self.assertIn('matched_on=case(kind=="signin" AND isnotnull(id_time), "transaction id", '
                      'isnotnull(ok_time) AND _time-ok_time<=600, "user and time", true(), "none"), ', query)
        # The table is the newest 500 rows, and the transaction id links rows without ever being a column.
        self.assertIn('| sort 0 -_time\n| head 500\n| table identity_key, ', query)
        self.assertNotIn('link', DUO_TO_AI_COLUMNS)
        self.assertNotRegex(query.split('\n')[-2], r'txid')

    def test_duo_to_ai_falls_back_to_the_nearest_earlier_success_within_ten_minutes(self):
        """A verified turn carries no Duo transaction id, and a sign-in record may
        lack one: both pair with the nearest earlier SUCCESSFUL Duo authentication
        of the identity within 10 minutes. A denial or another event in the same
        second can never be picked, and the order is fixed by a third sort key."""
        query = own_query(self.ds, 'ds_duo_to_ai')
        self.assertIn('ok=if(kind=="duo" AND duo_class=="success", 1, null()), ok_time=if(ok==1, duo_time, null()), ',
                      query)
        self.assertIn('| sort 0 _time, ord, str(link)\n'
                      '| streamstats last(ok_time) as ok_time, last(ok_application) as ok_application, '
                      'last(ok_factor) as ok_factor, last(ok_src) as ok_src, last(signin_time) as signin_anchor '
                      'by identity_key\n', query)
        self.assertIn('duo_result=case(matched_on=="transaction id", id_result, matched_on=="user and time", '
                      '"success", true(), "-")', query)
        # Denials stay visible as a count: the identity's denied or fraud Duo
        # authentications in the 10 minutes up to the application event.
        self.assertIn('bad=if(kind=="duo" AND (duo_class=="denied" OR duo_class=="fraud"), 1, 0), ', query)
        self.assertIn('| streamstats time_window=10m sum(bad) as duo_denied_10m by identity_key\n'
                      '| where kind!="duo"\n', query)
        self.assertLess(query.index('| sort 0 _time, ord, str(link)'), query.index('time_window=10m'))

    def test_duo_to_ai_first_turn_follows_an_application_sign_in(self):
        """One "first verified turn" row per application sign-in (or one for an
        identity with no sign-in in the range): a later Duo authentication to
        another application never starts a new row."""
        query = own_query(self.ds, 'ds_duo_to_ai')
        self.assertIn('signin_time=if(kind=="signin", _time, null())\n', query)
        self.assertIn('| eval signin_anchor=coalesce(signin_anchor, 0), ', query)
        self.assertIn('| streamstats count as nth by identity_key, kind, signin_anchor\n'
                      '| where kind=="signin" OR nth==1\n', query)
        self.assertIn('"application sign-in", "first verified turn"', query)
        self.assertNotIn('duo_anchor', query)

    def test_duo_to_ai_says_when_the_duo_log_may_not_be_in_yet(self):
        query = own_query(self.ds, 'ds_duo_to_ai')
        self.assertIn('duo_signin=case(matched_on!="none", strftime(duo_time, "%Y-%m-%d %H:%M:%S"), '
                      'now()-_time<900, "Duo log may not be in yet", true(), "none within 10 min"), ', query)
        self.assertIn('addresses_match=case(matched_on=="none" OR duo_src=="unknown" OR app_src=="unknown", "unknown", '
                      'duo_src==app_src, "yes", true(), "no")', query)
        colours = self.viz['viz_duo_to_ai']['context']['matchColors']
        self.assertEqual([c['match'] for c in colours], ['yes', 'no', 'unknown'])

    def test_duo_to_ai_description_says_what_each_row_is_matched_on(self):
        """Sign-ins on the transaction id, turns on user and time and not on a session
        key. It must never again say the application does not log Duo's transaction
        id: the sign-in record does (details.duo_txid); only a turn does not."""
        description = self.viz['viz_duo_to_ai']['description']
        self.assertTrue(description.startswith('An application sign-in is matched on Duo\'s transaction id: the '
                                               'sign-in record carries it (details.duo_txid)'), description)
        for needle in ('A verified turn carries neither that id nor a session key',
                       'are matched on user and time, not on a session key',
                       'nearest earlier successful Duo authentication of the same identity within 10 minutes',
                       'to any Duo-protected application', 'matched_on: transaction id, user and time, or none',
                       'yes, no, or unknown', 'Duo log may not be in yet', 're-runs every 5 minutes'):
            self.assertIn(needle, description)
        for text in (description, self.viz['viz_header']['options']['markdown']):
            self.assertNotRegex(text, r'does not log Duo')

    def test_source_addresses_split_duo_only_application_only_and_both(self):
        query = own_query(self.ds, 'ds_addresses')
        self.assertTrue(query.split('\n')[-2] == '| table identity_key, both, duo_only, application_only, addresses')
        self.assertIn('seen_by=case(duo_events>0 AND app_events>0, "both", duo_events>0, "duo", true(), "app")', query)
        self.assertIn(' by identity_key, address\n', query)
        # Loopback and placeholder values are not addresses.
        self.assertIn('| where isnotnull(address) AND NOT (in(lower(coalesce(address, "")), "", "null", "unknown", '
                      '"-", "::1") OR like(address, "127.%"))', query)

    def test_risk_by_detection_splits_each_identity_by_rule(self):
        query = own_query(self.ds, 'ds_risk')
        self.assertIn('by All_Risk.risk_object, source\n', query)
        self.assertIn('| rename All_Risk.risk_object as risk_object, source as detection\n', query)
        self.assertIn('    | eval identity_key=`genai_identity_join_key(risk_object)`\n' + NESTED_FILTER + '\n'
                      '    | stats sum(risk_score) as risk_score by identity_key, detection\n'
                      '    | sort 0 -risk_score ]\n', query)
        self.assertIn('| where feed_events>0 AND isnotnull(detection)\n' + IDENTITY_FILTER + '\n'
                      '| chart sum(risk_score) over identity_key by detection limit=10\n', query)
        chart = self.viz['viz_risk']
        self.assertEqual((chart['type'], chart['options']['stackMode']), ('splunk.bar', 'stacked'))
        # The bars are ES entity risk: a firing counts its risk event and its finding.
        self.assertIn('each firing counts its risk event and, when the rule also raises one, its finding',
                      chart['description'])


class ClaimedTurnTests(ViewTestCase):
    """A turn that only claims an identity's name (no verified session behind it: what a
    prompt-injection spray writes) is counted beside the verified turns and apart from
    them, per identity and on the timeline, and can never be read as a sign-in."""

    def test_claimed_turns_are_read_in_the_overview_and_the_timeline_only(self):
        """One more multisearch branch in two searches. The base search behind the five
        Duo and application tiles and the dropdown, the sign-in chain, the address table
        and Risk by detection never read a claimed turn, so none of them can move."""
        for name in self.ds:
            query = own_query(self.ds, name)
            if name not in CLAIMED_SEARCHES:
                self.assertNotIn('claimed', query, name)
                continue
            self.assertEqual(query.count('    [ search `genai_identity_claimed_events`\n    | eval '), 1, name)
            self.assertEqual(query.count('`genai_identity_claimed_events`'), 1, name)
            self.assertEqual(query.count('`genai_identity_claimed_turn`'), 1, name)
            # A branch of the multisearch, after the application's: before the first main-pipeline command.
            self.assertLess(query.index('`genai_identity_activity_events`'),
                            query.index('`genai_identity_claimed_events`'), name)
            self.assertLess(query.index('`genai_identity_claimed_events`'), query.index('\n| '), name)
        self.assertEqual(sorted(n for n in self.searches if 'claimed' in own_query(self.ds, n)),
                         sorted(CLAIMED_SEARCHES))
        for name, _label, _feed in KPIS[:5]:
            self.assertNotIn('claimed', self.feeds(name), name)
        self.assertNotIn('claimed', full_query(self.ds, 'ds_identities'))
        _root, home = studio(HOME)
        self.assertNotIn('claimed', home['dataSources']['ds_card_06']['options']['query'])

    def test_overview_counts_claimed_turns_beside_verified_turns_and_apart(self):
        query = own_query(self.ds, 'ds_overview')
        branch = branch_eval(query, 'genai_identity_claimed_events')
        self.assertEqual(branch, '| eval feed="claimed", identity_key=`genai_identity_join_key(user)`, '
                                 'claimed=if(`genai_identity_claimed_turn`, 1, 0), '
                                 'claimed_blocked=if(claimed==1 AND \'gen_ai.policy.blocked\'=="true", 1, 0)')
        # The branch sets none of the fields the verified columns are made from, and its
        # feed is not "app": ai_turns, ai_blocked, app_signins, gate_verdicts and the row
        # filter (app_events) cannot see a claimed turn.
        for field in ('turn', 'blocked', 'gate', 'app_action'):
            self.assertNotRegex(branch, r'[ ,]%s=' % field)
        self.assertIn('count(eval(feed=="app")) as app_events', query)
        self.assertIn('| fields _time, feed, identity_key, duo_class, duo_factor, duo_result, app_action, turn, '
                      'blocked, gate, claimed, claimed_blocked\n', query)
        self.assertIn('sum(turn) as ai_turns, sum(eval(turn*blocked)) as ai_blocked, values(gate) as gate_verdicts, '
                      'sum(claimed) as claimed_not_verified, sum(claimed_blocked) as claimed_blocked, ', query)
        # Its columns follow the verified ones (the gate's verdicts belong to verified turns).
        at = OVERVIEW_COLUMNS.index('claimed_not_verified')
        self.assertEqual(OVERVIEW_COLUMNS[at - 3:at + 2], ['ai_turns', 'ai_blocked', 'gate_verdicts',
                                                           'claimed_not_verified', 'claimed_blocked'])
        # Two counts, never one: nothing adds them, and the sort and the row filter ignore the new one.
        self.assertNotRegex(self.spl, r'(ai_turns|ai_blocked)\s*\+|\+\s*(ai_turns|ai_blocked|claimed)')
        self.assertIn('| sort 0 -risk_score, -duo_fraud, -ai_blocked, identity_key\n', query)
        fmt = self.viz['viz_overview']['options']['columnFormat']
        self.assertEqual(fmt['claimed_not_verified'],
                         {'rowColors': '> table | seriesByName("claimed_not_verified") | rangeValue(warnColors)'})
        description = self.viz['viz_overview']['description']
        self.assertIn('gate_verdicts: Identity Risk Gate verdicts on those turns. claimed_not_verified and '
                      'claimed_blocked: chat requests that carried this identity\'s name with no verified session '
                      'behind them', description)
        self.assertIn('never part of ai_turns', description)

    def test_a_claimed_name_never_creates_a_row_a_dropdown_entry_or_a_bar(self):
        """The name on an unverified turn is request text. It only enriches an identity
        that a Duo sign-in or an application identity event already put in the view."""
        overview = own_query(self.ds, 'ds_overview')
        self.assertLess(overview.index('sum(claimed) as claimed_not_verified'),
                        overview.index('\n| where duo_signins>0 OR app_events>0\n'))
        self.assertNotRegex(overview, r'\| where [^\n]*claimed')
        timeline = own_query(self.ds, 'ds_timeline')
        self.assertIn('OR activity=="%s", 0, 1))) as in_feed by identity_key\n| where in_feed==1\n' % CLAIMED,
                      timeline)
        self.assertIn('a name that is only claimed gets no row', self.viz['viz_overview']['description'])
        self.assertIn('drawn only for identities with a Duo sign-in or application identity activity in the range',
                      self.viz['viz_timeline']['description'])

    def test_timeline_draws_claimed_turns_as_one_series_of_their_own(self):
        query = own_query(self.ds, 'ds_timeline')
        self.assertEqual(branch_eval(query, 'genai_identity_claimed_events'),
                         '| eval identity_key=`genai_identity_join_key(user)`, '
                         'activity=if(`genai_identity_claimed_turn`, "%s", null()), n=1' % CLAIMED)
        colours = self.viz['viz_timeline']['options']['seriesColorsByField']
        self.assertEqual(colours[CLAIMED], CLAIMED_COLOUR)
        self.assertEqual(list(colours).index(CLAIMED), list(colours).index('AI turn blocked') + 1)
        # Pale: lighter than every other series by a wide margin, so it is told apart by
        # lightness, also by a viewer who cannot tell red, orange and green apart.
        others = [luminance(colour) for name, colour in colours.items() if name != CLAIMED]
        self.assertGreater(luminance(colours[CLAIMED]), max(others) + 0.25)
        self.assertEqual((round(luminance('#000000'), 3), round(luminance('#FFFFFF'), 3)), (0.0, 1.0))
        # timechart folds every series past its default limit of 10 into OTHER.
        self.assertLessEqual(len(ACTIVITIES), 10)
        self.assertNotRegex(query, r'timechart[^\n]*\blimit=')
        self.assertIn('AI turns claimed, not verified (chat requests that carried the identity\'s name with no '
                      'verified session, blocked or not: never a sign-in', self.viz['viz_timeline']['description'])

    def test_a_claimed_turn_can_never_be_read_as_a_sign_in(self):
        """Its label says "not verified" and names neither a sign-in nor Duo; the sign-in
        chain, which pairs application events with Duo sign-ins, never reads one; no tile
        counts one; and every text that explains it says it is never a sign-in."""
        self.assertIn('not verified', CLAIMED)
        self.assertNotRegex(CLAIMED.lower(), r'sign-?in|duo|application')
        self.assertNotIn('claimed', own_query(self.ds, 'ds_duo_to_ai'))
        self.assertFalse([c for c in DUO_TO_AI_COLUMNS if 'claimed' in c])
        for _name, label, _feed in KPIS:
            self.assertNotIn('claimed', label)
        for text in (self.viz['viz_header']['options']['markdown'], self.viz['viz_overview']['description'],
                     self.viz['viz_timeline']['description']):
            self.assertIn('never a sign-in', text)
        self.assertIn('A turn that only names an identity, with no verified session behind it '
                      '(genai_identity_claimed_turn), is counted apart as claimed, not verified: it is never a '
                      'sign-in.', self.viz['viz_header']['options']['markdown'])


class EnterpriseSecurityTests(ViewTestCase):
    """The ES side is Risk.All_Risk (user risk) and identity_lookup_expanded."""

    def fed_by_es(self, viz):
        return any(source in self.feeds(viz) for source in ES_SOURCES)

    def test_es_panels_say_so(self):
        fed = sorted(name for name, v in self.viz.items() if 'dataSources' in v and self.fed_by_es(name))
        self.assertEqual(fed, sorted(ES_PANELS))
        for name in fed:
            self.assertIn(ES_NOTE, self.viz[name]['description'], name)
            self.assertTrue(self.viz[name]['description'].startswith(ES_NOTE), name)
        # The overview and the timeline hold Duo and application content too, and still
        # fail as a whole without ES: they say that, not "needs ES for these columns".
        for name in ('viz_overview', 'viz_timeline'):
            self.assertTrue(self.viz[name]['description'].startswith(
                ES_NOTE + ': without it this panel shows an error. '), name)
        self.assertIn('The ES tile, Identity overview, Activity timeline and Risk by detection need Enterprise '
                      'Security', self.viz['viz_header']['options']['markdown'])

    def test_duo_and_application_panels_do_not_depend_on_es(self):
        """A tstats on a missing data model is fatal even inside append, so the ES
        reads stay out of the base search behind the five Duo and application
        tiles, the dropdown, the sign-in chain and the address table."""
        for name, v in self.viz.items():
            if 'dataSources' not in v or name in ES_PANELS:
                continue
            self.assertFalse(self.fed_by_es(name), name)
            self.assertNotIn('Enterprise Security', v.get('description', ''), name)
        for source in ES_SOURCES:
            self.assertNotIn(source, full_query(self.ds, 'ds_identities'))

    def test_risk_is_user_risk_bounded_by_the_time_input(self):
        reads = re.findall(r'\| tstats [^\n]+', self.spl)
        self.assertEqual(len(reads), 3)
        for read in reads:
            self.assertIn('summariesonly=false', read)
            self.assertIn('from datamodel=Risk.All_Risk where All_Risk.risk_object_type="user" by ', read)
        self.assertEqual(self.spl.count('sum(All_Risk.calculated_risk_score) as risk_score'), 2)


class MacroTests(unittest.TestCase):
    """The five macros behind the view (default/macros.conf): one definition each of
    the application's identity events, a verified AI turn, the events a claimed turn
    is read from, a claimed (not verified) AI turn, and a Duo outcome."""

    NAMES = ('genai_identity_activity_events', 'genai_identity_verified_turn', 'genai_identity_claimed_events',
             'genai_identity_claimed_turn', 'genai_identity_duo_class')

    def setUp(self):
        self.macros = read_conf('macros.conf')
        with io.open(os.path.join(REPO, 'default', 'macros.conf'), encoding='utf-8') as handle:
            self.text = handle.read()

    def test_definitions(self):
        self.assertEqual(self.macros['genai_identity_activity_events']['definition'], ACTIVITY_EVENTS)
        self.assertEqual(self.macros['genai_identity_verified_turn']['definition'], VERIFIED_TURN)
        self.assertEqual(self.macros['genai_identity_duo_class']['definition'], DUO_CLASS)
        self.assertEqual(self.macros['genai_identity_claimed_events']['definition'], CLAIMED_EVENTS)
        self.assertEqual(self.macros['genai_identity_claimed_turn']['definition'], CLAIMED_TURN)
        for name in self.NAMES:
            self.assertEqual(sorted(self.macros[name]), ['definition', 'iseval'], name)
            self.assertEqual(self.macros[name]['iseval'], '0', name)

    def test_documented_like_every_macro(self):
        for name in self.NAMES:
            head = self.text[:self.text.index('[%s]' % name)].rstrip().split('\n')
            block = '\n'.join(head[-30:])
            self.assertIn('# ' + name + '\n', block, name)
            self.assertIn('# Usage:', block, name)
        # The Duo feed keeps its five macros; these five are the view's, not the feed's.
        self.assertFalse([n for n in self.NAMES if n.startswith('genai_duo_')])

    def test_raw_term_only_narrows_the_scan(self):
        """Both fields of the filter are calculated at search time, so without a raw
        term every governance event in the range is read. identity_* loses nothing:
        gen_ai.identity.verified is computed from the flat key identity_verified
        alone, and an identity audit action is the literal value identity_<name>."""
        definition = self.macros['genai_identity_activity_events']['definition']
        self.assertTrue(definition.startswith('`genai_identity_ai_events` identity_* ('), definition)
        self.assertTrue(definition.endswith('(gen_ai.identity.verified="true" OR gen_ai.audit.action="identity_*")'))
        self.assertEqual(self.macros['genai_identity_ai_events']['definition'],
                         'index=gen_ai_log `exclude_scoring_sourcetypes`')
        props = read_conf('props.conf')
        verified = props['gen_ai:json']['EVAL-gen_ai.identity.verified']
        self.assertEqual(set(re.findall(r'\b[a-z_]*identity[a-z_]*\b', verified)), {'identity_verified'})
        # The audit action is the record's own action value on both audit paths.
        self.assertEqual(props['gen_ai:json']['FIELDALIAS-genai_audit_action_raw'], 'action AS gen_ai.audit.action_raw')
        self.assertEqual(props['demobot:audit']['FIELDALIAS-demobot_audit_action'], 'action AS gen_ai.audit.action')
        # No other stanza computes the flag from another key, which the term would miss.
        for stanza, keys in props.items():
            for key, value in keys.items():
                if 'gen_ai.identity.verified' in key and not key.endswith('_raw'):
                    self.assertEqual((stanza, key), ('gen_ai:json', 'EVAL-gen_ai.identity.verified'))

    def test_a_verified_turn_is_the_turns_own_chat_event(self):
        """PseudoCo Assistant stamps identity_verified on every event of a signed-in
        turn (tool_call, decision, prompt and error events, and the escalation
        record on a single-sourcetype destination). Only the chat event is written
        once per request, so the predicate names the operation and the provider."""
        turn = self.macros['genai_identity_verified_turn']['definition']
        for needle in ("isnull('gen_ai.audit.action')", "'gen_ai.identity.verified'==\"true\"",
                       "isnotnull('gen_ai.provider.name')", "'gen_ai.operation.name'==\"chat\""):
            self.assertIn(needle, turn)
        # Every term must hold: a missing field makes the whole test null, which if(),
        # case() and where all read as "no". An OR or a NOT would turn that around.
        self.assertNotRegex(turn, r'\bOR\b|\bNOT\b')
        self.assertTrue(turn.startswith('(') and turn.endswith(')'), turn)
        props = read_conf('props.conf')['gen_ai:json']
        self.assertEqual(props['FIELDALIAS-genai_operation_name'], 'operation_name AS gen_ai.operation.name')
        self.assertEqual(props['FIELDALIAS-genai_provider_name'], 'provider_name AS gen_ai.provider.name')
        # Audit and escalation sourcetypes alias neither, so their records can never be a turn.
        for stanza in ('demobot:audit', 'demobot:escalation'):
            text = ' '.join('%s = %s' % pair for pair in read_conf('props.conf')[stanza].items())
            self.assertNotRegex(text, r'gen_ai\.(operation|provider)\.name', stanza)

    def test_a_claimed_turn_is_a_chat_event_with_a_name_and_no_verified_identity(self):
        """The mirror of a verified turn: the same chat event (provider set, operation
        chat, not an audit record), a user named, and the identity NOT verified. No
        event can be both, because the two differ only in the identity term. A missing
        identity_verified is the normal case (a spray's turn and every anonymous turn
        write no identity key), so that one term reads null as not verified."""
        turn = self.macros['genai_identity_verified_turn']['definition']
        claimed = self.macros['genai_identity_claimed_turn']['definition']
        self.assertTrue(claimed.startswith('(') and claimed.endswith(')'), claimed)

        def terms(text):
            return set(text[1:-1].split(' AND '))
        self.assertEqual(terms(turn) & terms(claimed), {"isnull('gen_ai.audit.action')",
                                                        "isnotnull('gen_ai.provider.name')",
                                                        "'gen_ai.operation.name'==\"chat\""})
        self.assertEqual(terms(turn) - terms(claimed), {"'gen_ai.identity.verified'==\"true\""})
        self.assertEqual(terms(claimed) - terms(turn), {"coalesce('gen_ai.identity.verified', \"false\")!=\"true\"",
                                                        'isnotnull(user)'})
        self.assertNotRegex(claimed, r'\bOR\b|\bNOT\b')
        # The TA's own EVAL leaves a missing key null (it has no "false" default), which is why the term coalesces.
        verified = re.sub(r'\s+', ' ', read_conf('props.conf')['gen_ai:json']['EVAL-gen_ai.identity.verified'])
        self.assertTrue(verified.endswith('1=1, null())'), verified)

    def test_claimed_events_macro_only_narrows(self):
        """genai_identity_claimed_turn decides; the event macro only keeps the scan and
        the row count down. Its operation term is a field alias, so the value is also a
        raw term (chat); its identity term drops the chat events of signed-in turns.
        Both are implied by the predicate, so the count never rests on two definitions.
        It has no raw term identity_*: a claimed turn's events hold no identity key."""
        definition = self.macros['genai_identity_claimed_events']['definition']
        self.assertEqual(definition.split(' ', 1), ['`genai_identity_ai_events`',
                                                    'gen_ai.operation.name="chat" NOT gen_ai.identity.verified="true"'])
        self.assertNotIn('|', definition)
        self.assertNotIn('identity_*', definition)
        claimed = self.macros['genai_identity_claimed_turn']['definition']
        self.assertIn("'gen_ai.operation.name'==\"chat\"", claimed)
        self.assertIn("coalesce('gen_ai.identity.verified', \"false\")!=\"true\"", claimed)
        props = read_conf('props.conf')
        self.assertEqual(props['gen_ai:json']['FIELDALIAS-genai_operation_name'],
                         'operation_name AS gen_ai.operation.name')
        for stanza, keys in props.items():
            self.assertNotIn('EVAL-gen_ai.operation.name', keys, stanza)
        self.assertEqual(read_conf('fields.conf')['gen_ai.operation.name'], {'INDEXED': 'false'})

    def test_banner_names_the_detection_that_shares_two_macros(self):
        """An override of genai_identity_activity_events or genai_identity_verified_turn
        changes the joined rule (LR-06) as well as the panels, and the banner says
        so. The claimed-turn macros and the Duo class feed the view alone."""
        banner = self.text[self.text.index('# IDENTITY ACTIVITY MACROS - v1.9.0'):
                           self.text.index('# genai_identity_activity_events\n')]
        banner = re.sub(r'\s+', ' ', ' '.join(line.lstrip('#').strip() for line in banner.split('\n')))
        self.assertIn('Two of them are not the dashboard\'s alone. "%s" (LR-06) reads the application\'s events '
                      'through genai_identity_activity_events and decides what a blocked verified turn is with '
                      'genai_identity_verified_turn, so an override of either changes that detection as well as the '
                      'panels.' % JOINED_RULE, banner)
        self.assertIn('keep an override of it to index, sourcetype and field terms with no pipe', banner)
        searches = read_conf('savedsearches.conf')
        used_by = {name: sorted(stanza for stanza, keys in searches.items() if '`%s`' % name in keys.get('search', ''))
                   for name in self.NAMES}
        self.assertEqual(used_by, {'genai_identity_activity_events': [JOINED_RULE],
                                   'genai_identity_verified_turn': [JOINED_RULE],
                                   'genai_identity_claimed_events': [], 'genai_identity_claimed_turn': [],
                                   'genai_identity_duo_class': []})
        # Both event macros stay search terms only: the rule and the view put terms after them.
        for name in ('genai_identity_activity_events', 'genai_identity_claimed_events'):
            self.assertNotIn('|', self.macros[name]['definition'], name)

    def test_duo_classes_add_up_and_agree_with_the_cim_action(self):
        """fraud + denied is what the TA's CIM mapping calls action=failure (denied,
        failure and fraud), and other is its error / unknown."""
        action = read_conf('props.conf')['ta_gen_ai_cim:duo:authentication']['EVAL-action']
        self.assertIn('lower(result)=="denied" OR lower(result)=="failure" OR lower(result)=="fraud", "failure"',
                      re.sub(r'\s+', ' ', action))
        self.assertEqual(re.findall(r', "(\w+)"[,)]', DUO_CLASS), ['fraud', 'success', 'denied', 'other'])
        self.assertTrue(DUO_CLASS.endswith('true(), "other")'), 'every event falls in a class')


class MenuHomeAndDocsTests(unittest.TestCase):
    """The view is reachable (menu, home card 06) and documented."""

    def text(self, *path):
        with io.open(os.path.join(REPO, *path), encoding='utf-8') as handle:
            return handle.read()

    def test_menu_entry_follows_the_duo_identity_feed(self):
        self.assertEqual(nav_collection('Dashboards')[-2:], [(DUO_VIEW, 'Duo Identity Feed'),
                                                             (VIEW, 'Identity Activity')])
        self.assertEqual(self.text(*os.path.relpath(NAV, REPO).split(os.sep)).count('name="%s"' % VIEW), 1)

    def test_home_card_06_opens_the_view_with_its_kpi(self):
        _root, home = studio(HOME)
        viz, ds = home['visualizations'], home['dataSources']
        heading, purpose, link = viz['viz_md_06']['options']['markdown'].split('\n')
        self.assertEqual(heading, '## 06 Identity Activity')
        self.assertTrue(purpose.strip())
        self.assertEqual(link, '[Open Identity Activity](/app/TA-gen_ai_cim/%s)' % VIEW)
        count = viz['viz_count_06']
        self.assertEqual(count['options']['underLabel'], 'identities active, last 24h')
        source = ds[count['dataSources']['primary']]
        self.assertEqual(source['options']['queryParameters'], {'earliest': '-24h', 'latest': 'now'})
        # Distinct identity keys with a Duo sign-in or a verified AI turn, the turn
        # being the view's own definition of one.
        query = source['options']['query']
        self.assertIn('`genai_duo_auth_events` | search event_type="authentication" ', query)
        self.assertIn('`genai_identity_activity_events` | where `genai_identity_verified_turn` ', query)
        self.assertTrue(query.endswith('| stats dc(identity_key) as v'), query)
        # Every other card and the scoreboard are still there.
        self.assertEqual(sorted(v for v in viz if re.match(r'^viz_md_\d\d$', v)),
                         ['viz_md_%02d' % n for n in range(1, 7)])
        self.assertEqual(sorted(v for v in viz if re.match(r'^viz_score_\d$', v)),
                         ['viz_score_%d' % n for n in range(1, 6)])

    def test_readme_lists_the_dashboard_and_the_changelog_entry(self):
        readme = self.text('README.md')
        rows = [line for line in readme.split('\n') if line.startswith('| **')]
        at = [i for i, line in enumerate(rows) if line.startswith('| **Duo Identity Feed** |')]
        self.assertEqual(len(at), 1)
        row = rows[at[0] + 1]
        self.assertTrue(row.startswith('| **Identity Activity** | Per identity, '), row)
        self.assertIn('need Enterprise Security', row)
        self.assertIn('counted apart as claimed, not verified (never a sign-in)', row)
        self.assertIn('| *Identity Activity* dashboard | per identity: ', readme)
        self.assertIn('| `genai_identity_activity_events`, `genai_identity_verified_turn`, '
                      '`genai_identity_claimed_events`, `genai_identity_claimed_turn`, `genai_identity_duo_class` | '
                      'the five macros behind *Identity Activity*', readme)
        release = readme[readme.index('### v1.9.0'):readme.index('### v1.8.0')]
        entry = release[release.index('- ADDED: *Identity Activity* dashboard (`%s`,' % VIEW):]
        entry = re.sub(r'\s+', ' ', entry[:entry.index('\n- ', 2)])
        for needle in ('A time range input (default last 14 days) and an identity dropdown',
                       'an application sign-in is matched on that id', '`details.duo_txid`',
                       'matched on user and time, not on a session key', '`genai_identity_join_key`',
                       '`genai_identity_activity_events`', '`genai_identity_verified_turn`',
                       '`genai_identity_duo_class`', 'shows `risk_events` and `findings` apart',
                       '`Risk.All_Risk` (user risk) and `identity_lookup_expanded`',
                       'without it they show an error', 'Home card 06 (KPI *identities active, last 24h*',
                       'a Dashboards menu entry after *Duo Identity Feed*'):
            self.assertIn(needle, entry)
        # The release notes say what was verified live, without naming a user, a tenant or an address.
        validation = re.sub(r'\s+', ' ', release[release.index('- Validation: AppInspect'):])
        for needle in ('On 2026-11-16 the branch was loaded on a live Splunk 10.4.3 with Enterprise Security 8.5.1',
                       'a complete 8-user snapshot', 'ran on its 10-minute schedule',
                       'Not exercised: the UEBA pages'):
            self.assertIn(needle, validation)
        self.assertNotIn('Offline tests only', validation)
        self.assertNotRegex(validation, r'[\w.+-]+@[\w-]+\.[\w.-]+|\b\d{1,3}(?:\.\d{1,3}){3}\b|duosecurity')
        self.assertRegex(readme, r'(?m)^Version: 1\.9\.0\s*$')

    def test_readme_changelog_has_the_claimed_not_verified_entry(self):
        readme = self.text('README.md')
        release = readme[readme.index('### v1.9.0'):readme.index('### v1.8.0')]
        entry = release[release.index('- ADDED (*Identity Activity*, lab-readiness review 2026-11-17): claimed, not'):]
        entry = re.sub(r'\s+', ' ', entry[:entry.index('\n- ', 2)])
        for needle in ('read as 0 AI turns for that persona', '`claimed_not_verified` and `claimed_blocked` after '
                       '`gate_verdicts`', '*AI turn claimed, not verified*', '`genai_identity_claimed_turn`',
                       '`genai_identity_claimed_events`', 'never a sign-in, never part of `ai_turns`',
                       'gets no row, no dropdown entry and no bar', 'do not read claimed turns',
                       'the application\'s HEC feed does not'):
            self.assertIn(needle, entry)
        self.assertNotRegex(entry, r'[\w.+-]+@[\w-]+\.[\w.-]+|\b\d{1,3}(?:\.\d{1,3}){3}\b|duosecurity')
        # It follows the dashboard's own entry, which is unchanged.
        self.assertLess(release.index('- ADDED: *Identity Activity* dashboard'), release.index(
            '- ADDED (*Identity Activity*, lab-readiness review 2026-11-17)'))

    def claimed_section(self):
        """The README's "Identity Activity: claimed, not verified turns" section."""
        readme = self.text('README.md')
        start = readme.index('### Identity Activity: claimed, not verified turns\n')
        return readme[start:readme.index('\n### ', start + 4)]

    def test_readme_says_what_a_claimed_turn_is_and_what_a_staged_lab_needs(self):
        """A claimed count of 0 has three innocent causes a facilitator must rule out
        before the room looks: no spray named the persona, the application's events
        never reached this stack (its HEC feed does not backfill), or the persona is
        outside the time range. The README says each, in this order."""
        readme = self.text('README.md')
        # After the joined rule (which a claimed turn never counts for), before the input's section.
        self.assertLess(readme.index('### The joined rule: Duo burst, sign-in, blocked AI turn'),
                        readme.index('### Identity Activity: claimed, not verified turns'))
        section = self.claimed_section()
        self.assertTrue(readme[readme.index(section) + len(section):].startswith('\n### How the input reads Duo\n'))
        flat = re.sub(r'\s+', ' ', section)
        needles = ('counts two kinds of AI turn for an identity, side by side, and never adds them',
                   '**Verified** (`ai_turns`, `ai_blocked`;', '(`genai_identity_verified_turn`)',
                   '**Claimed, not verified** (`claimed_not_verified`, `claimed_blocked`;',
                   '(`genai_identity_claimed_turn`, read through `genai_identity_claimed_events`)',
                   'is never a sign-in, is never matched to a Duo sign-in, and never counts for the joined rule',
                   'gets no row, no dropdown entry and no bar',
                   '**What a staged lab needs.**',
                   '1. The staged scenario includes a prompt-injection spray that names the persona.',
                   '2. The application\'s events for the staging are in that stack.',
                   'the application\'s HEC feed does not',
                   'all read 0 for the staged days unless those events are sent to that stack as well. '
                   '`tools/staged_resend.py` does that',
                   'the view counts events and does not drop a second copy',
                   '3. The spray, and a Duo sign-in or an application identity event of the persona, fall inside '
                   'the time range of the view',
                   '0 means the stack holds no such turn in that range: no spray named the persona, the '
                   'application\'s events never reached this stack, or the spray is outside the range.')
        found = [flat.find(needle) for needle in needles]
        self.assertEqual([needle for needle, at in zip(needles, found) if at < 0], [])
        self.assertEqual(found, sorted(found))
        self.assertNotRegex(flat, r'[\w.+-]+@[\w-]+\.[\w.-]+|\b\d{1,3}(?:\.\d{1,3}){3}\b|duosecurity')

    def test_staging_check_is_the_views_own_definition_in_the_readme_and_the_runbook(self):
        """The read-only check a facilitator runs at T-1 counts with the view's two
        macros and its join key, and the README and the runbook print the same
        search (the runbook says victim where the README says persona). The
        runbook's .html carries the same section as its .md."""
        check = ['`genai_identity_claimed_events`', '| where `genai_identity_claimed_turn`',
                 '| eval identity_key=`genai_identity_join_key(user)`', '| search identity_key="<persona>"',
                 '| stats count as claimed_not_verified, count(eval(\'gen_ai.policy.blocked\'=="true")) as '
                 'claimed_blocked,', '    min(_time) as first, max(_time) as last',
                 '| eval first=strftime(first, "%F %T"), last=strftime(last, "%F %T")']

        def fenced(markdown_text):
            return markdown_text.split('```spl\n', 1)[1].split('\n```', 1)[0].split('\n')
        self.assertEqual(fenced(self.claimed_section()), check)
        self.assertIsNone(re.search(WRITES, ' '.join(check)))
        self.assertNotRegex(' '.join(check), r'\bindex\s*=|\bsourcetype\s*=')
        # The check's two counts are the overview's two columns.
        overview = studio(VIEW)[1]['dataSources']['ds_overview']['options']['query']
        for column in ('claimed_not_verified', 'claimed_blocked'):
            self.assertIn(' as %s' % column, overview)
            self.assertIn(' as %s' % column, ' '.join(check))
        heading = 'T-1: is the spray that named the victim in the stack?'
        runbook = self.text('tools', 'lab5-identity-runbook.md')
        start = runbook.index('## %s\n' % heading)
        section = runbook[start:runbook.index('\n## ', start + 4)]
        self.assertEqual([line.replace('<victim>', '<persona>') for line in fenced(section)], check)
        self.assertLess(runbook.index('## T-1: is the victim\'s evidence in the stack?'), start)
        self.assertLess(start, runbook.index('## Lab day'))
        html = self.text('tools', 'lab5-identity-runbook.html')
        page = html[html.index('>%s</h2>' % heading):]
        page = page[:page.index('<h2 ')]
        needs = ('The staged scenario includes a spray that names the victim.',
                 'PseudoCo Assistant\'s events for the staging are in this stack.',
                 'The victim has a Duo sign-in or an application identity event in the view\'s time range')
        for need in needs:
            self.assertIn('**%s' % need.split('\n')[0], re.sub(r'\s+', ' ', section))
            self.assertIn('<strong>%s' % need, re.sub(r'\s+', ' ', page))
        for text in (re.sub(r'\s+', ' ', section), re.sub(r'\s+', ' ', page)):
            for needle in ('staged_resend.py', 'does that, once per event and with its original time',
                           'the view counts events and does not drop a second copy',
                           'A name that is only claimed gets no row.',
                           '0 means the stack holds no such turn in that range: no spray named the victim, '
                           'PseudoCo Assistant\'s events never reached this stack, or the spray is outside the '
                           'range.'):
                self.assertIn(needle, text)
        # The page's code block is the same search, HTML-escaped.
        code = page.split('<pre><code class="language-spl">', 1)[1].split('</code></pre>', 1)[0]
        code = code.replace('&quot;', '"').replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        self.assertEqual([line.replace('<victim>', '<persona>') for line in code.rstrip('\n').split('\n')], check)

    def test_claude_md_lists_the_dashboard_and_its_tests(self):
        claude = re.sub(r'\s+', ' ', self.text('CLAUDE.md'))
        self.assertIn('*Identity Activity* (`%s`, v1.9.0' % VIEW, claude)
        self.assertIn('`test_identity_activity.py`', claude)
        for needle in ('`genai_identity_verified_turn`', '`genai_identity_activity_events`',
                       '`genai_identity_duo_class`', '`details.duo_txid`', 'assert_draw_order`',
                       '`genai_identity_claimed_turn`', '`genai_identity_claimed_events`',
                       'never creates a row, a dropdown entry or a bar',
                       'The first two macros also feed the joined rule (LR-06)',
                       'Its timeline colour is pale on purpose',
                       'the five `genai_identity_*` macros'):
            self.assertIn(needle, claude)


class ResolveTests(ViewTestCase):
    """Offline: the text the live tests dispatch is each data source's own, complete."""

    def test_resolved_queries_are_complete_and_hold_no_token(self):
        for name in self.ds:
            query = resolve(full_query(self.ds, name), 'avery.example')
            self.assertNotIn('$', query, name)
            self.assertTrue(query.startswith('| multisearch\n'), name)
            self.assertIsNone(re.search(WRITES, query), name)
            # The base holds every identity; its chains (not the dropdown's) filter.
            if name not in ('ds_base', 'ds_identities'):
                self.assertIn('| search identity_key="avery.example"', query, name)
        self.assertEqual(len(self.ds), 13)


###############################################################################
# Simulations: makeresults rows through the view's own text
###############################################################################

T0 = 'relative_time(now(), "-1d@d")'      # yesterday 00:00: every offset below is seconds after it
# Duo authentication rows: identity | offset | txid | result | reason | access device address.
# The Duo username is an email-shaped login in another case, the application's a bare
# one: both must reduce to the same identity join key.
DUO_ROW = ('eval f=split(row, "|"), user=upper(mvindex(f, 0)) . "@corp.test", _time=%s+tonumber(mvindex(f, 1)), '
           'txid=nullif(mvindex(f, 2), "-"), result=nullif(mvindex(f, 3), "-"), reason=nullif(mvindex(f, 4), "-"), '
           'src=mvindex(f, 5)' % T0)
# Application rows:
#   identity | offset (nNN = NN seconds ago) | shape | policy_blocked | details.duo_txid | client address.
# shape is the kind of record: chat, tool_call and decision are governance events of a
# signed-in turn, escalation its escalation record, signin the identity_signin_success
# audit record, anonymous a chat event with no identity. Each row gets the raw keys
# PseudoCo Assistant writes, then this branch's own props text makes the gen_ai.* fields.
APP_ROW = ('eval f=split(row, "|"), user=mvindex(f, 0), off=mvindex(f, 1), '
           '_time=if(like(off, "n%%"), now()-tonumber(substr(off, 2)), %s+tonumber(off)), shape=mvindex(f, 2), '
           'operation_name=case(shape=="anonymous", "chat", in(shape, "chat", "tool_call", "decision"), shape), '
           'provider_name=if(isnotnull(operation_name), "ollama", null()), '
           'identity_verified=if(in(shape, "signin", "anonymous"), null(), "true"), '
           'policy_blocked=nullif(mvindex(f, 3), "-"), audit_id=if(shape=="signin", "audit-1", null()), '
           'action=if(shape=="signin", "identity_signin_success", null()), '
           'escalation_id=if(shape=="escalation", "esc-1", null()), "details.duo_txid"=nullif(mvindex(f, 4), "-"), '
           'src=nullif(mvindex(f, 5), "-")' % T0)
# The sign-in chain's application rows, with the gen_ai.* fields set directly (the two
# simulations above cover the props): identity | offset (nNN = NN seconds ago) | shape |
# details.duo_txid | client address; shape is signin, chat or tool_call.
CHAIN_APP_ROW = ('eval f=split(row, "|"), user=mvindex(f, 0), off=mvindex(f, 1), '
                 '_time=if(like(off, "n%%"), now()-tonumber(substr(off, 2)), %s+tonumber(off)), shape=mvindex(f, 2), '
                 '"gen_ai.audit.action"=if(shape=="signin", "identity_signin_success", null()), '
                 '"gen_ai.identity.verified"=if(shape=="signin", null(), "true"), '
                 '"gen_ai.provider.name"=if(shape=="signin", null(), "ollama"), '
                 '"gen_ai.operation.name"=if(shape=="signin", null(), shape), '
                 '"details.duo_txid"=nullif(mvindex(f, 3), "-"), src=nullif(mvindex(f, 4), "-")' % T0)
APP_PROPS = ('FIELDALIAS-genai_operation_name', 'FIELDALIAS-genai_provider_name', 'FIELDALIAS-genai_audit_action_raw',
             'EVAL-gen_ai.identity.verified', 'EVAL-gen_ai.policy.blocked', 'EVAL-gen_ai.audit.action')
OUTCOMES = ['avery.example|10|-|success|-|192.0.2.10', 'avery.example|20|-|denied|-|192.0.2.10',
            'avery.example|30|-|fraud|-|192.0.2.10', 'avery.example|40|-|failure|-|192.0.2.10',
            'avery.example|50|-|error|-|192.0.2.10', 'avery.example|60|-|FAILURE|-|192.0.2.10',
            'avery.example|70|-|denied|user_marked_fraud|192.0.2.10', 'avery.example|80|-|-|-|192.0.2.10']
SHAPES = ['avery.example|100|chat|false|-|192.0.2.10', 'avery.example|101|tool_call|false|-|-',
          'avery.example|200|tool_call|true|-|-', 'avery.example|201|chat|true|-|192.0.2.10',
          'avery.example|202|escalation|-|-|-', 'avery.example|203|decision|-|-|-',
          'avery.example|90|signin|-|-|192.0.2.10', 'avery.example|300|anonymous|false|-|192.0.2.10']
# Application rows of the claimed-turn simulations: name | offset | shape | policy_blocked.
# chat, tool_call and signin are a signed-in turn's chat event, its tool call and the
# identity_signin_success audit record. claim is a chat event with no identity key at all
# (what a spray's turn and every anonymous turn write), claim_false one that says
# identity_verified false, claim_tool the tool call of such a turn, claim_audit the audit
# record of an anonymous session (session_started). A name of "-" is an event with no user.
CLAIM_ROW = ('eval f=split(row, "|"), user=nullif(mvindex(f, 0), "-"), _time=%s+tonumber(mvindex(f, 1)), '
             'shape=mvindex(f, 2), operation_name=case(in(shape, "chat", "claim", "claim_false"), "chat", '
             'in(shape, "tool_call", "claim_tool"), "tool_call"), '
             'provider_name=if(isnotnull(operation_name), "ollama", null()), '
             'identity_verified=case(in(shape, "chat", "tool_call"), "true", shape=="claim_false", "false"), '
             'policy_blocked=nullif(mvindex(f, 3), "-"), '
             'audit_id=if(in(shape, "signin", "claim_audit"), "audit-1", null()), '
             'action=case(shape=="signin", "identity_signin_success", shape=="claim_audit", "session_started")' % T0)
# nina.osei: two Duo sign-ins, an application sign-in, a signed-in turn with a tool call
#   (allowed) and one that was blocked; then four claimed turns, three blocked: one names her
#   with an email-shaped login in another case, one says identity_verified false. The tool
#   call and the audit record of an anonymous turn are not turns.
# jordan.reyes: one Duo sign-in and nothing signed in at the application; two claimed turns.
# marcus.bell: only claimed, in neither feed: no row and no bar. A name with words after
#   it is not jordan.reyes, and an event with no user claims nobody.
CLAIM_DUO = ['nina.osei|10|-|success|-|192.0.2.10', 'nina.osei|20|-|denied|-|192.0.2.10',
             'jordan.reyes|30|-|success|-|192.0.2.20']
CLAIM_APP = ['nina.osei|90|signin|-', 'nina.osei|100|chat|false', 'nina.osei|101|tool_call|false',
             'nina.osei|200|chat|true', 'nina.osei|300|claim|true', 'NINA.OSEI@corp.test|310|claim|true',
             'nina.osei|320|claim_false|true', 'nina.osei|330|claim|false', 'nina.osei|331|claim_tool|true',
             'nina.osei|332|claim_audit|-', 'jordan.reyes|400|claim|true', 'jordan.reyes|410|claim|false',
             'marcus.bell|500|claim|true', 'jordan.reyes extra words|510|claim|true', '-|520|claim|true']


def app_props():
    """This branch's [gen_ai:json] text for the fields the view reads, as eval
    commands: the aliases first, then the EVALs that read them (like search time)."""
    props = read_conf('props.conf')['gen_ai:json']
    aliases, evals = [], []
    for key in APP_PROPS:
        value = props[key].replace('\n', ' ')
        if key.startswith('FIELDALIAS-'):
            orig, new = re.match(r'^(\S+) AS (\S+)$', value).groups()
            aliases.append('"%s"=\'%s\'' % (new, orig))
        else:
            evals.append('"%s"=(%s)' % (key[len('EVAL-'):], value))
    return '| eval %s | eval %s' % (', '.join(aliases), ', '.join(evals))


def branch_eval(query, macro):
    """The eval command of the multisearch branch that reads `macro`."""
    found = re.search(r'\[ search `%s`\n(?:    \| search [^\n]+\n)?    (\| eval [^\n]+) \]\n' % macro, query)
    return found.group(1)


def risk_tail(query):
    """What a risk subsearch does to the rows of its tstats, one command per line."""
    found = re.search(r'    \[\| tstats [^\n]+\n((?:    \| [^\n]+\n)+?)(?=\| )', query + '| ')
    lines = [line.strip() for line in found.group(1).rstrip('\n').split('\n')]
    lines[-1] = re.sub(r' \]$', '', lines[-1])
    return ' '.join(lines)


def rows(items, parse):
    return '| makeresults | eval row=split("%s", ";") | mvexpand row | %s | fields - row, f' % (';'.join(items), parse)


def both_feeds(query, duo, app, app_row=None):
    """duo and app rows through the two branch evals of query, as multisearch would
    deliver them. Application rows get this branch's props text unless app_row
    (a parser that sets the gen_ai.* fields itself) is given."""
    parse = rows(app, app_row) if app_row else rows(app, APP_ROW) + ' ' + app_props()
    return ('%s %s | append [ %s %s ]' % (rows(duo, DUO_ROW), branch_eval(query, 'genai_duo_auth_events'), parse,
                                          branch_eval(query, 'genai_identity_activity_events')))


def answer(sig):
    return ' | eval sig=%s | stats list(sig) as sigs | eval got=mvjoin(sigs, "; ") | fields got' % sig


CHAIN_SIG = ('identity . "/" . app_event . "/" . duo_result . "/" . duo_src . "/" . duo_denied_10m . "/" . '
             'coalesce(seconds_apart, "-") . "/" . addresses_match . "/" . matched_on . '
             'if(matched_on=="none", " (" . duo_signin . ")", "")')


def sim_tiles(ds):
    q = ds['ds_base']['options']['query']
    return (both_feeds(q, OUTCOMES, SHAPES) + ' ' + q[q.index('| where isnotnull(identity_key)'):].replace('\n', ' ') +
            answer('identity_key . ": sign-ins " . duo_signins . ", succeeded " . duo_success . ", denied or fraud " . '
                   'duo_denied_fraud . ", turns " . ai_turns . ", blocked " . ai_blocked'))


def sim_timeline(ds):
    q = ds['ds_timeline']['options']['query']
    return (both_feeds(q, OUTCOMES, SHAPES) + ' | where isnotnull(activity) | stats sum(n) as n by activity '
            '| sort 0 str(activity)' + answer('activity . " " . n'))


def sim_chain(duo, app):
    def build(ds):
        q = ds['ds_duo_to_ai']['options']['query']
        tail = resolve(q[q.index('| where isnotnull(kind)'):]).replace('\n', ' ')
        return (both_feeds(q, duo, app, CHAIN_APP_ROW) + ' ' + tail + ' | sort 0 str(identity), app_time' +
                answer(CHAIN_SIG))
    return build


def field_filter(definition):
    """The field filter of an application event macro: its definition without the base
    search and without the raw term that only narrows the scan. Run as "| search" on
    makeresults rows it keeps what the macro would return."""
    found = re.match(r'^`genai_identity_ai_events` (?:identity_\* )?(.+)$', definition)
    return found.group(1)


def three_feeds(query, duo, app, macro_filters):
    """duo and app rows through the three branch evals of query. appendpipe forks the
    application rows into the application branch and the claimed branch, so their text
    is in the search once. With macro_filters each fork first applies the field filter
    of its event macro, as on a real search (the overview counts every event the
    application macro returns as application activity). Without, every row goes through
    BOTH branch evals, so the two predicates alone must keep the counts apart."""
    def fork(macro, definition, mark):
        keep = ' | search %s' % field_filter(definition) if macro_filters else ''
        return 'appendpipe [ where isnull(fork)%s %s | eval fork=%d ]' % (keep, branch_eval(query, macro), mark)
    return ('%s %s | %s | %s | where isnotnull(fork) | append [ %s %s ]' % (
        rows(app, CLAIM_ROW), app_props(), fork('genai_identity_activity_events', ACTIVITY_EVENTS, 1),
        fork('genai_identity_claimed_events', CLAIMED_EVENTS, 2), rows(duo, DUO_ROW),
        branch_eval(query, 'genai_duo_auth_events')))


def sim_overview_claimed(ds):
    q = ds['ds_overview']['options']['query']
    tail = resolve(q[q.index('| where isnotnull(identity_key)'):q.index('| lookup identity_lookup_expanded')])
    fill = [line for line in q.split('\n') if line.startswith('| fillnull value=0 ai_turns')][0]
    return (three_feeds(q, CLAIM_DUO, CLAIM_APP, True) + ' ' + tail.replace('\n', ' ') + fill +
            ' | sort 0 str(identity_key)' +
            answer('identity_key . ": verified " . ai_turns . " (blocked " . ai_blocked . "), claimed not verified " . '
                   'claimed_not_verified . " (blocked " . claimed_blocked . ")"'))


def sim_timeline_claimed(ds):
    q = ds['ds_timeline']['options']['query']
    in_feed = [line for line in q.split('\n') if line.startswith('| eventstats max(eval(if(activity==')][0]
    return (three_feeds(q, CLAIM_DUO, CLAIM_APP, False) + ' | where isnotnull(activity) '
            '| stats sum(n) as n by identity_key, activity ' + in_feed + ' | where in_feed==1 '
            '| sort 0 str(identity_key), str(activity)' + answer('identity_key . " " . activity . " " . n'))


def sim_risk(name):
    def build(ds):
        q = ds[name]['options']['query']
        feed = ('| makeresults | eval row=split("avery.example|risk|2|160;AVERY.EXAMPLE@corp.test|risk|1|80;'
                'avery.example|notable|1|80;blake.example|notable|1|60", ";") | mvexpand row '
                '| eval f=split(row, "|"), "All_Risk.risk_object"=mvindex(f, 0), index=mvindex(f, 1), '
                'n=tonumber(mvindex(f, 2)), risk_score=tonumber(mvindex(f, 3)), _time=%s+7200 | fields - row, f ' % T0)
        sig = ('identity_key . " " . activity . " " . n' if name == 'ds_timeline' else
               'identity_key . ": risk events " . risk_events . ", findings " . findings . ", score " . risk_score')
        order = ' | sort 0 str(identity_key), str(activity)' if name == 'ds_timeline' else ''
        return feed + resolve(risk_tail(q)) + order + answer(sig)
    return build


# name -> (builder taking the view's data sources, the one value the search returns in "got").
SIMULATIONS = [
    # Eight Duo outcomes: success 1, denied 3 (failure counts as denied), fraud 2, other 2.
    # Eight application records of two signed-in turns: one chat event each is a turn.
    ('tiles', sim_tiles, 'avery.example: sign-ins 8, succeeded 1, denied or fraud 5, turns 2, blocked 1'),
    ('timeline', sim_timeline, 'AI turn allowed 1; AI turn blocked 1; Duo failure 5; Duo other 2; Duo success 1; '
                               'application sign-in 1'),
    # a: the application's clock is behind (its record is dated before the Duo event it names).
    # b: a denial from another address between the success and the sign-in; a tool call before the chat event.
    # c: a sign-in record with no transaction id. d: a denied and a success in the same second.
    ('sign_in_chain_exact_and_fallback',
     sim_chain(['b|1000|T1|success|-|192.0.2.10', 'b|1001|T2|denied|-|198.51.100.7', 'a|2002|T3|success|-|192.0.2.20',
                'c|3000|T4|success|-|192.0.2.30', 'c|3025|T5|denied|-|203.0.113.5', 'd|5000|T6|denied|-|203.0.113.9',
                'd|5000|T7|success|-|192.0.2.40'],
               ['b|1003|signin|T1|192.0.2.10', 'b|1055|tool_call|-|-', 'b|1060|chat|-|192.0.2.10',
                'a|2000|signin|T3|192.0.2.20', 'c|3030|signin|-|192.0.2.30', 'd|5004|signin|-|192.0.2.40']),
     'a/application sign-in/success/192.0.2.20/0/-2/yes/transaction id; '
     'b/application sign-in/success/192.0.2.10/1/3/yes/transaction id; '
     'b/first verified turn/success/192.0.2.10/1/60/yes/user and time; '
     'c/application sign-in/success/192.0.2.30/1/30/yes/user and time; '
     'd/application sign-in/success/192.0.2.40/1/4/yes/user and time'),
    # e: later authentications to another application start no new "first verified turn" row.
    # f: a sign-in one minute old with nothing from Duo yet. g: a turn with no sign-in and no Duo event.
    ('sign_in_chain_anchor_and_lag',
     sim_chain(['e|6000|T8|success|-|192.0.2.50', 'e|6120|T9|success|-|198.51.100.50',
                'e|6240|T10|success|-|198.51.100.50'],
               ['e|6003|signin|T8|192.0.2.50', 'e|6060|chat|-|192.0.2.50', 'e|6180|chat|-|192.0.2.50',
                'e|6300|chat|-|192.0.2.50', 'f|n60|signin|T11|192.0.2.60', 'g|7000|chat|-|192.0.2.70']),
     'e/application sign-in/success/192.0.2.50/0/3/yes/transaction id; '
     'e/first verified turn/success/192.0.2.50/0/60/yes/user and time; '
     'f/application sign-in/-/-/0/-/unknown/none (Duo log may not be in yet); '
     'g/first verified turn/-/-/0/-/unknown/none (none within 10 min)'),
    # h: the nearest success is 11 minutes back (no match); four denials, a failure and a fraud
    # report in the last 10 minutes. i: the same burst, then a success 20 seconds before the turn.
    ('sign_in_chain_denials',
     sim_chain(['h|8000|T12|success|-|192.0.2.80', 'h|8100|T13|denied|-|203.0.113.80',
                'h|8200|T14|denied|-|203.0.113.80', 'h|8300|T15|denied|-|203.0.113.80',
                'h|8400|T16|denied|-|203.0.113.80', 'h|8500|T17|failure|-|203.0.113.80',
                'h|8600|T18|fraud|-|203.0.113.80', 'i|9000|T19|denied|-|203.0.113.90',
                'i|9010|T20|denied|-|203.0.113.90', 'i|9040|T21|success|-|203.0.113.90'],
               ['h|8660|chat|-|192.0.2.80', 'i|9060|chat|-|192.0.2.90']),
     'h/first verified turn/-/-/6/-/unknown/none (none within 10 min); '
     'i/first verified turn/success/203.0.113.90/2/20/no/user and time'),
    # One rule fired twice with a risk event each (once on an email-shaped risk object) and raised
    # one finding; another detection only raised a finding and must not vanish.
    ('overview_risk', sim_risk('ds_overview'), 'avery.example: risk events 3, findings 1, score 320; '
                                               'blake.example: risk events 0, findings 1, score 60'),
    ('timeline_risk', sim_risk('ds_timeline'), 'avery.example finding 1; avery.example risk event 3; '
                                               'blake.example finding 1'),
    # A spray names nina.osei (signed in elsewhere in the range) and jordan.reyes (Duo sign-in only):
    # their claimed turns sit beside their verified turns and never in them. marcus.bell is named
    # too but is in neither feed, and one name has words after it: neither gets a row.
    ('overview_claimed', sim_overview_claimed,
     'jordan.reyes: verified 0 (blocked 0), claimed not verified 2 (blocked 1); '
     'nina.osei: verified 2 (blocked 1), claimed not verified 4 (blocked 3)'),
    # The same rows with no event-macro filter: every application row goes through both branch
    # evals, and each chat event still gives exactly one bar.
    ('timeline_claimed', sim_timeline_claimed,
     'jordan.reyes AI turn claimed, not verified 2; jordan.reyes Duo success 1; nina.osei AI turn allowed 1; '
     'nina.osei AI turn blocked 1; nina.osei AI turn claimed, not verified 4; nina.osei Duo failure 1; '
     'nina.osei Duo success 1; nina.osei application sign-in 1'),
]


class SimulationTextTests(ViewTestCase):
    """Offline: every simulation is built from the view's current text, reads nothing
    but its own rows, and fits one search (the view's own queries stay under the
    5,000 characters some read-only search tools accept)."""

    def test_simulations_are_self_contained_and_read_only(self):
        self.assertEqual(len({name for name, _build, _expect in SIMULATIONS}), len(SIMULATIONS))
        for name, build, expect in SIMULATIONS:
            with self.subTest(name):
                spl = build(self.ds)
                self.assertTrue(spl.startswith('| makeresults | eval row=split("'), spl[:60])
                self.assertTrue(spl.endswith('| fields got'), spl[-60:])
                self.assertNotIn('$', spl)
                self.assertNotIn('\n', spl)
                self.assertIsNone(re.search(WRITES, spl), name)
                # Its only source of rows is makeresults: no index, no event macro, no data model.
                self.assertNotRegex(spl, r'\|\s*(tstats|inputlookup|inputcsv|from|loadjob|savedsearch|pivot|rest|'
                                         r'metadata|dbinspect|multisearch|datamodel)\b')
                self.assertNotRegex(spl, r'`genai_\w+_events`|\bsearch\s+index\s*=|\[\s*search\b')
                self.assertLess(len(spl), 5000, name)
                self.assertTrue(expect.strip())
                for ip in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', spl + expect):
                    self.assertRegex(ip, r'^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$', ip)
                for email in re.findall(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+', spl):
                    self.assertTrue(email.lower().endswith('@corp.test'), email)

    def test_simulations_run_the_views_own_text(self):
        """A branch's eval and a search's tail are cut from the view, so a change to
        the view changes what the live run checks."""
        base, chain = own_query(self.ds, 'ds_base'), own_query(self.ds, 'ds_duo_to_ai')
        built = {name: build(self.ds) for name, build, _expect in SIMULATIONS}
        self.assertIn(branch_eval(base, 'genai_identity_activity_events'), built['tiles'])
        self.assertIn(branch_eval(base, 'genai_duo_auth_events'), built['tiles'])
        self.assertIn('turn=if(`genai_identity_verified_turn`, 1, 0)',
                      branch_eval(base, 'genai_identity_activity_events'))
        tail = resolve(chain[chain.index('| where isnotnull(kind)'):]).replace('\n', ' ')
        for name in ('sign_in_chain_exact_and_fallback', 'sign_in_chain_anchor_and_lag', 'sign_in_chain_denials'):
            self.assertIn(tail, built[name])
            self.assertIn(branch_eval(chain, 'genai_duo_auth_events'), built[name])
        self.assertIn('risk_events=if(risk_index=="notable", 0, n)', built['overview_risk'])
        # The claimed-turn simulations run all three branch evals of their search, the two
        # application ones on the same rows; the overview's also runs the macros' own filters.
        for name, source in (('overview_claimed', 'ds_overview'), ('timeline_claimed', 'ds_timeline')):
            query = own_query(self.ds, source)
            for macro in ('genai_duo_auth_events', 'genai_identity_activity_events', 'genai_identity_claimed_events'):
                self.assertIn(branch_eval(query, macro), built[name], (name, macro))
            self.assertEqual(built[name].count('appendpipe [ where isnull(fork)'), 2, name)
        self.assertEqual(field_filter(ACTIVITY_EVENTS),
                         '(gen_ai.identity.verified="true" OR gen_ai.audit.action="identity_*")')
        self.assertEqual(field_filter(CLAIMED_EVENTS),
                         'gen_ai.operation.name="chat" NOT gen_ai.identity.verified="true"')
        for definition in (ACTIVITY_EVENTS, CLAIMED_EVENTS):
            self.assertIn(' | search %s | eval ' % field_filter(definition), built['overview_claimed'])
            self.assertNotIn(' | search %s | eval ' % field_filter(definition), built['timeline_claimed'])
        self.assertIn('sum(claimed) as claimed_not_verified', built['overview_claimed'])
        self.assertIn('| where duo_signins>0 OR app_events>0 ', built['overview_claimed'])
        self.assertIn('OR activity=="%s", 0, 1))) as in_feed by identity_key | where in_feed==1 ' % CLAIMED,
                      built['timeline_claimed'])
        self.assertIn('| addinfo | eval span=', built['timeline_risk'])
        # The application rows get this branch's props text, not a copy of it.
        props = read_conf('props.conf')['gen_ai:json']
        self.assertIn('(%s)' % props['EVAL-gen_ai.identity.verified'].replace('\n', ' '), app_props())
        self.assertIn('"gen_ai.operation.name"=\'operation_name\'', app_props())

    def test_views_own_queries_fit_a_5000_character_search(self):
        for name in self.ds:
            self.assertLess(len(resolve(full_query(self.ds, name), 'avery.example')), 5000, name)


LIVE = bool(os.environ.get('SPLUNK_TEST_URL') and
            (os.environ.get('SPLUNK_TEST_PASSWORD') or os.environ.get('SPLUNK_TEST_TOKEN')))


@unittest.skipUnless(LIVE, 'set SPLUNK_TEST_URL and SPLUNK_TEST_PASSWORD (or SPLUNK_TEST_TOKEN)')
class IdentityActivityLiveTests(ViewTestCase):
    """R-CONF-003: a search that parses is not a search that runs. Dispatches every
    data source of the view (a chain joined to its base) with the tokens filled
    in. Read-only. The four searches fed by Enterprise Security are skipped on
    a Splunk without it, where they cannot run by design."""

    def dispatch(self, name, earliest, latest, identity='*'):
        from test_duo_spl import export_window
        return export_window(resolve(full_query(self.ds, name), identity), earliest, latest)

    def runnable(self):
        from test_duo_spl import export_window
        _rows, errors = export_window('| tstats count from datamodel=Risk.All_Risk '
                                      '| lookup identity_lookup_expanded identity as count OUTPUT category', '1', '2')
        for name in sorted(self.ds):
            if errors and any(source in full_query(self.ds, name) for source in ES_SOURCES):
                continue
            yield name

    def kpi_sources(self):
        return [self.viz[name]['dataSources']['primary'] for name, _label, _feed in KPIS]

    def test_every_search_runs_and_every_kpi_is_zero_on_an_empty_window(self):
        ran = 0
        for name in self.runnable():
            with self.subTest(name):
                rows, errors = self.dispatch(name, '1', '2')     # two seconds of 1970: no event
                self.assertEqual(errors, [], name)
                if name in self.kpi_sources():
                    self.assertEqual(rows, [{'v': '0'}], name)
                ran += 1
        self.assertGreaterEqual(ran, 9)

    def test_every_search_runs_over_the_default_window(self):
        default = self.d['inputs']['input_time']['options']['defaultValue'].split(',')
        for name in self.runnable():
            with self.subTest(name):
                rows, errors = self.dispatch(name, *default)
                self.assertEqual(errors, [], name)
                if name in self.kpi_sources():
                    self.assertEqual(len(rows), 1, name)
                    self.assertRegex(rows[0].get('v', ''), r'^\d+$', name)

    def test_identity_value_is_never_read_as_spl(self):
        """A value that would widen the filter if it were pasted in unquoted matches
        no identity once it is quoted and escaped the way |s does."""
        for name in ('ds_kpi_duo_identities', 'ds_kpi_ai_identities'):
            rows, errors = self.dispatch(name, *self.d['inputs']['input_time']['options']['defaultValue'].split(','),
                                         identity='nobody" OR identity_key="*')
            self.assertEqual(errors, [], name)
            self.assertEqual(rows, [{'v': '0'}], name)

    def test_home_card_returns_a_row_on_an_empty_window(self):
        from test_duo_spl import export_window
        _root, home = studio(HOME)
        rows, errors = export_window(home['dataSources']['ds_card_06']['options']['query'], '1', '2')
        self.assertEqual(errors, [])
        self.assertEqual(rows, [{'v': '0'}])


@unittest.skipUnless(LIVE, 'set SPLUNK_TEST_URL and SPLUNK_TEST_PASSWORD (or SPLUNK_TEST_TOKEN)')
class SimulationLiveTests(ViewTestCase):
    """R-CONF-003 for the view's logic: each simulation's rows go through the view's
    own text and the macros on a real splunkd, and the answer is compared. Read-only
    (makeresults only)."""

    def test_simulations(self):
        from test_duo_spl import export_window
        for name, build, expect in SIMULATIONS:
            with self.subTest(name):
                found, errors = export_window(build(self.ds), '-1m')
                self.assertEqual(errors, [], name)
                self.assertEqual(found, [{'got': expect}], name)


if __name__ == '__main__':
    # "python3 tools/tests/test_identity_activity.py --simulations" prints each simulation's
    # SPL and its expected answer, to paste into any search bar (they only read makeresults).
    if '--simulations' in sys.argv:
        _root, _definition = studio(VIEW)
        for _name, _build, _expect in SIMULATIONS:
            print('### %s\n%s\n### expect got = %s\n' % (_name, _build(_definition['dataSources']), _expect))
        sys.exit(0)
    unittest.main()
