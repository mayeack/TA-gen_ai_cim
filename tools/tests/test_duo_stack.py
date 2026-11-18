# encoding=utf-8
"""
Offline tests for the Cisco Duo feed steps of tools/show_postdeploy.py
(tools/duo_steps.py: --duo and --duo-teardown), against fake_splunk_rest.py, a
loopback stand-in for one Splunk Cloud stack's splunkd REST and ACS index
endpoints. Nothing here reaches a real Splunk, ACS or Duo.

What is pinned:
  * the order the lab model needs: index confirmed, account stored and rules
    enabled before the authentication input (whose first poll is the backfill)
    is created; no input into a missing index; no backfill twice, none skipped;
  * the rules are checked as they SHIP (the fake serves the stanzas of
    default/savedsearches.conf): each judges by index time on a slot exactly
    one cron period wide, and its dispatch.earliest_time is never read as an
    event-time reach;
  * a second run writes nothing and needs no Duo key; --dry-run makes the reads
    and no write;
  * the Duo secret key comes only from a named environment variable or the
    hidden prompt, travels only in the body of the account write, and is never
    printed, not by this tool, argparse or a reply that echoes its request; a
    Duo run verifies the stack's certificate unless told not to, and says so;
  * what a stack holds is explicit: the users snapshot and the identity lookup
    search are opt-in, and every setup run prints what the stack will hold;
  * the polling interval is a parameter with no default;
  * D8 says whether every burst and chain that is indexed was raised;
  * the teardown removes everything, the key included, and deletes the index
    and the checkpoints together or not at all;
  * every guard refuses on an answer it cannot read: a read that fails never
    lets an input be created, an index, a checkpoint or the lookup file be
    deleted, or a catch-up be advised;
  * the command line itself: main() is run with valid command lines against
    the fake stack, and no token from argv is ever printed back;
  * the tool's names agree with the shipped confs and docs, and a new rule
    that reads the Duo feed cannot land without the tool knowing it.

    python3 -m unittest discover -s tools/tests -p 'test_duo_stack.py' -v
"""

import contextlib
import http.server
import io
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
for _path in (os.path.join(REPO, 'bin'), os.path.join(REPO, 'tools'), HERE):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import genai_es_seed as seed  # noqa: E402
import fake_splunk_rest as fake_rest  # noqa: E402
import duo_steps as duo  # noqa: E402
import lab5_steps as lab5  # noqa: E402
import show_postdeploy  # noqa: E402
import test_duo_account as acct  # noqa: E402
import test_duo_conf  # noqa: E402
from test_lab5_conf import read_conf  # noqa: E402

DUO_RULE, CHAIN_RULE, LOOKUP_GEN = fake_rest.DUO_RULE, fake_rest.CHAIN_RULE, fake_rest.LOOKUP_GEN

HOST, IKEY, SKEY, SKEY2 = acct.DUO_HOST, acct.IKEY, acct.SKEY, acct.SKEY2
ENV = {duo.ENV_HOST: HOST, duo.ENV_IKEY: IKEY, duo.ENV_SKEY: SKEY}
CP_AUTH = 'ta_gen_ai_cim_duo://duo_authentication'
CP_USERS = 'ta_gen_ai_cim_duo://duo_users'
ACCOUNT_PATH = '/servicesNS/nobody/TA-gen_ai_cim/ta_gen_ai_cim_account/ta_gen_ai_cim_account'
INPUT_PATH = '/servicesNS/nobody/TA-gen_ai_cim/data/inputs/ta_gen_ai_cim_duo'
REALM = ('ta_gen_ai_cim_account__duo', 'client_secret')
STACK_URL = 'https://{}.splunkcloud.com'.format(fake_rest.STACK)
BASE = ['--stack', STACK_URL, '--password', fake_rest.ADMIN_PASSWORD, '--acs-token', fake_rest.ACS_TOKEN]
RULE_NAME = re.compile(r'^AI Governance - .* - Rule$')
READS_DUO = re.compile(r'genai_duo_|ta_gen_ai_cim:duo:')
REAL_HOST = re.compile(r'api-[a-z0-9]{6,}\.duo(?:security|federal)\.com')


def text_of(*parts):
    with io.open(os.path.join(*parts), encoding='utf-8') as handle:
        return handle.read()


class StackCase(unittest.TestCase):

    def setUp(self):
        self.fake = fake_rest.FakeStack()
        self.server = self.fake.serve()
        self.base = 'http://127.0.0.1:{}'.format(self.server.server_address[1])
        self.printed = io.StringIO()
        self.prompts = []
        self.sleeps = []
        self._tick = [0.0]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        # Whatever a test did, the secret key was printed nowhere and travelled
        # only in the body of an account write.
        self.assert_secret_stayed_put()

    def assert_secret_stayed_put(self):
        text = self.printed.getvalue()
        for secret in (SKEY, SKEY2):
            self.assertNotIn(secret, text)
            for chunk in (secret[:12], secret[-12:]):
                self.assertNotIn(chunk, text)
            for request in self.fake.requests:
                carried = secret in request['raw'] or secret in request['query'] or secret in request['path'] \
                    or secret in json.dumps(request['headers'])
                if carried:
                    self.assertEqual(request['method'], 'POST')
                    self.assertTrue(request['path'].startswith(ACCOUNT_PATH), request['path'])
                    self.assertNotIn(secret, request['query'])
                    self.assertNotIn(secret, request['path'])
                    self.assertNotIn(secret, json.dumps(request['headers']))

    def clock(self):
        self._tick[0] += 10.0
        return self._tick[0]

    def clients(self, dry_run=False):
        echo = lambda line: self.printed.write(line + '\n')     # noqa: E731
        splunkd = seed.Splunkd(self.base, username=fake_rest.ADMIN_USER, password=fake_rest.ADMIN_PASSWORD,
                               dry_run=dry_run, echo=echo)
        acs = show_postdeploy.AcsClient(fake_rest.STACK, fake_rest.ACS_TOKEN, dry_run=dry_run)
        acs.base = self.base
        return splunkd, acs, seed.Reporter(echo=echo)

    def creds(self, env=None, interactive=False, typed=None):
        def hidden(text):
            self.prompts.append(('hidden', text))
            if typed is None:
                raise AssertionError('the secret key was prompted for')
            return typed.get('skey', '')

        def visible(text):
            self.prompts.append(('visible', text))
            if typed is None:
                raise AssertionError('prompted for ' + text)
            return typed.get('host' if 'hostname' in text else 'ikey', '')

        return duo.Credentials(env=dict(ENV if env is None else env), interactive=interactive,
                               hidden_prompt=hidden, visible_prompt=visible)

    def setup_run(self, dry_run=False, env=None, interactive=False, typed=None, skip_acs=False, **settings):
        settings.setdefault('auth_interval', '300')
        splunkd, acs, rep = self.clients(dry_run)
        with contextlib.redirect_stdout(self.printed), contextlib.redirect_stderr(self.printed):
            duo.setup(splunkd, acs, rep, self.creds(env, interactive, typed), duo.Settings(**settings),
                      skip_acs, sleep=self.sleeps.append, clock=self.clock)
        return rep

    def teardown_run(self, dry_run=False, purge=True, skip_acs=False, roles=(duo.ATTENDEE_ROLE,)):
        splunkd, acs, rep = self.clients(dry_run)
        with contextlib.redirect_stdout(self.printed), contextlib.redirect_stderr(self.printed):
            duo.teardown(splunkd, acs, rep, skip_acs, purge, roles, sleep=self.sleeps.append, clock=self.clock)
        return rep

    def checkpoints(self):
        return sorted(self.fake.kv.get('ta_gen_ai_cim_duo_checkpoint', {}))

    @staticmethod
    def rows(rep, status=None):
        return [(s, step, detail) for s, step, detail in rep.rows if status is None or s == status]

    def row(self, rep, needle):
        found = [r for r in rep.rows if needle in r[1]]
        self.assertEqual(len(found), 1, (needle, rep.rows))
        return found[0]


class SetupTests(StackCase):

    def test_fresh_stack_ends_fully_set_up(self):
        """The fake serves the stanzas that SHIP: a fresh --duo against them has
        no failure and creates the authentication input (reviewer correction 2:
        the first build's tests passed against a rule schedule invented in the
        fake, while the real rule would have been refused)."""
        rep = self.setup_run()
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        fake = self.fake
        self.assertEqual(fake.acs_indexes['duo'], {'searchableDays': 90})
        self.assertEqual(fake.account_store.conf['duo'],
                         {'url': 'https://' + HOST, 'auth_type': 'duo_hmac', 'client_id': IKEY})
        self.assertEqual(fake.secret(), SKEY)
        self.assertEqual(fake.roles['splunker']['srchIndexesAllowed'], ['main', 'gen_ai_log', 'duo'])
        self.assertEqual(fake.roles['splunker']['srchIndexesDefault'], ['main'])
        self.assertFalse(fake.saved[DUO_RULE]['disabled'])
        self.assertFalse(fake.saved[CHAIN_RULE]['disabled'])
        self.assertTrue(fake.saved[LOOKUP_GEN]['disabled'])               # opt-in: not asked for
        self.assertEqual(fake.inputs, {'duo_authentication': {
            'account': 'duo', 'endpoint': 'authentication', 'index': 'duo', 'interval': '300',
            'initial_lookback_hours': '720', 'lag_seconds': '180', 'disabled': False}})
        self.assertEqual(self.prompts, [])
        self.assertIn('judged once, by index time, in slots of 10 and 5 min',
                      self.row(rep, 'D5. the rules judge the backfill')[2])

    def test_with_users_and_lookup_gen_everything_the_readme_lists_is_on(self):
        rep = self.setup_run(users_input=True, lookup_gen=True)
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertFalse(self.fake.saved[LOOKUP_GEN]['disabled'])
        self.assertEqual(self.fake.inputs['duo_users'],
                         {'account': 'duo', 'endpoint': 'users', 'index': 'duo', 'interval': '86400',
                          'lag_seconds': '180', 'disabled': False})
        self.assertIn('duo_authentication', self.fake.inputs)
        created = [r['form']['name'] for r in self.fake.requests if r['method'] == 'POST' and r['path'] == INPUT_PATH]
        self.assertEqual(created, ['duo_users', 'duo_authentication'])

    def test_order_index_account_rules_then_inputs(self):
        """The lab model's order: the index exists and the rules are on before
        the authentication input is created, because its first poll is the
        backfill and a rule judges an event once, by index time."""
        self.setup_run(users_input=True, lookup_gen=True)
        writes = self.fake.writes()

        def at(method, suffix):
            hits = [i for i, (m, p) in enumerate(writes) if m == method and p.endswith(suffix)]
            self.assertEqual(len(hits), 1, (method, suffix, writes))
            return hits[0]

        index = at('POST', '/adminconfig/v2/indexes')
        account = at('POST', '/ta_gen_ai_cim_account/ta_gen_ai_cim_account')
        rule = at('POST', '/saved/searches/' + duo.q(duo.DUO_DETECTION))
        chain = at('POST', '/saved/searches/' + duo.q(duo.DUO_CHAIN_DETECTION))
        lookup = at('POST', '/saved/searches/' + duo.q(duo.LOOKUP_GEN))
        inputs = [i for i, (m, p) in enumerate(writes) if m == 'POST' and p == INPUT_PATH]
        self.assertEqual(len(inputs), 2)
        self.assertLess(max(index, account, rule, chain, lookup), min(inputs))
        # ... and the index was confirmed (GET by name answered 200) before either input.
        requests = self.fake.requests
        first_input = [i for i, r in enumerate(requests) if r['method'] == 'POST' and r['path'] == INPUT_PATH][0]
        ready = [i for i, r in enumerate(requests)
                 if r['method'] == 'GET' and r['path'].endswith('/adminconfig/v2/indexes/duo')]
        # absent, then polled until there (all of that before either input), and asked once
        # more by the backfill guard: the search sees no event in the index, and ACS has to
        # agree before the authentication input, whose first poll is the backfill, is created.
        self.assertEqual(len(ready), 2 + self.fake.acs_ready_after)
        self.assertLess(ready[-2], first_input)
        auth_input = [i for i, r in enumerate(requests) if r['method'] == 'POST' and r['path'] == INPUT_PATH
                      and r['form'].get('name') == 'duo_authentication'][0]
        self.assertLess(first_input, ready[-1])
        self.assertLess(ready[-1], auth_input)
        self.assertEqual(self.sleeps, [duo.INDEX_POLL_SECONDS] * (self.fake.acs_ready_after - 1))

    def test_second_run_writes_nothing_and_needs_no_duo_key(self):
        self.setup_run(users_input=True, lookup_gen=True)
        before = self.fake.state()
        del self.fake.requests[:]
        rep = self.setup_run(env={}, users_input=True, lookup_gen=True)    # nothing Duo in the environment
        self.assertEqual(self.fake.writes(), [])
        self.assertEqual(self.fake.state(), before)
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertIn('not compared', self.row(rep, 'D2.')[2])
        self.assertEqual(self.prompts, [])

    def test_dry_run_changes_nothing_and_never_asks_for_the_key(self):
        before = self.fake.state()
        rep = self.setup_run(dry_run=True, interactive=True)       # a terminal is there; still no prompt
        self.assertEqual(self.fake.writes(), [])
        self.assertEqual(self.fake.state(), before)
        self.assertEqual(self.prompts, [])
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        text = self.printed.getvalue()
        for needle in ('DRY-RUN POST', 'would create it, searchable 90 days', 'client_secret=<hidden>',
                       'secret key from $DUO_LOG_FEED_SKEY', '"name": "duo_authentication"',
                       '"initial_lookback_hours": "720"', 'dry-run - would be enabled',
                       'dry-run - would set srchIndexesAllowed +duo'):
            self.assertIn(needle, text)
        # A plan never reads as done: no row of a dry run says a write happened.
        for status, step, detail in rep.rows:
            if status == 'OK' and step.startswith(('D1.', 'D2.', 'D3.', 'D5. enable', 'D6.')):
                self.assertIn('dry-run', detail, step)
        self.assertNotIn(HOST, text)
        self.assertNotIn(IKEY, text)
        self.assertNotIn('"name": "duo_users"', text)              # not asked for, not planned

    def test_dry_run_reads_run_for_real(self):
        """A plan is only as good as its reads: the checkpoint and the event
        count are read in a dry run too, so it reports the same refusal."""
        self.fake.add_index()
        self.fake.events = {fake_rest.AUTH_ST: 57}
        rep = self.setup_run(dry_run=True)
        self.assertIn('already holds 57 Duo authentication events', self.row(rep, 'D6. input duo_authentication')[2])
        self.assertEqual(self.fake.writes(), [])


class LabModelTests(StackCase):

    def test_index_not_ready_means_no_input(self):
        self.fake.acs_ready_after = 10 ** 6
        rep = self.setup_run(users_input=True)
        self.assertIn('not there after', self.row(rep, 'D1.')[2])
        self.assertEqual(self.fake.inputs, {})
        for name in ('duo_users', 'duo_authentication'):
            self.assertEqual(self.row(rep, 'D6. input ' + name)[0], 'SKIP')
        # the rules are on all the same, ready for the run that creates the inputs
        self.assertFalse(self.fake.saved[DUO_RULE]['disabled'])
        self.assertFalse(self.fake.saved[CHAIN_RULE]['disabled'])

    def test_acs_is_asked_by_name_never_through_the_30_row_list(self):
        self.fake.add_index()
        self.setup_run()
        acs = [(r['method'], r['path']) for r in self.fake.requests if r.get('service') == 'acs']
        self.assertEqual(set(acs), {('GET', '/{}/adminconfig/v2/indexes/duo'.format(fake_rest.STACK))})

    def test_short_retention_blocks_the_inputs_unless_forced(self):
        self.fake.add_index(days=30)
        rep = self.setup_run()
        self.assertEqual(self.row(rep, 'D1.')[0], 'FAIL')
        self.assertIn('keeps 30 days', self.row(rep, 'D1.')[2])
        self.assertEqual(self.fake.inputs, {})
        rep = self.setup_run(force=True)
        self.assertEqual(sorted(self.fake.inputs), ['duo_authentication'])

    def test_a_rule_that_cannot_be_enabled_blocks_the_inputs(self):
        self.fake.fail[('POST', '/saved/searches/' + duo.q(duo.DUO_DETECTION))] = (500, '{}')
        rep = self.setup_run()
        self.assertTrue(self.fake.saved[DUO_RULE]['disabled'])
        self.assertEqual(self.fake.inputs, {})
        self.assertIn('the rules failed above', self.row(rep, 'D6. input duo_authentication')[2])

    def test_a_missing_rule_blocks_the_inputs(self):
        """A TA build without the joined rule: the tool does not go on as if it
        had enabled it."""
        del self.fake.saved[CHAIN_RULE]
        rep = self.setup_run()
        rows = [r for r in rep.rows if r[0] == 'FAIL']
        self.assertEqual(len(rows), 1)
        self.assertIn('not found', rows[0][2])
        self.assertEqual(self.fake.inputs, {})

    def test_the_data_model_scope_is_a_note_and_never_blocks(self):
        """Reviewer correction 3: the TA's rules read the Duo events themselves,
        so cim_Authentication_indexes decides nothing about the inputs. It is
        still read, because ES's own Authentication content and UEBA need it."""
        macro = ('Splunk_SA_CIM', 'cim_Authentication_indexes')
        self.fake.macros[macro] = '(index=main OR index=okta)'
        rep = self.setup_run()
        row = self.row(rep, 'D4.')
        self.assertEqual(row[0], 'SKIP')
        self.assertIn('lists main, okta and not duo', row[2])
        self.assertIn("it matters to ES's own Authentication content and UEBA, not to the TA's rules", row[2])
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertIn('duo_authentication', self.fake.inputs)
        self.assertEqual([p for m, p in self.fake.writes() if 'conf-macros' in p], [])    # never edited here
        for definition in ('()', '', '(index=main OR index=duo)', 'index IN (main, duo)', '(index=*)', 'index::duo'):
            self.fake.macros[macro] = definition
            splunkd, _acs, rep = self.clients()
            duo.step_datamodel_scope(splunkd, rep)
            self.assertEqual(rep.rows[0][0], 'OK', definition)
        # No Splunk_SA_CIM at all (no ES): a skip, never a failure.
        del self.fake.macros[macro]
        splunkd, _acs, rep = self.clients()
        duo.step_datamodel_scope(splunkd, rep)
        self.assertEqual(rep.rows[0][0], 'SKIP')
        self.assertIn('nothing to check', rep.rows[0][2])
        for text in (duo.step_datamodel_scope.__doc__, duo.__doc__):
            self.assertNotIn('the Duo rule would see nothing', text)
            self.assertNotIn('The Duo rule reads the Authentication data model', text)

    def test_a_data_model_that_returns_nothing_is_a_note(self):
        self.fake.add_index()
        self.fake.events = {fake_rest.AUTH_ST: 81}
        self.fake.kv['ta_gen_ai_cim_duo_checkpoint'] = {CP_AUTH: {'_key': CP_AUTH, 'maxtime_ms': 1794900000000}}
        self.fake.datamodel_events = 0
        rep = self.setup_run()
        row = self.row(rep, 'D7. note: the Authentication data model')
        self.assertEqual(row[0], 'SKIP')
        self.assertIn('returns none of the 81 Duo authentication events', row[2])
        self.assertIn("The TA's rules read the events themselves and are not affected", row[2])
        self.assertEqual(self.rows(rep, 'FAIL'), [])

    def test_leftover_checkpoint_on_an_empty_index_is_refused(self):
        """Would resume from the old position and never read the history."""
        self.fake.kv['ta_gen_ai_cim_duo_checkpoint'] = {CP_AUTH: {'_key': CP_AUTH, 'maxtime_ms': 1794900000000}}
        rep = self.setup_run(users_input=True)
        row = self.row(rep, 'D6. input duo_authentication')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('--duo-reset-checkpoint', row[2])
        self.assertNotIn('duo_authentication', self.fake.inputs)
        self.assertIn('duo_users', self.fake.inputs)
        rep = self.setup_run(users_input=True, reset_checkpoint=True)
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertEqual(self.fake.kv['ta_gen_ai_cim_duo_checkpoint'], {})
        self.assertIn('duo_authentication', self.fake.inputs)

    def test_events_without_a_checkpoint_are_refused(self):
        """Would index the backfill a second time and double every count."""
        self.fake.add_index()
        self.fake.events = {fake_rest.AUTH_ST: 81, fake_rest.USER_ST: 152}
        rep = self.setup_run(reset_checkpoint=True)          # the reset flag does not excuse it
        row = self.row(rep, 'D6. input duo_authentication')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('already holds 81', row[2])
        self.assertNotIn('duo_authentication', self.fake.inputs)

    def test_events_with_their_checkpoint_resume(self):
        self.fake.add_index()
        self.fake.events = {fake_rest.AUTH_ST: 81}
        self.fake.kv['ta_gen_ai_cim_duo_checkpoint'] = {CP_AUTH: {'_key': CP_AUTH, 'maxtime_ms': 1794900000000}}
        rep = self.setup_run()
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertIn('duo_authentication', self.fake.inputs)
        self.assertIn(CP_AUTH, self.fake.kv['ta_gen_ai_cim_duo_checkpoint'])
        self.assertIn('81 of 81', self.row(rep, 'D7. note: the Authentication data model')[2])

    def test_interval_is_a_parameter_and_only_it_changes(self):
        self.setup_run(auth_interval='300')
        del self.fake.requests[:]
        rep = self.setup_run(auth_interval=duo.poll_slot('3/20'), env={})
        self.assertEqual(self.fake.writes(), [('POST', INPUT_PATH + '/duo_authentication')])
        posted = [r['form'] for r in self.fake.requests if r['method'] == 'POST' and r['path'].startswith(INPUT_PATH)]
        self.assertEqual(posted, [{'account': 'duo', 'endpoint': 'authentication', 'interval': '3,23,43 * * * *'}])
        self.assertEqual(self.fake.inputs['duo_authentication']['interval'], '3,23,43 * * * *')
        self.assertEqual(self.fake.inputs['duo_authentication']['initial_lookback_hours'], '720')
        self.assertIn('interval 300 -> 3,23,43 * * * *', self.row(rep, 'D6. input duo_authentication')[2])

    def test_an_input_is_never_repointed(self):
        self.setup_run()
        self.fake.inputs['duo_authentication']['index'] = 'main'
        del self.fake.requests[:]
        rep = self.setup_run(env={})
        self.assertEqual(self.row(rep, 'D6. input duo_authentication')[0], 'FAIL')
        self.assertEqual(self.fake.writes(), [])


class GuardTests(StackCase):
    """Every guard that stands between a read that failed and a write refuses.
    The first build's tests exercised each guard only on answers it could
    read: its four fail-closed returns in the setup could be flipped to
    fail-open with the suite green, and two teardown guards deleted when their
    check came back with an error."""

    LEFTOVER = {'ta_gen_ai_cim_duo_checkpoint': {CP_AUTH: {'_key': CP_AUTH, 'maxtime_ms': 1794900000000}}}

    def assert_not_created(self, rep, needle):
        rows = [r for r in rep.rows if r[1] == 'D6. input duo_authentication']
        self.assertEqual(len(rows), 1, rep.rows)                  # one row, and not a "created" after it
        self.assertIn(rows[0][0], ('FAIL', 'SKIP'))
        self.assertIn(needle, rows[0][2])
        self.assertEqual(self.fake.inputs, {})
        self.assertEqual([p for m, p in self.fake.writes() if m == 'POST' and p == INPUT_PATH], [])

    def test_a_rule_that_cannot_be_read_blocks_the_inputs(self):
        self.fake.fail[('GET', '/saved/searches/' + duo.q(duo.DUO_DETECTION))] = (500, '{}')
        rep = self.setup_run()
        self.assertIn('could not read it (HTTP 500)', self.row(rep, 'D5. enable "' + DUO_RULE[:56])[2])
        self.assertTrue(self.fake.saved[DUO_RULE]['disabled'])
        self.assert_not_created(rep, 'the rules failed above')

    def test_a_checkpoint_that_cannot_be_read_blocks_the_input(self):
        self.fake.fail[('GET', duo.checkpoint_path(duo.AUTH_INPUT))] = (500, '{}')
        rep = self.setup_run()
        self.assert_not_created(rep, 'could not read its checkpoint (HTTP 500); not created')

    def test_an_index_that_cannot_be_counted_blocks_the_input(self):
        self.fake.fail[('POST', '/services/search/jobs')] = (503, '{}')
        rep = self.setup_run()
        self.assert_not_created(rep, 'could not count the events already in index duo (search failed (HTTP 503)); '
                                     'not created')

    def test_an_old_checkpoint_that_cannot_be_deleted_blocks_the_input(self):
        """With --duo-reset-checkpoint: were the input created all the same, it
        would resume from the old position and never read the history."""
        self.fake.kv.update(json.loads(json.dumps(self.LEFTOVER)))
        self.fake.fail[('DELETE', duo.checkpoint_path(duo.AUTH_INPUT))] = (500, '{}')
        rep = self.setup_run(reset_checkpoint=True)
        self.assert_not_created(rep, 'could not delete the old checkpoint (HTTP 500); not created')
        self.assertEqual(self.checkpoints(), [CP_AUTH])

    def test_events_acs_counts_and_the_search_cannot_see_block_the_input(self):
        """No row from the count is not proof of an empty index."""
        self.fake.add_index()
        self.fake.acs_event_count = 57
        rep = self.setup_run()
        self.assert_not_created(rep, 'a search finds no Duo authentication event in index duo but ACS counts 57')
        self.fake.acs_event_count = 0
        rep = self.setup_run()
        self.assertIn('duo_authentication', self.fake.inputs)

    def test_an_existing_input_is_not_touched_while_a_check_failed(self):
        self.setup_run(auth_interval='300')
        self.fake.inputs['duo_authentication']['disabled'] = True          # paused by the operator
        self.fake.saved[DUO_RULE]['dispatch.earliest_time'] = '-31d@m'      # a catch-up range left in
        del self.fake.requests[:]
        rep = self.setup_run(auth_interval='600', env={})
        row = self.row(rep, 'D6. input duo_authentication')
        self.assertEqual(row[0], 'SKIP')
        self.assertIn('exists; not changed while: the rules failed above', row[2])
        self.assertEqual((self.fake.inputs['duo_authentication']['disabled'],
                          self.fake.inputs['duo_authentication']['interval']), (True, '300'))
        self.assertEqual([p for m, p in self.fake.writes() if p.startswith(INPUT_PATH)], [])

    def test_a_disabled_input_is_enabled_again(self):
        self.setup_run()
        self.fake.inputs['duo_authentication']['disabled'] = True
        del self.fake.requests[:]
        rep = self.setup_run(env={})
        row = self.row(rep, 'D6. input duo_authentication')
        self.assertEqual((row[0], row[2]), ('OK', 'enabled'))
        self.assertFalse(self.fake.inputs['duo_authentication']['disabled'])
        self.assertEqual(self.fake.writes(), [('POST', INPUT_PATH + '/duo_authentication/enable')])
        self.assertEqual(self.rows(rep, 'FAIL'), [])

    def test_a_refused_read_is_never_called_a_missing_ta(self):
        """D0 (automation finding 7): only a 404 means "not there". A 403 on the
        same read used to send the operator off to install the TA, or to restart
        the stack."""
        for suffix, status in (('/services/apps/local/TA-gen_ai_cim', 403), ('/services/apps/local/TA-gen_ai_cim', 503),
                               ('/services/data/modular-inputs/ta_gen_ai_cim_duo', 403)):
            self.fake.fail.clear()
            self.fake.fail[('GET', suffix)] = (status, '{}')
            rep = self.setup_run()
            self.assertEqual([r[0] for r in rep.rows], ['FAIL'], suffix)
            self.assertIn('the stack refused or failed the read of {} (HTTP {}); nothing was written'.format(
                suffix, status), rep.rows[0][2])
            for wrong in ('is not installed', 'not registered', 'restart the stack', 'install 1.9.0'):
                self.assertNotIn(wrong, rep.rows[0][2], suffix)
            self.assertEqual(self.fake.writes(), [])
        self.fake.fail.clear()
        self.fake.schemes.clear()                                 # a real 404: the scheme is not registered
        rep = self.setup_run()
        self.assertIn('its input scheme is not registered', rep.rows[0][2])
        self.assertIn('restart the stack', rep.rows[0][2])

    def test_a_stack_that_does_not_serve_the_input_endpoint_is_stopped_before_any_write(self):
        """It used to find out at D6, with the index created, the Duo secret key
        stored, the role granted and both rules enabled."""
        self.fake.fail[('GET', INPUT_PATH)] = (403, '{}')
        rep = self.setup_run()
        self.assertEqual([r[0] for r in rep.rows], ['FAIL'])
        self.assertIn('does not serve the endpoint its inputs are created through', rep.rows[0][2])
        self.assertIn('HTTP 403', rep.rows[0][2])
        self.assertEqual(self.fake.writes(), [])
        self.assertIsNone(self.fake.secret())
        self.assertEqual(self.fake.acs_indexes, {})
        self.assertEqual(self.prompts, [])

    def test_acs_404_means_missing_only_when_acs_says_the_index_is(self):
        """ACS answers 404 for a stack it does not know too. Read as "the index
        is missing", that created nothing useful at setup and, at teardown,
        cleared the checkpoints of an index that was still there."""
        self.assertEqual(duo.ACS_INDEX_NOT_FOUND, '404-index-not-found')
        self.fake.fail[('GET', '/adminconfig/v2/indexes/duo')] = (404, '{"code": "404-stack-not-found", "message": "x"}')
        rep = self.setup_run()
        row = self.row(rep, 'D1.')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('HTTP 404 404-stack-not-found: ACS did not say that index duo is missing', row[2])
        self.assertEqual([p for m, p in self.fake.writes() if 'adminconfig' in p], [])     # nothing created
        self.assertEqual(self.fake.inputs, {})
        for body in ('not json at all', '{}'):
            self.fake.fail[('GET', '/adminconfig/v2/indexes/duo')] = (404, body)
            splunkd, acs, _rep = self.clients()
            self.assertEqual(duo.acs_index(acs)[0], 'error', body)
        del self.fake.fail[('GET', '/adminconfig/v2/indexes/duo')]
        splunkd, acs, _rep = self.clients()
        self.assertEqual(duo.acs_index(acs)[0], duo.MISSING)       # the fake answers ACS's own code


class RuleScheduleTests(StackCase):
    """Step D5 (reviewer correction 1). The rules judge by index time: their
    dispatch.earliest_time is the edge of the slot one run judges, never how
    far back they read events. The first build read it as an event-time reach
    and would have refused every stack that runs the shipped rule."""

    def shipped(self, name=DUO_RULE, **changes):
        live = dict(fake_rest.shipped_saved_searches()[name])
        live.update(changes)
        return live

    def test_the_shipped_rules_are_index_time_slots_one_period_wide(self):
        self.assertEqual(duo.slot_minutes(self.shipped(DUO_RULE)), (10, None))
        self.assertEqual(duo.slot_minutes(self.shipped(CHAIN_RULE)), (5, None))
        conf = read_conf('savedsearches.conf')
        self.assertEqual(conf[DUO_RULE]['dispatch.earliest_time'], '-12m@m')       # 0.2 h, were it a reach
        for name in duo.DUO_DETECTIONS:
            # Whatever the lookback: the slot edge is not compared with it.
            for hours in (1, 720, duo.duo_input.MAX_LOOKBACK_HOURS):
                self.assertIsNone(duo.backfill_problem(name, self.shipped(name), hours), name)
            # splunkd answers booleans as JSON booleans or as the conf's 0/1.
            self.assertEqual(duo.slot_minutes(self.shipped(name, realtime_schedule='0'))[1], None)
            self.assertEqual(duo.slot_minutes(self.shipped(name, realtime_schedule=0))[1], None)

    def test_a_schedule_that_would_not_tile_is_named(self):
        cases = (({'cron_schedule': '*/5 * * * *'}, 'is 10 min wide but it runs every 5 min: index-time slots would '
                                                    'overlap'),
                 ({'dispatch.earliest_time': '-7m@m'}, 'is 5 min wide but it runs every 10 min: index-time slots '
                                                       'would leave gaps'),
                 ({'dispatch.earliest_time': '-30m@m'}, 'is 28 min wide but it runs every 10 min'),
                 ({'dispatch.earliest_time': '-31d@m'}, 'index-time slots would overlap'),       # a catch-up left in
                 ({'dispatch.earliest_time': '-12m'}, 'not every N minutes over -Xm@m to -Ym@m'),
                 ({'dispatch.latest_time': 'now'}, 'not every N minutes over -Xm@m to -Ym@m'),
                 ({'cron_schedule': '3-59/10 * * * *'}, 'not every N minutes over -Xm@m to -Ym@m'),
                 ({'cron_schedule': '*/7 * * * *', 'dispatch.earliest_time': '-9m@m'}, 'does not divide the hour'),
                 ({'realtime_schedule': True}, 'realtime_schedule is on'),
                 ({'realtime_schedule': '1'}, 'realtime_schedule is on'),
                 ({'allow_data_time_skew': '1'}, 'allow_data_time_skew is on'),
                 ({'dispatch.index_earliest': '-1h'}, 'dispatch.index_earliest / dispatch.index_latest is set'),
                 ({'is_scheduled': False}, 'it is not scheduled'))
        for changes, needle in cases:
            period, why = duo.slot_minutes(self.shipped(**changes))
            self.assertIsNone(period, changes)
            self.assertIn(needle, why, changes)
            self.assertIn(needle, duo.backfill_problem(DUO_RULE, self.shipped(**changes), 720))

    def test_a_changed_schedule_blocks_the_inputs_unless_forced(self):
        self.fake.saved[DUO_RULE]['dispatch.earliest_time'] = '-31d@m'      # a catch-up range never set back
        rep = self.setup_run()
        row = self.row(rep, 'D5. the rules judge the backfill')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('index-time slots would overlap', row[2])
        self.assertIn('restore the shipped schedule', row[2])
        self.assertEqual(self.fake.inputs, {})
        self.assertIn('the rules failed above', self.row(rep, 'D6. input duo_authentication')[2])
        rep = self.setup_run(force=True)
        self.assertIn('duo_authentication', self.fake.inputs)

    def test_an_event_time_build_is_held_to_its_reach(self):
        """A build of the rule from before it judged by index time has no
        index-time terms, and only then is dispatch.earliest_time its reach."""
        old = {'search': '| tstats count from datamodel=Authentication.Authentication by Authentication.user',
               'dispatch.earliest_time': '-30m@m', 'dispatch.latest_time': 'now'}
        self.assertEqual(duo.slot_minutes(self.shipped(**old)), (None, duo.EVENT_TIME))
        self.fake.saved[DUO_RULE].update(old)
        rep = self.setup_run()
        row = self.row(rep, 'D5. the rules judge the backfill')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('selects by event time, -30m@m (0.5 h), but the input backfills 720 h', row[2])
        self.assertIn('install the TA build whose rules judge by index time', row[2])
        self.assertEqual(self.fake.inputs, {})
        self.fake.saved[DUO_RULE]['dispatch.earliest_time'] = '-7d@d'
        rep = self.setup_run(lookback_hours=168)
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertEqual(self.fake.inputs['duo_authentication']['initial_lookback_hours'], '168')

    def test_reach_is_read_only_from_an_event_time_rule(self):
        for text, hours in (('-30m@m', 0.5), ('-24h', 24), ('-30d', 720), ('-30d@d', 720), ('-1mon', 720),
                            ('-2w', 336), ('0', duo.UNBOUNDED), ('', duo.UNBOUNDED), (None, duo.UNBOUNDED),
                            ('rt-5m', duo.UNKNOWN), ('@d', duo.UNKNOWN), ('1794900000', duo.UNKNOWN)):
            self.assertEqual(duo.reach_hours(text), hours, text)
        # The only caller of reach_hours is behind the EVENT_TIME branch.
        source = text_of(REPO, 'tools', 'duo_steps.py')
        body = source[source.index('def backfill_problem('):source.index('def _switch(')]
        self.assertLess(body.index('if why != EVENT_TIME:'), body.index('reach_hours('))
        self.assertEqual(source.count('reach_hours('), 2)                  # its definition and that one call
        self.assertIn("dispatch.earliest_time", duo.slot_minutes.__doc__ + duo.reach_hours.__doc__)


class SettingsTests(unittest.TestCase):

    def test_interval_forms(self):
        self.assertEqual(duo.parse_interval('120'), '120')
        self.assertEqual(duo.parse_interval(' 3,23,43  * * * * '), '3,23,43 * * * *')
        self.assertEqual(duo.parse_interval('*/5 * * * *'), '*/5 * * * *')
        self.assertEqual(duo.parse_interval('0 */2 * * *'), '0 */2 * * *')        # not hourly: not second-guessed
        for bad in ('119', '0', '', 'soon', '* * * *', '5m', '-300', '300; rm',
                    '* * * * *', '*/1 * * * *', '0,1,30 * * * *', '61 * * * *', '9-3 * * * *', '*/0 * * * *'):
            with self.assertRaises(ValueError):
                duo.parse_interval(bad)

    def test_poll_slots_never_share_a_minute(self):
        """N stacks on one Duo tenant: stack K polls every N minutes, K minutes
        past. The schedule is a plain list of minutes (reviewer correction 8),
        and every minute of the hour belongs to exactly one stack."""
        self.assertEqual(duo.poll_slot('3/20'), '3,23,43 * * * *')
        self.assertEqual(duo.poll_slot('0/30'), '0,30 * * * *')
        for period in duo.POLL_SLOT_PERIODS:
            minutes = []
            for slot in range(period):
                cron = duo.poll_slot('{}/{}'.format(slot, period))
                self.assertEqual(duo.parse_interval(cron), cron)             # the tool accepts what it emits
                self.assertRegex(cron, r'^\d+(,\d+)* \* \* \* \*$')          # a list: no range, no step
                mine = [int(m) for m in cron.split(' ')[0].split(',')]
                self.assertEqual(mine, duo.cron_minutes(cron.split(' ')[0]))
                self.assertTrue(all(b - a == period for a, b in zip(mine, mine[1:])))
                self.assertEqual(60 - mine[-1] + mine[0], period)            # across the hour too
                minutes.extend(mine)
            self.assertEqual(sorted(minutes), list(range(60)))               # one stack a minute, every minute
        for bad in ('5/5', '0/7', '1/1', '0/60', 'x', '3', '-1/5'):
            with self.assertRaises(ValueError):
                duo.poll_slot(bad)

    def test_what_is_posted_passes_the_inputs_own_validator(self):
        settings = duo.Settings('300')
        self.assertEqual(settings.input_fields('authentication')['initial_lookback_hours'], '720')
        self.assertNotIn('initial_lookback_hours', settings.input_fields('users'))
        self.assertEqual((settings.need_days, settings.create_days), (44, 90))
        self.assertEqual(duo.Settings('300', lookback_hours=4320).create_days, 194)
        for kwargs in ({'users_interval': '600'}, {'lookback_hours': 0}, {'lookback_hours': 4321},
                       {'lookback_hours': 'x'}, {'attendee_roles': ('bad role',)}):
            with self.assertRaises(ValueError):
                duo.Settings('300', **kwargs)

    def test_the_two_opt_in_pieces_are_off_unless_asked_for(self):
        settings = duo.Settings('300')
        self.assertEqual((settings.users_input, settings.lookup_gen), (False, False))
        with self.assertRaises(ValueError) as caught:
            duo.Settings('300', lookup_gen=True)                             # it reads the users snapshot
        self.assertIn('--duo-with-lookup-gen needs --duo-with-users', str(caught.exception))
        settings = duo.Settings('300', users_input=True, lookup_gen=True)
        self.assertEqual((settings.users_input, settings.lookup_gen), (True, True))


class SecretTests(StackCase):

    def test_key_comes_from_the_named_variable(self):
        env = {duo.ENV_HOST: HOST, duo.ENV_IKEY: IKEY, 'ROOM_SEVEN_DUO_KEY': SKEY2}
        splunkd, acs, rep = self.clients()
        creds = duo.Credentials(skey_env='ROOM_SEVEN_DUO_KEY', env=env, interactive=False)
        self.assertTrue(duo.step_account(splunkd, rep, creds, duo.Settings('300')))
        self.assertEqual(self.fake.secret(), SKEY2)
        sent = [r for r in self.fake.requests if r['method'] == 'POST' and r['path'] == ACCOUNT_PATH]
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]['form'], {'name': 'duo', 'auth_type': 'duo_hmac', 'url': 'https://' + HOST,
                                           'client_id': IKEY, 'client_secret': SKEY2})

    def test_a_value_where_the_variable_name_belongs_is_refused_unechoed(self):
        for bad in (SKEY, 'lower_case', '9LIVES', '', 'A B'):
            with self.assertRaises(ValueError) as caught:
                duo.Credentials(skey_env=bad, env={})
            self.assertNotIn(bad or 'x' * 99, str(caught.exception))

    def test_hidden_prompt_only_on_a_terminal_and_only_when_needed(self):
        rep = self.setup_run(env={}, interactive=True, typed={'host': HOST, 'ikey': IKEY, 'skey': SKEY})
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertEqual(self.fake.secret(), SKEY)
        self.assertEqual([kind for kind, _ in self.prompts], ['visible', 'visible', 'hidden'])
        del self.prompts[:]
        self.setup_run(env={}, interactive=True, typed={})          # second run: the account is there
        self.assertEqual(self.prompts, [])

    def test_the_prompt_never_falls_back_to_echo(self):
        """getpass echoes when it has no terminal to switch off and only warns.
        The tool turns that warning into "no key", so the key is never typed
        in the clear."""
        import getpass

        def echoing(prompt, stream=None):
            import warnings
            warnings.warn('Can not control echo on the terminal.', getpass.GetPassWarning)
            return SKEY                                              # what an echoing fallback would return

        with mock.patch('getpass.getpass', echoing):
            self.assertEqual(duo._hidden_prompt('Duo secret key: '), '')
        creds = duo.Credentials(env={}, interactive=True, hidden_prompt=lambda text: '', visible_prompt=None)
        self.assertEqual(creds.secret(), (None, 'the secret key must be 20-128 characters with no spaces'))

    def test_no_variable_and_no_terminal_sends_nothing(self):
        rep = self.setup_run(env={duo.ENV_HOST: HOST, duo.ENV_IKEY: IKEY})
        row = self.row(rep, 'D2.')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('set $DUO_LOG_FEED_SKEY or run in a terminal', row[2])
        self.assertEqual([p for m, p in self.fake.writes() if p.startswith(ACCOUNT_PATH)], [])
        self.assertEqual(self.fake.inputs, {})                      # no account, no input
        self.assertEqual(self.prompts, [])

    def test_bad_values_are_refused_before_any_write_and_never_echoed(self):
        cases = (({duo.ENV_HOST: 'https://evil.example.test/api'}, 'API hostname'),
                 ({duo.ENV_IKEY: 'short'}, 'integration key'),
                 ({duo.ENV_SKEY: 'too short'}, 'secret key must be 20-128'),
                 ({duo.ENV_SKEY: '********'}, 'secret key must be 20-128'))
        for change, needle in cases:
            env = dict(ENV, **change)
            rep = self.setup_run(env=env)
            row = self.row(rep, 'D2.')
            self.assertEqual(row[0], 'FAIL', change)
            self.assertIn(needle, row[2])
            self.assertNotIn(list(change.values())[0], json.dumps(rep.rows))
        self.assertEqual([p for m, p in self.fake.writes() if p.startswith(ACCOUNT_PATH)], [])

    def test_a_reply_that_echoes_the_request_is_scrubbed(self):
        self.fake.echo_secret = True
        rep = self.setup_run()
        row = self.row(rep, 'D2.')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('HTTP 500', row[2])
        self.assertIn(duo.HIDDEN, row[2])
        for value in (SKEY, HOST, IKEY):
            self.assertNotIn(value, json.dumps(rep.rows))
        self.assertIsNone(self.fake.secret())
        # a reply that is not splunkd's JSON is not shown at all
        self.fake.echo_secret = False
        self.fake.fail[('POST', '/ta_gen_ai_cim_account/ta_gen_ai_cim_account')] = (502, 'gateway said: ' + SKEY)
        rep = self.setup_run()
        self.assertEqual(self.row(rep, 'D2.')[2], 'HTTP 502')

    def test_a_connection_that_drops_shows_no_error_text(self):
        """http_request answers (0, the exception's text) when there is no
        reply. That text is never printed for the account write."""
        splunkd, _acs, rep = self.clients()
        with mock.patch.object(seed, 'http_request', return_value=(0, 'boom ' + SKEY)) as sent:
            duo.step_account(splunkd, rep, self.creds(), duo.Settings('300'))
        self.assertEqual(sent.call_count, 1)                         # the account read
        self.assertEqual(rep.rows[0][0], 'FAIL')
        self.assertNotIn(SKEY, json.dumps(rep.rows))
        splunkd, _acs, rep = self.clients()
        real = seed.http_request

        def drop_the_write(ctx, url, method='GET', **kwargs):
            if method == 'POST':
                return 0, '<urlopen error ' + SKEY + '>'
            return real(ctx, url, method, **kwargs)

        with mock.patch.object(seed, 'http_request', drop_the_write):
            self.assertFalse(duo.step_account(splunkd, rep, self.creds(), duo.Settings('300')))
        self.assertIn('no reply from the stack', rep.rows[0][2])
        self.assertNotIn(SKEY, json.dumps(rep.rows))

    def test_scrub_covers_the_encoded_forms(self):
        secret = 'p@ss/word+with space&more=1234'
        for carried in (secret, 'client_secret=p%40ss%2Fword%2Bwith%20space%26more%3D1234',
                        'client_secret=p%40ss%2Fword%2Bwith+space%26more%3D1234'):
            self.assertNotIn('word', duo.scrub('x ' + carried + ' y', secret))
        self.assertEqual(duo.scrub('nothing here', None, ''), 'nothing here')
        # scrubbed before it is cut: a cut through the key would leave a piece of it
        self.assertNotIn(SKEY[:8], duo.scrub('x' * 150 + SKEY, SKEY)[:160])

    def test_no_secret_reaches_argv_help_or_a_plan(self):
        self.assertIsNone(self.creds(env={}).secret_source())
        self.assertEqual(self.creds().secret_source(), 'from $DUO_LOG_FEED_SKEY')
        self.assertEqual(self.creds(env={}, interactive=True).secret_source(), 'from a hidden prompt')

    def test_rules_match_the_handler(self):
        self.assertEqual(duo.IKEY_RE.pattern, acct.HANDLER.DUO_IKEY_RE.pattern)
        self.assertEqual(duo.SKEY_RE.pattern, acct.HANDLER.DUO_SKEY_RE.pattern)
        self.assertEqual(duo.SECRET_MASK, acct.HANDLER.SECRET_MASK)
        self.assertEqual(duo.duo_input.REALM_PREFIX, acct.HANDLER.REALM_PREFIX)

    def test_another_kind_of_account_with_that_name_is_left_alone(self):
        self.fake.account_store.conf['duo'] = {'auth_type': 'basic', 'url': acct.SNOW_URL, 'username': 'svc'}
        before = json.dumps(self.fake.account_store.conf, sort_keys=True)
        rep = self.setup_run()
        self.assertIn('not a Cisco Duo account', self.row(rep, 'D2.')[2])
        self.assertEqual(json.dumps(self.fake.account_store.conf, sort_keys=True), before)
        self.assertEqual(self.fake.inputs, {})
        rep = self.teardown_run()
        self.assertIn('not a Cisco Duo account', self.row(rep, 'DT3.')[2])
        self.assertEqual(json.dumps(self.fake.account_store.conf, sort_keys=True), before)

    def test_changed_integration_key_needs_rotate(self):
        self.setup_run()
        other = dict(ENV, **{duo.ENV_IKEY: 'DIFIXTUREIKEY0000002', duo.ENV_SKEY: SKEY2})
        rep = self.setup_run(env=other)
        self.assertEqual(self.row(rep, 'D2.')[0], 'FAIL')
        self.assertIn('--duo-rotate-key', self.row(rep, 'D2.')[2])
        self.assertEqual(self.fake.secret(), SKEY)
        rep = self.setup_run(env=other, rotate_key=True)
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertEqual(self.fake.secret(), SKEY2)
        self.assertEqual(self.fake.account_store.conf['duo']['client_id'], 'DIFIXTUREIKEY0000002')

    def test_the_tool_never_reads_a_stored_password(self):
        self.setup_run(users_input=True, lookup_gen=True)
        self.teardown_run()
        reads = [r['path'] for r in self.fake.requests if r['method'] == 'GET' and '/storage/passwords' in r['path']]
        self.assertEqual(reads, [])


class RoleTests(StackCase):

    def run_role(self, on=True):
        splunkd, _acs, rep = self.clients()
        duo.step_role(splunkd, rep, 'splunker', on=on)
        return rep

    def test_wildcard_or_inherited_access_is_left_alone(self):
        for own, imported in ((['*'], []), (['main'], ['d*']), (['duo'], [])):
            self.fake.roles['splunker'].update(srchIndexesAllowed=list(own), imported_srchIndexesAllowed=imported)
            del self.fake.requests[:]
            self.assertEqual(self.run_role().rows[0][2], 'already allowed')
            self.assertEqual(self.fake.writes(), [])

    def test_search_access_only_never_a_default_index(self):
        self.run_role()
        self.assertEqual(self.fake.roles['splunker']['srchIndexesAllowed'], ['main', 'gen_ai_log', 'duo'])
        self.assertEqual(self.fake.roles['splunker']['srchIndexesDefault'], ['main'])
        sent = [r['form'] for r in self.fake.requests if r['method'] == 'POST']
        self.assertEqual([sorted(form) for form in sent], [['srchIndexesAllowed']])

    def test_removing_the_last_entry_really_clears_the_list(self):
        self.fake.roles['splunker']['srchIndexesAllowed'] = ['duo']
        self.run_role(on=False)
        self.assertEqual(self.fake.roles['splunker']['srchIndexesAllowed'], [])
        sent = [r['raw'] for r in self.fake.requests if r['method'] == 'POST']
        self.assertEqual(sent, ['srchIndexesAllowed='])

    def test_missing_role_is_a_skip(self):
        splunkd, _acs, rep = self.clients()
        duo.step_role(splunkd, rep, 'no_such_role')
        self.assertEqual(rep.rows[0][0], 'SKIP')


class TeardownTests(StackCase):

    def live_stack(self):
        self.setup_run(users_input=True, lookup_gen=True)
        self.fake.events = {fake_rest.AUTH_ST: 81, fake_rest.USER_ST: 152}
        self.fake.kv['ta_gen_ai_cim_duo_checkpoint'] = {CP_AUTH: {'_key': CP_AUTH}, CP_USERS: {'_key': CP_USERS}}
        self.fake.lookup_files.add('ta_gen_ai_cim_duo_identities.csv')
        del self.fake.requests[:]

    def test_purge_undoes_everything(self):
        self.live_stack()
        rep = self.teardown_run(purge=True)
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        fake = self.fake
        for name in (DUO_RULE, CHAIN_RULE, LOOKUP_GEN):
            self.assertTrue(fake.saved[name]['disabled'], name)
        self.assertEqual(fake.inputs, {})
        self.assertNotIn('duo', fake.account_store.conf)
        self.assertEqual(fake.account_store.passwords, {})
        self.assertEqual(fake.roles['splunker']['srchIndexesAllowed'], ['main', 'gen_ai_log'])
        self.assertEqual(fake.lookup_files, set())
        self.assertNotIn('duo', fake.acs_indexes)
        self.assertEqual(fake.kv['ta_gen_ai_cim_duo_checkpoint'], {})
        # order: rules off, inputs gone, account gone, then the data; checkpoints only after the index
        order = [p.rsplit('/', 1)[-1] if m == 'DELETE' else 'POST ' + p.rsplit('/', 1)[-1] for m, p in fake.writes()]
        self.assertLess(order.index('POST ' + duo.q(DUO_RULE)), order.index('duo_authentication'))
        self.assertLess(order.index('duo_authentication'), order.index('duo'))
        deletes = [(m, p) for m, p in fake.writes() if m == 'DELETE']
        index_at = [i for i, (m, p) in enumerate(deletes) if p.endswith('/adminconfig/v2/indexes/duo')][0]
        kv_at = [i for i, (m, p) in enumerate(deletes) if 'storage/collections' in p]
        self.assertEqual(len(kv_at), 3)                 # both checkpoints, then the pending-delete marker
        self.assertLess(index_at, min(kv_at))
        self.assertTrue(deletes[kv_at[-1]][1].endswith('/' + duo.PURGE_MARKER))
        # The delete was marked as under way before ACS was asked for it.
        writes = fake.writes()
        marked = writes.index(('POST', '/servicesNS/nobody/TA-gen_ai_cim/storage/collections/data/'
                                       'ta_gen_ai_cim_duo_checkpoint'))
        self.assertLess(marked, writes.index(('DELETE', '/{}/adminconfig/v2/indexes/duo'.format(fake_rest.STACK))))
        # a new setup now backfills cleanly
        rep = self.setup_run()
        self.assertEqual(self.rows(rep, 'FAIL'), [])

    def test_a_stack_set_up_without_the_opt_in_pieces_tears_down_the_same_way(self):
        self.setup_run()                                             # authentication input only
        del self.fake.requests[:]
        rep = self.teardown_run(purge=True)
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertEqual((self.fake.inputs, self.fake.account_store.passwords), ({}, {}))
        self.assertEqual(self.row(rep, 'DT2. delete input duo_users')[2], 'not present')
        self.assertTrue(self.fake.saved[DUO_RULE]['disabled'])

    def test_second_teardown_finds_nothing_to_do(self):
        self.live_stack()
        self.teardown_run(purge=True)
        del self.fake.requests[:]
        rep = self.teardown_run(purge=True)
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        writes = self.fake.writes()
        # only the four "make sure it is gone" deletes, each answered 404
        self.assertEqual(sorted(p.rsplit('/', 1)[-1] for m, p in writes),
                         sorted([duo.q('ta_gen_ai_cim_account__duo:client_secret:'), duo.q(CP_AUTH), duo.q(CP_USERS),
                                 duo.PURGE_MARKER]))

    def test_keep_data_keeps_the_index_and_the_checkpoints_together(self):
        self.live_stack()
        rep = self.teardown_run(purge=False)
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertIn('duo', self.fake.acs_indexes)
        self.assertEqual(sorted(self.fake.kv['ta_gen_ai_cim_duo_checkpoint']), [CP_AUTH, CP_USERS])
        self.assertEqual(self.fake.account_store.passwords, {})
        self.assertEqual(self.fake.inputs, {})
        rep = self.setup_run()                 # resumes: events and checkpoint agree
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertIn('duo_authentication', self.fake.inputs)

    def test_an_index_holding_anything_else_is_kept_with_its_checkpoints(self):
        self.live_stack()
        self.fake.events['cisco:duo:authentication'] = 9
        rep = self.teardown_run(purge=True)
        row = self.row(rep, 'DT6.')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('cisco:duo:authentication', row[2])
        self.assertIn('duo', self.fake.acs_indexes)
        self.assertEqual(sorted(self.fake.kv['ta_gen_ai_cim_duo_checkpoint']), [CP_AUTH, CP_USERS])
        self.assertEqual(self.fake.account_store.passwords, {})       # the key is gone all the same

    def test_an_index_the_search_cannot_see_into_is_kept(self):
        """No row from the count is not proof of an empty index (a role that
        cannot search it gets none either): ACS has to agree before a delete."""
        self.live_stack()
        self.fake.events = {}
        self.fake.acs_event_count = 12
        rep = self.teardown_run(purge=True)
        row = self.row(rep, 'DT6.')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('ACS counts 12', row[2])
        self.assertIn('duo', self.fake.acs_indexes)
        self.assertEqual(sorted(self.fake.kv['ta_gen_ai_cim_duo_checkpoint']), [CP_AUTH, CP_USERS])
        self.assertEqual([p for m, p in self.fake.writes() if m == 'DELETE' and 'adminconfig' in p], [])
        self.fake.acs_event_count = 0                    # really empty: it goes
        rep = self.teardown_run(purge=True)
        self.assertEqual(self.row(rep, 'DT6.')[0], 'OK')
        self.assertNotIn('duo', self.fake.acs_indexes)

    def test_rejected_index_delete_keeps_the_checkpoints(self):
        self.live_stack()
        self.fake.fail[('DELETE', '/adminconfig/v2/indexes/duo')] = (500, '{"code":"500"}')
        rep = self.teardown_run(purge=True)
        self.assertEqual(self.row(rep, 'DT6.')[0], 'FAIL')
        # ... and no marker is left: nothing is under way, so a later --duo may resume.
        self.assertEqual(self.checkpoints(), [CP_AUTH, CP_USERS])
        del self.fake.fail[('DELETE', '/adminconfig/v2/indexes/duo')]
        rep = self.setup_run()
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertIn('duo_authentication', self.fake.inputs)

    def test_account_stays_while_another_input_uses_it(self):
        self.live_stack()
        self.fake.inputs['duo_activity'] = {'account': 'duo', 'endpoint': 'activity', 'index': 'duo', 'interval': '300'}
        rep = self.teardown_run(purge=False)
        row = self.row(rep, 'DT3.')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('duo_activity', row[2])
        self.assertEqual(self.fake.secret(), SKEY)
        self.assertIn('duo', self.fake.account_store.conf)

    def test_orphaned_key_is_removed_and_a_stuck_one_is_reported(self):
        self.fake.account_store.passwords[REALM] = SKEY              # no account stanza, a key left behind
        rep = self.teardown_run(purge=False)
        self.assertIn('a secret key left behind was removed', self.row(rep, 'DT3.')[2])
        self.assertEqual(self.fake.account_store.passwords, {})
        self.fake.account_store.passwords[REALM] = SKEY
        stuck = ('DELETE', duo.q('ta_gen_ai_cim_account__duo:client_secret:'))
        self.fake.fail[stuck] = (403, '{"clear_password":"%s"}' % SKEY)
        rep = self.teardown_run(purge=False)
        row = self.row(rep, 'DT3.')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('may still be stored (HTTP 403)', row[2])

    def test_lookup_file_stays_while_an_identity_source_reads_it(self):
        self.live_stack()
        self.fake.conf_inputs[duo.IDENTITY_SOURCE] = {'disabled': True}
        rep = self.teardown_run(purge=False)
        self.assertEqual(self.row(rep, 'DT5.')[0], 'FAIL')
        self.assertIn('ta_gen_ai_cim_duo_identities.csv', self.fake.lookup_files)

    def test_dry_run_teardown_changes_nothing_and_plans_all_of_it(self):
        self.live_stack()
        before = self.fake.state()
        rep = self.teardown_run(dry_run=True, purge=True)
        self.assertEqual(self.fake.writes(), [])
        self.assertEqual(self.fake.state(), before)
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertIn('would delete it and its secret key', self.row(rep, 'DT3.')[2])
        self.assertIn('would delete the index (233 events', self.row(rep, 'DT6.')[2])

    def test_teardown_needs_no_duo_credentials_and_says_to_rotate_the_key(self):
        self.live_stack()
        rep = self.teardown_run(purge=True)
        self.assertEqual(self.prompts, [])
        row = self.row(rep, 'DT7.')
        self.assertIn("rotate the application's secret key in the Duo Admin Panel", row[2])
        self.assertIn('one read-only Admin API application per delivery', row[2])

    def test_without_acs_the_index_is_never_assumed_gone(self):
        self.live_stack()
        rep = self.teardown_run(purge=True, skip_acs=True)
        self.assertEqual(self.row(rep, 'DT6.')[0], 'FAIL')
        self.assertEqual(sorted(self.fake.kv['ta_gen_ai_cim_duo_checkpoint']), [CP_AUTH, CP_USERS])
        self.fake.indexes.discard('duo')                    # deleted by hand
        self.fake.events = {}
        rep = self.teardown_run(purge=True, skip_acs=True)
        self.assertEqual(self.row(rep, 'DT6.')[0], 'OK')
        self.assertEqual(self.fake.kv['ta_gen_ai_cim_duo_checkpoint'], {})


    def test_no_index_from_the_stack_and_events_from_the_search_keep_the_checkpoints(self):
        """cloud finding: DT6 trusted "no such index" although its own search had
        just counted events there, cleared the checkpoints and reported OK. The
        next --duo then refused to backfill and pointed back to this purge."""
        for skip_acs in (True, False):
            self.live_stack()
            if skip_acs:
                self.fake.indexes.discard('duo')          # the search head answers 404 for the index
            else:
                del self.fake.acs_indexes['duo']          # ACS answers 404-index-not-found
            rep = self.teardown_run(purge=True, skip_acs=skip_acs)
            row = self.row(rep, 'DT6.')
            self.assertEqual(row[0], 'FAIL', skip_acs)
            self.assertIn('the stack says index duo does not exist, but a search still counts 233 event(s)', row[2])
            self.assertEqual(self.checkpoints(), [CP_AUTH, CP_USERS])
            self.assertEqual([p for m, p in self.fake.writes() if 'storage/collections' in p], [])
            self.fake.__init__()                              # a fresh stack for the next round
            self.server.shutdown()
            self.server.server_close()
            self.server = self.fake.serve()
            self.base = 'http://127.0.0.1:{}'.format(self.server.server_address[1])

    def test_a_404_that_is_not_about_the_index_keeps_everything(self):
        self.live_stack()
        self.fake.events = {}                                 # even with nothing to be seen in it
        self.fake.fail[('GET', '/adminconfig/v2/indexes/duo')] = (404, '{"code": "404-stack-not-found"}')
        rep = self.teardown_run(purge=True)
        row = self.row(rep, 'DT6.')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('kept: HTTP 404 404-stack-not-found', row[2])
        self.assertEqual(self.checkpoints(), [CP_AUTH, CP_USERS])
        self.assertIn('duo', self.fake.acs_indexes)

    def test_an_identity_source_check_that_fails_keeps_the_lookup_file(self):
        """automation finding 2: only "no such stanza" (404) is a go-ahead. A 403,
        a 500 or no reply used to delete the file under a source that may still
        read it, which breaks ES's identity merge for every source."""
        source = '/configs/conf-inputs/' + duo.q(duo.IDENTITY_SOURCE)
        for status in (403, 500, 503):
            self.live_stack()
            self.fake.fail[('GET', source)] = (status, '{}')
            rep = self.teardown_run(purge=False)
            row = self.row(rep, 'DT5.')
            self.assertEqual(row[0], 'FAIL', status)
            self.assertIn('kept: could not check whether an ES identity source still reads it (HTTP {})'.format(
                status), row[2])
            self.assertIn('ta_gen_ai_cim_duo_identities.csv', self.fake.lookup_files)
            self.assertEqual([p for m, p in self.fake.writes() if 'lookup-table-files' in p], [])
            self.fake.fail.clear()
        rep = self.teardown_run(purge=False)                  # the source is confirmed absent: 404
        self.assertEqual(self.row(rep, 'DT5.')[0], 'OK')
        self.assertEqual(self.fake.lookup_files, set())

    def test_an_index_acs_gives_no_count_for_is_kept(self):
        """automation finding 2: the search sees no event and ACS does not say how
        many there are. That is not "empty"."""
        self.live_stack()
        self.fake.events = {}
        self.fake.acs_event_count = 'unknown'
        rep = self.teardown_run(purge=True)
        row = self.row(rep, 'DT6.')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('ACS did not say how many it holds', row[2])
        self.assertIn('duo', self.fake.acs_indexes)
        self.assertEqual(self.checkpoints(), [CP_AUTH, CP_USERS])
        self.assertEqual([p for m, p in self.fake.writes() if m == 'DELETE' and 'adminconfig' in p], [])

    def test_a_role_named_only_at_setup_is_reported_by_the_teardown(self):
        """automation finding 3: --duo --duo-attendee-role X is undone only by a
        teardown that names X. It used to end green with the grant still there."""
        self.fake.roles['lab_attendee'] = {'srchIndexesAllowed': ['main'], 'srchIndexesDefault': ['main'],
                                           'imported_srchIndexesAllowed': []}
        self.setup_run(attendee_roles=('lab_attendee',))
        self.assertEqual(self.fake.roles['lab_attendee']['srchIndexesAllowed'], ['main', 'duo'])
        rep = self.teardown_run(purge=False)                  # the documented command: the default role
        row = self.row(rep, 'DT4. other roles that list index duo')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('role lab_attendee still lists index duo', row[2])
        self.assertIn('--duo-attendee-role lab_attendee', row[2])
        self.assertEqual(self.fake.roles['lab_attendee']['srchIndexesAllowed'], ['main', 'duo'])   # never removed unasked
        rep = self.teardown_run(purge=False, roles=('lab_attendee',))
        self.assertEqual(self.fake.roles['lab_attendee']['srchIndexesAllowed'], ['main'])
        self.assertEqual(self.row(rep, 'DT4. other roles that list index duo')[0:3:2], ('OK', 'none'))
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        # A wildcard or an inherited entry is not the literal entry this tool adds.
        self.fake.roles['lab_attendee'].update(srchIndexesAllowed=['d*'], imported_srchIndexesAllowed=['duo'])
        rep = self.teardown_run(purge=False)
        self.assertEqual(self.row(rep, 'DT4. other roles that list index duo')[0], 'OK')
        self.fake.fail[('GET', '/services/authorization/roles')] = (403, '{}')
        rep = self.teardown_run(purge=False)
        row = self.row(rep, 'DT4. other roles that list index duo')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('could not list the roles (HTTP 403)', row[2])

    def test_a_delete_acs_has_accepted_but_not_done_keeps_the_checkpoints_and_blocks_the_setup(self):
        """automation finding 4: ACS deletes an index in the background. The purge
        used to clear the checkpoints and report OK with the index still listed,
        and a --duo run in between sent the backfill into an index about to go."""
        self.live_stack()
        self.fake.acs_delete_removes = False
        rep = self.teardown_run(purge=True)
        row = self.row(rep, 'DT6.')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('index delete accepted (233 events', row[2])
        self.assertIn('not confirmed after 120 s', row[2])
        self.assertIn('run this teardown again', row[2])
        self.assertEqual(self.checkpoints(), sorted([CP_AUTH, CP_USERS, duo.PURGE_MARKER]))
        self.assertGreater(len(self.sleeps), 5)                  # it waited, read after read
        # Whatever the index now shows, no input goes into it; --duo-force does not help.
        for events, force in (({fake_rest.AUTH_ST: 81}, False), ({}, False), ({}, True)):
            self.fake.events = dict(events)
            rep = self.setup_run(force=force, reset_checkpoint=True)
            row = self.row(rep, 'D6. input duo_authentication')
            self.assertEqual(row[0], 'SKIP')
            self.assertIn('an index delete asked for by --duo-teardown --duo-purge-data is not confirmed yet', row[2])
            self.assertEqual(self.fake.inputs, {})
        # ACS finishes; the teardown, run again, confirms it and clears marker and checkpoints.
        del self.fake.acs_indexes['duo']
        self.fake.indexes.discard('duo')
        self.fake.events = {}
        rep = self.teardown_run(purge=True)
        self.assertEqual(self.row(rep, 'DT6.')[0::2], ('OK', 'the index was already gone; checkpoints cleared'))
        self.assertEqual(self.checkpoints(), [])
        rep = self.setup_run()
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertIn('duo_authentication', self.fake.inputs)

    def test_a_confirmation_that_cannot_be_read_is_not_a_confirmation(self):
        self.live_stack()
        answers = [(duo.READY, 90, '')]                       # the first read: the index is there

        def acs_index(acs):
            return answers.pop(0) if answers else ('error', None, 'HTTP 503')

        with mock.patch.object(duo, 'acs_index', acs_index):
            rep = self.teardown_run(purge=True)
        row = self.row(rep, 'DT6.')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('not confirmed after 120 s', row[2])
        self.assertNotIn('index deleted', row[2])
        self.assertIn(duo.PURGE_MARKER, self.checkpoints())
        self.assertIn(CP_AUTH, self.checkpoints())

    def test_a_delete_that_cannot_be_marked_is_not_asked_for(self):
        self.live_stack()
        self.fake.fail[('POST', '/storage/collections/data/ta_gen_ai_cim_duo_checkpoint')] = (500, '{}')
        rep = self.teardown_run(purge=True)
        row = self.row(rep, 'DT6.')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('could not record that the delete is under way (HTTP 500); nothing was deleted', row[2])
        self.assertIn('duo', self.fake.acs_indexes)
        self.assertEqual([p for m, p in self.fake.writes() if m == 'DELETE' and 'adminconfig' in p], [])
        self.assertEqual(self.checkpoints(), [CP_AUTH, CP_USERS])

    def test_a_marker_that_cannot_be_read_blocks_the_setup(self):
        self.fake.fail[('GET', '/' + duo.PURGE_MARKER)] = (503, '{}')
        rep = self.setup_run()
        self.assertIn('could not read whether an index delete is still under way (HTTP 503)',
                      self.row(rep, 'D6. input duo_authentication')[2])
        self.assertEqual(self.fake.inputs, {})

    def test_an_input_this_tool_did_not_make_keeps_the_index_it_writes_to(self):
        """automation finding 8: the purge used to delete index duo under a
        hand-made input that was still enabled and still held the Duo key."""
        for other, account_row in (({'account': 'duo', 'endpoint': 'activity', 'index': 'duo'}, 'FAIL'),
                                   ({'account': 'duo_east', 'endpoint': 'authentication', 'index': 'duo'}, 'OK')):
            self.live_stack()
            self.fake.inputs['duo_by_hand'] = dict(other, interval='300', disabled=False)
            rep = self.teardown_run(purge=True)
            self.assertEqual(self.row(rep, 'DT3.')[0], account_row, other)
            row = self.row(rep, 'DT6.')
            self.assertEqual(row[0], 'FAIL', other)
            self.assertIn('kept: input duo_by_hand still writes to index duo and is not one this tool made', row[2])
            self.assertIn('duo', self.fake.acs_indexes)
            self.assertEqual(self.checkpoints(), [CP_AUTH, CP_USERS])
            del self.fake.inputs['duo_by_hand']
        # An input of that account that writes somewhere else does not hold the index.
        self.live_stack()
        self.fake.inputs['duo_elsewhere'] = {'account': 'duo', 'endpoint': 'activity', 'index': 'duo_archive',
                                             'interval': '300', 'disabled': False}
        rep = self.teardown_run(purge=True)
        self.assertEqual(self.row(rep, 'DT6.')[0], 'OK')
        self.assertNotIn('duo', self.fake.acs_indexes)
        # ... and inputs that cannot be listed are not assumed to be none.
        self.fake.__init__()
        self.live_stack()
        self.fake.fail[('GET', INPUT_PATH)] = (500, '{}')
        rep = self.teardown_run(purge=True)
        self.assertIn('kept: could not list the inputs to see whether another one writes to the index (HTTP 500)',
                      self.row(rep, 'DT6.')[2])
        self.assertIn('duo', self.fake.acs_indexes)

    def test_an_input_that_could_not_be_deleted_keeps_the_index_and_the_checkpoints(self):
        self.live_stack()
        self.fake.fail[('DELETE', INPUT_PATH + '/duo_authentication')] = (500, '{}')
        rep = self.teardown_run(purge=True)
        self.assertEqual(self.row(rep, 'DT2. delete input duo_authentication')[0], 'FAIL')
        row = self.row(rep, 'DT6.')
        self.assertEqual(row[0], 'FAIL')
        self.assertIn('kept: an input could not be deleted and may still be writing', row[2])
        self.assertIn('duo_authentication', self.fake.inputs)
        self.assertIn('duo', self.fake.acs_indexes)
        self.assertEqual(self.checkpoints(), [CP_AUTH, CP_USERS])


class PreflightTests(StackCase):

    def test_old_ta_or_unregistered_scheme_stops_before_anything_is_written(self):
        for change in ('old', 'scheme'):
            if change == 'old':
                self.fake.apps['TA-gen_ai_cim'] = '1.8.0'
            else:
                self.fake.apps['TA-gen_ai_cim'] = '1.9.0'
                self.fake.schemes.clear()
            rep = self.setup_run()
            self.assertEqual([r[0] for r in rep.rows], ['FAIL'])
            self.assertEqual(self.fake.writes(), [])

    def test_skip_acs_takes_the_index_from_splunkd(self):
        rep = self.setup_run(skip_acs=True)
        self.assertEqual(self.row(rep, 'D1.')[0], 'FAIL')
        self.assertEqual(self.fake.inputs, {})
        self.fake.indexes.add('duo')
        rep = self.setup_run(skip_acs=True)
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        self.assertEqual([r for r in self.fake.requests if r.get('service') == 'acs'], [])


class JudgedTests(StackCase):
    """Step D8 (reviewer correction 7). The top risk of a backfill is history
    indexed while a rule was off: the rules never judge an index-time slot
    twice. D8 dispatches each rule's own search in one pass over all index time
    and compares the ids it yields with the ids on the rule's risk events."""

    BURSTS = ['nina.osei:burst:1794112177', 'nina.osei:burst:1794876180', 'jordan.reyes:fraud:1794276119']
    CHAIN = ['nina.osei:takeover:1794893749']

    def live_stack(self):
        """Index, events with their checkpoint, and one setup run: rules on."""
        self.fake.add_index()
        self.fake.events = {fake_rest.AUTH_ST: 81}
        self.fake.kv['ta_gen_ai_cim_duo_checkpoint'] = {CP_AUTH: {'_key': CP_AUTH, 'maxtime_ms': 1794900000000}}
        self.setup_run()
        del self.fake.requests[:]
        del self.fake.searches[:]

    def d8(self, rep):
        return [row for row in rep.rows if row[1].startswith('D8.')]

    def test_everything_indexed_was_raised(self):
        self.live_stack()
        self.fake.judged = {DUO_RULE: list(self.BURSTS), CHAIN_RULE: list(self.CHAIN)}
        self.fake.raised = {DUO_RULE: self.BURSTS + ['jordan.reyes:burst:1794275921'], CHAIN_RULE: list(self.CHAIN)}
        rep = self.setup_run()
        rows = self.d8(rep)
        self.assertEqual([row[0] for row in rows], ['OK', 'OK'])
        self.assertIn('3 of 3 bursts raised (of what was indexed more than 20 minutes ago)', rows[0][2])
        self.assertIn('1 of 1 chains raised (of what was indexed more than 15 minutes ago)', rows[1][2])
        self.assertEqual(self.rows(rep, 'FAIL'), [])
        # What was dispatched: the rule's OWN text as the stack has it, in the TA's namespace, in one
        # pass over all index time up to the last slot a scheduled run has certainly finished.
        shipped = read_conf('savedsearches.conf')
        own = [s for s in self.fake.searches if '| stats count by burst_id' in s['search']
               and not s['search'].startswith('search index=risk')]
        self.assertEqual(len(own), 1)
        self.assertEqual(own[0]['search'], 'search {} | stats count by burst_id'.format(shipped[DUO_RULE]['search']))
        self.assertIn('\n', own[0]['search'])            # the rule's text as stored, line breaks included
        self.assertEqual((own[0]['earliest'], own[0]['latest'], own[0]['app']), ('0', '-20m@m', 'TA-gen_ai_cim'))
        chain = [s for s in self.fake.searches if s['search'].endswith('| stats count by chain_id')
                 and not s['search'].startswith('search index=risk')]
        self.assertEqual((chain[0]['earliest'], chain[0]['latest']), ('0', '-15m@m'))
        risk = [s for s in self.fake.searches if s['search'].startswith('search index=risk')]
        self.assertEqual([(s['earliest'], s['latest']) for s in risk], [('0', 'now')] * 2)
        self.assertIn('search_name="{}"'.format(DUO_RULE), risk[0]['search'])
        self.assertEqual(self.fake.writes(), [])

    def test_history_indexed_while_a_rule_was_off_is_named(self):
        self.live_stack()
        self.fake.judged = {DUO_RULE: self.BURSTS + ['jordan.reyes:burst:1794276418'], CHAIN_RULE: list(self.CHAIN)}
        self.fake.raised = {DUO_RULE: [self.BURSTS[1]]}
        rep = self.setup_run()
        rows = self.d8(rep)
        self.assertEqual([row[0] for row in rows], ['FAIL', 'FAIL'])
        self.assertIn('3 of 4 bursts never raised: jordan.reyes:burst:1794276418, jordan.reyes:fraud:1794276119, '
                      'nina.osei:burst:1794112177.', rows[0][2])
        self.assertIn('README, "Judging history that is already indexed"', rows[0][2])
        self.assertIn('1 of 1 chains never raised: nina.osei:takeover:1794893749.', rows[1][2])

    def test_nothing_indexed_yet_is_one_skip(self):
        rep = self.setup_run()                               # a fresh stack: the first poll has not run
        rows = self.d8(rep)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 'SKIP')
        self.assertIn('run this again after the first poll', rows[0][2])
        self.assertEqual([s for s in self.fake.searches if 'stats count by' in s['search']], [])

    def test_no_burst_among_what_is_indexed_is_a_skip(self):
        self.live_stack()
        rep = self.setup_run()
        rows = self.d8(rep)
        self.assertEqual([row[0] for row in rows], ['SKIP', 'SKIP'])
        self.assertIn('no burst among the events indexed more than 20 minutes ago', rows[0][2])
        self.assertIn('no chain among the events indexed more than 15 minutes ago', rows[1][2])
        # Nothing to look up when nothing is expected.
        self.assertEqual([s for s in self.fake.searches if s['search'].startswith('search index=risk')], [])

    def test_a_disabled_rule_is_not_compared(self):
        self.live_stack()
        self.fake.judged = {DUO_RULE: list(self.BURSTS)}
        self.fake.saved[DUO_RULE]['disabled'] = True
        splunkd, _acs, rep = self.clients()
        duo.step_judged(splunkd, rep, dict(self.fake.events))
        self.assertEqual(rep.rows[0][0], 'SKIP')
        self.assertIn('the rule is disabled', rep.rows[0][2])
        self.assertEqual([s for s in self.fake.searches if 'burst_id' in s['search']], [])

    def test_risk_events_from_before_the_rule_had_ids_are_not_comparable(self):
        """The dev instance's case: the first build of the rule raised its
        findings with no burst_id. Advising a catch-up there would raise every
        one of them a second time."""
        self.live_stack()
        self.fake.judged = {DUO_RULE: list(self.BURSTS)}
        self.fake.raised = {DUO_RULE: [None, None, None]}
        rep = self.setup_run()
        row = self.d8(rep)[0]
        self.assertEqual(row[0], 'SKIP')
        self.assertIn('not comparable: 3 of 3 bursts have no risk event under their id', row[2])
        self.assertIn('it would raise them a second time', row[2])
        self.assertEqual(self.rows(rep, 'FAIL'), [])

    def test_without_a_risk_index_there_is_nothing_to_compare(self):
        self.live_stack()
        self.fake.judged = {DUO_RULE: list(self.BURSTS)}
        self.fake.indexes.discard('risk')
        rep = self.setup_run()
        rows = self.d8(rep)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 'SKIP')
        self.assertIn('need Enterprise Security', rows[0][2])

    def test_a_rule_text_that_writes_is_never_dispatched(self):
        self.live_stack()
        self.fake.saved[DUO_RULE]['search'] += ' | collect index=main'
        rep = self.setup_run()
        row = self.d8(rep)[0]
        self.assertEqual(row[0], 'SKIP')
        self.assertIn('holds a command that writes', row[2])
        self.assertEqual([s for s in self.fake.searches if 'collect' in s['search']], [])
        for spl in ('x | outputlookup y', 'x |sendalert z', 'x | COLLECT index=i', 'x | delete', 'x | map search="y"'):
            self.assertIsNotNone(duo.WRITES.search(spl), spl)
        shipped = read_conf('savedsearches.conf')
        for name in duo.DUO_DETECTIONS:
            self.assertIsNone(duo.WRITES.search(shipped[name]['search']), name)

    def test_the_write_guard_knows_the_aliases_and_the_tas_own_commands(self):
        """cloud finding: the guard missed collect's aliases (stash, summaryindex,
        sumindex), dump, and this TA's commands that write or call out. D8 runs
        the stack's own copy of a rule over all index time with the admin's
        rights, in a dry run too."""
        custom = sorted(read_conf('commands.conf'))
        self.assertEqual(custom, ['aicase', 'genaiscore', 'genaiseedes'])
        for name in custom + ['stash', 'summaryindex', 'sumindex', 'dump', 'runshellscript', 'collect', 'tscollect',
                              'mcollect', 'meventcollect', 'outputcsv', 'sendemail', 'script', 'run']:
            self.assertIn(name, duo.WRITING_COMMANDS)
            for form in ('x | {} index=main', 'x |{}', 'x [| {} ]', 'x | ' + name.upper()):
                self.assertIsNotNone(duo.WRITES.search(form.format(name)), form.format(name))
        # Field names and arguments that only contain such a word are not commands.
        for harmless in ('x | eval script_name="a", run_id=1', 'x | stats dc(collect_id) by map_key',
                         'x | search delete=1 dump="y"'):
            self.assertIsNone(duo.WRITES.search(harmless), harmless)
        # A pipe inside a quoted string reads as a command too: the safe side (a skip).
        self.assertIsNotNone(duo.WRITES.search('x | eval a="| collect"'))
        self.live_stack()
        self.fake.judged = {DUO_RULE: list(self.BURSTS)}
        for suffix in (' | stash index=main', ' | summaryindex index=main', ' | sumindex', ' | dump basefilename=x',
                       ' | aicase', ' | genaiscore', ' | append [| genaiseedes ]'):
            self.fake.saved[DUO_RULE]['search'] = read_conf('savedsearches.conf')[DUO_RULE]['search'] + suffix
            del self.fake.searches[:]
            for dry_run in (False, True):
                rep = self.setup_run(dry_run=dry_run)
                row = self.d8(rep)[0]
                self.assertEqual(row[0], 'SKIP', suffix)
                self.assertIn('holds a command that writes', row[2])
            self.assertEqual([s for s in self.fake.searches if 'burst_id' in s['search']
                              and not s['search'].startswith('search index=risk')], [], suffix)

    def test_risk_events_that_cannot_be_read_are_a_skip_never_a_catch_up_advice(self):
        """Both bursts were raised; only the read of their risk events fails. Read
        as "none raised", that used to advise judging the index time once more,
        which raises every burst a second time."""
        self.live_stack()
        self.fake.judged = {DUO_RULE: list(self.BURSTS), CHAIN_RULE: list(self.CHAIN)}
        self.fake.raised = {DUO_RULE: list(self.BURSTS), CHAIN_RULE: list(self.CHAIN)}
        real = duo.oneshot

        def only_the_risk_read_fails(splunkd, spl, *args, **kwargs):
            if spl.startswith('search index=risk'):
                return None, 'search failed (HTTP 503)'
            return real(splunkd, spl, *args, **kwargs)

        with mock.patch.object(duo, 'oneshot', only_the_risk_read_fails):
            rep = self.setup_run()
        rows = self.d8(rep)
        self.assertEqual([row[0] for row in rows], ['SKIP', 'SKIP'])
        for row in rows:
            self.assertIn('not compared: the risk events could not be read (search failed (HTTP 503))', row[2])
            self.assertNotIn('never raised', row[2])
            self.assertNotIn('judge that index time once more', row[2])
        self.assertEqual(self.rows(rep, 'FAIL'), [])

    def test_a_search_that_fails_is_a_skip_not_a_failure(self):
        self.live_stack()
        self.fake.judged = {DUO_RULE: list(self.BURSTS)}
        self.fake.fail[('POST', '/TA-gen_ai_cim/search/jobs')] = (500, '{"messages":[{"type":"FATAL","text":"x"}]}')
        rep = self.setup_run()
        rows = self.d8(rep)
        self.assertEqual([row[0] for row in rows], ['SKIP', 'SKIP'])
        self.assertIn("the rule's own search did not run (search failed (HTTP 500))", rows[0][2])

    def test_it_reads_in_a_dry_run_and_writes_nothing(self):
        self.live_stack()
        self.fake.judged = {DUO_RULE: list(self.BURSTS)}
        self.fake.raised = {DUO_RULE: list(self.BURSTS)}
        before = self.fake.state()
        rep = self.setup_run(dry_run=True)
        self.assertEqual(self.d8(rep)[0][0], 'OK')
        self.assertEqual(self.fake.writes(), [])
        self.assertEqual(self.fake.state(), before)

    def test_every_rule_the_tool_enables_has_an_id_to_compare(self):
        shipped = read_conf('savedsearches.conf')
        self.assertEqual(sorted(duo.JUDGED_IDS), sorted(duo.DUO_DETECTIONS))
        for name, field in duo.JUDGED_IDS.items():
            # the id is the rule's own suppression key, and its search makes it
            self.assertIn(field, shipped[name]['alert.suppress.fields'].split(','), name)
            self.assertRegex(shipped[name]['search'], r'\b%s=user \. ' % field)
            self.assertEqual(shipped[name]['action.risk'], '1', name)
            self.assertIn(name, duo.JUDGED_NOUNS)


class PrivacyTests(StackCase):
    """Reviewer correction 6: what an attendee stack holds is an explicit
    choice. The users snapshot and the identity lookup search are created only
    when asked for, and every setup run says what the stack will hold."""

    def test_users_input_and_lookup_search_are_off_unless_asked_for(self):
        rep = self.setup_run()
        self.assertEqual(sorted(self.fake.inputs), ['duo_authentication'])
        self.assertTrue(self.fake.saved[LOOKUP_GEN]['disabled'])
        users = self.row(rep, 'D6. input duo_users')
        self.assertEqual(users[0], 'SKIP')
        self.assertIn('no --duo-with-users', users[2])
        self.assertIn("the tenant owner's own record included", users[2])
        lookup = self.row(rep, 'D5. enable "GenAI - Identity - Duo Identity Lookup Gen"')
        self.assertEqual(lookup[0], 'SKIP')
        self.assertIn('left disabled: no --duo-with-lookup-gen', lookup[2])
        self.assertIn("the tenant owner's own Duo user", lookup[2])
        # Not asked for and not there: D7 does not report it a second time.
        self.assertEqual([r for r in rep.rows if 'verify input duo_users' in r[1]], [])
        self.assertEqual([p for m, p in self.fake.writes() if duo.q(LOOKUP_GEN) in p], [])

    def test_a_later_run_without_the_flags_leaves_what_an_earlier_run_added(self):
        """Only the teardown removes an input. A rerun to change the interval
        must not silently take the users snapshot away, nor add it."""
        self.setup_run(users_input=True, lookup_gen=True)
        before = self.fake.state()
        del self.fake.requests[:]
        rep = self.setup_run(env={})
        self.assertEqual(self.fake.writes(), [])
        self.assertEqual(self.fake.state(), before)
        self.assertIn('an earlier run created it; left as it is', self.row(rep, 'D6. input duo_users')[2])
        self.assertIn('left enabled, as an earlier run set it',
                      self.row(rep, 'D5. enable "GenAI - Identity - Duo Identity Lookup Gen"')[2])
        self.assertEqual(self.row(rep, 'D7. verify input duo_users')[0], 'OK')

    def test_every_setup_says_what_the_stack_will_hold(self):
        lines = '\n'.join(duo.scope_lines(duo.Settings(duo.poll_slot('1/5'))))
        for needle in ('interval 1,6,11,16,21,26,31,36,41,46,51,56 * * * *', 'the first poll reads the last 720 h',
                       'every sign-in of the WHOLE Duo tenant, all users, with their source addresses',
                       'Users   : not indexed (--duo-with-users adds the user list)',
                       'Lookup  : the identity lookup search is not enabled (--duo-with-lookup-gen)',
                       'Readers : role splunker may search index duo',
                       'opens the whole tenant for reading to anyone who administers the stack'):
            self.assertIn(needle, lines)
        lines = '\n'.join(duo.scope_lines(duo.Settings('300', users_input=True, lookup_gen=True, attendee_roles=())))
        for needle in ("Users   : the tenant's user list, every 86400 s (--duo-with-users)",
                       'Lookup  : the identity lookup search is enabled (--duo-with-lookup-gen)',
                       "Readers : the stack's admins only (no --duo-attendee-role)"):
            self.assertIn(needle, lines)

    def test_role_access_can_be_withheld(self):
        rep = self.setup_run(attendee_roles=())
        self.assertEqual(self.row(rep, 'D3.')[0], 'SKIP')
        self.assertEqual(self.fake.roles['splunker']['srchIndexesAllowed'], ['main', 'gen_ai_log'])
        self.assertEqual(self.rows(rep, 'FAIL'), [])

    def test_the_tool_never_adds_the_identity_source(self):
        self.setup_run(users_input=True, lookup_gen=True)
        self.assertEqual(self.fake.conf_inputs, {})
        self.assertEqual([p for m, p in self.fake.writes() if 'conf-inputs' in p or 'identity_manager' in p], [])


CERT_ERROR = ('<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self signed '
              'certificate in certificate chain (_ssl.c:1129)>')


class CommandLineCase(StackCase):

    def main(self, argv, env=None):
        """main(argv) with a clean environment; (exit code, everything printed)."""
        out = io.StringIO()
        with mock.patch.dict(os.environ, env or {}, clear=True), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                code = show_postdeploy.main(argv)
            except SystemExit as exc:
                code = exc.code
        self.printed.write(out.getvalue())
        return code, out.getvalue()

    def main_on_the_fake(self, argv, env=None):
        """main(argv), with the two clients built exactly as main() builds them
        and then pointed at the fake stack: (exit code, everything printed,
        what Splunkd and AcsClient were built with)."""
        real_splunkd, real_acs = seed.Splunkd, show_postdeploy.AcsClient
        built = {'splunkd': [], 'acs': []}

        def splunkd(mgmt_uri, **kwargs):
            built['splunkd'].append((mgmt_uri, dict(kwargs)))
            return real_splunkd(self.base, username=kwargs.get('username'), password=kwargs.get('password'),
                                dry_run=kwargs.get('dry_run', False), echo=kwargs.get('echo'))

        def acs(stack_name, token, dry_run=False):
            built['acs'].append((stack_name, token, dry_run))
            client = real_acs(stack_name, token, dry_run=dry_run)
            client.base = self.base
            return client

        with mock.patch.object(seed, 'Splunkd', splunkd), mock.patch.object(show_postdeploy, 'AcsClient', acs):
            code, text = self.main(argv, env)
        return code, text, built

    def run_duo(self, argv, dry_run=False, env=None):
        args = show_postdeploy.build_parser().parse_args(BASE + argv + (['--dry-run'] if dry_run else []))
        splunkd, acs, _rep = self.clients(dry_run)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = show_postdeploy.run_duo(args, splunkd=splunkd, acs=acs, creds=self.creds(env),
                                           sleep=self.sleeps.append, clock=self.clock)
        self.printed.write(out.getvalue())
        return code, out.getvalue()


class TlsTests(CommandLineCase):
    """Reviewer correction 5: the Duo secret key travels to the stack's :8089.
    A Duo run verifies that server's certificate unless told not to, and a run
    that does not verify says so."""

    def unreachable(self, *extra):
        args = show_postdeploy.build_parser().parse_args(BASE + ['--duo', '--duo-auth-interval', '300'] + list(extra))
        out = io.StringIO()
        with mock.patch.object(seed, 'Splunkd') as made, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            made.return_value.mgmt = 'https://{}.splunkcloud.com:8089'.format(fake_rest.STACK)
            made.return_value.call.return_value = (0, CERT_ERROR)
            code = show_postdeploy.run_duo(args, creds=self.creds())
        self.printed.write(out.getvalue())
        return code, out.getvalue(), made

    def test_the_certificate_is_verified_unless_the_run_is_told_not_to(self):
        code, text, made = self.unreachable()
        self.assertIs(made.call_args[1]['verify'], True)
        self.assertEqual(made.call_args[0], ('https://{}.splunkcloud.com:8089'.format(fake_rest.STACK),))
        self.assertEqual(code, 2)
        self.assertIn('did not verify, so nothing was sent', text)
        self.assertIn('--duo-no-tls-verify', text)
        # The remedy it names is one that works under any Python: the CA file, loaded
        # explicitly. SSL_CERT_FILE is named only to say that it is no way in.
        self.assertIn('pass --duo-ca-file PATH', text)
        self.assertIn('The SSL_CERT_FILE variable is not a way in', text)
        self.assertNotIn('Point SSL_CERT_FILE', text)
        self.assertEqual(made.return_value.call.call_count, 1)        # the first read, and nothing after it
        self.assertEqual(self.fake.requests, [])
        _code, _text, made = self.unreachable('--duo-no-tls-verify')
        self.assertIs(made.call_args[1]['verify'], False)
        # The teardown sends the admin password over the same connection: verified too.
        args = show_postdeploy.build_parser().parse_args(BASE + ['--duo-teardown', '--duo-keep-data'])
        with mock.patch.object(seed, 'Splunkd') as made, contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            made.return_value.call.return_value = (0, CERT_ERROR)
            self.assertEqual(show_postdeploy.run_duo(args), 2)
        self.assertIs(made.call_args[1]['verify'], True)

    def test_the_run_says_whether_the_certificate_is_verified(self):
        code, text = self.run_duo(['--duo', '--duo-auth-interval', '300'], dry_run=True)
        self.assertEqual(code, 0, text)
        self.assertIn("TLS     : the stack's certificate is verified", text)
        code, text = self.run_duo(['--duo', '--duo-auth-interval', '300', '--duo-no-tls-verify'], dry_run=True)
        self.assertEqual(code, 0, text)
        self.assertIn('TLS     : NOT VERIFIED (--duo-no-tls-verify): the Duo secret key and the admin password go '
                      'to a server that was not authenticated', text)

    def test_other_failures_are_not_called_a_certificate_problem(self):
        self.assertTrue(duo.certificate_refused(0, CERT_ERROR))
        self.assertTrue(duo.certificate_refused(0, 'certificate verify failed: Hostname mismatch'))
        for code, text in ((0, '<urlopen error [Errno 61] Connection refused>'), (0, 'timed out'),
                           (401, 'certificate verify failed'), (200, '{}')):
            self.assertFalse(duo.certificate_refused(code, text), (code, text))

    def throwaway_certificate(self):
        """(certificate file, key file) of a self-signed certificate for 127.0.0.1
        and localhost, made here and thrown away; skips where openssl is missing."""
        openssl = shutil.which('openssl')
        if not openssl:
            self.skipTest('no openssl here to make a throwaway certificate')
        work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, work, True)
        cert, key, conf = (os.path.join(work, name) for name in ('cert.pem', 'key.pem', 'req.cnf'))
        with open(conf, 'w') as handle:
            handle.write('[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=localhost\n'
                         '[v3]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:TRUE\n')
        made = subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
                               '-days', '2', '-config', conf], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if made.returncode != 0 or not os.path.exists(cert):
            self.skipTest('openssl could not make a throwaway certificate')
        return cert, key

    def test_a_private_ca_is_trusted_through_duo_ca_file_under_this_python(self):
        """cloud finding: the only remedy the tool named was SSL_CERT_FILE, which
        Apple's Python (LibreSSL) ignores and Splunk's launcher overwrites, so
        every run against a privately signed :8089 ended at --duo-no-tls-verify.
        Not a mock: the fake stack is served over TLS with a certificate no
        default root knows, and the real command line is run against it."""
        cert, key = self.throwaway_certificate()
        self.fake.indexes.add('duo')                       # --skip-acs: the index is taken from splunkd
        self.server.shutdown()
        self.server.server_close()
        try:
            self.server = self.fake.serve(tls=(cert, key))
        except (AttributeError, OSError) as exc:
            self.server = self.fake.serve()
            self.skipTest('this Python cannot serve TLS on loopback ({})'.format(type(exc).__name__))
        port = self.server.server_address[1]
        real, built = seed.Splunkd, []

        def splunkd(mgmt_uri, **kwargs):
            built.append((mgmt_uri, dict(kwargs)))
            return real('https://127.0.0.1:{}'.format(port), **kwargs)

        argv = BASE + ['--duo', '--duo-auth-interval', '300', '--dry-run', '--skip-acs']
        with mock.patch.object(seed, 'Splunkd', splunkd):
            code, text = self.main(argv, ENV)
            self.assertEqual(code, 2, text)                # no CA file: given up in the handshake
            self.assertIn('did not verify, so nothing was sent', text)
            self.assertEqual(self.fake.requests, [])
            code, text = self.main(argv + ['--duo-ca-file', cert], ENV)
        self.assertEqual(code, 0, text)
        self.assertIn("TLS     : the stack's certificate is verified (default roots and --duo-ca-file {})".format(cert),
                      text)
        self.assertIn('OK] D0. ', text)
        self.assertEqual(self.fake.requests[0]['path'], '/services/server/info')
        self.assertTrue(all(kwargs['verify'] is True for _uri, kwargs in built))
        self.assertEqual(self.fake.writes(), [])           # a dry run all the same

    def test_a_ca_file_that_is_no_certificate_stops_the_run_before_any_request(self):
        work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, work, True)
        junk = os.path.join(work, 'not-a-certificate.pem')
        with open(junk, 'w') as handle:
            handle.write('this is not a certificate\n')
        base = BASE + ['--duo', '--duo-auth-interval', '300']
        with mock.patch.object(seed, 'http_request', side_effect=AssertionError('a request was attempted')):
            for extra, needle in ((['--duo-ca-file', os.path.join(work, 'missing.pem')], 'does not name a file'),
                                  (['--duo-ca-file', junk], 'no PEM certificate could be read from that file'),
                                  (['--duo-ca-file', junk, '--duo-no-tls-verify'], 'contradict each other')):
                code, text = self.main(base + extra, ENV)
                self.assertEqual(code, 2, extra)
                self.assertIn(needle, text)
                self.assertNotIn(work, text)                 # what was typed there is not repeated
        self.assertEqual(self.fake.requests, [])
        # ACS keeps the default roots: the CA file is loaded into the stack's context only.
        source = text_of(REPO, 'tools', 'show_postdeploy.py')
        self.assertEqual(source.count('load_verify_locations('), 1)
        self.assertIn('splunkd.ctx.load_verify_locations(cafile=ca_file)', source)
        self.assertNotIn('SSL_CERT_FILE', text_of(REPO, 'bin', 'genai_es_seed.py'))

    def test_a_real_handshake_with_an_unknown_certificate_gets_no_request(self):
        """Not a mock: a loopback HTTPS server with a throwaway self-signed
        certificate. The verifying client gives up in the handshake, so the
        server never sees a request (and so never a password or a key); the
        error is the one certificate_refused recognizes."""
        openssl = shutil.which('openssl')
        if not openssl:
            self.skipTest('no openssl here to make a throwaway certificate')
        work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, work, True)
        cert, key = os.path.join(work, 'cert.pem'), os.path.join(work, 'key.pem')
        made = subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
                               '-out', cert, '-days', '2', '-subj', '/CN=localhost'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if made.returncode != 0 or not os.path.exists(cert):
            self.skipTest('openssl could not make a throwaway certificate')
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get('Authorization')))
                body = b'{"entry": [{"content": {"version": "10.4.3"}}]}'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        self.addCleanup(server.server_close)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        try:
            server.socket = context.wrap_socket(server.socket, server_side=True)
        except (AttributeError, OSError) as exc:
            # Splunk's own Python 3.9 on macOS cannot wrap a listening socket (its ssl.py
            # names a Windows-only errno there). The client under test is not involved.
            self.skipTest('this Python cannot serve TLS on loopback ({})'.format(type(exc).__name__))
        threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True).start()
        self.addCleanup(server.shutdown)
        url = 'https://127.0.0.1:{}'.format(server.server_address[1])
        strict = seed.Splunkd(url, username='admin', password='fixture-admin-password', verify=True)
        code, text = strict.call('/services/server/info')
        self.assertEqual(code, 0)
        self.assertTrue(duo.certificate_refused(code, text), text)
        self.assertEqual(seen, [])
        loose = seed.Splunkd(url, username='admin', password='fixture-admin-password', verify=False)
        self.assertEqual(loose.call('/services/server/info')[0], 200)
        self.assertEqual(len(seen), 1)


class CommandLineTests(CommandLineCase):

    def test_bad_command_lines_stop_before_any_request(self):
        cases = (['--duo'],                                                     # no interval: there is no default
                 ['--duo', '--duo-auth-interval', '300', '--duo-poll-slot', '0/5'],
                 ['--duo', '--duo-auth-interval', '60'],
                 ['--duo', '--duo-auth-interval', '* * * * *'],                 # every minute: under the floor
                 ['--duo', '--duo-poll-slot', '5/5'],
                 ['--duo', '--duo-poll-slot', '0/5', '--duo-lookback-hours', '99999'],
                 ['--duo', '--duo-poll-slot', '0/5', '--duo-users-interval', '60'],
                 ['--duo', '--duo-poll-slot', '0/5', '--duo-with-lookup-gen'],  # it reads the users snapshot
                 ['--duo', '--duo-poll-slot', '0/5', '--out', 'stack.json'],    # a Duo run writes no file
                 ['--duo', '--duo-poll-slot', '0/5', '--lab5'],
                 ['--duo', '--duo-teardown', '--duo-keep-data'],
                 ['--duo-teardown'],
                 ['--duo-teardown', '--duo-purge-data', '--duo-keep-data'])
        # "Before any request" is asserted, not assumed: the stand-in hostname resolves
        # nowhere, so a client that did reach the network layer would fail just as
        # quietly as a refused command line. Here it fails the test.
        with mock.patch.object(seed, 'http_request', side_effect=AssertionError('a request was attempted')):
            for argv in cases:
                code, text = self.main(BASE + argv)
                self.assertEqual(code, 2, argv)
                self.assertIn('ERROR', text, argv)
            code, _text = self.main(['--stack', STACK_URL, '--duo', '--duo-poll-slot', '0/5'])      # no password
            self.assertEqual(code, 2)
            code, _text = self.main(['--password', fake_rest.ADMIN_PASSWORD, '--duo', '--duo-poll-slot', '0/5'])
            self.assertEqual(code, 2)                                                           # no stack
        self.assertEqual(self.fake.requests, [])
        self.assertFalse(os.path.exists('stack.json'))

    def test_main_runs_a_setup_and_a_teardown_through_the_real_entry_point(self):
        """tests finding: every success path used to call run_duo() or duo.setup()
        directly, so the routing in main() could break either way with the suite
        green (--duo unusable, or falling through to the base Show-stack mode,
        which writes a different set of objects)."""
        self.fake.acs_ready_after = 1                        # main() waits with the real time.sleep
        before = self.fake.state()
        slot = ['--duo', '--duo-poll-slot', '0/5']
        code, text, built = self.main_on_the_fake(BASE + slot + ['--dry-run'], ENV)
        self.assertEqual(code, 0, text)
        self.assertEqual(self.fake.state(), before)
        self.assertEqual(self.fake.writes(), [])
        self.assertIn('Mode    : DRY RUN (Duo feed setup)', text)
        self.assertLess(text.index('Holds   : every sign-in of the WHOLE Duo tenant'), text.index('] D0. '))
        self.assertIn('ACS     : ' + fake_rest.STACK, text)
        self.assertNotIn('1. index gen_ai_log', text)        # not the base mode's steps
        self.assertNotIn('L1.', text)
        self.assertEqual(len(built['splunkd']), 1)
        mgmt, kwargs = built['splunkd'][0]
        self.assertEqual(mgmt, 'https://{}.splunkcloud.com:8089'.format(fake_rest.STACK))
        self.assertEqual((kwargs['username'], kwargs['password'], kwargs['verify'], kwargs['dry_run']),
                         ('admin', fake_rest.ADMIN_PASSWORD, True, True))
        self.assertEqual(built['acs'], [(fake_rest.STACK, fake_rest.ACS_TOKEN, True)])
        # For real, with the secret key in a variable of another name: the option reaches
        # the step that sends the key.
        env = {duo.ENV_HOST: HOST, duo.ENV_IKEY: IKEY, 'ROOM_SEVEN_DUO_KEY': SKEY2}
        code, text, built = self.main_on_the_fake(BASE + slot + ['--duo-skey-env', 'ROOM_SEVEN_DUO_KEY'], env)
        self.assertEqual(code, 0, text)
        self.assertIn('Mode    : apply (Duo feed setup)', text)
        self.assertEqual(built['splunkd'][0][1]['dry_run'], False)
        self.assertEqual(built['acs'], [(fake_rest.STACK, fake_rest.ACS_TOKEN, False)])
        self.assertEqual(self.fake.secret(), SKEY2)
        self.assertEqual(self.fake.inputs['duo_authentication']['interval'], '0,5,10,15,20,25,30,35,40,45,50,55 * * * *')
        self.assertFalse(self.fake.saved[DUO_RULE]['disabled'])
        self.assertIn('SUMMARY:', text)
        code, text, built = self.main_on_the_fake(BASE + ['--duo-teardown', '--duo-keep-data'], {})
        self.assertEqual(code, 0, text)
        self.assertIn('Mode    : apply (Duo feed teardown)', text)
        self.assertIn('] DT1. ', text)
        self.assertEqual((self.fake.inputs, self.fake.account_store.passwords), ({}, {}))
        self.assertIn('duo', self.fake.acs_indexes)          # --duo-keep-data
        self.assertTrue(self.fake.saved[DUO_RULE]['disabled'])

    def test_each_mode_reaches_its_own_runner_and_only_that(self):
        with mock.patch.object(show_postdeploy, 'run_duo', return_value=0) as run_duo, \
                mock.patch.object(show_postdeploy, 'run_lab5', return_value=0) as run_lab5, \
                mock.patch.object(seed, 'http_request', side_effect=AssertionError('a request was attempted')):
            for argv, calls in ((['--duo', '--duo-poll-slot', '0/5'], (1, 0)),
                                (['--duo-teardown', '--duo-keep-data'], (1, 0)),
                                (['--lab5', '--lab5-victim', 'nina.osei'], (0, 1)),
                                (['--lab5-teardown'], (0, 1))):
                run_duo.reset_mock()
                run_lab5.reset_mock()
                code, text = self.main(BASE + argv)
                self.assertEqual((code, run_duo.call_count, run_lab5.call_count), (0,) + calls, (argv, text))
            # Two modes at once are refused before either runner is called.
            run_duo.reset_mock()
            run_lab5.reset_mock()
            code, text = self.main(BASE + ['--duo', '--duo-poll-slot', '0/5', '--lab5-teardown'])
            self.assertEqual((code, run_duo.call_count, run_lab5.call_count), (2, 0, 0))
            self.assertIn('are separate runs', text)

    def test_without_an_acs_token_acs_is_never_asked(self):
        self.fake.indexes.add('duo')                         # ACS skipped: the index is taken from splunkd
        local = ['--stack', STACK_URL, '--password', fake_rest.ADMIN_PASSWORD, '--duo', '--duo-auth-interval', '300',
                 '--dry-run']
        for argv in (local, BASE + ['--duo', '--duo-auth-interval', '300', '--dry-run', '--skip-acs']):
            del self.fake.requests[:]
            code, text, built = self.main_on_the_fake(argv, ENV)
            self.assertEqual(code, 0, text)
            self.assertIn('ACS     : skipped', text)
            self.assertIn('exists (ACS skipped; make sure it keeps 44 days or more)', text)
            self.assertEqual([r for r in self.fake.requests if r.get('service') == 'acs'], [])
            self.assertTrue(self.fake.requests)                 # splunkd was asked

    def test_a_secret_typed_on_the_command_line_is_never_repeated(self):
        for argv in (['--duo', '--duo-poll-slot', '0/5', '--duo-skey-env', SKEY],
                     ['--duo', '--duo-poll-slot', '0/5', '--duo-skey', SKEY],           # abbreviates --duo-skey-env
                     ['--duo', '--duo-poll-slot', '0/5', '--duo-secret-key', SKEY],     # no such option
                     ['--duo', '--duo-poll-slot', '0/5', SKEY],
                     ['--duo', '--duo-auth-interval', SKEY],
                     ['--duo', '--duo-poll-slot', SKEY],
                     ['--duo', '--duo-poll-slot', '0/5', '--duo-lookback-hours', SKEY],
                     ['--duo', '--duo-poll-slot', '0/5', '--duo-users-interval', SKEY],
                     ['--duo', '--duo-poll-slot', '0/5', '--duo-attendee-role', SKEY + ' x']):
            code, text = self.main(BASE + argv)
            self.assertEqual(code, 2, argv)
            self.assertNotIn(SKEY, text, argv)
            self.assertNotIn(SKEY[:10], text, argv)
        self.assertEqual(self.fake.requests, [])
        # automation finding 1: a value glued to a flag that takes none ("--duo-rotate-key=<key>"
        # is the natural slip when rotating) came back as "ignored explicit argument '<key>'",
        # and "--duo-p=<key>" as "ambiguous option: --duo-p=<key> could match ...". Abbreviations
        # are off now, and an option's name is all that is ever repeated.
        base = BASE + ['--duo', '--duo-poll-slot', '0/5']
        for argv, said in ((['--duo-rotate-key=' + SKEY], 'argument --duo-rotate-key: takes no value'),
                           (['--duo=' + SKEY], 'argument --duo: takes no value'),
                           (['--dry-run=' + SKEY], 'argument --dry-run: takes no value'),
                           (['--skip-acs=' + SKEY], 'argument --skip-acs: takes no value'),
                           (['--duo-p=' + SKEY], 'unrecognized arguments: --duo-p (values are not repeated'),
                           (['--duo-rotate=' + SKEY], 'unrecognized arguments: --duo-rotate (values are not repeated'),
                           (['--duo-r=' + SKEY], 'unrecognized arguments: --duo-r (values are not repeated'),
                           (['--duo-p', SKEY], 'unrecognized arguments: --duo-p (values are not repeated'),
                           (['--duo-ca-file', SKEY], 'ERROR: --duo-ca-file does not name a file.'),
                           (['--duo-ca-file=' + SKEY], 'ERROR: --duo-ca-file does not name a file.')):
            with mock.patch.object(seed, 'http_request', side_effect=AssertionError('a request was attempted')):
                code, text = self.main(base + argv)
            self.assertEqual(code, 2, argv)
            self.assertIn(said, text, argv)
            for piece in (SKEY, SKEY[:10], SKEY[-10:]):
                self.assertNotIn(piece, text, argv)
        self.assertEqual(self.fake.requests, [])
        self.assertIs(show_postdeploy.build_parser().allow_abbrev, False)
        # Whatever else argparse may say one day: nothing in quotes, nothing after an "=".
        for message in ("argument --x: invalid choice: '{0}' (choose from 'a', 'b')", 'ambiguous option: --duo-p={0} '
                        'could match --duo-poll-slot, --duo-purge-data', 'argument --y: invalid int value: "{0}"'):
            out = io.StringIO()
            with contextlib.redirect_stderr(out), self.assertRaises(SystemExit) as caught:
                show_postdeploy.build_parser().error(message.format(SKEY))
            self.assertEqual(caught.exception.code, 2)
            self.assertNotIn(SKEY[:10], out.getvalue(), message)
            self.assertIn('(not repeated)', out.getvalue())
        # A mistyped option is still named, so a typo can be found; its value never is.
        for argv in (['--duo-secret-key', SKEY], ['--duo-secret-key=' + SKEY], ['--lab5-victm', SKEY]):
            code, text = self.main(BASE + ['--duo', '--duo-poll-slot', '0/5'] + argv)
            self.assertEqual(code, 2)
            self.assertIn('unrecognized arguments: ' + argv[0].split('=')[0] + ' (values are not repeated', text)
            self.assertNotIn(SKEY[:10], text)

    def test_no_option_takes_a_key_and_help_shows_none(self):
        parser = show_postdeploy.build_parser()
        options = [s for action in parser._actions for s in action.option_strings if s.startswith('--duo')]
        self.assertEqual([s for s in options if any(word in s for word in ('skey', 'secret', 'ikey', 'host', 'key'))],
                         ['--duo-skey-env', '--duo-rotate-key'])
        for action in parser._actions:
            if action.option_strings and action.option_strings[0].startswith('--duo'):
                self.assertIsNone(action.type, action.option_strings)          # argparse would repeat a bad value
                self.assertIsNone(action.choices, action.option_strings)
        with mock.patch.dict(os.environ, ENV, clear=True):
            text = show_postdeploy.build_parser().format_help()
        for value in (SKEY, IKEY, HOST):
            self.assertNotIn(value, text)
        self.assertIn('DUO_LOG_FEED_SKEY', text)
        for option in ('--duo-with-users', '--duo-with-lookup-gen', '--duo-no-tls-verify', '--duo-poll-slot',
                       '--duo-auth-interval', '--duo-purge-data', '--duo-keep-data'):
            self.assertIn(option, options)
        self.assertNotIn('--duo-no-lookup-gen', options)                       # opt-in now, not opt-out

    def test_dry_run_then_apply_then_teardown(self):
        before = self.fake.state()
        code, text = self.run_duo(['--duo', '--duo-poll-slot', '2/5'], dry_run=True)
        self.assertEqual((code, self.fake.state()), (0, before))
        self.assertIn('DRY RUN (Duo feed setup)', text)
        # what the stack will hold is printed before the first step
        self.assertLess(text.index('Holds   : every sign-in of the WHOLE Duo tenant'), text.index('D0. '))
        self.assertIn('Users   : not indexed', text)
        code, text = self.run_duo(['--duo', '--duo-poll-slot', '2/5'])
        self.assertEqual(code, 0, text)
        self.assertEqual(self.fake.inputs['duo_authentication']['interval'],
                         '2,7,12,17,22,27,32,37,42,47,52,57 * * * *')
        self.assertEqual(sorted(self.fake.inputs), ['duo_authentication'])
        self.assertIn('SUMMARY:', text)
        self.assertIn('Next: the inputs poll within one interval', text)
        code, text = self.run_duo(['--duo', '--duo-poll-slot', '2/5'], env={})         # again: nothing to do
        self.assertEqual(code, 0, text)
        code, text = self.run_duo(['--duo-teardown', '--duo-purge-data'])
        self.assertEqual(code, 0, text)
        self.assertEqual((self.fake.inputs, self.fake.account_store.passwords), ({}, {}))
        self.assertNotIn('duo', self.fake.acs_indexes)
        self.assertNotIn('Holds   :', text)                                     # a teardown adds nothing

    def test_the_opt_in_flags_reach_the_steps(self):
        code, text = self.run_duo(['--duo', '--duo-auth-interval', '300', '--duo-with-users', '--duo-with-lookup-gen'])
        self.assertEqual(code, 0, text)
        self.assertEqual(sorted(self.fake.inputs), ['duo_authentication', 'duo_users'])
        self.assertFalse(self.fake.saved[LOOKUP_GEN]['disabled'])
        self.assertIn("Users   : the tenant's user list, every 86400 s (--duo-with-users)", text)

    def test_a_failed_step_is_exit_code_1(self):
        self.fake.apps['TA-gen_ai_cim'] = '1.8.0'
        code, text = self.run_duo(['--duo', '--duo-auth-interval', '300'])
        self.assertEqual(code, 1)
        self.assertIn('1 failed', text)

    def test_no_attendee_role(self):
        code, text = self.run_duo(['--duo', '--duo-auth-interval', '300', '--duo-attendee-role', ''])
        self.assertEqual(code, 0, text)
        self.assertEqual(self.fake.roles['splunker']['srchIndexesAllowed'], ['main', 'gen_ai_log'])
        self.assertIn('[SKIP] D3. attendee role', text)
        self.assertIn("Readers : the stack's admins only", text)

    def test_existing_modes_still_parse(self):
        args = show_postdeploy.build_parser().parse_args(['--stack', STACK_URL, '--lab5', '--lab5-victim', 'nina.osei'])
        self.assertTrue(args.lab5)
        self.assertFalse(args.duo)
        self.assertEqual(args.duo_skey_env, 'DUO_LOG_FEED_SKEY')
        self.assertEqual((args.duo_with_users, args.duo_with_lookup_gen, args.duo_no_tls_verify), (False,) * 3)


class ShippedConfTests(unittest.TestCase):

    def test_every_rule_that_reads_the_duo_feed_is_known_to_the_tool(self):
        """A rule that reads the Duo feed and is not in the tool's lists would
        stay off on every scripted stack, and D8 would never look for what it
        failed to raise. A new one fails here until it is added."""
        saved = read_conf('savedsearches.conf')
        reading = sorted(name for name, stanza in saved.items()
                         if RULE_NAME.match(name) and READS_DUO.search(stanza.get('search', '')))
        known = duo.DUO_DETECTIONS + duo.DUO_OPTIONAL_DETECTIONS
        self.assertEqual([name for name in reading if name not in known], [])
        self.assertEqual(sorted(reading), sorted(duo.DUO_DETECTIONS))        # both rules, and nothing else
        self.assertEqual(duo.DUO_DETECTIONS, (DUO_RULE, CHAIN_RULE))
        for name in duo.DUO_DETECTIONS + (duo.LOOKUP_GEN,):
            self.assertIn(name, saved)
        for name in known + (duo.LOOKUP_GEN,):
            if name in saved:
                self.assertEqual(saved[name].get('disabled'), '1', name)      # the tool is what turns it on
        self.assertEqual(len(set(known)), len(known))

    def test_the_fake_stack_serves_the_shipped_stanzas(self):
        """Reviewer correction 2: every schedule key and search text the fake
        answers with is read from default/savedsearches.conf."""
        saved = read_conf('savedsearches.conf')
        served = fake_rest.shipped_saved_searches()
        self.assertEqual(sorted(served), sorted(duo.DUO_DETECTIONS + (duo.LOOKUP_GEN,)))
        for name, content in served.items():
            for key in ('search', 'cron_schedule', 'dispatch.earliest_time', 'dispatch.latest_time'):
                self.assertEqual(content[key], saved[name][key], (name, key))
            self.assertIs(content['disabled'], True)
            self.assertIs(content['realtime_schedule'], saved[name].get('realtime_schedule', '1') == '1')
            invented = sorted(key for key in content if key not in saved[name] and key not in fake_rest.BOOLEAN_KEYS)
            self.assertEqual(invented, [], name)
        source = text_of(HERE, 'fake_splunk_rest.py')
        self.assertNotRegex(source, r"'dispatch\.earliest_time'\s*:")        # no schedule typed into the fake
        self.assertNotIn("'-30d'", source)

    def test_names_agree_with_the_confs(self):
        macros = read_conf('macros.conf')
        self.assertEqual(macros['genai_duo_index']['definition'], 'index=' + duo.DUO_INDEX)
        self.assertEqual(read_conf('transforms.conf')['ta_gen_ai_cim_duo_identities']['filename'], duo.LOOKUP_FILE)
        self.assertEqual('[%s]' % duo.IDENTITY_SOURCE, test_duo_conf.DUO_IDENTITY_STANZA[0])
        self.assertIn(duo.duo_input.COLLECTION, read_conf('collections.conf'))
        self.assertEqual(duo.ATTENDEE_ROLE, lab5.PARTICIPANT_ROLE)
        readme = text_of(REPO, 'README.md')
        for name, _endpoint in duo.INPUTS:
            self.assertIn('[{}://{}]'.format(duo.SCHEME, name), readme)
        self.assertIn('account = ' + duo.DUO_ACCOUNT, readme)
        # the feed's read-only keys are never the Lab 5 keys, which can write
        self.assertEqual({duo.ENV_HOST, duo.ENV_IKEY, duo.ENV_SKEY}
                         & {lab5.ENV_DUO_HOST, lab5.ENV_DUO_IKEY, lab5.ENV_DUO_SKEY}, set())
        self.assertNotIn(duo.DUO_INDEX, ('gen_ai_log',))
        self.assertIn('gen_ai_log', duo.PROTECTED_INDEXES)
        self.assertIn(duo.RISK_INDEX, duo.PROTECTED_INDEXES)

    def test_new_scripts_are_executable_and_stay_out_of_the_package(self):
        for name in ('duo_steps.py', os.path.join('tests', 'fake_splunk_rest.py'),
                     os.path.join('tests', 'test_duo_stack.py')):
            self.assertTrue(os.stat(os.path.join(REPO, 'tools', name)).st_mode & 0o111, name)
        self.assertIn("--exclude='tools'", text_of(REPO, 'package.sh'))


class DocsTests(StackCase):

    def labels(self, rep):
        return sorted(set(step.split('.', 1)[0] for _status, step, _detail in rep.rows))

    def duo_section(self, heading, runbook=None):
        runbook = runbook or text_of(REPO, 'tools', 'lab5-identity-runbook.md')
        start = runbook.index('## %s\n' % heading)
        return runbook[start:runbook.index('\n## ', start + 4)]

    def test_runbook_table_lists_the_steps_the_code_reports(self):
        setup = self.labels(self.setup_run())
        self.assertEqual(setup, ['D%d' % n for n in range(9)])
        teardown = self.labels(self.teardown_run())
        self.assertEqual(teardown, ['DT%d' % n for n in range(1, 8)])
        section = self.duo_section('`--duo` (per stack that polls Duo)')
        self.assertEqual(re.findall(r'^\| (D\d) \|', section, flags=re.M), setup)
        runbook = text_of(REPO, 'tools', 'lab5-identity-runbook.md')
        tail = runbook[runbook.index('The Duo feed has its own teardown:'):runbook.index('## What the TA reads')]
        self.assertEqual(sorted(set(re.findall(r'\bDT\d\b', tail))), teardown)
        flat = re.sub(r'\s+', ' ', tail)
        for needle in ('or while that could not be checked', 'DT4 changes only the roles the command line names',
                       'pass the same option to the teardown', 'is reported as a failure and left as it is',
                       'no other input of the scheme writes to it',
                       'The checkpoints are cleared only once ACS confirms the index is gone',
                       'Run the teardown again until DT6 reports the index gone'):
            self.assertIn(needle, flat)
        # The module's own list of steps says the same.
        self.assertEqual(re.findall(r'^  (D\d)  ', duo.__doc__, flags=re.M), setup)
        # Sections in the order a facilitator needs them.
        order = [runbook.index('## ' + heading) for heading in (
            '`--lab5` (per room stack)', '`--duo` (per stack that polls Duo)',
            "T-1: is the victim's evidence in the stack?", 'T-1: is the staged Duo evidence in the stack?',
            'T-1: is the spray that named the victim in the stack?', 'Lab day', 'Teardown')]
        self.assertEqual(order, sorted(order))

    def test_runbook_says_what_a_stack_holds_and_how_the_key_travels(self):
        flat = re.sub(r'\s+', ' ', self.duo_section('`--duo` (per stack that polls Duo)'))
        for needle in ('--duo --duo-poll-slot <K>/<N> --dry-run', 'never the Identity Ops keys',
                       'not on the command line and not in a file', 'hidden prompt', '`--duo-skey-env NAME`',
                       "verifies the stack's certificate on port 8089", '`--duo-no-tls-verify`',
                       'Create one read-only application per delivery',
                       'every sign-in of the whole Duo tenant, all users, with their source addresses',
                       '`--duo-with-users` creates the users input', '`--duo-with-lookup-gen` (needs '
                       '`--duo-with-users`)', "the tenant owner's own Duo user",
                       'only the teardown removes it', 'The script never adds the Duo identity source',
                       'stack 3 of 20 gets the schedule `3,23,43 * * * *`', 'there is no default',
                       'It never holds the inputs back', 'exactly one cron period wide',
                       # Review fixes: a private CA, the pending delete, the first run.
                       'pass `--duo-ca-file PATH` with the CA\'s certificate (PEM)',
                       'The `SSL_CERT_FILE` variable is not a way in',
                       'the stack serves the endpoint the inputs are created through',
                       'no index delete is still under way', '`--duo-force` does not override this',
                       'Every one of these checks refuses on an answer it cannot read',
                       '**The first run against a stack is a dry run.**',
                       'ACS answers `404-index-not-found` for a missing index',
                       'So the rules are enabled **before** the input exists',
                       'not how far back it reads events', '`--duo-force` overrides these two',
                       '`never raised` means history was indexed while the rule was off'):
            self.assertIn(needle, flat)
        for stale in ('--duo-no-lookup-gen', 'the rule reaches back as far as the backfill',
                      'does not hide index `duo` from the Authentication data model'):
            self.assertNotIn(stale, flat)

    def test_runbook_t1_searches_are_read_only_and_name_the_findings(self):
        section = self.duo_section('T-1: is the staged Duo evidence in the stack?')
        searches = [block.split('\n```', 1)[0] for block in section.split('```spl\n')[1:]]
        self.assertEqual(len(searches), 5)
        for spl in searches:
            self.assertIsNone(duo.WRITES.search(spl), spl)
            self.assertLessEqual(len(spl), 4900)             # each fits a read-only search tool
        progress, buckets, findings, joined, application = searches
        self.assertIn('where `genai_duo_auth_events`', progress)
        self.assertIn('search identity_user="<victim>"', buckets)
        self.assertIn('"backfill", "live"', buckets)
        self.assertIn('search_name="{}"'.format(DUO_RULE), findings)
        for field in ('orig_time', 'burst_time', 'burst_id'):                     # reviewer correction 9
            self.assertIn(field, findings)
        self.assertIn('search_name="{}"'.format(CHAIN_RULE), joined)
        for field in ('orig_time', 'signin_time', 'blocked_time', 'chain_id'):
            self.assertIn(field, joined)
        # ... and whether the assistant's identity events for the victim are in the stack at all.
        self.assertTrue(application.startswith('`genai_identity_activity_events`'))
        for needle in ('`genai_identity_join_key(user)`', '`genai_identity_verified_turn`',
                       'identity_signin_success', 'search identity_key="<victim>"'):
            self.assertIn(needle, application)
        self.assertNotRegex(buckets + application, r'\bindex\s*=|\bsourcetype\s*=')     # contract macros only
        flat = re.sub(r'\s+', ' ', section)
        for needle in ("the assistant's HEC feed does not", 'nothing in the TA sends those events again',
                       'its last step (D8) says whether every burst and chain that is indexed was raised'):
            self.assertIn(needle, flat)
        # The ids the findings search prints are the ids D8 compares.
        self.assertEqual(sorted(duo.JUDGED_IDS.values()), ['burst_id', 'chain_id'])

    def test_runbook_md_and_html_say_the_same(self):
        """The .html is the rendered .md. Where Python-Markdown is missing only
        the needles are checked and the byte comparison is SKIPPED, which is
        not a pass (CLAUDE.md says so)."""
        md = text_of(REPO, 'tools', 'lab5-identity-runbook.md')
        html = text_of(REPO, 'tools', 'lab5-identity-runbook.html')
        for needle in ('--duo --duo-poll-slot', '--duo-teardown --duo-purge-data', 'DUO_LOG_FEED_SKEY',
                       'hidden prompt', '--duo-keep-data', '--duo-with-users', '--duo-with-lookup-gen',
                       '--duo-no-tls-verify', 'orig_time', 'burst_id', 'chain_id', '3,23,43 * * * *'):
            self.assertIn(needle, md)
            self.assertIn(needle, html)
        self.assertEqual(html.count('<h2 '), len(re.findall(r'^## ', md, flags=re.M)))
        claude = re.sub(r'\s+', ' ', text_of(REPO, 'CLAUDE.md'))
        self.assertIn('SKIPS elsewhere (it is not in Splunk\'s Python): a skip there is not a pass', claude)
        try:
            import markdown
        except ImportError:
            self.skipTest('Python-Markdown is not installed here: the byte comparison did not run')
        body = html[html.index('<main>') + len('<main>'):html.index('</main>')].strip()
        self.assertEqual(markdown.markdown(md, extensions=['tables', 'fenced_code', 'toc']).strip(), body)

    def test_readme_has_the_scripted_paragraph_and_says_what_ran(self):
        readme = text_of(REPO, 'README.md')
        start = readme.index('**Scripted, on a Splunk Cloud stack.**')
        # After step 7, before the section that follows the steps (reviewer correction 9).
        self.assertLess(readme.index('7. Enable the rule.'), start)
        paragraph = readme[start:readme.index('\n\n', start)]
        self.assertTrue(readme[start + len(paragraph):].startswith('\n\n### How the rule judges Duo events\n'))
        flat = re.sub(r'\s+', ' ', paragraph)
        for needle in ('`tools/show_postdeploy.py --duo` does steps 2, 3, 4 and 7', 'both rules enabled, and only '
                       'then the authentication input', '`--duo-with-users` adds the users input',
                       '`--duo-with-lookup-gen` the search of step 5', 'both are off unless asked for',
                       '`--duo-teardown` undoes all of it', 'pass it the same `--duo-attendee-role` as the setup',
                       'never from the command line',
                       "the stack's certificate is verified", '`--duo-ca-file PATH` adds the CA',
                       'the `SSL_CERT_FILE` variable is not read',
                       'Every guard in it refuses on an answer it cannot read',
                       'It never adds the identity source (step 6)',
                       'has no default: `--duo-auth-interval`, or `--duo-poll-slot K/N`',
                       'is reported, not assumed'):
            self.assertIn(needle, flat)
        release = readme[readme.index('### v1.9.0'):readme.index('### v1.8.0')]
        entry = release[release.index('- ADDED (dev tooling, review decision LR-09, 2026-11-17):'):]
        entry = re.sub(r'\s+', ' ', entry[:entry.index('\n- ', 2)])
        for needle in ('never argv, never a file', 'verifies the stack\'s certificate unless `--duo-no-tls-verify`',
                       'written as a list of minutes', 'are off unless asked for',
                       'is never read as an event-time reach', '`N of N raised`',
                       'its saved searches are the shipped stanzas',
                       '**not yet run against a Splunk Cloud stack**'):
            self.assertIn(needle, entry)
        validation = re.sub(r'\s+', ' ', release[release.index('- Validation: AppInspect'):])
        for needle in ("the stack tool's own searches (LR-09), read-only on that data",
                       'the tool itself was not run against this or any Splunk',
                       'and `tools/show_postdeploy.py --duo` against any real stack.'):
            self.assertIn(needle, validation)

    def test_claude_md_keeps_the_tools_rules(self):
        claude = re.sub(r'\s+', ' ', text_of(REPO, 'CLAUDE.md'))
        for needle in ('**The Duo stack tool** (`tools/duo_steps.py`, LR-09',
                       'never argv, never a file, never a printed line or an exception\'s text',
                       '**It reads a rule\'s schedule only through `slot_minutes`**',
                       'It never compares `dispatch.earliest_time` with the backfill',
                       'goes into `DUO_DETECTIONS` and, with the field that names one finding, into `JUDGED_IDS`',
                       'are opt-in (`--duo-with-users`, `--duo-with-lookup-gen`)',
                       '`fake_splunk_rest.py` serves the SHIPPED saved-search stanzas',
                       'is regenerated from the `.md`',
                       # What the review of the first build added.
                       'never tell an operator to set `SSL_CERT_FILE`', '`allow_abbrev=False`',
                       '**Every guard refuses on an answer it cannot read.**',
                       'Never write `if code == 200: keep ... else: delete`',
                       '**An index delete is asynchronous.**', '`--duo-force` does not override that',
                       '`WRITING_COMMANDS`', '`main_on_the_fake`', '`GuardTests`',
                       'Nothing in it has run against a real Splunk Cloud stack, ACS or Duo.'):
            self.assertIn(needle, claude)
        # ... and the code agrees with what it says.
        self.assertEqual(duo.PURGE_MARKER, 'index_delete_pending')
        self.assertIs(show_postdeploy.build_parser().allow_abbrev, False)
        self.assertIn('--duo-ca-file', show_postdeploy.build_parser().format_help())
        # The contract LR-07 wrote for other tools is still there, and the tool obeys it.
        self.assertIn('No tool or test may read it as one.', claude)

    def test_nothing_names_a_real_tenant_or_puts_a_key_on_a_command_line(self):
        for parts in ((REPO, 'tools', 'lab5-identity-runbook.md'), (REPO, 'tools', 'lab5-identity-runbook.html'),
                      (REPO, 'README.md'), (REPO, 'CLAUDE.md'), (REPO, 'tools', 'duo_steps.py'),
                      (REPO, 'tools', 'show_postdeploy.py'), (HERE, 'fake_splunk_rest.py')):
            text = text_of(*parts)
            self.assertEqual(REAL_HOST.findall(text), [], parts[-1])
            self.assertIsNone(re.search(r'--duo-(skey|secret|ikey|api-host)[ =]', text.replace(
                '--duo-skey-env', '')), parts[-1])
            self.assertIsNone(re.search(r"DUO_LOG_FEED_SKEY='[^.']", text), parts[-1])
            # No address outside loopback and the documentation ranges (RFC 5737).
            for address in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
                if parts[-1] in ('README.md', 'CLAUDE.md'):
                    continue                                  # their own tests cover them
                self.assertRegex(address, r'^(127\.0\.0\.1|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)', parts[-1])


if __name__ == '__main__':
    unittest.main()
