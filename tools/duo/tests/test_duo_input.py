# encoding=utf-8
"""
Offline tests for bin/ta_gen_ai_cim_duo_input.py against tools/duo/fake_duo.py
(which defaults to DESCENDING order, so a missing sort=ts:asc fails here):
the checkpointed window (+1 ms boundary, crash resume, empty-window skip),
429 backoff, the users allowlist snapshot, the SHC guard, credentials, the
scheme, and that no key or signature reaches a log.

    python3 -m unittest discover -s tools/duo/tests -v
"""

import io
import json
import logging
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
for _p in (os.path.join(REPO, 'bin'), os.path.join(REPO, 'lib'), os.path.dirname(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import fake_duo  # noqa: E402
import ta_gen_ai_cim_duo_api as duo_api  # noqa: E402
import ta_gen_ai_cim_duo_input as duo_input  # noqa: E402

for _name in ('ta_gen_ai_cim_duo_input', 'ta_gen_ai_cim_duo_api'):
    logging.getLogger(_name).addHandler(logging.NullHandler())   # keep test output quiet

NAME = 'ta_gen_ai_cim_duo://duo_auth'
T0 = 1700000000.0          # a fixed "now", epoch seconds
LAG_MS = 180 * 1000


class FakeAccess(object):
    def __init__(self, roles=('search_head',), server='sh1', captain='sh1', info_error=False,
                 auth_type='duo_hmac', url='https://' + fake_duo.HOST, secret=fake_duo.SKEY):
        self.roles, self.server, self.captain, self.info_error = roles, server, captain, info_error
        self._account = {'auth_type': auth_type, 'url': url, 'client_id': fake_duo.IKEY}
        self._secret = secret
        self.checkpoints, self.saves = {}, []

    def server_info(self):
        if self.info_error:
            raise IOError('splunkd unreachable')
        return {'server_roles': list(self.roles), 'serverName': self.server}

    def captain_info(self):
        return {'label': self.captain}

    def account(self, name):
        return dict(self._account)

    def secret(self, name):
        if not self._secret:
            raise duo_api.DuoError('no client_secret is stored for account "{}"'.format(name))
        return self._secret

    def load_checkpoint(self, key):
        return dict(self.checkpoints.get(key, {}))

    def save_checkpoint(self, key, state):
        self.checkpoints[key] = dict(state)
        self.saves.append(dict(state))


class Harness(object):
    def __init__(self, endpoint='authentication', **access_kw):
        self.fake = fake_duo.FakeDuo()
        self.access = FakeAccess(**access_kw)
        self.events = []
        self.sleeps = []
        self.params = {'account': 'duo', 'endpoint': endpoint, 'index': 'duo'}
        self.crash_on = None

    def write(self, data, time_s, sourcetype, index):
        record = json.loads(data)
        if self.crash_on and record.get('txid') == self.crash_on:
            self.crash_on = None
            raise RuntimeError('killed mid-page')
        self.events.append((record, time_s, sourcetype, index, data))

    def run(self, now_s, pages=1):
        return duo_input.run_input(NAME, self.params, self.access, self.write, now=lambda: now_s,
                                   sleep=self.sleeps.append, transport=self.fake.transport, pages=pages,
                                   jitter=lambda: 0.25)

    def log_requests(self):
        return [p for path, p in self.fake.requests if path.startswith('/admin/v2/logs')]

    def txids(self):
        return [e[0]['txid'] for e in self.events]


class LogWindowTests(unittest.TestCase):

    def setUp(self):
        self.h = Harness()
        self.now_ms = int(T0 * 1000)

    def test_first_window_and_sort(self):
        h = self.h
        for i in range(3):
            h.fake.add_auth(self.now_ms - 3600 * 1000 + i, 'tx-{}'.format(i))
        self.assertEqual(h.run(T0), 3)
        (req,) = h.log_requests()
        self.assertEqual(req['sort'], 'ts:asc')
        self.assertEqual(int(req['mintime']), self.now_ms - 24 * 3600 * 1000)
        self.assertEqual(int(req['maxtime']), self.now_ms - LAG_MS)
        self.assertEqual(h.txids(), ['tx-0', 'tx-1', 'tx-2'])           # oldest first
        record, time_s, sourcetype, index, data = h.events[0]
        self.assertEqual((sourcetype, index), ('ta_gen_ai_cim:duo:authentication', 'duo'))
        self.assertEqual(time_s, record['timestamp'])
        self.assertNotIn(' ', data.split('"isotimestamp"')[0])            # compact JSON
        cursor = '{},tx-2'.format(self.now_ms - 3600 * 1000 + 2)
        self.assertEqual(h.access.checkpoints[NAME], {                    # Duo's last page carries a cursor
            'mintime_ms': self.now_ms - 24 * 3600 * 1000, 'maxtime_ms': self.now_ms - LAG_MS,
            'next_offset': cursor, 'backoff_until': 0, 'updated': T0})
        self.assertEqual(h.run(T0 + 300), 0)                              # resumes after it: nothing new
        req = h.log_requests()[-1]
        self.assertEqual((int(req['mintime']), int(req['maxtime']), req['next_offset']),
                         (self.now_ms - 3600 * 1000 + 2, self.now_ms + 300 * 1000 - LAG_MS, cursor))
        self.assertEqual(h.access.checkpoints[NAME]['next_offset'], None)  # the empty page completes it
        h.run(T0 + 600)
        req = h.log_requests()[-1]
        self.assertEqual(int(req['mintime']), self.now_ms + 300 * 1000 - LAG_MS + 1)
        self.assertNotIn('next_offset', req)

    def test_plus_one_ms_boundary(self):
        # A Duo that omits next_offset on the last page completes the window at
        # once; the next window starts at maxtime + 1 because both are inclusive.
        h = self.h
        h.fake.last_page_offset = False
        maxtime1 = self.now_ms - LAG_MS
        h.fake.add_auth(maxtime1, 'at-maxtime')
        h.fake.add_auth(maxtime1 + 1, 'just-after')
        h.run(T0)
        self.assertEqual(h.txids(), ['at-maxtime'])                       # maxtime is inclusive
        self.assertIsNone(h.access.checkpoints[NAME]['next_offset'])
        h.run(T0 + 300)
        second = h.log_requests()[-1]
        self.assertEqual(int(second['mintime']), maxtime1 + 1)
        self.assertEqual(h.txids(), ['at-maxtime', 'just-after'])         # each exactly once

    def test_boundary_record_is_read_once_through_the_cursor(self):
        h = self.h                                                        # the Duo-like default
        maxtime1 = self.now_ms - LAG_MS
        h.fake.add_auth(maxtime1, 'at-maxtime')
        h.fake.add_auth(maxtime1 + 1, 'just-after')
        for step in range(4):
            h.run(T0 + step * 300)
        self.assertEqual(h.txids(), ['at-maxtime', 'just-after'])

    def test_multi_page_window_resumes_after_its_cursor(self):
        h = self.h
        start = self.now_ms - 7200 * 1000
        with mock.patch.object(duo_api, 'LOG_PAGE_LIMIT', 2):
            for i in range(5):
                h.fake.add_auth(start + i * 1000, 'tx-{}'.format(i))
            for step in range(5):
                h.run(T0 + step * 120)
        reqs = h.log_requests()
        self.assertEqual(len(reqs), 5)                                    # one Duo call per run
        self.assertNotIn('next_offset', reqs[0])
        self.assertEqual([r.get('next_offset') for r in reqs[1:4]],
                         ['{},tx-{}'.format(start + i * 1000, i) for i in (1, 3, 4)])
        self.assertEqual([int(r['mintime']) for r in reqs[1:4]], [start + i * 1000 for i in (1, 3, 4)])
        self.assertEqual([int(r['maxtime']) for r in reqs[:4]],           # maxtime follows now - lag
                         [self.now_ms + step * 120 * 1000 - LAG_MS for step in range(4)])
        self.assertEqual(int(reqs[4]['mintime']), self.now_ms + 3 * 120 * 1000 - LAG_MS + 1)
        self.assertNotIn('next_offset', reqs[4])
        self.assertEqual(h.txids(), ['tx-{}'.format(i) for i in range(5)])

    def test_crash_resume_duplicates_at_most_one_page(self):
        h = self.h
        with mock.patch.object(duo_api, 'LOG_PAGE_LIMIT', 2):
            for i in range(5):
                h.fake.add_auth(self.now_ms - 7200 * 1000 + i * 1000, 'tx-{}'.format(i))
            h.crash_on = 'tx-3'
            with self.assertRaises(RuntimeError):
                h.run(T0, pages=3)
            saved = h.access.checkpoints[NAME]
            self.assertEqual(saved['next_offset'], '{},tx-1'.format(self.now_ms - 7200 * 1000 + 1000))
            h.run(T0 + 600, pages=3)
        resumed = h.log_requests()[2]
        self.assertEqual(resumed['next_offset'], saved['next_offset'])     # resumes after the saved cursor
        self.assertEqual(int(resumed['mintime']), self.now_ms - 7200 * 1000 + 1000)
        self.assertEqual(int(resumed['maxtime']), self.now_ms + 600 * 1000 - LAG_MS)
        self.assertEqual(sorted(set(h.txids())), ['tx-{}'.format(i) for i in range(5)])
        self.assertEqual(h.txids(), ['tx-0', 'tx-1', 'tx-2', 'tx-2', 'tx-3', 'tx-4'])
        self.assertIsNone(h.access.checkpoints[NAME]['next_offset'])

    def test_missing_sort_is_caught_by_the_descending_fake(self):
        h = self.h
        for i in range(4):
            h.fake.add_auth(self.now_ms - 7200 * 1000 + i, 'tx-{}'.format(i))
        original = duo_api.DuoAdminClient.request

        def drop_sort(self_, path, params=None):
            params = dict(params or {})
            params.pop('sort', None)
            return original(self_, path, params)

        with mock.patch.object(duo_api.DuoAdminClient, 'request', drop_sort):
            h.run(T0)
        self.assertNotEqual(h.txids(), sorted(h.txids()))                 # the regression is visible

    def test_empty_window_is_skipped_without_a_call(self):
        h = self.h
        h.access.checkpoints[NAME] = {'mintime_ms': 1, 'maxtime_ms': self.now_ms - LAG_MS,
                                      'next_offset': None, 'backoff_until': 0, 'updated': T0 - 600}
        self.assertEqual(h.run(T0), 0)                                    # mintime = maxtime + 1 >= end
        self.assertEqual(h.fake.requests, [])
        self.assertEqual(h.access.saves, [])
        h.run(T0 + 0.001)                                                 # mintime == maxtime: invalid
        self.assertEqual(h.fake.requests, [])
        h.run(T0 + 0.002)                                                 # the first valid 1 ms window
        (req,) = h.log_requests()
        self.assertEqual((int(req['mintime']), int(req['maxtime'])),
                         (self.now_ms - LAG_MS + 1, self.now_ms - LAG_MS + 2))

    def test_interval_floor_holds_without_validation(self):
        h = self.h
        h.fake.add_auth(self.now_ms - 600 * 1000, 'tx-1')
        h.run(T0)
        h.run(T0 + 60)                                                    # interval = 60 in local/
        self.assertEqual(len(h.fake.requests), 1)
        h.run(T0 + 116)                                                   # scheduler jitter allowed
        self.assertEqual(len(h.fake.requests), 2)

    def test_default_index_is_left_to_splunkd(self):
        for value in ('default', '', None):
            self.assertIsNone(duo_input.parse_params({'account': 'duo', 'endpoint': 'users',
                                                      'index': value})['index'])

    def test_retention_floor_and_corrupt_checkpoint(self):
        h = self.h
        h.access.checkpoints[NAME] = {'maxtime_ms': 5, 'next_offset': None}
        h.run(T0)
        req = h.log_requests()[-1]
        self.assertEqual(int(req['mintime']), self.now_ms - duo_input.RETENTION_MS)
        h.access.checkpoints[NAME] = {'mintime_ms': 'x', 'maxtime_ms': None, 'next_offset': '1,a'}
        h.run(T0 + 300)
        self.assertNotIn('next_offset', h.log_requests()[-1])

    def test_activity_time_from_ts(self):
        h = Harness(endpoint='activity')
        h.fake.add_activity(self.now_ms - 600 * 1000 + 250, 'act-1')
        h.run(T0)
        record, time_s, sourcetype, _, _ = h.events[0]
        self.assertEqual(sourcetype, 'ta_gen_ai_cim:duo:activity')
        self.assertAlmostEqual(time_s, T0 - 600 + 0.25, places=3)


class RetentionResumeTests(unittest.TestCase):
    """A window is never abandoned while Duo still holds records it has not read."""

    def test_max_lookback_backfill_collects_every_record_once(self):
        # initial_lookback_hours = 4320 clamps the first mintime exactly to the
        # floor, and the floor moves on by 120 s before run 2. Up to 1.9.0's
        # review that run abandoned the window and skipped all but page 1.
        h = Harness()
        h.params['initial_lookback_hours'] = '4320'
        now_ms = int(T0 * 1000)
        span = 179 * 86400 * 1000
        for i in range(400):
            h.fake.add_auth(now_ms - span + i * (span // 400), 'tx-{:04d}'.format(i))
        with mock.patch.object(duo_api, 'LOG_PAGE_LIMIT', 50), \
                self.assertLogs('ta_gen_ai_cim_duo_input', level='INFO') as logs:
            for step in range(12):
                h.run(T0 + step * 120)
        self.assertEqual(int(h.log_requests()[0]['mintime']), now_ms - duo_input.RETENTION_MS)
        self.assertEqual(h.txids(), ['tx-{:04d}'.format(i) for i in range(400)])   # all, once, in order
        self.assertTrue(all('next_offset' in r for r in h.log_requests()[1:9]))
        self.assertFalse([r for r in logs.records if 'retention' in r.getMessage() and r.levelname == 'WARNING'
                          and 'passed' in r.getMessage()])

    def test_floor_overtaking_the_cursor_resumes_at_the_floor_and_skips_nothing_after_it(self):
        h = Harness()
        now_ms = int(T0 * 1000)
        floor = now_ms - duo_input.RETENTION_MS
        h.fake.add_auth(floor - 600 * 1000, 'aged-out')                 # gone from Duo by now
        h.fake.add_auth(floor + 1000, 'after-floor-1')
        h.fake.add_auth(floor + 2000, 'after-floor-2')
        h.access.checkpoints[NAME] = {'mintime_ms': floor - 7200 * 1000, 'maxtime_ms': floor + 5000,
                                      'next_offset': '{},earlier'.format(floor - 3600 * 1000),
                                      'backoff_until': 0, 'updated': T0 - 300}
        with self.assertLogs('ta_gen_ai_cim_duo_input', level='WARNING') as logs:
            h.run(T0)
        req = h.log_requests()[0]
        self.assertEqual(int(req['mintime']), floor)
        self.assertNotIn('next_offset', req)                             # the old cursor is before every record left
        self.assertEqual(h.txids(), ['after-floor-1', 'after-floor-2'])
        self.assertIn('Duo retention passed this window', '\n'.join(logs.output))

    def test_cursor_inside_retention_resumes_from_the_cursor(self):
        h = Harness()
        now_ms = int(T0 * 1000)
        floor = now_ms - duo_input.RETENTION_MS
        cursor_ms = floor + 60 * 1000
        h.fake.add_auth(cursor_ms, 'read-already')
        h.fake.add_auth(cursor_ms + 1, 'unread')
        h.access.checkpoints[NAME] = {'mintime_ms': floor - 3600 * 1000, 'maxtime_ms': floor + 7200 * 1000,
                                      'next_offset': '{},read-already'.format(cursor_ms),
                                      'backoff_until': 0, 'updated': T0 - 300}
        h.run(T0)
        req = h.log_requests()[0]
        self.assertEqual((int(req['mintime']), req['next_offset']), (cursor_ms, '{},read-already'.format(cursor_ms)))
        self.assertEqual(h.txids(), ['unread'])

    def test_unreadable_cursor_starts_a_new_window(self):
        h = Harness()
        h.access.checkpoints[NAME] = {'mintime_ms': 1699990000000, 'maxtime_ms': 1699999000000,
                                      'next_offset': 'not-a-cursor', 'backoff_until': 0, 'updated': T0 - 300}
        with self.assertLogs('ta_gen_ai_cim_duo_input', level='WARNING'):
            h.run(T0)
        req = h.log_requests()[0]
        self.assertEqual(int(req['mintime']), 1699999000001)
        self.assertNotIn('next_offset', req)

    def test_offset_ms(self):
        self.assertEqual(duo_input.offset_ms('1547486297000,5bea1c1e-612c-4f1d-b310-75fd31385b15'), 1547486297000)
        for bad in (None, '', 'x,1', ',1', '-5,a'):
            self.assertIsNone(duo_input.offset_ms(bad))


class NextOffsetTests(unittest.TestCase):
    """Duo returns a next_offset on the last page with records too."""

    def stream(self, fake, runs=30, per_run=100, every=1):
        """runs runs 120 s apart; before a run, when step % every == 0, Duo gains
        per_run auths spread over the last 120 s. A backlog older than the lag
        is there from the start. Returns (harness, records per Duo call, the
        txids due by the last run's maxtime)."""
        h = Harness()
        h.fake = fake
        h.params['initial_lookback_hours'] = '1'
        n = 0
        for k in range(per_run):
            n += 1
            fake.add_auth(int((T0 - 900 + k * 1.2) * 1000), 'tx-{:06d}'.format(n))
        calls = []
        for step in range(runs):
            t = T0 + step * 120
            if step % every == 0:
                for k in range(per_run):
                    n += 1
                    fake.add_auth(int((t - 120 + k * 1.2) * 1000), 'tx-{:06d}'.format(n))
            before, reqs = len(h.events), len(fake.requests)
            h.run(t)
            self.assertLessEqual(len(fake.requests) - reqs, 1)              # never more than one Duo call a run
            if len(fake.requests) > reqs:
                calls.append(len(h.events) - before)
        cutoff = int((T0 + (runs - 1) * 120) * 1000) - LAG_MS
        due = sorted(txid for ts, txid, _ in fake.auth_logs if ts <= cutoff)
        return h, calls, due

    def test_a_cursor_on_the_last_page_costs_no_extra_run(self):
        # Up to 1.9.0's review a window closed only on a null next_offset, so
        # against a real Duo every other call came back empty.
        h, calls, due = self.stream(fake_duo.FakeDuo())
        self.assertEqual(len(calls), 30)                                 # one Duo call per run
        self.assertEqual([c for c in calls if c == 0], [])                # and none of them came back empty
        self.assertEqual(sorted(h.txids()), due)
        self.assertEqual(len(h.txids()), len(set(h.txids())))

    def test_an_echoed_next_offset_never_stalls_the_input(self):
        # Quiet spells give empty pages, which this Duo answers with the
        # next_offset it was sent; up to the review that held one window forever.
        h, calls, due = self.stream(fake_duo.FakeDuo(echo_offset=True), every=3)
        self.assertIn(0, calls)                                          # the echo case was exercised
        self.assertEqual(sorted(h.txids()), due)
        self.assertEqual(len(h.txids()), len(set(h.txids())))
        state = h.access.checkpoints[NAME]
        self.assertGreaterEqual(state['maxtime_ms'], int((T0 + 29 * 120) * 1000) - LAG_MS)

    def test_echo_on_an_empty_page_completes_the_window(self):
        h = Harness()
        h.fake = fake_duo.FakeDuo(echo_offset=True)
        h.fake.add_auth(int(T0 * 1000) - 600 * 1000, 'tx-1')
        h.run(T0)
        cursor = h.access.checkpoints[NAME]['next_offset']
        self.assertTrue(cursor)
        h.run(T0 + 300)                                                  # empty page, cursor echoed back
        self.assertEqual(h.log_requests()[-1]['next_offset'], cursor)
        self.assertIsNone(h.access.checkpoints[NAME]['next_offset'])
        h.run(T0 + 600)
        self.assertNotIn('next_offset', h.log_requests()[-1])
        self.assertEqual(h.txids(), ['tx-1'])

    def test_an_echo_with_records_closes_the_window_with_a_warn(self):
        class EchoingDuo(fake_duo.FakeDuo):
            def _logs(self, store, params, key, as_list):
                status, text, headers = super(EchoingDuo, self)._logs(store, params, key, as_list)
                body = json.loads(text)
                if params.get('next_offset') and body['response'][key]:
                    body['response']['metadata']['next_offset'] = params['next_offset'].split(',', 1)
                return status, json.dumps(body), headers

        h = Harness()
        h.fake = EchoingDuo()
        now_ms = int(T0 * 1000)
        with mock.patch.object(duo_api, 'LOG_PAGE_LIMIT', 2):
            for i in range(4):
                h.fake.add_auth(now_ms - 3600 * 1000 + i, 'tx-{}'.format(i))
            h.run(T0)
            with self.assertLogs('ta_gen_ai_cim_duo_input', level='WARNING') as logs:
                h.run(T0 + 300)
            h.run(T0 + 600)
        self.assertIn('returned the next_offset it was sent', '\n'.join(logs.output))
        self.assertEqual(h.txids(), ['tx-0', 'tx-1', 'tx-2', 'tx-3'])
        last = h.log_requests()[-1]
        self.assertNotIn('next_offset', last)                            # a new window, never the echo again
        self.assertEqual(int(last['mintime']), now_ms + 300 * 1000 - LAG_MS + 1)


class UrlNeverEchoedTests(unittest.TestCase):

    def test_a_secret_pasted_into_url_never_reaches_a_log(self):
        pasted = 'FakeSkeyAbCdEfGhIjKlMnOpQrStUvWxYz012345'                # invented, key-shaped
        for url in (pasted, 'https://' + pasted, 'https://' + pasted + '.corp.test'):
            with self.subTest(url=url):
                stream = io.StringIO()
                handler = logging.StreamHandler(stream)
                handler.setLevel(logging.DEBUG)
                loggers = [logging.getLogger(n) for n in ('ta_gen_ai_cim_duo_input', 'ta_gen_ai_cim_duo_api', '')]
                old = [(lg, lg.level) for lg in loggers]
                for lg in loggers:
                    lg.addHandler(handler)
                    lg.setLevel(logging.DEBUG)
                try:
                    h = Harness(url=url)
                    h.run(T0)
                finally:
                    for lg, level in old:
                        lg.removeHandler(handler)
                        lg.setLevel(level)
                text = stream.getvalue()
                self.assertIn('is not a Duo Admin API hostname', text)
                self.assertEqual(h.fake.requests, [])
                self.assertNotIn(pasted.lower(), text.lower())


class BackoffTests(unittest.TestCase):

    def test_429_backs_off_exponentially_and_keeps_the_window(self):
        h = Harness()
        window = {'mintime_ms': 1699990000000, 'maxtime_ms': 1699999000000, 'next_offset': '1699995000000,tx',
                  'backoff_until': 0, 'updated': T0 - 120}
        h.access.checkpoints[NAME] = dict(window)
        h.fake.queue_failure(429, 42901)
        self.assertEqual(h.run(T0), 0)
        state = h.access.checkpoints[NAME]
        self.assertEqual(state['backoff_until'], T0 + 120)
        for key in ('mintime_ms', 'maxtime_ms', 'next_offset'):
            self.assertEqual(state[key], window[key])
        calls = len(h.fake.requests)
        h.run(T0 + 60)                                                    # still backing off
        self.assertEqual(len(h.fake.requests), calls)
        h.fake.queue_failure(429, 42901)
        h.run(T0 + 121)
        self.assertEqual(h.access.checkpoints[NAME]['backoff_until'], T0 + 121 + 240)
        h.fake.queue_failure(400, 42901, headers={'Retry-After': '3000'})
        h.run(T0 + 1000)
        self.assertEqual(h.access.checkpoints[NAME]['backoff_until'], T0 + 1000 + 3000)
        h.run(T0 + 5000)
        self.assertEqual(h.access.checkpoints[NAME]['backoff_until'], 0)  # success resets it
        self.assertEqual(h.log_requests()[-1]['next_offset'], window['next_offset'])

    def test_backoff_is_capped(self):
        state = {'backoff_until': T0 + 3000, 'updated': T0}
        self.assertEqual(duo_input.next_backoff_until(state, T0 + 4000), T0 + 4000 + 3600)


class UsersSnapshotTests(unittest.TestCase):

    ALLOWED = set(duo_input.USER_SCALAR_FIELDS) | {'aliases', 'groups', 'snapshot_id',
                                                     'snapshot_total', 'snapshot_seq'}

    def user(self, i):
        return {'user_id': 'DUFAKE{:014d}'.format(i), 'username': 'user{}'.format(i),
                'realname': 'User {}'.format(i), 'firstname': 'User', 'lastname': str(i),
                'email': 'user{}@corp.test'.format(i), 'status': 'active', 'is_enrolled': True,
                'created': 1600000000, 'last_login': None, 'alias1': 'u{}'.format(i), 'alias2': None,
                'aliases': {'alias1': 'u{}'.format(i)},
                'groups': [{'name': 'Lab', 'group_id': 'DGFAKE', 'desc': 'x', 'mobile_otp_enabled': False}],
                'phones': [{'number': '+15550100', 'phone_id': 'DPFAKE'}], 'tokens': [{'serial': '1'}],
                'u2ftokens': [{'registration_id': 'x'}], 'webauthncredentials': [{'label': 'key'}],
                'desktop_authenticators': [{'dakey': 'x'}], 'desktoptokens': [{'name': 'x'}],
                'notes': 'free text', 'lockout_reason': None, 'is_enrolled_extra': 1}

    def test_allowlist_snapshot_across_pages(self):
        h = Harness(endpoint='users')
        h.fake.users = [self.user(i) for i in range(5)] + [self.user(4)]   # Duo repeating one
        with mock.patch.object(duo_api, 'USERS_PAGE_LIMIT', 2):
            self.assertEqual(h.run(T0), 5)
        self.assertEqual(len(h.sleeps), 2)                                # a pause between pages
        ids = set()
        for seq, (record, time_s, sourcetype, _, _) in enumerate(h.events, 1):
            self.assertLessEqual(set(record), self.ALLOWED)
            self.assertEqual((record['snapshot_total'], record['snapshot_seq']), (5, seq))
            self.assertEqual(record['groups'], [{'name': 'Lab'}])
            self.assertEqual((time_s, sourcetype), (T0, 'ta_gen_ai_cim:duo:user'))
            ids.add(record['snapshot_id'])
        self.assertEqual(ids, {'duo-users-{}'.format(int(T0 * 1000))})
        self.assertNotIn('phones', json.dumps([e[0] for e in h.events]))
        self.assertNotIn('+15550100', ''.join(e[4] for e in h.events))

    def test_page_cap_never_writes_a_partial_snapshot(self):
        h = Harness(endpoint='users')
        h.fake.users = [self.user(i) for i in range(5)]
        with mock.patch.object(duo_api, 'USERS_PAGE_LIMIT', 2), mock.patch.object(duo_input, 'MAX_USER_PAGES', 2):
            self.assertEqual(h.run(T0), 0)
        self.assertEqual(h.events, [])

    def snapshot(self, failures, users=5):
        """Run one users snapshot (pages of 2) with failures = {request number: (status, code, headers)}."""
        h = Harness(endpoint='users')
        h.fake.users = [self.user(i) for i in range(users)]
        for at, (status, code, headers) in failures.items():
            h.fake.queue_failure(status, code, headers=headers, at_request=at)
        with mock.patch.object(duo_api, 'USERS_PAGE_LIMIT', 2):
            written = h.run(T0)
        return h, written

    def test_a_page_that_answers_429_once_is_retried_and_the_snapshot_completes(self):
        h, written = self.snapshot({2: (429, 42901, None)})
        self.assertEqual(written, 5)
        self.assertEqual([e[0]['snapshot_seq'] for e in h.events], [1, 2, 3, 4, 5])
        self.assertEqual({e[0]['snapshot_total'] for e in h.events}, {5})
        self.assertEqual([p['offset'] for path, p in h.fake.requests], ['0', '2', '2', '4'])
        retry_waits = [s for s in h.sleeps if s != duo_input.USERS_PAGE_PAUSE_SECONDS]
        self.assertEqual(retry_waits, [1.25])                              # 1 s + the stubbed jitter
        self.assertEqual(h.access.checkpoints[NAME]['backoff_until'], 0)

    def test_transient_errors_back_off_exponentially_and_honour_retry_after(self):
        h, written = self.snapshot({2: (503, 50000, None), 3: (500, 50000, None),
                                    4: (429, 42901, {'Retry-After': '30'})})
        self.assertEqual(written, 5)
        retry_waits = [s for s in h.sleeps if s != duo_input.USERS_PAGE_PAUSE_SECONDS]
        self.assertEqual(retry_waits, [1.25, 2.25, 30.0])                 # 1, 2, then Retry-After over 4

    def test_a_page_still_failing_after_every_retry_writes_nothing(self):
        failures = dict((n, (429, 42901, None)) for n in range(2, 2 + duo_input.USERS_RETRIES_PER_PAGE + 1))
        h, written = self.snapshot(failures)
        self.assertEqual((written, h.events), (0, []))
        retry_waits = [s for s in h.sleeps if s != duo_input.USERS_PAGE_PAUSE_SECONDS]
        self.assertEqual(retry_waits, [1.25, 2.25, 4.25, 8.25, 16.25, 32.25])
        self.assertEqual(h.access.checkpoints[NAME]['backoff_until'], T0 + 120)   # then the run backs off

    def test_retry_waits_stay_within_the_snapshot_budget(self):
        h, written = self.snapshot({2: (429, 42901, {'Retry-After': '600'})})
        self.assertEqual((written, h.events), (0, []))                    # 600 s is over the 120 s budget
        self.assertEqual([s for s in h.sleeps if s != duo_input.USERS_PAGE_PAUSE_SECONDS], [])
        self.assertEqual(h.access.checkpoints[NAME]['backoff_until'], T0 + 600)
        failures = dict((n, (503, 50000, None)) for n in range(2, 40))
        with mock.patch.object(duo_input, 'USERS_RETRY_BUDGET_SECONDS', 10.0):
            h, written = self.snapshot(failures)
        self.assertEqual((written, h.events), (0, []))
        self.assertLessEqual(sum(s for s in h.sleeps if s != duo_input.USERS_PAGE_PAUSE_SECONDS), 10.0)

    def test_a_permanent_error_is_not_retried(self):
        h, written = self.snapshot({2: (401, 40103, None)})
        self.assertEqual((written, h.events), (0, []))
        self.assertEqual(len(h.fake.requests), 2)
        self.assertEqual([s for s in h.sleeps if s != duo_input.USERS_PAGE_PAUSE_SECONDS], [])


class GuardAndCredentialTests(unittest.TestCase):

    def test_shc_guard(self):
        cases = [({}, 1), ({'roles': ('shc_member',), 'server': 'sh1', 'captain': 'sh1'}, 1),
                 ({'roles': ('shc_member',), 'server': 'sh2', 'captain': 'sh1'}, 0),
                 ({'info_error': True}, 0)]
        for kw, calls in cases:
            with self.subTest(kw=kw):
                h = Harness(**kw)
                with self.assertLogs('ta_gen_ai_cim_duo_input', level='INFO') as logs:
                    h.run(T0)
                self.assertEqual(len(h.fake.requests), calls)
                if kw.get('info_error'):
                    self.assertTrue(any(r.levelname == 'WARNING' for r in logs.records))
                if calls == 0:
                    self.assertEqual(h.access.saves, [])

    def test_credentials(self):
        for kw, message in (({'auth_type': 'basic'}, 'auth_type = duo_hmac'),
                            ({'url': 'http://' + fake_duo.HOST}, 'https'),
                            ({'secret': ''}, 'no client_secret')):
            with self.subTest(kw=kw):
                h = Harness(**kw)
                with self.assertLogs('ta_gen_ai_cim_duo_input', level='ERROR') as logs:
                    h.run(T0)
                self.assertEqual(h.fake.requests, [])
                self.assertIn(message, '\n'.join(logs.output))

    def test_no_key_signature_or_header_in_any_log(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setLevel(logging.DEBUG)
        loggers = [logging.getLogger(n) for n in ('ta_gen_ai_cim_duo_input', 'ta_gen_ai_cim_duo_api', '')]
        old = [(lg, lg.level) for lg in loggers]
        for lg in loggers:
            lg.addHandler(handler)
            lg.setLevel(logging.DEBUG)
        seen = []
        try:
            h = Harness()
            h.fake.add_auth(int(T0 * 1000) - 600000, 'tx-1')
            h.run(T0)                                     # success
            h.fake.queue_failure(429, 42901)
            h.run(T0 + 600)                               # rate limited
            seen += h.fake.auth_headers
            bad = Harness(secret='a-different-fake-secret')
            bad.run(T0)                                   # Duo answers 401
            seen += bad.fake.auth_headers
            out, err = io.StringIO(), io.StringIO()
            from splunklib.modularinput.event_writer import EventWriter
            from splunklib.modularinput.input_definition import InputDefinition
            definition = InputDefinition()
            definition.metadata = {'server_uri': 'https://127.0.0.1:8089', 'session_key': 'fake-session-key'}
            definition.inputs = {NAME: dict(h.params)}
            with mock.patch.object(duo_input.SplunkAccess, 'from_metadata', return_value=h.access), \
                    mock.patch.object(duo_api, 'urllib_transport', h.fake.transport):
                duo_input.DuoInput().stream_events(definition, EventWriter(out, err))
            seen += h.fake.auth_headers
        finally:
            for lg, level in old:
                lg.removeHandler(handler)
                lg.setLevel(level)
        text = stream.getvalue() + err.getvalue()
        self.assertIn('rate limit', text)
        self.assertIn('HTTP 401', text)
        forbidden = [fake_duo.IKEY, fake_duo.SKEY, 'a-different-fake-secret', 'Authorization', 'Basic ',
                     'fake-session-key'] + [s for s in seen if s]
        for secret in forbidden:
            self.assertNotIn(secret, text)
        for header in seen:
            import base64
            signature = base64.b64decode(header.split(' ', 1)[1]).decode('ascii').split(':', 1)[1]
            self.assertNotIn(signature, text)


class SchemeTests(unittest.TestCase):

    def test_scheme_arguments(self):
        xml = duo_input.DuoInput().get_scheme().to_xml()
        args = dict((a.get('name'), a) for a in xml.iter('arg'))
        self.assertEqual(set(args), {'account', 'endpoint', 'lag_seconds', 'initial_lookback_hours'})
        for name in ('account', 'endpoint'):
            self.assertEqual(args[name].findtext('required_on_create'), 'true')
        self.assertEqual(xml.findtext('use_external_validation'), 'true')
        self.assertEqual(xml.findtext('use_single_instance'), 'false')

    def test_validation(self):
        ok = {'account': 'duo', 'endpoint': 'users', 'interval': '86400'}
        self.assertEqual(duo_input.parse_params(ok, check_interval=True)['lag_seconds'], 180)
        self.assertEqual(duo_input.parse_params(dict(ok, interval='*/5 * * * *'), True)['endpoint'], 'users')
        for bad in ({'endpoint': 'telephony'}, {'lag_seconds': '60'}, {'lag_seconds': 'x'},
                    {'interval': '60'}, {'initial_lookback_hours': '5000'}, {'account': '../x'},
                    {'index': 'gen_ai_log'},
                    {'account': ''}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    duo_input.parse_params(dict(ok, **bad), check_interval=True)

    def test_iso8601_on_every_runtime(self):
        for text, expected in (('2023-11-14T22:13:20+00:00', T0), ('2023-11-14T22:13:20.5Z', T0 + 0.5),
                               ('2023-11-14T22:13:20.123456789+0000', T0 + 0.123456),
                               ('2023-11-15T00:13:20.25+02:00', T0 + 0.25)):
            self.assertAlmostEqual(duo_input.parse_iso8601(text), expected, places=5)
        self.assertIsNone(duo_input.parse_iso8601('yesterday'))

    def test_no_splunklib_name_collisions(self):
        with open(os.path.join(REPO, 'bin', 'ta_gen_ai_cim_duo_input.py')) as handle:
            source = handle.read()
        self.assertNotIn('self.service =', source)
        for name in ('_service', '_input_definition'):
            self.assertFalse(hasattr(duo_input.DuoInput, name) and callable(getattr(duo_input.DuoInput, name)))
        self.assertNotRegex(source, r'(?m)^\s*(import|from)\s+\S*(soar_apps|pseudoco_identity)')


class SplunkAccessTests(unittest.TestCase):
    """SplunkAccess over a stand-in for splunklib's Service."""

    def make(self):
        from splunklib.binding import HTTPError
        docs = {}

        class Resp(object):
            def __init__(self, status, payload=b''):
                self.status, self.reason, self.headers = status, 'x', []
                self.body = io.BytesIO(payload)

        class Data(object):
            def query_by_id(self, key):
                if key not in docs:
                    raise HTTPError(Resp(404))
                return dict(docs[key])

            def update(self, key, body):
                if key not in docs:
                    raise HTTPError(Resp(404))
                docs[key] = json.loads(body)

            def insert(self, body):
                doc = json.loads(body)
                docs[doc['_key']] = doc

        class Cred(object):
            content = {'clear_password': fake_duo.SKEY}

        class Service(object):
            kvstore = {duo_input.COLLECTION: type('C', (), {'data': Data()})()}
            confs = {'ta_gen_ai_cim_account': {'duo': type('S', (), {'content': {'auth_type': 'duo_hmac'}})()}}
            storage_passwords = {'ta_gen_ai_cim_account__duo:client_secret:': Cred()}

            def get(self, path, output_mode=None):
                body = {'server/info': {'entry': [{'content': {'server_roles': ['shc_member'],
                                                               'serverName': 'sh1'}}]},
                        'shcluster/captain/info': {'entry': [{'content': {'label': 'sh1'}}]}}[path]
                return type('R', (), {'body': io.BytesIO(json.dumps(body).encode('utf-8'))})()

        return duo_input.SplunkAccess(Service()), docs

    def test_checkpoint_round_trip(self):
        access, docs = self.make()
        self.assertEqual(access.load_checkpoint(NAME), {})
        access.save_checkpoint(NAME, {'maxtime_ms': 5})                    # insert
        access.save_checkpoint(NAME, {'maxtime_ms': 6})                    # update
        self.assertEqual(docs[NAME], {'maxtime_ms': 6, '_key': NAME})
        self.assertEqual(access.load_checkpoint(NAME)['maxtime_ms'], 6)

    def test_account_secret_and_captain(self):
        access, _ = self.make()
        self.assertEqual(access.account('duo')['auth_type'], 'duo_hmac')
        self.assertEqual(access.secret('duo'), fake_duo.SKEY)
        with self.assertRaises(duo_api.DuoError):
            access.secret('other')
        with self.assertRaises(duo_api.DuoError):
            access.account('other')
        self.assertEqual(duo_input.shc_poll_decision(access), (True, 'search head cluster captain'))


if __name__ == '__main__':
    unittest.main()
