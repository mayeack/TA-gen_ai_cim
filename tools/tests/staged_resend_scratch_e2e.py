#!/usr/bin/env python3
# encoding=utf-8
"""
staged_resend_scratch_e2e.py - the re-send contract of tools/staged_resend.py
on a real splunkd and a real HEC: a DEV Splunk on this machine and a SCRATCH
index, nothing else. Opt-in, never part of the unit tests, never a room stack.

The offline suite proves the tool against a fake. This proves what no fake
can: that HEC stores the text of a re-send line byte for byte (sha256), keeps
the digits of its time, indexes the three label fields with no fields.conf
stanza, and that the presence, label, identity and rule searches read the
copies. It sends the lines of fixtures/staged_resend_golden.json (invented
persona data; ids that exist in no index) in the tool's own order: one canary,
then the rest once the canary is back identical.

    export STAGED_RESEND_SCRATCH_E2E=1                 # the opt-in
    export SPLUNK_TEST_URL=https://127.0.0.1:8090      # your dev splunkd
    read -rs SPLUNK_TEST_PASSWORD && export SPLUNK_TEST_PASSWORD   # or SPLUNK_TEST_TOKEN
    export SCRATCH_HEC_URL=https://127.0.0.1:8088
    read -rs SCRATCH_HEC_TOKEN && export SCRATCH_HEC_TOKEN         # may write rs_scratch_*
    python3 tools/tests/staged_resend_scratch_e2e.py plan          # contacts nothing
    python3 tools/tests/staged_resend_scratch_e2e.py send
    python3 tools/tests/staged_resend_scratch_e2e.py verify

It refuses: no opt-in; a splunkd or HEC host that is not loopback; an index
not named rs_scratch_*, or one the TA's macros read; a Splunk Cloud instance;
an index that holds anyone else's events; a fixture id found anywhere else.
It creates no index and deletes nothing: create rs_scratch_copy (and
rs_scratch_source for `originals`) on the dev Splunk yourself, and remove them
when done. A sent event cannot be taken back. The dev Splunk must run this
branch's TA: the searches use its props and macros, and the rule text and the
two index macros are read from this checkout's default/ (a checkout without
the joined rule's stanza is refused, not skipped).

Why it does not call `staged_resend.py send`: that command refuses a bundle of
the Splunk it came from (R3) and an index the stack's macros do not read, both
on purpose. So this script sends resend_line() of the fixture generator, which
the offline suite pins the tool's own line to, and runs the searches with the
scratch index written in place of the two macros that fix an index (the way
lab5_scratch_e2e.py does), because `genai_identity_ai_events` and
`genai_duo_index` would read gen_ai_log and duo and pass on events that are
not the copy. `originals` seeds a second scratch index with the assistant's
own lines so that the real `staged_resend.py export` can be run against it,
and `bundle` checks the file that export wrote.

Exit: 0 ok, 1 a check failed, 2 refused or usage, 3 delivery unknown.
"""
import argparse
import base64
import http.client
import io
import json
import os
import re
import ssl
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, 'fixtures'), HERE]      # the generator, and test_lab5_conf for read_conf
import staged_resend_gen as gen  # noqa: E402  (never run as a script here: it only reads the golden file)

OPT_IN = 'STAGED_RESEND_SCRATCH_E2E'
SCRATCH = re.compile(r'^rs_scratch_[a-z0-9_]{1,40}$')
LOOPBACK = ('127.0.0.1', 'localhost', '::1')
RULE = 'AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule'
DUO_SOURCETYPE = 'ta_gen_ai_cim:duo:authentication'
DUO_HOST, DUO_SOURCE = 'rs-scratch-duo', 'staged-resend-scratch-e2e'
RULE_REACH_DAYS = 181          # the rule's own event-time reach (earliest=-181d@d in its text)
POLL_SECONDS = 10
# Every search runs over this range: the fixture has fixed dates. A relative time, so that the rule's own
# subsearches get an ordinary epoch for the index time they ask for.
ALL_TIME = '-10y'


class Refused(Exception):
    """Exit 2: this script will not do that."""


class Failed(Exception):
    """Exit 1: a check did not hold."""


class Unknown(Exception):
    """Exit 3: a request may or may not have been taken; nothing more is sent."""


def endpoint(name):
    """(scheme, host, port, path) of the URL in environment variable `name`,
    which must be on this machine."""
    parts = urllib.parse.urlsplit(os.environ.get(name, ''))
    if parts.scheme not in ('https', 'http') or parts.hostname not in LOOPBACK:
        raise Refused('{} must be an http(s) URL on 127.0.0.1, localhost or ::1: this script only talks to a '
                      'dev Splunk on this machine'.format(name))
    return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == 'https' else 80), parts.path


def scratch_index(name, macros):
    """`name`, if it is a scratch index that nothing in the TA reads."""
    fixed = ' '.join(macros[macro]['definition'] for macro in ('genai_identity_ai_events', 'genai_duo_index'))
    if not SCRATCH.match(name) or re.search(r'index\s*=\s*"?{}\b'.format(re.escape(name)), fixed):
        raise Refused('index {!r}: only an index named rs_scratch_<name> that no TA macro reads'.format(name))
    return name


def shipped(name):
    """default/<name> of this checkout as {stanza: {key: value}}."""
    from test_lab5_conf import read_conf
    return read_conf(name)


def inline(text, index, macros):
    """`text` with the two macros that fix an index replaced by the scratch
    index, through the shipped definitions and nothing else."""
    events, duo_index = macros['genai_identity_ai_events']['definition'], macros['genai_duo_index']['definition']
    if events.count('index=gen_ai_log') != 1 or duo_index.strip() != 'index=duo':
        raise Refused('genai_identity_ai_events or genai_duo_index no longer fixes its index the way this '
                      'script replaces it: re-read both and this function')
    here = 'index="{}"'.format(index)
    bodies = {'genai_identity_ai_events': events.replace('index=gen_ai_log', here)}
    bodies['genai_identity_activity_events'] = macros['genai_identity_activity_events']['definition'].replace(
        '`genai_identity_ai_events`', bodies['genai_identity_ai_events'])
    bodies['genai_duo_auth_events'] = macros['genai_duo_auth_events']['definition'].replace('`genai_duo_index`', here)
    for name in ('genai_identity_activity_events', 'genai_duo_auth_events', 'genai_identity_ai_events'):
        if '|' in bodies[name]:
            raise Refused('macro {} now holds a pipe: it cannot be written into a search term'.format(name))
        text = text.replace('`{}`'.format(name), bodies[name])
    if re.search(r'index\s*=\s*"?(gen_ai_log|duo)\b|`genai_duo_index`', text):
        raise Refused('the text would still read gen_ai_log or duo after the scratch index was written in')
    return text


def rule_text(savedsearches):
    """The joined rule's search as shipped, on one line. A checkout without the
    stanza is an error, never a skipped check."""
    if RULE not in savedsearches:
        raise Refused('default/savedsearches.conf has no [{}]: this script needs the commit that adds the '
                      'joined rule underneath it'.format(RULE))
    return savedsearches[RULE]['search'].replace('\n', ' ')


def quoted(values, joiner):
    return joiner.join('"{}"'.format(value) for value in values)


def searches(index, macros, savedsearches, ids, story_ids, txids, bundle_id=gen.BUNDLE_ID):
    """{name: search text}: spec 3.9 with the scratch index written in. P1 asks
    for every id sent, E1 for the eight of the story (the splice texts are no
    part of it). P1 leaves out the TA's own response-action records, which
    copy a turn's event_id (review finding splunk-p1-counts-response-action-record)."""
    own_id = 'eval rs_id=coalesce(spath(_raw, "audit_id"), spath(_raw, "escalation_id"), spath(_raw, "event_id"))'
    ai, duo = inline('`genai_identity_ai_events`', index, macros), inline('`genai_duo_auth_events`', index, macros)
    return {
        'P1': 'index="{0}" sourcetype!="ai_cim:response:*" ({1}) | {2} | search rs_id IN ({3}) '
              '| eval rs_sha256=sha256(_raw), rs_time=printf("%.3f", _time), rs_time_text=tostring(_time), '
              'rs_log_type=coalesce(mvjoin(log_type, ","), "none"), '
              'rs_bundle=coalesce(mvjoin(resend_bundle, ","), "none") '
              '| stats count as copies, values(rs_sha256) as sha256, values(rs_time) as time, '
              'values(rs_time_text) as time_text, values(host) as host, values(source) as source, '
              'values(sourcetype) as sourcetype, values(index) as index, values(rs_log_type) as log_type, '
              'values(rs_bundle) as resend_bundle, min(_indextime) as first_indexed, '
              'max(_indextime) as last_indexed by rs_id'.format(index, quoted(ids, ' OR '), own_id, quoted(ids, ', ')),
        'P2': '| tstats count as events, dc(resend_orig_indextime) as orig_indextimes where index="{}" resend="true" '
              'resend_bundle="{}" by sourcetype, log_type, host'.format(index, bundle_id),
        'E1': '{0} ({1}) | {2} | search rs_id IN ({3}) | eval identity_key=`genai_identity_join_key(user)`, '
              'turn=if(`genai_identity_verified_turn`, 1, 0), '
              'blocked=if(turn==1 AND \'gen_ai.policy.blocked\'=="true", 1, 0), '
              'signin=if(\'gen_ai.audit.action\'=="identity_signin_success", 1, 0), '
              'identity_event=if(\'gen_ai.identity.verified\'=="true" OR like(\'gen_ai.audit.action\', "identity_%"), 1, 0) '
              '| stats dc(rs_id) as events, count as copies, sum(identity_event) as identity_events, '
              'sum(turn) as ai_turns, sum(blocked) as ai_blocked, sum(signin) as app_signins '
              'by identity_key'.format(ai, quoted(story_ids, ' OR '), own_id, quoted(story_ids, ', ')),
        'D1': '{0} ({1}) | eval rs_txid=mvindex(txid, 0), identity_user=`genai_identity_join_key(user)` '
              '| search rs_txid IN ({2}) | stats count as copies, values(action) as action, '
              'values(identity_user) as identity_user by rs_txid | stats count as txids_found, '
              'sum(eval(if(copies==1, 1, 0))) as found_once, values(action) as action, '
              'values(identity_user) as identity_user'.format(duo, quoted(txids, ' OR '), quoted(txids, ', ')),
        'V5': inline(rule_text(savedsearches), index, macros) + ' | table chain_id, user, _time, blocked_turns, '
              'duo_failures_10m, duo_app, signin_duo, guardrails',
    }


def connect(scheme, host, port, timeout):
    """A connection to this machine. The certificate of a dev Splunk is
    self-signed, so it is not verified; endpoint() has made sure the host is
    loopback. http.client follows no redirect, so no header leaves for another
    origin (review finding secrets-003)."""
    if scheme == 'http':
        return http.client.HTTPConnection(host, port, timeout=timeout)
    context = ssl.create_default_context()
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    return http.client.HTTPSConnection(host, port, timeout=timeout, context=context)


def dispatch_text(spl):
    """`spl` as splunkd takes it: a text that starts with a pipe as it is, any
    other with `search ` in front (a generating command after `search` is FATAL)."""
    return spl if spl.lstrip().startswith('|') else 'search ' + spl


def as_list(value):
    """A result value as a list of strings: splunkd gives a bare string for one
    value, a list for several, and leaves the key out for none."""
    if value is None:
        return []
    return [str(item) for item in value] if isinstance(value, list) else [str(value)]


class Splunkd(object):
    """Read-only searches on the dev splunkd named by SPLUNK_TEST_URL."""

    def __init__(self):
        self.scheme, self.host, self.port, _ = endpoint('SPLUNK_TEST_URL')
        self.app = os.environ.get('SPLUNK_TEST_APP', 'TA-gen_ai_cim')
        if os.environ.get('SPLUNK_TEST_TOKEN'):
            self.auth = 'Bearer ' + os.environ['SPLUNK_TEST_TOKEN']
        elif os.environ.get('SPLUNK_TEST_PASSWORD'):
            pair = '{}:{}'.format(os.environ.get('SPLUNK_TEST_USER', 'admin'), os.environ['SPLUNK_TEST_PASSWORD'])
            self.auth = 'Basic ' + base64.b64encode(pair.encode('utf-8')).decode('ascii')
        else:
            raise Refused('set SPLUNK_TEST_PASSWORD (with SPLUNK_TEST_USER, default admin) or SPLUNK_TEST_TOKEN')

    def call(self, method, path, form=None):
        conn = connect(self.scheme, self.host, self.port, 180)
        headers = {'Authorization': self.auth, 'Connection': 'close'}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form).encode('utf-8')
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            return response.status, response.read().decode('utf-8', 'replace')
        except (OSError, http.client.HTTPException) as error:
            raise Failed('splunkd did not answer {} ({})'.format(path.split('?')[0], type(error).__name__))
        finally:
            conn.close()

    def info(self):
        status, text = self.call('GET', '/services/server/info?output_mode=json')
        if status != 200:
            raise Failed('GET server/info answered HTTP {} (401: wrong account or password)'.format(status))
        return json.loads(text)['entry'][0]['content']

    def search(self, spl, earliest=None, latest=None):
        """The rows of one oneshot search. FATAL or ERROR fails; a WARN is
        retried twice, because splunkd warns about a slow dispatch on a busy
        box and that says nothing about the rows."""
        form = {'search': dispatch_text(spl), 'output_mode': 'json',
                'exec_mode': 'oneshot', 'count': 0}
        form.update({key: value for key, value in (('earliest_time', earliest), ('latest_time', latest))
                     if value is not None})
        path = '/servicesNS/nobody/{}/search/jobs'.format(urllib.parse.quote(self.app))
        for attempt in range(3):
            status, text = self.call('POST', path, form)
            try:
                answer = json.loads(text)
            except ValueError:
                answer = {}
            messages = [(str(message.get('type', '')).upper(), str(message.get('text', ''))[:300])
                        for message in answer.get('messages') or [] if isinstance(message, dict)]
            if status != 200 or any(kind in ('FATAL', 'ERROR') for kind, _ in messages):
                raise Failed('a search answered HTTP {}: {}'.format(status, messages or 'no message'))
            warnings = [text for kind, text in messages if kind == 'WARN']
            if not warnings:
                return answer.get('results') or []
            time.sleep(5)
        raise Failed('a search still came back with a warning after three tries: {}'.format(warnings))


class Hec(object):
    """POSTs to the dev HEC named by SCRATCH_HEC_URL. One request per call and
    never a second try: what a request did is read back with a search."""

    def __init__(self):
        self.scheme, self.host, self.port, path = endpoint('SCRATCH_HEC_URL')
        path = path.rstrip('/') or '/services/collector/event'
        self.path = path + '/event' if path.endswith('/services/collector') else path
        if self.path != '/services/collector/event' or not os.environ.get('SCRATCH_HEC_TOKEN'):
            raise Refused('SCRATCH_HEC_URL must end in /services/collector/event (or have no path), and '
                          'SCRATCH_HEC_TOKEN must be set')

    def post(self, lines):
        """Returns on HTTP 200 with code 0, 24 or 25. Raises Failed when nothing
        was indexed for sure, Unknown for every other answer or none."""
        headers = {'Authorization': 'Splunk ' + os.environ['SCRATCH_HEC_TOKEN'],
                   'Content-Type': 'application/json; charset=utf-8', 'Connection': 'close'}
        conn = connect(self.scheme, self.host, self.port, 60)
        try:
            try:
                conn.connect()
            except OSError as error:
                raise Failed('HEC was not reached ({}): nothing was sent'.format(type(error).__name__))
            broke = None
            try:
                conn.request('POST', self.path, body='\n'.join(lines).encode('utf-8'), headers=headers)
            except OSError as error:        # an early 413 is still there to read (review finding delivery-04)
                broke = type(error).__name__
            try:
                response = conn.getresponse()
                status, text = response.status, response.read(4096).decode('utf-8', 'replace')
            except (OSError, http.client.HTTPException) as error:
                raise Unknown('HEC gave no answer ({}): the request may have been taken'.format(
                    broke or type(error).__name__))
        finally:
            conn.close()
        try:
            answer = json.loads(text)
            code, at = answer.get('code'), answer.get('invalid-event-number', 0)
        except (ValueError, AttributeError):
            code, at = None, None
        if status == 200 and code in (0, 24, 25):
            return
        what = 'HEC answered HTTP {} code {}'.format(status, code)
        if status in (401, 403, 413) or (status == 400 and at == 0):
            raise Failed(what + ': refused, nothing was indexed')
        raise Unknown(what + ': this script does not know that answer as "nothing was indexed"')


def duo_rows(story):
    """The Duo half the rule needs, as the TA's Duo input would write it: five
    denials within ten minutes before the first sign-in, and the successful
    authentication of each sign-in (its txid is the record's details.duo_txid).
    The second sign-in is 34 minutes after the burst, so it starts no chain."""
    signins = [(float(case['time']), json.loads(case['raw'])['details']['duo_txid']) for case in story
               if json.loads(case['raw']).get('action') == 'identity_signin_success']
    first = int(signins[0][0])
    rows = [(first - back, 'denied', 'no_response', gen.uid(6, 100 + n), 'Corp VPN')
            for n, back in enumerate((420, 360, 300, 240, 180))]
    rows += [(int(when) - 2, 'success', 'user_approved', txid, 'Corp Sign-in') for when, txid in signins]
    return [{'access_device': {'ip': '198.51.100.23'}, 'application': {'key': 'DIAPPKEY000000000001', 'name': app},
             'email': gen.PERSONA + '@corp.test', 'event_type': 'authentication', 'factor': 'duo_push',
             'isotimestamp': time.strftime('%Y-%m-%dT%H:%M:%S.000000+00:00', time.gmtime(when)), 'reason': reason,
             'result': result, 'timestamp': when, 'txid': txid,
             'user': {'key': 'DUUSERKEY00000000001', 'name': gen.PERSONA}}
            for when, result, reason, txid, app in rows]


def duo_line(row, index):
    return json.dumps({'time': row['timestamp'], 'host': DUO_HOST, 'source': DUO_SOURCE,
                       'sourcetype': DUO_SOURCETYPE, 'index': index, 'event': row}, separators=(',', ':'))


def differences(row, entry, index, golden, bundle_id):
    """How the copies of one id on the stack differ from the line sent: an
    empty list for exactly one identical, labelled copy."""
    want = {'copies': '1', 'sha256': entry['sha256'], 'time': '%.3f' % float(entry['time']),
            'time_text': entry['time'], 'host': golden['destination']['host'],
            'source': golden['destination']['source'], 'sourcetype': entry['sourcetype'], 'index': index,
            'log_type': entry['log_type'], 'resend_bundle': bundle_id}
    return ['{} is {} (sent {})'.format(key, '/'.join(as_list(row.get(key))) or 'missing', value)
            for key, value in sorted(want.items()) if as_list(row.get(key)) != [value]]


class Run(object):
    """One invocation: the fixture, the shipped conf and the scratch indexes."""

    def __init__(self, args):
        self.golden = gen.load()
        problems = gen.self_check(self.golden)
        if problems:
            raise Refused('the golden file is not sound ({} problem(s)): {}'.format(len(problems), problems[0]))
        self.macros, self.saved = shipped('macros.conf'), shipped('savedsearches.conf')
        self.index, self.source_index = (scratch_index(name, self.macros) for name in (args.index, args.source_index))
        if self.index == self.source_index:
            raise Refused('--index and --source-index must be two indexes')
        self.dest, self.bundle_id = self.golden['destination'], self.golden['resend']['bundle_id']
        self.story = self.golden['cases']
        self.entries = self.story + self.golden['splice']
        self.duo = duo_rows(self.story)
        self.txids = [row['txid'] for row in self.duo if row['result'] == 'success']
        self.texts = self.searches_for(self.index, self.entries)
        self.settle, self.state_dir, self.splunkd = args.settle, os.path.expanduser(args.state_dir), None
        self.results = []

    def searches_for(self, index, entries):
        return searches(index, self.macros, self.saved, [entry['id'] for entry in entries],
                        [case['id'] for case in self.story], self.txids, self.bundle_id)

    def rows(self, spl):
        return self.splunkd.search(spl, ALL_TIME, 'now')

    def open(self, *indexes):
        """The guards that need the dev Splunk. Every mode that contacts it runs
        them before its first search of the fixture, and before any POST."""
        if os.environ.get(OPT_IN) != '1':
            raise Refused('set {}=1 to let this script talk to your dev Splunk'.format(OPT_IN))
        self.splunkd = Splunkd()
        info = self.splunkd.info()
        if 'cloud' in '{} {}'.format(info.get('instance_type', ''), info.get('product_type', '')).lower():
            raise Refused('this is a Splunk Cloud instance: this script is for a dev Splunk only')
        print('dev splunkd {}, guid ends {}'.format(info.get('version'), str(info.get('guid', ''))[-4:]))
        for index in indexes:
            if not self.rows('| eventcount summarize=false index="{}"'.format(index)):
                raise Refused('index {} is not there, or this account cannot search it: create it on the dev '
                              'Splunk first (an index that cannot be searched looks empty)'.format(index))
            hosts = {host for row in self.rows('| tstats count where index="{}" by host'.format(index))
                     for host in as_list(row.get('host'))}
            if hosts - {self.dest['host'], DUO_HOST}:
                raise Refused('index {} holds events of {} other host(s): it is not this script\'s scratch '
                              'index'.format(index, len(hosts - {self.dest['host'], DUO_HOST})))
        ids = quoted([entry['id'] for entry in self.entries], ' OR ')
        other = self.rows('index=* NOT index="{}" NOT index="{}" ({}) | stats count by index'.format(
            self.index, self.source_index, ids))
        if other:
            raise Refused('a fixture id is in index {}: the fixture must exist nowhere else'.format(
                ', '.join(sorted(index for row in other for index in as_list(row.get('index'))))))

    def present(self, text):
        """{id: P1 row} of the ids the search `text` finds."""
        return {as_list(row.get('rs_id'))[0]: row for row in self.rows(text) if row.get('rs_id')}

    def wait(self, text, ids):
        """P1 rows once every one of `ids` is searchable, else what is there
        when --settle is over. An accepted event is never sent again."""
        deadline = time.time() + self.settle
        while True:
            seen = self.present(text)
            if all(one in seen for one in ids) or time.time() >= deadline:
                return seen
            time.sleep(POLL_SECONDS)

    def intent_path(self, index):
        return os.path.join(self.state_dir, '{}.{}.intent'.format(index, self.bundle_id))

    def write_intent(self, index):
        """Says, before the first POST, that a send to `index` was started. A
        later run that finds it and not every id on the index sends nothing:
        an unanswered or unseen request is never repeated (review finding
        delivery-03). Created new, 0600, never through a link, and synced."""
        try:
            os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
            fd = os.open(self.intent_path(index), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except OSError as error:
            raise Refused('the intent file {} could not be created ({}); nothing was sent'.format(
                self.intent_path(index), type(error).__name__))
        with os.fdopen(fd, 'w') as handle:
            handle.write(json.dumps({'index': index, 'bundle_id': self.bundle_id, 'started': int(time.time())}) + '\n')
            handle.flush()
            os.fsync(handle.fileno())

    def start(self, index, entries, text, label):
        """Decides from the presence search whether a send to `index` may start.
        Returns False when there is nothing to send; raises when it must not."""
        seen = self.present(text)
        wrong = {entry['id']: differences(seen[entry['id']], entry, index, self.golden, label)
                 for entry in entries if entry['id'] in seen}
        wrong = {one: found for one, found in wrong.items() if found}
        if wrong:
            one = sorted(wrong)[0]
            raise Failed('{} id(s) are on {} in another form or more than once; nothing sent. {}: {}'.format(
                len(wrong), index, one, '; '.join(wrong[one])))
        if len(seen) == len(entries):
            print('nothing to send: all {} ids are on {} once and identical'.format(len(entries), index))
            return False
        if seen or os.path.lexists(self.intent_path(index)):
            raise Unknown('an earlier send to {} was started and {} of {} ids are on it. Nothing is sent again: '
                          'run verify in a few minutes, or use a fresh scratch index (and only then remove '
                          '{})'.format(index, len(seen), len(entries), self.intent_path(index)))
        self.write_intent(index)
        return True

    def copy_line(self, entry):
        return gen.resend_line(entry['time'], entry['sourcetype'], entry['log_type'], entry['raw'],
                               entry['resend_orig_indextime'], index=self.index, bundle_id=self.bundle_id)

    def original_line(self, case):
        """The assistant's own line with only the envelope's index changed."""
        head, body = case['hec_line'].split(',"event":', 1)
        old = '"index":{}'.format(json.dumps(self.dest['index']))
        if head.count(old) != 1:
            raise Refused('the golden line of {} has no envelope index to replace'.format(case['id']))
        return head.replace(old, '"index":{}'.format(json.dumps(self.source_index))) + ',"event":' + body

    def first_post(self, hec, lines, index):
        """The first request of a send. An answer that proves nothing was indexed
        (not reached, 401, 403, 413, 400 at event 0) takes the intent back, so the
        run can be repeated once the cause is fixed; any other answer leaves it."""
        try:
            hec.post(lines)
        except Failed:
            os.remove(self.intent_path(index))
            raise

    def send(self):
        """The copy: the canary alone, the Duo context, then everything else."""
        self.open(self.index)
        hec, text = Hec(), self.texts['P1']
        if not self.start(self.index, self.entries, text, self.bundle_id):
            return
        canary = next((case for case in self.story if case['log_type'] == 'audit'
                       and json.loads(case['raw']).get('action') != 'identity_signin_success'), self.story[0])
        self.first_post(hec, [self.copy_line(canary)], self.index)
        seen = self.wait(text, [canary['id']])
        if canary['id'] not in seen:
            raise Unknown('the canary {} was accepted and is not searchable after {} s; nothing more was sent'
                          .format(canary['id'], self.settle))
        found = differences(seen[canary['id']], canary, self.index, self.golden, self.bundle_id)
        if found:
            raise Failed('the canary came back different, nothing more was sent: ' + '; '.join(found))
        print('canary {} is back once and identical'.format(canary['id']))
        hec.post([duo_line(row, self.index) for row in self.duo])
        rest = [entry for entry in self.entries if entry is not canary]
        hec.post([self.copy_line(entry) for entry in rest])
        seen = self.wait(text, [entry['id'] for entry in self.entries])
        print('sent {} copies and {} Duo context events to {}; {} of {} ids are searchable. Now run: verify'.format(
            len(self.entries), len(self.duo), self.index, len(seen), len(self.entries)))
        if len(seen) != len(self.entries):
            raise Unknown('not every accepted id is searchable yet: run verify later, never send again')

    def originals(self):
        """Seeds --source-index with the eight lines as the assistant sent them,
        so that `staged_resend.py export` can be run against a real splunkd."""
        self.open(self.source_index)
        hec, text = Hec(), self.searches_for(self.source_index, self.story)['P1']
        if self.start(self.source_index, self.story, text, 'none'):
            self.first_post(hec, [self.original_line(case) for case in self.story], self.source_index)
            seen = self.wait(text, [case['id'] for case in self.story])
            print('sent {} originals to {}; {} are searchable'.format(len(self.story), self.source_index, len(seen)))
        window = self.golden['selection']
        print('Now run the tool itself (it reads STAGED_RESEND_SOURCE_PASSWORD or _TOKEN; add '
              '--no-verify-source if it asks for it on this self-signed splunkd):\n'
              '  python3 tools/staged_resend.py export --source {} --index {} --host {} --persona {} \\\n'
              '      --from {} --to {} --bundle {}\n'
              'It must list {} events. Then: staged_resend_scratch_e2e.py bundle --bundle <that file>'.format(
                  os.environ.get('SPLUNK_TEST_URL', ''), self.source_index, window['host'], window['persona'],
                  window['from'], window['to'], os.path.join(self.state_dir, 'scratch.bundle.json'),
                  len(self.story)))

    def bundle(self, path):
        """Reads the file `export` wrote, by content only: every id of the story
        with the sha256 and the time text Splunk gave for it, and no other fixture id."""
        try:
            mode, link = os.lstat(path).st_mode & 0o777, os.path.islink(path)
            with io.open(path, encoding='utf-8') as handle:
                text = handle.read()
        except (OSError, ValueError) as error:
            raise Refused('the bundle could not be read ({})'.format(type(error).__name__))
        missing = ['{} {}'.format(case['id'], what) for case in self.story
                   for what, value in (('id', case['id']), ('sha256', case['sha256']), ('time', case['time']))
                   if value not in text]
        extra = [entry['id'] for entry in self.golden['splice'] if entry['id'] in text]
        self.report('B1', not missing, 'every id, sha256 and time text of the {} originals is in the bundle'
                    .format(len(self.story)), ', '.join(missing))
        self.report('B2', not extra, 'no id that was never seeded is in it', ', '.join(extra))
        self.report('B3', mode == 0o600 and not link, 'the bundle is a 0600 file, not a link',
                    'mode {:o}{}'.format(mode, ', a link' if link else ''))

    def report(self, name, held, what, detail=''):
        self.results.append(bool(held))
        print('{} {}: {}{}'.format('PASS' if held else 'FAIL', name, what, '' if held or not detail else ' - ' + detail))

    def expected(self):
        """What the searches must answer for the story, derived from its bodies."""
        bodies = [(case, json.loads(case['raw'])) for case in self.story]
        signins = [float(case['time']) for case, body in bodies if body.get('action') == 'identity_signin_success']
        turns = [body for case, body in bodies if case['sourcetype'] == 'gen_ai:json' and 'action' not in body
                 and body.get('operation_name') == 'chat' and body.get('provider_name')
                 and body.get('identity_verified') is True]
        blocked = sum(1 for body in turns if body.get('policy_blocked') is True)
        return {'signins': len(signins), 'turns': len(turns), 'blocked': blocked,
                # The TA maps identity_verified for gen_ai:json only, so the escalation and the error record
                # are no identity events; the error record's sourcetype has no props at all, so whether it
                # surfaces a user (and so counts as an event of the persona) is the stack's own business.
                'identity_events': len(signins) + len(turns),
                'events': (len(self.story) - sum(1 for case in self.story if case['log_type'] == 'error'),
                           len(self.story)),
                'chain_id': '{}:takeover:{}'.format(gen.PERSONA, int(signins[0]))}

    def verify(self):
        """V1 to V5, read-only, over the last ten years of event time."""
        self.open(self.index)
        seen = self.wait(self.texts['P1'], [entry['id'] for entry in self.entries])
        age = (time.time() - max(float(case['time']) for case in self.story)) / 86400
        fetched = {name: self.rows(self.texts[name]) for name in ('P2', 'E1', 'D1')}
        fetched['V5'] = self.rows(self.texts['V5']) if age < RULE_REACH_DAYS - 1 else None
        for name, held, what, detail in judge(self, seen, fetched, age):
            self.report(name, held, what, detail)

    def plan(self):
        """What send and verify would do, and every search with its answer.
        Contacts nothing; the searches can be pasted into a search bar."""
        want = self.expected()
        print('send -> index {}: 1 canary, {} Duo context events, then the other {} copies (the story has {}, the '
              'splice texts {}), label resend_bundle={}'.format(
                  self.index, len(self.duo), len(self.entries) - 1, len(self.story), len(self.golden['splice']),
                  self.bundle_id))
        print('verify -> earliest {}, app TA-gen_ai_cim:'.format(ALL_TIME))
        answers = {
            'P1': '{} rows, each copies=1, resend_bundle={}, sha256 and time as sent'.format(
                len(self.entries), self.bundle_id),
            'P2': 'events and orig_indextimes equal per sourcetype and log_type, {} in all'.format(len(self.entries)),
            'E1': 'one row: {} events={} or {} (= copies), identity_events={}, ai_turns={}, ai_blocked={}, '
                  'app_signins={}'.format(gen.PERSONA, want['events'][0], want['events'][1], want['identity_events'],
                                          want['turns'], want['blocked'], want['signins']),
            'D1': 'txids_found={0}, found_once={0}, action=success, identity_user={1}'.format(
                len(self.txids), gen.PERSONA),
            'V5': 'one row: chain_id={}, blocked_turns={}, duo_failures_10m=5, duo_app=Corp VPN, '
                  'signin_duo=duo_push on Corp Sign-in, guardrails=cisco_ai_defense'.format(
                      want['chain_id'], want['blocked']),
        }
        for name in ('P1', 'P2', 'E1', 'D1', 'V5'):
            text = self.texts[name]
            print('### {} ({} characters)\n{}\nEXPECT: {}\n'.format(
                name, len(text), dispatch_text(text), answers[name]))


def judge(run, seen, fetched, age):
    """V1 to V5 from what the searches returned: (name, held, what, detail) each.
    V1 is the story, V1s the splice texts: a stack that rewrites only those
    still copies today's events, which are compact ASCII, and the run says so.
    seen is {id: P1 row}; fetched holds the rows of P2, E1 and D1, and of V5
    (None when the fixture is too old for the rule to be asked)."""
    want, results = run.expected(), []

    def report(name, held, what, detail=''):
        results.append((name, bool(held), what, detail))

    for name, entries, what in (
            ('V1', run.story, 'each of the {} copies of the story is on {} once, with the text, time digits, '
                              'host, source, sourcetype, log_type and label that were sent'),
            ('V1s', run.golden['splice'], 'HEC also kept each of the {} hand-written texts on {} byte for byte '
                                          '(odd spacing, raw UTF-8, escapes, number forms, a duplicate key)')):
        wrong = ['{}: {}'.format(entry['id'], '; '.join(found)) for entry, found in (
            (entry, differences(seen.get(entry['id'], {}), entry, run.index, run.golden, run.bundle_id))
            for entry in entries) if found]
        report(name, not wrong, what.format(len(entries), run.index), ' | '.join(wrong[:3]))
    sent = {}
    for entry in run.entries:
        key = (entry['sourcetype'], entry['log_type'], run.dest['host'])
        sent[key] = sent.get(key, 0) + 1
    got = {tuple('/'.join(as_list(row.get(key))) for key in ('sourcetype', 'log_type', 'host')):
           (as_list(row.get('events')), as_list(row.get('orig_indextimes'))) for row in fetched['P2']}
    report('V2', got == {key: ([str(n)], [str(n)]) for key, n in sent.items()},
           'tstats finds the label as indexed fields, per sourcetype and log_type', str(sorted(got.items())))
    rows = fetched['E1']
    row = rows[0] if len(rows) == 1 else {}
    counts = [as_list(row.get(key)) for key in ('identity_events', 'ai_turns', 'ai_blocked', 'app_signins')]
    events = as_list(row.get('events'))
    report('V3', as_list(row.get('identity_key')) == [gen.PERSONA] and events == as_list(row.get('copies'))
           and events in [[str(n)] for n in want['events']]
           and counts == [[str(want[key])] for key in ('identity_events', 'turns', 'blocked', 'signins')],
           'the identity search reads the copies: {} sign-ins, {} AI turns, {} blocked'.format(
               want['signins'], want['turns'], want['blocked']), '{} row(s): {}'.format(len(rows), row))
    rows = fetched['D1']
    row = rows[0] if rows else {}
    report('V4', [as_list(row.get(key)) for key in ('txids_found', 'found_once', 'action', 'identity_user')]
           == [[str(len(run.txids))]] * 2 + [['success'], [gen.PERSONA]],
           'each sign-in\'s Duo authentication is in the Duo events once', str(row))
    rows = fetched['V5'] or []
    row = rows[0] if len(rows) == 1 else {}
    chain = [as_list(row.get(key)) for key in ('chain_id', 'blocked_turns', 'duo_failures_10m', 'duo_app',
                                                'signin_duo', 'guardrails')]
    report('V5', chain == [[want['chain_id']], [str(want['blocked'])], ['5'], ['Corp VPN'],
                           ['duo_push on Corp Sign-in'], ['cisco_ai_defense']],
           'the shipped rule text raises one chain for the first sign-in and none for the second',
           'not asked: the fixture is {:.0f} days old, past the rule\'s {}-day reach; regenerate it with newer '
           'dates'.format(age, RULE_REACH_DAYS) if fetched['V5'] is None else '{} row(s): {}'.format(len(rows), row))
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description='Re-send contract on a dev Splunk and a scratch index only.')
    parser.add_argument('mode', choices=('plan', 'send', 'verify', 'originals', 'bundle'))
    parser.add_argument('--index', default='rs_scratch_copy', help='scratch index for the copies')
    parser.add_argument('--source-index', default='rs_scratch_source', help='scratch index for `originals`')
    parser.add_argument('--settle', type=int, default=180, help='seconds to wait for sent events to be searchable')
    parser.add_argument('--state-dir', default='~/.staged-resend-scratch-e2e',
                        help='where the write-ahead intent files live (0700, outside any git tree)')
    parser.add_argument('--bundle', help='for `bundle`: the file staged_resend.py export wrote')
    args = parser.parse_args(argv)
    results = []
    try:
        run = Run(args)
        results = run.results
        if args.mode == 'bundle':
            if not args.bundle:
                raise Refused('bundle needs --bundle PATH')
            run.bundle(os.path.expanduser(args.bundle))
        else:
            getattr(run, args.mode)()
    except Refused as error:
        print('REFUSED: {}'.format(error))
        return 2
    except Unknown as error:
        print('UNKNOWN: {}'.format(error))
        return 3
    except Failed as error:
        print('FAILED: {}'.format(error))
        return 1
    return 0 if all(results) else 1


if __name__ == '__main__':
    sys.exit(main())
