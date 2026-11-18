# encoding=utf-8
"""
duo_spl_gen.py - builds duo_spl.json, the live SPL fixtures for
tools/tests/test_duo_spl.py (dev only; tools/ never ships).

    python3 tools/tests/fixtures/duo_spl_gen.py           # rewrite duo_spl.json
    python3 tools/tests/fixtures/duo_spl_gen.py --check   # exit 1 if it is stale

Invented identities (dana.ortiz, lee.park, sam.lee @corp.test) and RFC 5737
addresses only. A persona login is never written here: fixtures use the
<<persona_key>> (a persona's short name) and <<persona_email>> (a persona's
email) tokens, which test_duo_spl.py reads from the persona lookup. The one
exception is the rule-timing fixtures (LR-07) and the chain fixtures (LR-06):
they replay the lab's staged scenarios, so they name the two lab personas
those scenarios use by short name only (nina.osei for a denial burst and the
takeover chain, jordan.reyes for fraud reports and a second identity), never
by email or Duo username.
"""
import json
import os
import sys
import zlib

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'duo_spl.json')
T0 = 1767225600   # 2026-01-01T00:00:00Z
AUTH = 'ta_gen_ai_cim:duo:authentication'
ACT = 'ta_gen_ai_cim:duo:activity'


def lit(obj):
    """An SPL string literal holding obj as compact JSON."""
    text = json.dumps(obj, separators=(',', ':'))
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'


def auth_event(**over):
    ev = {
        'access_device': {'browser': 'Chrome', 'browser_version': '120.0', 'hostname': None,
                          'ip': '198.51.100.23', 'location': {'city': 'Springfield', 'country': 'Testland',
                                                              'state': 'North'},
                          'os': 'Mac OS X', 'os_version': '14.1'},
        'alias': '',
        'application': {'key': 'DIAPPKEY000000000001', 'name': 'Corp VPN'},
        'auth_device': {'ip': '203.0.113.50', 'key': 'DPDEVKEY000000000001', 'name': 'Duo Mobile device'},
        'email': 'dana.ortiz@corp.test',
        'event_type': 'authentication',
        'factor': 'duo_push',
        'isotimestamp': '2026-01-01T00:00:00.000000+00:00',
        'reason': 'user_approved',
        'result': 'success',
        'timestamp': T0,
        'trusted_endpoint_status': 'not trusted',
        'txid': '0f5e8c1a-0000-4000-8000-000000000001',
        'user': {'groups': ['Duo Users'], 'key': 'DUUSERKEY00000000001', 'name': 'dana.ortiz'},
    }
    ev.update(over)
    return ev


def activity_event(name, outcome='SUCCESS', target=None):
    ev = {
        'access_device': {'browser': 'Firefox', 'browser_version': '121.0', 'ip': {'address': '192.0.2.44'},
                          'location': {'city': 'Springfield', 'country': 'Testland', 'state': 'North'},
                          'os': 'Windows', 'os_version': '11'},
        'action': {'details': None, 'name': name, 'type': 'admin'},
        'activity_id': '7c1d2e3f-0000-4000-8000-0000000000aa',
        'actor': {'details': None, 'key': 'DEADMINKEY0000000001', 'name': 'ops.admin@corp.test', 'type': 'admin'},
        'akey': 'DAACCOUNT00000000001',
        'outcome': {'result': outcome},
        'target': target,
        'ts': '2026-01-01T00:00:00.000000+00:00',
    }
    return ev


A = 'ta_gen_ai_cim:duo:authentication|'
V = 'ta_gen_ai_cim:duo:activity|'
AUTH_ALIASES = ', '.join('<<alias:%s%s>>' % (A, k) for k in (
    'FIELDALIAS-duo_auth_user', 'FIELDALIAS-duo_auth_user_id', 'FIELDALIAS-duo_auth_app',
    'FIELDALIAS-duo_auth_method'))
AUTH_EVALS = ', '.join('%s=<<props:%s%s>>' % (out, A, key) for out, key in (
    ('action_out', 'EVAL-action'), ('status_out', 'EVAL-status'), ('src', 'EVAL-src'), ('src_ip', 'EVAL-src_ip'),
    ('signature_out', 'EVAL-signature'),
    ('signature_id_out', 'EVAL-signature_id'), ('service_out', 'EVAL-authentication_service'),
    ('vendor_product_out', 'EVAL-vendor_product'), ('object_out', 'EVAL-object'),
    ('object_category_out', 'EVAL-object_category'), ('change_type_out', 'EVAL-change_type'),
    ('command_out', 'EVAL-command')))
AUTH_TABLE = ('user, user_id, src, src_ip, app, dest, authentication_method, action_out, status_out, signature_out, '
              'signature_id_out, service_out, vendor_product_out, object_out, object_category_out, change_type_out, '
              'command_out')

ACT_ALIASES = ', '.join('<<alias:%s%s>>' % (V, k) for k in (
    'FIELDALIAS-duo_activity_command', 'FIELDALIAS-duo_activity_object'))
ACT_EVALS = ', '.join('%s=<<props:%s%s>>' % (out, V, key) for out, key in (
    ('action_out', 'EVAL-action'), ('status_out', 'EVAL-status'), ('user_out', 'EVAL-user'),
    ('src', 'EVAL-src'), ('src_ip', 'EVAL-src_ip'), ('src_user_out', 'EVAL-src_user'), ('object_category_out', 'EVAL-object_category'),
    ('change_type_out', 'EVAL-change_type'), ('app_out', 'EVAL-app'), ('dest_out', 'EVAL-dest'),
    ('signature_out', 'EVAL-signature'), ('service_out', 'EVAL-authentication_service')))
ACT_TABLE = ('src, src_ip, command, signature_id, object, object_id, action_out, status_out, user_out, src_user_out, '
             'object_category_out, change_type_out, app_out, dest_out, signature_out, service_out')


def auth_fx(name, event, expect):
    spl = ('| makeresults | eval _raw=%s | spath | eval %s | eval %s | table %s'
           % (lit(event), AUTH_ALIASES, AUTH_EVALS, AUTH_TABLE))
    return {'name': name, 'spl': spl, 'expect': expect}


def act_fx(name, event, expect):
    spl = ('| makeresults | eval _raw=%s | spath | eval %s | eval %s | table %s'
           % (lit(event), ACT_ALIASES, ACT_EVALS, ACT_TABLE))
    return {'name': name, 'spl': spl, 'expect': expect}


def multi_rows(events):
    """| makeresults count=N with row n carrying events[n-1] as _raw."""
    cases = ', '.join('n==%d, %s' % (i, lit(ev)) for i, ev in enumerate(events, 1))
    return '| makeresults count=%d | streamstats count as n | eval _raw=case(%s) | spath' % (len(events), cases)


def eventtype_fx(name, sourcetype, event, eventtype, matches):
    spl = ('| makeresults | eval _raw=%s | spath | eval sourcetype="%s" | search <<eventtype:%s>> '
           '| eval matched="yes" | table matched' % (lit(event), sourcetype, eventtype))
    return {'name': name, 'spl': spl, 'expect': [{'matched': 'yes'}] if matches else []}


RULE = 'AI Governance - Duo Authentication Fraud or Denial Burst - Rule'
RULE_TAIL = {'search': RULE, 'from': '| eval identity_user='}
# The rule judges by INDEX time: its job time range is the slot of index time it
# judges. Every rule fixture runs over [SLOT_START, SLOT_END) (the fixture's
# "window", which test_duo_spl.py passes as the job's earliest and latest), and
# each row says when it was indexed: OLD (before the slot) or NEW (in it).
SLOT_END = T0 + 30 * 86400
SLOT_START = SLOT_END - 600
OLD, NEW = SLOT_START - 7200, SLOT_START + 60
RULE_TABLE = (' | eval at=_time-%d | sort 0 user, at | table user, at, risk_score, signature, severity, '
              'fraud_reports, failures, max_failures_10m, duo_users, src, app, burst_id, burst_earliest, '
              'burst_latest' % T0)
LOOKUP_GEN = 'GenAI - Identity - Duo Identity Lookup Gen'
GEN_TAIL = {'search': LOOKUP_GEN, 'from': '| eval snapshot_total=tonumber(snapshot_total)', 'to': '| outputlookup'}


def event_rows(rows):
    """makeresults rows shaped like the Duo authentication events the rule reads
    (the fields its props set, plus the index time and Duo's txid): each row
    (offset_seconds, user, signature_id, src, indexed[, txid[, action]]). The
    txid defaults to one per row; give two rows the same txid for a page Duo
    sent twice."""
    parts = []
    for i, row in enumerate(rows, 1):
        off, user, sig, src, indexed = row[:5]
        txid = row[5] if len(row) > 5 else 'tx-%04d' % i
        action = row[6] if len(row) > 6 else 'failure'
        parts.append((i, off, user, sig, src, indexed, txid, action))

    def col(idx):
        return 'case(%s)' % ', '.join('n==%d, %s' % (p[0], json.dumps(p[idx])) for p in parts)
    return ('| makeresults count=%d | streamstats count as n | eval _time=%d+%s, user=%s, signature_id=%s, '
            'src=%s, _indextime=%s, txid=%s, action=%s, app="Corp VPN" | fields - n'
            % (len(parts), T0, col(1), col(2), col(3), col(4), col(5), col(6), col(7)))


def rule_fx(name, rows, expect):
    return {'name': name, 'spl': event_rows(rows), 'tail': RULE_TAIL, 'append': RULE_TABLE, 'expect': expect,
            'window': [SLOT_START, SLOT_END]}


def burst(user, start, indexed, n=5, step=10, sig='no_response', src='198.51.100.23'):
    """n failures of one user, step seconds apart from offset start, all indexed at `indexed`."""
    return [(start + i * step, user, sig, src, indexed) for i in range(n)]


CHAIN = 'AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule'
CHAIN_TAIL = {'search': CHAIN, 'from': '| eval identity_user='}
# The joined rule judges a 5-minute slot of index time. A chain row is indexed
# in the slot's first second (N: the inclusive edge) or in the last second
# before it (O), so every chain fixture also pins that edge. The rule reads the
# slot's start in an append subsearch (| makeresults | addinfo), where it is the
# job's own time range: these rows cannot show what `addinfo` returns in the main
# pipeline of the dispatched search (there it is the event-time range the base
# search was given inline, which is how the first build judged every row as
# new). DuoSlotEdgeTests and DuoChainSplitTests in test_duo_spl.py dispatch the
# full text for that.
CHAIN_START = SLOT_END - 300
CHAIN_TABLE = (' | eval at=_time-%d | sort 0 user, at | table user, at, chain_id, signin_duo, duo_failures_10m, duo_app, '
               'blocked_turns, guardrails, app, src, chain_earliest, chain_latest' % T0)
N = 'nina.osei'


def chain_rows(rows, user=N):
    """makeresults rows shaped like the events the joined rule reads, one
    (offset, kind, 'N' or 'O'[, link]) each, all of one user (`user` is the
    login, or an SPL expression over k when it starts with "if("). Kinds: F a
    failed Duo authentication; D a successful one (link = its txid); S the
    application's sign-in record (link = details.duo_txid; like the real record
    it also says action=success); X the application's own sign-in FAILURE
    record; B a blocked verified AI turn (link = its event id, for a turn sent
    twice), G one blocked by the Identity Risk Gate, A an allowed one, C a
    blocked turn that only claims the name. A row with no link gets an id of
    its own ("r" and its row number, so never write a link that starts with
    "r"); the four chat kinds are the rows with no action.

    Written as 'offset|kind[|link]', the kind in capitals for a row indexed in
    the slot (N) and in lower case for one indexed before it (O): every chain
    fixture has to fit the 5,000 characters of the read-only Splunk MCP together
    with the rule's own text, so the rows are as short as they can be."""
    for row in rows:
        assert row[1] in tuple('FDSXBGAC') and row[2] in ('N', 'O'), row
        assert not str(row[3] if len(row) > 3 else '').startswith('r'), row
    spec = ';'.join('|'.join(str(col) for col in (row[0], row[1] if row[2] == 'N' else row[1].lower()) + tuple(row[3:]))
                    for row in rows)
    return ('| makeresults count=%d | streamstats count as n | eval f=split(mvindex(split("%s", ";"), n-1), "|"), '
            '_time=%d+tonumber(mvindex(f, 0)), K=mvindex(f, 1), k=upper(K), user=%s, '
            '_indextime=if(k==K, %d, %d), l=mvindex(f, 2), i=coalesce(l, "r" . n), '
            'txid=if(in(k, "F", "D"), i, null()), '
            'action=case(in(k, "F", "X"), "failure", in(k, "D", "S"), "success"), '
            'op=if(isnull(action), "chat", null()), '
            'app=case(in(k, "F", "D"), "Corp VPN", isnotnull(op), "assistant"), '
            'authentication_method="duo_push", src="192.0.2.10", '
            'details.duo_txid=if(k=="S", l, null()), '
            'gen_ai.audit.action=case(k=="S", "identity_signin_success", k=="X", "identity_signin_failure"), '
            'gen_ai.operation.name=op, gen_ai.provider.name=op, '
            'gen_ai.policy.blocked=case(k=="A", "false", isnotnull(op), "true"), '
            'gen_ai.identity.verified=if(in(k, "A", "B", "G"), "true", null()), '
            'gen_ai.event.id=if(isnull(txid), i, null()), '
            'gen_ai.guardrail.ids=case(k=="G", "cisco_identity_intelligence", in(k, "B", "C"), "cisco_ai_defense")'
            % (len(rows), spec, T0, user if user.startswith('if(') else json.dumps(user),
               CHAIN_START, CHAIN_START - 1))


def chain_fx(name, rows, expect, user=N):
    return {'name': name, 'spl': chain_rows(rows, user), 'tail': CHAIN_TAIL, 'append': CHAIN_TABLE, 'expect': expect,
            'window': [CHAIN_START, SLOT_END]}


def fails(start, indexed, n=5, step=10):
    """n failed Duo authentications, step seconds apart from offset start."""
    return [(start + i * step, 'F', indexed) for i in range(n)]


def found(signin, at, burst, last=None, user=N, **more):
    """One finding the joined rule returns: the sign-in it is named after, its
    first blocked turn (the finding's time), the burst it names and its last
    blocked turn, all as offsets. The drill-down reads from 10 minutes before
    the burst to one second after the last blocked turn."""
    row = {'user': user, 'at': str(at), 'chain_id': '%s:takeover:%d' % (user, T0 + signin),
           'chain_earliest': str(T0 + burst - 600), 'chain_latest': str(T0 + (at if last is None else last) + 1)}
    row.update(more)
    return row


def user_rec(username, snapshot, total, seq, **over):
    rec = {'user_id': 'DU%018d' % zlib.crc32(username.encode('utf-8')),
           'username': username, 'realname': None, 'firstname': None, 'lastname': None,
           'email': username + '@corp.test', 'status': 'active', 'is_enrolled': True, 'created': 1700000000,
           'last_login': 1767200000, 'alias1': None, 'alias2': None, 'alias3': None, 'alias4': None,
           'aliases': {}, 'groups': [],
           'snapshot_id': 'duo-users-%d' % (snapshot * 1000), 'snapshot_total': total, 'snapshot_seq': seq}
    rec.update(over)
    return rec


def gen_fx(name, records, expect):
    """records: (time, record). Rows run through the lookup gen up to its outputlookup."""
    cases = ', '.join('n==%d, %s' % (i, lit(rec)) for i, (_t, rec) in enumerate(records, 1))
    times = ', '.join('n==%d, %d' % (i, t) for i, (t, _rec) in enumerate(records, 1))
    spl = ('| makeresults count=%d | streamstats count as n | eval _raw=case(%s), _time=case(%s) | spath | fields - n'
           % (len(records), cases, times))
    return {'name': name, 'spl': spl, 'tail': GEN_TAIL, 'expect': expect}


fixtures = []

# --- Authentication log: CIM Authentication ----------------------------------
fixtures.append(auth_fx(
    'auth: an approved push maps to CIM Authentication success',
    auth_event(),
    [{'user': 'dana.ortiz', 'user_id': 'DUUSERKEY00000000001', 'src': '198.51.100.23', 'src_ip': '198.51.100.23',
      'app': 'Corp VPN', 'dest': 'Corp VPN', 'authentication_method': 'duo_push', 'action_out': 'success',
      'status_out': None, 'signature_out': 'Duo authentication success', 'signature_id_out': 'user_approved',
      'service_out': 'duo', 'vendor_product_out': 'Cisco Duo', 'object_out': None, 'command_out': None}]))
fixtures.append(auth_fx(
    'auth: a JSON null access device IP never becomes src (auth_device.ip is never used)',
    auth_event(access_device={'browser': 'Chrome', 'ip': None}, reason=None),
    [{'user': 'dana.ortiz', 'src': None, 'src_ip': None, 'action_out': 'success', 'signature_id_out': 'success'}]))
fixtures.append(auth_fx(
    'auth: a fraud report is a failure with signature_id user_marked_fraud',
    auth_event(result='fraud', reason='user_marked_fraud'),
    [{'action_out': 'failure', 'signature_out': 'Duo authentication fraud', 'signature_id_out': 'user_marked_fraud'}]))
rows = [auth_event(result='denied', reason='no_response'), auth_event(result='failure', reason='invalid_passcode'),
        auth_event(result='error', reason=None), auth_event(result='queued', reason='')]
fixtures.append({
    'name': 'auth: denied and failure are failures, error stays error, anything else is unknown',
    'spl': '%s | eval action_out=<<props:%sEVAL-action>>, signature_id_out=<<props:%sEVAL-signature_id>> '
           '| table n, action_out, signature_id_out' % (multi_rows(rows), A, A),
    'expect': [{'n': '1', 'action_out': 'failure', 'signature_id_out': 'no_response'},
               {'n': '2', 'action_out': 'failure', 'signature_id_out': 'invalid_passcode'},
               {'n': '3', 'action_out': 'error', 'signature_id_out': 'error'},
               {'n': '4', 'action_out': 'unknown', 'signature_id_out': 'queued'}]})
fixtures.append(auth_fx(
    'auth: an enrollment is an account change (created), its outcome in status',
    auth_event(event_type='enrollment', factor='not_available', reason='user_enrolled'),
    [{'action_out': 'created', 'status_out': 'success', 'object_out': 'dana.ortiz', 'object_category_out': 'user',
      'change_type_out': 'AAA', 'command_out': 'duo_enrollment', 'signature_out': 'Duo enrollment success'}]))
fixtures.append(auth_fx(
    'auth: a failed enrollment has status failure',
    auth_event(event_type='enrollment', result='failure', reason='error'),
    [{'action_out': 'created', 'status_out': 'failure'}]))

# --- Activity log v2 (public preview shape) ------------------------------------
fixtures.append(act_fx(
    'activity: an admin_login is a privileged authentication of the actor (no src_user)',
    activity_event('admin_login'),
    [{'src': '192.0.2.44', 'src_ip': '192.0.2.44', 'command': 'admin_login', 'signature_id': 'admin_login',
      'action_out': 'success', 'status_out': 'success', 'user_out': 'ops.admin@corp.test', 'src_user_out': None,
      'app_out': 'Duo Admin Panel', 'dest_out': 'Duo Admin Panel', 'signature_out': 'Duo admin_login success',
      'service_out': 'duo'}]))
fixtures.append(act_fx(
    'activity: a failed admin_login is a failure',
    activity_event('admin_login', outcome='FAILURE'),
    [{'action_out': 'failure', 'status_out': 'failure', 'signature_out': 'Duo admin_login failure'}]))
fixtures.append(act_fx(
    'activity: a user_update is an account change: user is the target, src_user the admin',
    activity_event('user_update', target={'details': None, 'key': 'DUTARGETKEY000000001', 'name': 'lee.park',
                                          'type': 'user'}),
    [{'command': 'user_update', 'object': 'lee.park', 'object_id': 'DUTARGETKEY000000001', 'action_out': 'modified',
      'status_out': 'success', 'user_out': 'lee.park', 'src_user_out': 'ops.admin@corp.test',
      'object_category_out': 'user', 'change_type_out': 'AAA', 'app_out': None, 'dest_out': None}]))
rows = [activity_event('integration_create', target={'name': 'Corp VPN', 'type': 'integration'}),
        activity_event('policy_delete', target={'name': 'Legacy policy', 'type': 'policy'})]
fixtures.append({
    'name': 'activity: create and delete names map to Change created / deleted; a non-user target keeps the actor',
    'spl': '%s | eval action_out=<<props:%sEVAL-action>>, user_out=<<props:%sEVAL-user>>, '
           'object_category_out=<<props:%sEVAL-object_category>> | table n, action_out, user_out, object_category_out'
           % (multi_rows(rows), V, V, V),
    'expect': [{'n': '1', 'action_out': 'created', 'user_out': 'ops.admin@corp.test', 'object_category_out': 'integration'},
               {'n': '2', 'action_out': 'deleted', 'user_out': 'ops.admin@corp.test', 'object_category_out': 'policy'}]})

# --- Eventtypes (their search text run as a filter) ----------------------------
auth_ev, enr_ev = auth_event(), auth_event(event_type='enrollment')
login_ev = activity_event('admin_login')
upd_ev = activity_event('user_update', target={'name': 'lee.park', 'type': 'user'})
for label, st, ev, et, hit in (
        ('authentication event -> ta_gen_ai_cim_duo_authentication', AUTH, auth_ev, 'ta_gen_ai_cim_duo_authentication', True),
        ('authentication event -/-> ta_gen_ai_cim_duo_enrollment', AUTH, auth_ev, 'ta_gen_ai_cim_duo_enrollment', False),
        ('enrollment event -> ta_gen_ai_cim_duo_enrollment', AUTH, enr_ev, 'ta_gen_ai_cim_duo_enrollment', True),
        ('enrollment event -/-> ta_gen_ai_cim_duo_authentication', AUTH, enr_ev, 'ta_gen_ai_cim_duo_authentication', False),
        ('admin_login -> ta_gen_ai_cim_duo_admin_login', ACT, login_ev, 'ta_gen_ai_cim_duo_admin_login', True),
        ('admin_login -/-> ta_gen_ai_cim_duo_activity', ACT, login_ev, 'ta_gen_ai_cim_duo_activity', False),
        ('user_update -> ta_gen_ai_cim_duo_activity', ACT, upd_ev, 'ta_gen_ai_cim_duo_activity', True),
        ('user_update -/-> ta_gen_ai_cim_duo_admin_login', ACT, upd_ev, 'ta_gen_ai_cim_duo_admin_login', False),
        ('a gen_ai:json row with event_type=authentication is not Duo', 'gen_ai:json', auth_ev,
         'ta_gen_ai_cim_duo_authentication', False)):
    fixtures.append(eventtype_fx('eventtype: ' + label, st, ev, et, hit))

# --- Macros --------------------------------------------------------------------
fixtures.append({
    'name': 'genai_duo_auth_events keeps Duo\'s own log and drops a PseudoCo sign-in that also says authentication_service=duo',
    'spl': '| makeresults count=3 | streamstats count as n | eval index=case(n==1, "gen_ai_log", n==2, "duo", 1=1, "duo"), '
           'sourcetype=case(n==1, "gen_ai:json", n==2, "ta_gen_ai_cim:duo:authentication", 1=1, "demobot:audit"), '
           'authentication_service="duo", action="failure", user="dana.ortiz" | search `genai_duo_auth_events` | table n',
    'expect': [{'n': '2'}]})
fixtures.append({
    'name': 'genai_duo_identity_scope drops l5-* (any key), a persona email key, and a persona short name '
            'with no Duo email; keeps a customer user who only shares a persona short name',
    'spl': '| makeresults count=6 | streamstats count as n | eval identity_keys=case(n==1, split("dana.ortiz|dana.ortiz@corp.test", "|"), '
           'n==2, split("l5-ws1-03|l5-ws1-03@corp.test", "|"), n==3, split("sam.lee|l5-ws2-01", "|"), '
           'n==4, "<<persona_key>>", n==5, split("<<persona_key>>|<<persona_key>>@corp.test", "|"), '
           '1=1, split("lee.park|<<persona_email>>", "|")), '
           'email=case(n==1, "dana.ortiz@corp.test", n==2, "l5-ws1-03@corp.test", n==3, "sam.lee@corp.test", '
           'n==4, null(), n==5, "<<persona_key>>@corp.test", 1=1, "<<persona_email>>") '
           '| `genai_duo_identity_scope` | table n',
    'expect': [{'n': '1'}, {'n': '5'}]})

# --- Risk rule (its pipeline after the base search, rows shaped like Duo events) ---
IP = '198.51.100.23'
fixtures.append(rule_fx(
    'rule: 5 failures within 10 minutes raise risk 40 on the join key, dated at the 5th failure',
    [(0, 'dana.ortiz', 'no_response', IP, NEW), (60, 'dana.ortiz', 'no_response', IP, NEW),
     (120, 'dana.ortiz', 'no_response', 'unknown', NEW), (180, 'dana.ortiz', 'no_response', IP, NEW),
     (240, 'dana.ortiz', 'user_cancelled', IP, NEW)],
    [{'user': 'dana.ortiz', 'at': '240', 'risk_score': '40', 'signature': 'Duo authentication denial burst',
      'severity': 'medium', 'fraud_reports': '0', 'failures': '5', 'max_failures_10m': '5', 'duo_users': 'dana.ortiz',
      'src': IP, 'app': 'Corp VPN', 'burst_id': 'dana.ortiz:burst:%d' % (T0 + 240),
      'burst_earliest': str(T0 - 600), 'burst_latest': str(T0 + 240 + 601)}]))
fixtures.append(rule_fx(
    'rule: 4 failures in 10 minutes and a 5th 18 minutes later raise nothing',
    burst('dana.ortiz', 0, NEW, n=4, step=60) + [(1080, 'dana.ortiz', 'no_response', IP, NEW)],
    []))
fixtures.append(rule_fx(
    'rule: five failures in the same second are five failures',
    burst('dana.ortiz', 0, NEW, step=0),
    [{'user': 'dana.ortiz', 'at': '0', 'risk_score': '40', 'failures': '5', 'max_failures_10m': '5'}]))
fixtures.append(rule_fx(
    'rule: 5 failures spanning 599 seconds are inside the 10-minute window',
    [(off, 'dana.ortiz', 'no_response', IP, NEW) for off in (0, 150, 300, 450, 599)],
    [{'user': 'dana.ortiz', 'at': '599', 'max_failures_10m': '5'}]))
fixtures.append(rule_fx(
    'rule: 5 failures spanning exactly 600 seconds are not (the window excludes its far edge)',
    [(off, 'dana.ortiz', 'no_response', IP, NEW) for off in (0, 150, 300, 450, 600)],
    []))
fixtures.append(rule_fx(
    'rule: one fraud report raises risk 80',
    [(0, 'lee.park', 'user_marked_fraud', '203.0.113.9', NEW)],
    [{'user': 'lee.park', 'at': '0', 'risk_score': '80', 'signature': 'Duo user marked fraud', 'severity': 'high',
      'fraud_reports': '1', 'failures': '0', 'max_failures_10m': '0', 'burst_id': 'lee.park:fraud:%d' % T0}]))
fixtures.append(rule_fx(
    'rule: five fraud reports and one other failure raise one finding (80): a fraud report is never one of the 5 failures',
    [(0, 'lee.park', 'invalid_device', IP, NEW)] + burst('lee.park', 20, NEW, sig='user_marked_fraud'),
    [{'user': 'lee.park', 'at': '20', 'risk_score': '80', 'signature': 'Duo user marked fraud', 'severity': 'high',
      'fraud_reports': '5', 'failures': '1', 'max_failures_10m': '1', 'burst_id': 'lee.park:fraud:%d' % (T0 + 20)}]))
fixtures.append(rule_fx(
    'rule: 4 failures and a fraud report within 10 minutes are not a burst: only the fraud finding',
    burst('lee.park', 0, NEW, n=4) + [(100, 'lee.park', 'user_marked_fraud', IP, NEW)],
    [{'user': 'lee.park', 'at': '100', 'risk_score': '80', 'fraud_reports': '1', 'failures': '4',
      'max_failures_10m': '4'}]))
fixtures.append(rule_fx(
    'rule: a burst of 5 other failures and a fraud report indexed together raise both, each dated at its own event',
    burst('lee.park', 0, NEW) + [(100, 'lee.park', 'user_marked_fraud', IP, NEW)],
    [{'user': 'lee.park', 'at': '40', 'risk_score': '40', 'signature': 'Duo authentication denial burst',
      'failures': '5', 'fraud_reports': '1', 'burst_id': 'lee.park:burst:%d' % (T0 + 40)},
     {'user': 'lee.park', 'at': '100', 'risk_score': '80', 'signature': 'Duo user marked fraud',
      'failures': '5', 'fraud_reports': '1', 'burst_id': 'lee.park:fraud:%d' % (T0 + 100)}]))
fixtures.append(rule_fx(
    'rule: a fraud report indexed after its burst was judged raises only the fraud finding',
    burst('lee.park', 0, OLD) + [(160, 'lee.park', 'user_marked_fraud', IP, NEW)],
    [{'user': 'lee.park', 'at': '160', 'risk_score': '80', 'signature': 'Duo user marked fraud', 'failures': '5',
      'fraud_reports': '1'}]))
fixtures.append(rule_fx(
    'rule: Lab 5 participant accounts never raise it',
    burst('l5-ws1-03', 0, NEW, n=6, step=30, src='198.51.100.40'),
    []))
fixtures.append(rule_fx(
    'rule: an email-form Duo username keys on its lowercased local part',
    burst('Dana.Ortiz@corp.test', 0, NEW, step=30),
    [{'user': 'dana.ortiz', 'duo_users': 'Dana.Ortiz@corp.test', 'risk_score': '40'}]))
fixtures.append(rule_fx(
    'rule: a null or unknown Duo user never becomes a risk object',
    [(i * 30, 'null' if i % 2 else 'unknown', 'no_response', IP, NEW) for i in range(10)],
    []))
mixed = ([(i * 40, 'dana.ortiz', 'denied', '198.51.100.7', NEW) for i in range(3)] +
         [(200 + i * 40, 'dana.ortiz', 'no_response', IP, NEW) for i in range(5)])
scope = (' | eval index=if(n<=3, "gen_ai_log", "duo"), sourcetype=if(n<=3, "gen_ai:json", "%s")' % AUTH)
fx = rule_fx('rule: a PseudoCo sign-in denial never adds to a Duo burst (scope emulated with genai_duo_auth_events)',
             mixed, [{'user': 'dana.ortiz', 'failures': '5', 'max_failures_10m': '5', 'src': IP}])
fx['spl'] = fx['spl'].replace(' | fields - n', scope + ' | search `genai_duo_auth_events` | fields - n')
fixtures.append(fx)
few = ([(i * 40, 'dana.ortiz', 'denied', '198.51.100.7', NEW) for i in range(3)] +
       [(200 + i * 40, 'dana.ortiz', 'no_response', IP, NEW) for i in range(3)])
fx = rule_fx('rule: 3 PseudoCo + 3 Duo denials for one user raise nothing (only Duo\'s 3 count)', few, [])
fx['spl'] = fx['spl'].replace(' | fields - n', scope + ' | search `genai_duo_auth_events` | fields - n')
fixtures.append(fx)

# --- Risk rule timing (LR-07): judged once by index time, counted by event time ---
fixtures.append(rule_fx(
    'rule timing: late arrival - a 5th failure indexed long after the other 4 raises the burst, dated at that failure',
    burst('nina.osei', 0, OLD, n=4, step=60) + [(240, 'nina.osei', 'no_response', IP, NEW)],
    [{'user': 'nina.osei', 'at': '240', 'risk_score': '40', 'failures': '5', 'max_failures_10m': '5',
      'burst_id': 'nina.osei:burst:%d' % (T0 + 240)}]))
fixtures.append(rule_fx(
    'rule timing: late arrival - a 6th failure indexed after the burst was judged raises nothing',
    burst('nina.osei', 0, OLD) + [(50, 'nina.osei', 'no_response', IP, NEW)],
    []))
fixtures.append(rule_fx(
    'rule timing: late arrival - a second fraud report of a burst whose first was judged raises nothing',
    [(0, 'jordan.reyes', 'user_marked_fraud', IP, OLD), (30, 'jordan.reyes', 'user_marked_fraud', IP, NEW)],
    []))
fixtures.append(rule_fx(
    'rule timing: repeat burst - a fraud report 11 minutes after a judged one opens a new burst and raises again',
    [(0, 'jordan.reyes', 'user_marked_fraud', IP, OLD), (700, 'jordan.reyes', 'user_marked_fraud', IP, NEW)],
    [{'user': 'jordan.reyes', 'at': '700', 'risk_score': '80', 'fraud_reports': '1', 'failures': '0',
      'burst_id': 'jordan.reyes:fraud:%d' % (T0 + 700)}]))
fixtures.append(rule_fx(
    'rule timing: a burst split over two polls (3 indexed before the slot, 3 in it) raises one finding',
    burst('nina.osei', 0, OLD, n=3, step=5) + burst('nina.osei', 15, NEW, n=3, step=5),
    [{'user': 'nina.osei', 'at': '20', 'failures': '6', 'max_failures_10m': '6',
      'burst_id': 'nina.osei:burst:%d' % (T0 + 20)}]))
fixtures.append(rule_fx(
    'rule timing: an event indexed in the first second of the slot is judged in it',
    burst('nina.osei', 0, SLOT_START - 1, n=4) + [(40, 'nina.osei', 'no_response', IP, SLOT_START)],
    [{'user': 'nina.osei', 'at': '40', 'failures': '5'}]))
fixtures.append(rule_fx(
    'rule timing: a burst indexed wholly before the slot was judged by an earlier run',
    burst('nina.osei', 0, SLOT_START - 1),
    []))
fixtures.append(rule_fx(
    'rule timing: repeat burst - a second burst 11 minutes after a judged one raises its own finding',
    burst('nina.osei', 0, OLD) + burst('nina.osei', 700, NEW),
    [{'user': 'nina.osei', 'at': '740', 'risk_score': '40', 'failures': '5', 'max_failures_10m': '5',
      'burst_id': 'nina.osei:burst:%d' % (T0 + 740), 'burst_earliest': str(T0 + 700 - 600)}]))
fixtures.append(rule_fx(
    'rule timing: repeat burst - failures 9 minutes after a judged burst belong to it and raise nothing',
    burst('nina.osei', 0, OLD) + burst('nina.osei', 560, NEW, n=3),
    []))
DAY20 = 20 * 86400
backfill = [{'user': 'jordan.reyes', 'at': '300', 'risk_score': '80', 'signature': 'Duo user marked fraud',
             'burst_id': 'jordan.reyes:fraud:%d' % (T0 + 300)},
            {'user': 'nina.osei', 'at': '40', 'risk_score': '40', 'failures': '5',
             'burst_id': 'nina.osei:burst:%d' % (T0 + 40)},
            {'user': 'nina.osei', 'at': str(DAY20 + 40), 'risk_score': '40', 'failures': '6',
             'burst_id': 'nina.osei:burst:%d' % (T0 + DAY20 + 40)}]   # the table sorts by user, then time
fixtures.append(rule_fx(
    'rule timing: 30-day backfill - bursts 20 days apart indexed in one slot raise one finding each, dated at the event',
    burst('nina.osei', 0, NEW) + burst('nina.osei', DAY20, NEW, n=6) + [(300, 'jordan.reyes', 'user_marked_fraud', IP, NEW)],
    backfill))
fixtures.append(rule_fx(
    'rule timing: backfill equals live - the same events with the first burst already judged raise the same second finding',
    burst('nina.osei', 0, OLD) + burst('nina.osei', DAY20, NEW, n=6) + [(300, 'jordan.reyes', 'user_marked_fraud', IP, OLD)],
    [backfill[2]]))
fixtures.append(rule_fx(
    'rule timing: a page Duo sent twice counts once (txid), so 3 failures indexed twice raise nothing',
    [(i * 10, 'nina.osei', 'no_response', IP, OLD, 'dup-%d' % i) for i in range(3)] +
    [(i * 10, 'nina.osei', 'no_response', IP, NEW, 'dup-%d' % i) for i in range(3)],
    []))
fixtures.append(rule_fx(
    'rule timing: a judged burst sent again in a later slot raises nothing (its first copy decides when it was indexed)',
    [(i * 10, 'nina.osei', 'no_response', IP, OLD, 'dup-%d' % i) for i in range(5)] +
    [(i * 10, 'nina.osei', 'no_response', IP, NEW, 'dup-%d' % i) for i in range(5)],
    []))

# --- Joined rule (LR-06): Duo denial burst, then application sign-in, then blocked AI turn ---
staged = found(1000, 1060, 940, signin_duo='duo_push on Corp VPN', duo_failures_10m='5', duo_app='Corp VPN',
               blocked_turns='1', guardrails='cisco_ai_defense', app='assistant', src='192.0.2.10')
unmatched = dict(staged, signin_duo='none indexed')
fixtures.append(chain_fx(
    'chain: backfill - burst, sign-in (with Duo\'s record of it) and blocked turn indexed in one slot raise one '
    'finding, dated at the blocked turn',
    fails(900, 'N') + [(998, 'D', 'N', 't1'), (1000, 'S', 'N', 't1'), (1060, 'B', 'N')],
    [staged]))
fixtures.append(chain_fx(
    'chain: backfill equals live - the same events with the application\'s half indexed earlier raise the same finding',
    fails(900, 'N') + [(998, 'D', 'N', 't1'), (1000, 'S', 'O', 't1'), (1060, 'B', 'O')],
    [staged]))
fixtures.append(chain_fx(
    'chain: live order - Duo\'s record of the sign-in is not indexed yet: the chain still raises, signin_duo says so',
    fails(900, 'N') + [(1000, 'S', 'O', 't1'), (1060, 'B', 'O')],
    [unmatched]))
fixtures.append(chain_fx(
    'chain: a chain indexed wholly before the slot was judged by an earlier run',
    fails(900, 'O') + [(998, 'D', 'O', 't1'), (1000, 'S', 'O', 't1'), (1060, 'B', 'O')],
    []))
fixtures.append(chain_fx(
    'chain: Duo\'s record of the sign-in arriving after the chain was judged raises nothing',
    fails(900, 'O') + [(998, 'D', 'N', 't1'), (1000, 'S', 'O', 't1'), (1060, 'B', 'O')],
    []))
fixtures.append(chain_fx(
    'chain: a burst that comes after the sign-in and its turns raises nothing (the first staged pass)',
    [(1000, 'S', 'N', 't1'), (1030, 'A', 'N'), (1060, 'B', 'N')] + fails(1100, 'N', n=6),
    []))
fixtures.append(chain_fx(
    'chain: a burst 30 min 05 s before the sign-in is outside the window',
    fails(0, 'N') + [(1845, 'S', 'N'), (1900, 'B', 'N')],
    []))
fixtures.append(chain_fx(
    'chain: a burst 29 min 59 s before the sign-in is inside it',
    fails(0, 'N') + [(1839, 'S', 'N'), (1900, 'B', 'N')],
    [found(1839, 1900, 40)]))
fixtures.append(chain_fx(
    'chain: a blocked turn 61 minutes after the sign-in is outside the window',
    fails(0, 'N') + [(100, 'S', 'N'), (3760, 'B', 'N')],
    []))
fixtures.append(chain_fx(
    'chain: a blocked turn exactly 60 minutes after the sign-in is inside the window',
    fails(0, 'N') + [(100, 'S', 'N'), (3700, 'B', 'N')],
    [found(100, 3700, 40)]))
fixtures.append(chain_fx(
    'chain: a blocked turn 60 min 01 s after the sign-in is outside it',
    fails(0, 'N') + [(100, 'S', 'N'), (3701, 'B', 'N')],
    []))
fixtures.append(chain_fx(
    'chain: a second blocked turn after a judged one raises nothing',
    fails(0, 'O') + [(100, 'S', 'O'), (200, 'B', 'O'), (300, 'B', 'N')],
    []))
fixtures.append(chain_fx(
    'chain: a late sign-in record between a judged sign-in and its blocked turn raises nothing',
    fails(0, 'O') + [(100, 'S', 'O'), (200, 'B', 'O'), (150, 'S', 'N')],
    []))
fixtures.append(chain_fx(
    'chain: a late sign-in record ahead of two judged turns raises nothing (it holds the turn that completed the '
    'judged chain)',
    fails(0, 'O') + [(100, 'S', 'O'), (200, 'B', 'O'), (300, 'B', 'O'), (150, 'S', 'N')],
    []))
fixtures.append(chain_fx(
    'chain: a late sign-in record after the turn that completed a judged chain raises its own finding for the '
    'later turn, as one pass would',
    fails(0, 'O') + [(100, 'S', 'O'), (200, 'B', 'O'), (300, 'B', 'O'), (250, 'S', 'N')],
    [found(250, 300, 40, blocked_turns='1')]))
fixtures.append(chain_fx(
    'chain: Lab 5 participant accounts never raise it',
    fails(900, 'N') + [(1000, 'S', 'N'), (1060, 'B', 'N')],
    [], user='l5-ws1-01'))
fixtures.append(chain_fx(
    'chain: allowed turns only raise nothing',
    fails(900, 'N') + [(1000, 'S', 'N'), (1060, 'A', 'N'), (1120, 'A', 'N')],
    []))
fixtures.append(chain_fx(
    'chain: 4 failures are not a burst',
    fails(900, 'N', n=4) + [(1000, 'S', 'N'), (1060, 'B', 'N')],
    []))
fixtures.append(chain_fx(
    'chain: an email-form Duo username and the application\'s short name are one identity; two blocked turns are '
    'one finding',
    fails(900, 'N') + [(1000, 'S', 'N'), (1060, 'B', 'N'), (1120, 'B', 'N')],
    [found(1000, 1060, 940, last=1120, user='dana.ortiz', blocked_turns='2', signin_duo='none indexed')],
    user='if(k=="F", "Dana.Ortiz@corp.test", "dana.ortiz")'))
fixtures.append(chain_fx(
    'chain: a Duo page sent twice counts once (txid): 3 failures indexed twice are not a burst',
    [(900 + i * 10, 'F', 'O', 'dup%d' % i) for i in range(3)] +
    [(900 + i * 10, 'F', 'N', 'dup%d' % i) for i in range(3)] + [(1000, 'S', 'N'), (1060, 'B', 'N')],
    []))
fixtures.append(chain_fx(
    'chain: a turn that only claims the name (not verified) never counts',
    fails(900, 'N') + [(1000, 'S', 'N'), (1060, 'C', 'N')],
    []))
fixtures.append(chain_fx(
    'chain: the application\'s own sign-in failure records are not Duo failures (4 Duo + 2 of them are not a burst)',
    fails(900, 'N', n=4) + [(950, 'X', 'N'), (960, 'X', 'N'), (1000, 'S', 'N'), (1060, 'B', 'N')],
    []))
fixtures.append(chain_fx(
    'chain: the application\'s sign-in failure record is not a sign-in',
    fails(900, 'N') + [(1000, 'X', 'N'), (1060, 'B', 'N')],
    []))
fixtures.append(chain_fx(
    'chain: two sign-ins after one burst, each with a blocked turn, are two findings',
    fails(0, 'N') + [(100, 'S', 'N'), (200, 'B', 'N'), (300, 'S', 'N'), (400, 'B', 'N')],
    [found(100, 200, 40, blocked_turns='1'), found(300, 400, 40, blocked_turns='1')]))
fixtures.append(chain_fx(
    'chain: a block by the Identity Risk Gate counts and is named in guardrails',
    fails(900, 'N') + [(1000, 'S', 'N'), (1060, 'G', 'N')],
    [found(1000, 1060, 940, user='jordan.reyes', guardrails='cisco_identity_intelligence')],
    user='jordan.reyes'))
fixtures.append(chain_fx(
    'chain: a successful Duo authentication alone is never a sign-in',
    fails(900, 'N') + [(998, 'D', 'N', 't1'), (1060, 'B', 'N')],
    []))
fixtures.append(chain_fx(
    'chain: the burst named is the last one before the sign-in, with its own count',
    fails(0, 'N') + fails(1400, 'N', n=6) + [(1500, 'S', 'N'), (1560, 'B', 'N')],
    [found(1500, 1560, 1450, duo_failures_10m='6')]))
fixtures.append(chain_fx(
    'chain: failures after the sign-in do not change the burst the finding names',
    fails(0, 'N') + [(100, 'S', 'N')] + fails(200, 'N', n=6) + [(400, 'B', 'N')],
    [found(100, 400, 40, duo_failures_10m='5', blocked_turns='1')]))
fixtures.append(chain_fx(
    'chain: the application\'s events sent again (same transaction id, same event id) raise nothing',
    fails(900, 'O') + [(1000, 'S', 'O', 't1'), (1060, 'B', 'O', 'e1'), (1000, 'S', 'N', 't1'), (1060, 'B', 'N', 'e1')],
    []))

# A chain is raised in the run that indexes its LAST missing step, whichever of
# the three that is. Live it is usually the burst (above); on a stack that gets
# the application's events after the Duo backfill it is the sign-in or the turn.
fixtures.append(chain_fx(
    'chain: arrival order - the blocked turn indexed last raises the chain',
    fails(900, 'O') + [(998, 'D', 'O', 't1'), (1000, 'S', 'O', 't1'), (1060, 'B', 'N')],
    [staged]))
fixtures.append(chain_fx(
    'chain: arrival order - the sign-in record indexed last raises the chain',
    fails(900, 'O') + [(1000, 'S', 'N'), (1060, 'B', 'O')],
    [unmatched]))
fixtures.append(chain_fx(
    'chain: arrival order - the sign-in record indexed after Duo\'s own record of it raises the chain and names '
    'that record',
    fails(900, 'O') + [(998, 'D', 'O', 't1'), (1000, 'S', 'N', 't1'), (1060, 'B', 'O')],
    [staged]))
fixtures.append(chain_fx(
    'chain: arrival order - the application\'s events indexed after the whole burst raise the chain',
    fails(900, 'O') + [(1000, 'S', 'N'), (1060, 'B', 'N')],
    [unmatched]))
fixtures.append(chain_fx(
    'chain: arrival order - a burst split over two slots (3 failures before, 2 in it) raises the chain',
    fails(900, 'O', n=3) + fails(930, 'N', n=2) + [(1000, 'S', 'O'), (1060, 'B', 'O')],
    [unmatched]))

# One finding per sign-in, also when a second chain follows the first within the
# hour and its burst is the step indexed last (Duo's log trails the application
# by minutes, so live that is the usual order). The second chain's blocked turn
# was first counted as one more turn of the first chain, which had been raised:
# it never completed that chain, so it still completes its own.
second = found(1920, 1980, 1840, blocked_turns='1', duo_failures_10m='5')
fixtures.append(chain_fx(
    'chain: second chain - more blocked turns of a judged sign-in raise nothing while the second burst is not '
    'indexed',
    fails(0, 'O') + [(120, 'S', 'O'), (180, 'B', 'O'), (1920, 'S', 'N'), (1980, 'B', 'N')],
    []))
fixtures.append(chain_fx(
    'chain: second chain - its burst indexed last raises the second sign-in\'s own finding',
    fails(0, 'O') + [(120, 'S', 'O'), (180, 'B', 'O')] + fails(1800, 'N') + [(1920, 'S', 'O'), (1980, 'B', 'O')],
    [second]))
fixtures.append(chain_fx(
    'chain: second chain - the same events indexed in one slot raise both findings',
    fails(0, 'N') + [(120, 'S', 'N'), (180, 'B', 'N')] + fails(1800, 'N') + [(1920, 'S', 'N'), (1980, 'B', 'N')],
    [found(120, 180, 40, blocked_turns='1'), second]))

# What a finding SAYS is what was indexed when it was raised. A chain raised
# while the burst nearest to the sign-in is still in Duo's lag names an earlier
# burst (any burst within 30 minutes makes the chain), and nothing corrects it
# afterwards: the chain is raised once. chain_id, the finding's time and the
# risk are the same either way.
fixtures.append(chain_fx(
    'chain: nearest burst - raised while the nearer burst is not indexed, the finding names the earlier one',
    fails(0, 'O') + [(1660, 'S', 'N'), (1720, 'B', 'N')],
    [found(1660, 1720, 40, duo_failures_10m='5')]))
fixtures.append(chain_fx(
    'chain: nearest burst - the nearer burst arriving after the chain was judged raises nothing',
    fails(0, 'O') + fails(1560, 'N', n=6) + [(1660, 'S', 'O'), (1720, 'B', 'O')],
    []))
fixtures.append(chain_fx(
    'chain: nearest burst - the same events indexed in one slot name the nearer one',
    fails(0, 'N') + fails(1560, 'N', n=6) + [(1660, 'S', 'N'), (1720, 'B', 'N')],
    [found(1660, 1720, 1610, duo_failures_10m='6')]))

# --- Identity lookup gen (up to, never including, its outputlookup) -------------
DAY = 86400
dana = dict(firstname='Dana', lastname='Ortiz', email='Dana.Ortiz@corp.test', aliases={'alias1': 'D.Ortiz'},
            groups=[{'name': 'Sales'}, {'name': 'Engineering'}])
lee = dict(realname='Lee Park', status='locked out', is_enrolled=False, email='lee.park@corp.test', alias1='',
           alias2=None)
fixtures.append(gen_fx(
    'lookup gen: the newest COMPLETE snapshot wins over a newer incomplete one',
    [(T0, user_rec('dana.ortiz', T0, 2, 1, **dana)), (T0, user_rec('lee.park', T0, 2, 2, **lee)),
     (T0 + DAY, user_rec('dana.ortiz', T0 + DAY, 2, 1, status='disabled'))],
    [{'identity': 'dana.ortiz|dana.ortiz@corp.test|d.ortiz', 'nick': 'dana.ortiz', 'first': 'Dana', 'last': 'Ortiz',
      'email': 'dana.ortiz@corp.test', 'bunit': 'Engineering', 'category': 'cisco_duo|duo_status_active|duo_enrolled',
      'watchlist': 'false', 'startDate': '1700000000'},
     {'identity': 'lee.park|lee.park@corp.test', 'nick': 'lee.park', 'first': 'Lee', 'last': 'Park',
      'bunit': 'cisco_duo', 'category': 'cisco_duo|duo_status_locked_out|duo_unenrolled', 'watchlist': 'true'}]))
fixtures.append(gen_fx(
    'lookup gen: the newer of two complete snapshots is used',
    [(T0, user_rec('dana.ortiz', T0, 1, 1)), (T0 + DAY, user_rec('dana.ortiz', T0 + DAY, 1, 1, status='bypass'))],
    [{'identity': 'dana.ortiz|dana.ortiz@corp.test', 'category': 'cisco_duo|duo_status_bypass|duo_enrolled',
      'watchlist': 'true'}]))
fixtures.append(gen_fx(
    'lookup gen: with no complete snapshot it emits nothing (the file is kept)',
    [(T0, user_rec('dana.ortiz', T0, 3, 1)), (T0, user_rec('lee.park', T0, 3, 2))],
    []))
fixtures.append(gen_fx(
    'lookup gen: participants and personas stay out; a list of aliases is read',
    [(T0, user_rec('l5-ws1-03', T0, 3, 1)), (T0, user_rec('<<persona_key>>', T0, 3, 2, email=None)),
     (T0, user_rec('sam.lee', T0, 3, 3, aliases=['S.Lee']))],
    [{'identity': 'sam.lee|sam.lee@corp.test|s.lee', 'nick': 'sam.lee'}]))
fixtures.append(gen_fx(
    'lookup gen: JSON nulls and empty strings never become identity keys',
    [(T0, user_rec('dana.ortiz', T0, 2, 1, email=None, alias1='', alias3=None)),
     (T0, user_rec('lee.park', T0, 2, 2, email=None))],
    [{'identity': 'dana.ortiz'}, {'identity': 'lee.park'}]))

text = json.dumps(fixtures, indent=1) + '\n'
if '--check' in sys.argv[1:]:
    with open(OUT) as handle:
        stale = handle.read() != text
    print('%s is %s' % (OUT, 'STALE: rerun duo_spl_gen.py' if stale else 'current'))
    sys.exit(1 if stale else 0)
with open(OUT, 'w') as handle:
    handle.write(text)
print(len(fixtures), 'fixtures ->', OUT)
