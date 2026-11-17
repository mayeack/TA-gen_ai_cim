# encoding=utf-8
"""
duo_spl_gen.py - builds duo_spl.json, the live SPL fixtures for
tools/tests/test_duo_spl.py (dev only; tools/ never ships).

    python3 tools/tests/fixtures/duo_spl_gen.py           # rewrite duo_spl.json
    python3 tools/tests/fixtures/duo_spl_gen.py --check   # exit 1 if it is stale

Invented identities (dana.ortiz, lee.park, sam.lee @corp.test) and RFC 5737
addresses only. A persona login is never written here: fixtures use the
<<persona_key>> (a persona's short name) and <<persona_email>> (a persona's
email) tokens, which test_duo_spl.py reads from the persona lookup.
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
RULE_TABLE = ' | table user, risk_score, signature, severity, fraud_reports, failures, max_failures_10m, duo_users, src, app'
LOOKUP_GEN = 'GenAI - Identity - Duo Identity Lookup Gen'
GEN_TAIL = {'search': LOOKUP_GEN, 'from': '| eval snapshot_total=tonumber(snapshot_total)', 'to': '| outputlookup'}


def tstats_rows(rows):
    """makeresults rows shaped like the rule's tstats output after its rename
    (its BY list: _time, user, action, signature_id, src, app; no result):
    each row (offset_seconds, user, action, signature_id, src, count)."""
    parts = []
    for i, (off, user, action, sig, src, count) in enumerate(rows, 1):
        parts.append((i, off, user, action, sig, src, count))

    def col(idx):
        return 'case(%s)' % ', '.join('n==%d, %s' % (p[0], json.dumps(p[idx])) for p in parts)
    return ('| makeresults count=%d | streamstats count as n | eval _time=%d+%s, user=%s, action=%s, '
            'signature_id=%s, src=%s, app="Corp VPN", count=%s | fields - n'
            % (len(parts), T0, col(1), col(2), col(3), col(4), col(5), col(6)))


def rule_fx(name, rows, expect, pre=''):
    return {'name': name, 'spl': tstats_rows(rows) + pre, 'tail': RULE_TAIL, 'append': RULE_TABLE, 'expect': expect}


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

# --- Risk rule (its post-tstats pipeline, rows shaped like the tstats output) ---
fixtures.append(rule_fx(
    'rule: 5 failures within 10 minutes raise risk 40 on the join key',
    [(0, 'dana.ortiz', 'failure', 'no_response', '198.51.100.23', 1),
     (60, 'dana.ortiz', 'failure', 'no_response', '198.51.100.23', 1),
     (120, 'dana.ortiz', 'failure', 'no_response', 'unknown', 1),
     (180, 'dana.ortiz', 'failure', 'no_response', '198.51.100.23', 1),
     (240, 'dana.ortiz', 'failure', 'user_cancelled', '198.51.100.23', 1)],
    [{'user': 'dana.ortiz', 'risk_score': '40', 'signature': 'Duo authentication denial burst', 'severity': 'medium',
      'fraud_reports': '0', 'failures': '5', 'max_failures_10m': '5', 'duo_users': 'dana.ortiz',
      'src': '198.51.100.23', 'app': 'Corp VPN'}]))
fixtures.append(rule_fx(
    'rule: 4 failures in 10 minutes and a 5th 18 minutes later raise nothing',
    [(0, 'dana.ortiz', 'failure', 'no_response', '198.51.100.23', 1),
     (60, 'dana.ortiz', 'failure', 'no_response', '198.51.100.23', 1),
     (120, 'dana.ortiz', 'failure', 'no_response', '198.51.100.23', 1),
     (180, 'dana.ortiz', 'failure', 'no_response', '198.51.100.23', 1),
     (1080, 'dana.ortiz', 'failure', 'no_response', '198.51.100.23', 1)],
    []))
fixtures.append(rule_fx(
    'rule: a tstats row with count=5 is five failures',
    [(0, 'dana.ortiz', 'failure', 'no_response', '198.51.100.23', 5)],
    [{'user': 'dana.ortiz', 'risk_score': '40', 'failures': '5', 'max_failures_10m': '5'}]))
fixtures.append(rule_fx(
    'rule: one fraud report raises risk 80',
    [(0, 'lee.park', 'failure', 'user_marked_fraud', '203.0.113.9', 1)],
    [{'user': 'lee.park', 'risk_score': '80', 'signature': 'Duo user marked fraud', 'severity': 'high',
      'fraud_reports': '1', 'failures': '1'}]))
fixtures.append(rule_fx(
    'rule: Lab 5 participant accounts never raise it',
    [(i * 30, 'l5-ws1-03', 'failure', 'no_response', '198.51.100.40', 1) for i in range(6)],
    []))
fixtures.append(rule_fx(
    'rule: an email-form Duo username keys on its lowercased local part',
    [(i * 30, 'Dana.Ortiz@corp.test', 'failure', 'no_response', '198.51.100.23', 1) for i in range(5)],
    [{'user': 'dana.ortiz', 'duo_users': 'Dana.Ortiz@corp.test', 'risk_score': '40'}]))
fixtures.append(rule_fx(
    'rule: a null or unknown Duo user never becomes a risk object',
    [(i * 30, 'null' if i % 2 else 'unknown', 'failure', 'no_response', '198.51.100.23', 1) for i in range(10)],
    []))
mixed = ([(i * 40, 'dana.ortiz', 'failure', 'denied', '198.51.100.7', 1) for i in range(3)] +
         [(200 + i * 40, 'dana.ortiz', 'failure', 'no_response', '198.51.100.23', 1) for i in range(5)])
scope = (' | eval index=if(n<=3, "gen_ai_log", "duo"), sourcetype=if(n<=3, "gen_ai:json", "%s")' % AUTH)
fx = rule_fx('rule: a PseudoCo sign-in denial never adds to a Duo burst (scope emulated with genai_duo_auth_events)',
             mixed, [{'user': 'dana.ortiz', 'failures': '5', 'max_failures_10m': '5', 'src': '198.51.100.23'}])
fx['spl'] = fx['spl'].replace(' | fields - n', scope + ' | search `genai_duo_auth_events` | fields - n')
fixtures.append(fx)
few = ([(i * 40, 'dana.ortiz', 'failure', 'denied', '198.51.100.7', 1) for i in range(3)] +
       [(200 + i * 40, 'dana.ortiz', 'failure', 'no_response', '198.51.100.23', 1) for i in range(3)])
fx = rule_fx('rule: 3 PseudoCo + 3 Duo denials for one user raise nothing (only Duo\'s 3 count)', few, [])
fx['spl'] = fx['spl'].replace(' | fields - n', scope + ' | search `genai_duo_auth_events` | fields - n')
fixtures.append(fx)

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
