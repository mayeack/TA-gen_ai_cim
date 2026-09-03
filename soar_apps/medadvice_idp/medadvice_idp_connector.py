# encoding=utf-8
"""
medadvice_idp_connector.py - Splunk SOAR connector for the "MedAdvice Identity
Provider" stub app.

This app is a SIMULATOR. It exists so that Splunk Enterprise Security (response
plan tasks, the Automation tab and the Guided Response agent) can run a real,
repeatable "disable user" containment action against the MedAdvice / DemoBot
workshop personas without any directory, API or network call. Every result
carries "simulated": true; that flag is the only thing separating a lab
containment record from a real one, so never strip it.

Design notes:
  - Stateless: disabling a user never changes what the next call sees, so any
    number of attendees can run the same action with the same outcome.
  - Personas come from medadvice_idp_consts.PERSONAS, generated from the TA's
    ES identity lookup (lookups/medadvice_identities.csv). Unknown usernames
    get a synthesised, clearly labelled record rather than an error, because
    a containment step that fails on an unfamiliar name is a worse demo than
    one that succeeds and says so.
  - A username that still contains "$" (or its percent-encoded form %24, since
    Mission Control stores plan strings URL-encoded) is an unresolved ES token
    such as $user$; the action fails with an explicit message instead of
    "disabling" a token.
  - Standard library only; Python 3.9 and 3.13.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from medadvice_idp_consts import (
    CLIENT_ADDRESSES, DEPARTMENTS, DIRECTORY_DEFAULT, EMAIL_INDEX, MODE_DEFAULT,
    MSG_DISABLED, MSG_ENABLED, MSG_GET_USER, MSG_LIST_SESSIONS,
    MSG_MODE_UNSUPPORTED, MSG_SESSIONS_CLEARED, MSG_TEST_OK,
    MSG_TOKEN_UNRESOLVED, MSG_USERNAME_MISSING, PERSONAS, SESSION_APP,
)


def _utcnow():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _digest(*parts):
    return hashlib.sha1(':'.join(parts).encode('utf-8')).hexdigest()


class MedadviceIdpConnector(BaseConnector):

    def __init__(self):
        super(MedadviceIdpConnector, self).__init__()
        self._mode = MODE_DEFAULT
        self._directory = DIRECTORY_DEFAULT

    # -- lifecycle -----------------------------------------------------------

    def initialize(self):
        config = self.get_config() or {}
        self._mode = (config.get('mode') or MODE_DEFAULT).strip().lower()
        self._directory = (config.get('directory_name') or DIRECTORY_DEFAULT).strip()
        return phantom.APP_SUCCESS

    def finalize(self):
        return phantom.APP_SUCCESS

    def handle_action(self, param):
        action_id = self.get_action_identifier()
        self.debug_print('action_id', action_id)
        handlers = {
            'test_connectivity': self._handle_test_connectivity,
            'get_user': self._handle_get_user,
            'list_user_sessions': self._handle_list_user_sessions,
            'disable_user': self._handle_disable_user,
            'enable_user': self._handle_enable_user,
            'clear_user_sessions': self._handle_clear_user_sessions,
        }
        handler = handlers.get(action_id)
        if handler is None:
            action_result = self.add_action_result(ActionResult(dict(param)))
            return action_result.set_status(
                phantom.APP_ERROR, 'Unknown action identifier: {}'.format(action_id))
        return handler(param)

    # -- helpers ---------------------------------------------------------------

    def _mode_ok(self, action_result):
        if self._mode != MODE_DEFAULT:
            action_result.set_status(phantom.APP_ERROR,
                                     MSG_MODE_UNSUPPORTED.format(mode=self._mode))
            return False
        return True

    def _resolve_username(self, action_result, param):
        """Normalise the username parameter; return None after setting an error."""
        raw = (param.get('username') or '').strip()
        if not raw:
            action_result.set_status(phantom.APP_ERROR, MSG_USERNAME_MISSING)
            return None
        if '$' in raw or '%24' in raw.upper() or any(ch.isspace() for ch in raw):
            action_result.set_status(phantom.APP_ERROR,
                                     MSG_TOKEN_UNRESOLVED.format(value=raw))
            return None
        value = raw.lower()
        if '@' in value:
            value = EMAIL_INDEX.get(value, value.split('@', 1)[0])
        return value

    def _persona(self, username):
        persona = PERSONAS.get(username)
        if persona:
            record = dict(persona)
        else:
            record = {
                'username': username,
                'email': '{}@{}'.format(username, self._directory),
                'display_name': username.replace('.', ' ').replace('_', ' ').title(),
                'first_name': '', 'last_name': '',
                'business_unit': 'medadvice', 'category': 'unknown',
                'watchlist': False, 'priority': 'medium', 'known': False,
            }
        digest = _digest(username)
        idx = int(digest[:8], 16)
        record['user_id'] = 'MA-{}'.format(digest[:8].upper())
        record['department'] = DEPARTMENTS[idx % len(DEPARTMENTS)]
        record['mfa_enrolled'] = True
        record['last_login'] = _iso(_utcnow() - timedelta(minutes=5 + idx % 240))
        record['directory'] = self._directory
        record['status'] = 'active'
        record['simulated'] = True
        return record

    def _sessions(self, username):
        digest = _digest(username, 'sessions')
        count = 1 + int(digest[:2], 16) % 2
        now = _utcnow()
        sessions = []
        for n in range(count):
            sid = _digest(username, 'session', str(n))[:12]
            addr = CLIENT_ADDRESSES[int(digest[2 + n], 16) % len(CLIENT_ADDRESSES)]
            started = now - timedelta(minutes=12 + 30 * n + int(digest[4:6], 16) % 20)
            sessions.append({
                'session_id': 'demobot-{}'.format(sid),
                'username': username,
                'app': SESSION_APP,
                'client_address': addr,
                'started': _iso(started),
                'last_seen': _iso(now - timedelta(minutes=n)),
                'status': 'active',
                'simulated': True,
            })
        return sessions

    def _transaction(self, record, new_status, param, message):
        record['previous_status'] = 'active' if new_status == 'disabled' else 'disabled'
        record['status'] = new_status
        record['reason'] = (param.get('reason') or '').strip()
        record['transaction_id'] = str(uuid.uuid4())
        record['timestamp'] = _iso(_utcnow())
        record['message'] = message
        return record

    # -- actions -----------------------------------------------------------------

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._mode_ok(action_result):
            self.save_progress('Test Connectivity Failed')
            return action_result.get_status()
        message = MSG_TEST_OK.format(mode=self._mode, directory=self._directory)
        self.save_progress(message)
        self.save_progress('Test Connectivity Passed')
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._mode_ok(action_result):
            return action_result.get_status()
        username = self._resolve_username(action_result, param)
        if username is None:
            return action_result.get_status()
        record = self._persona(username)
        action_result.add_data(record)
        action_result.update_summary({
            'username': username, 'status': record['status'],
            'known': record['known'], 'simulated': True,
        })
        return action_result.set_status(phantom.APP_SUCCESS, MSG_GET_USER.format(
            username=username,
            known='known persona' if record['known'] else 'synthesised record'))

    def _handle_list_user_sessions(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._mode_ok(action_result):
            return action_result.get_status()
        username = self._resolve_username(action_result, param)
        if username is None:
            return action_result.get_status()
        sessions = self._sessions(username)
        for session in sessions:
            action_result.add_data(session)
        action_result.update_summary({
            'username': username, 'session_count': len(sessions), 'simulated': True,
        })
        return action_result.set_status(phantom.APP_SUCCESS, MSG_LIST_SESSIONS.format(
            count=len(sessions), username=username))

    def _handle_disable_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._mode_ok(action_result):
            return action_result.get_status()
        username = self._resolve_username(action_result, param)
        if username is None:
            return action_result.get_status()
        message = MSG_DISABLED.format(username=username)
        record = self._transaction(self._persona(username), 'disabled', param, message)
        action_result.add_data(record)
        action_result.update_summary({
            'username': username, 'status': 'disabled',
            'transaction_id': record['transaction_id'], 'simulated': True,
        })
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_enable_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._mode_ok(action_result):
            return action_result.get_status()
        username = self._resolve_username(action_result, param)
        if username is None:
            return action_result.get_status()
        message = MSG_ENABLED.format(username=username)
        record = self._transaction(self._persona(username), 'active', param, message)
        action_result.add_data(record)
        action_result.update_summary({
            'username': username, 'status': 'active',
            'transaction_id': record['transaction_id'], 'simulated': True,
        })
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_clear_user_sessions(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._mode_ok(action_result):
            return action_result.get_status()
        username = self._resolve_username(action_result, param)
        if username is None:
            return action_result.get_status()
        transaction_id = str(uuid.uuid4())
        sessions = self._sessions(username)
        for session in sessions:
            session['status'] = 'revoked'
            session['transaction_id'] = transaction_id
            action_result.add_data(session)
        action_result.update_summary({
            'username': username, 'sessions_revoked': len(sessions),
            'transaction_id': transaction_id, 'simulated': True,
        })
        return action_result.set_status(phantom.APP_SUCCESS, MSG_SESSIONS_CLEARED.format(
            count=len(sessions), username=username))


if __name__ == '__main__':
    import json
    import sys
    # Local smoke run: python3 medadvice_idp_connector.py <action_id> '<param json>'
    # (needs the phantom package on sys.path; see tools/soar/tests/phantom_shim)
    connector = MedadviceIdpConnector()
    action = sys.argv[1] if len(sys.argv) > 1 else 'test_connectivity'
    params = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    connector._shim_prepare({}, action)
    connector.initialize()
    connector.handle_action(params)
    for result in connector.get_action_results():
        print(json.dumps({'status': result.get_status(), 'message': result.get_message(),
                          'summary': result.get_summary(), 'data': result.get_data()},
                         indent=2, default=str))
