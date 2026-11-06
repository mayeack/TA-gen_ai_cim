# encoding=utf-8
"""
pseudoco_identity_connector.py - Splunk SOAR connector "PseudoCo Identity", the
containment step of AI Trust Lab 5 ("Verify: Cisco Identity Intelligence").

NOT a simulator. disable user sets the room's victim persona to
status=disabled in Duo through the Duo Admin API, which ends the victim's
PseudoCo Assistant sessions (the app revokes them when Duo reports the account
disabled). Every result carries "simulated": false.

Guard rails, all checked before any call that writes:
  - disable user acts on exactly one account: the asset's victim_username. Any
    other username is refused, so a mis-typed or mis-resolved prompt can never
    disable another room's victim, a trusted persona or the facilitator.
  - The configured victim must be a Lab 5 victim persona
    (pseudoco_identity_personas.VICTIM_PERSONAS, generated from the TA's persona
    lookup); a trusted persona or a participant account (l5-*) is a
    configuration error.
  - Participant accounts and identities outside the persona domain are refused
    by every action.
  - A username that still holds "$" (or %24, Mission Control's URL-encoded
    form) is an unresolved ES token such as $user$ and is refused.
  - No undo: re-enabling the victim belongs to the lab's persona tooling
    (provision_personas.py --reset), not to an analyst.
  - TLS verified; the secret key is only used to sign and is never logged.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import uuid
from datetime import datetime, timezone

import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from pseudoco_identity_duo import DuoAdminClient, DuoError
from pseudoco_identity_personas import (
    PARTICIPANT_PREFIX, PERSONA_DOMAINS, TRUSTED_PERSONAS, VICTIM_PERSONAS,
)

MSG_USERNAME_MISSING = 'username is required'
MSG_TOKEN_UNRESOLVED = ("username '{value}' looks like an unresolved token - supply the "
                        "actual username (e.g. the finding's user)")
MSG_PARTICIPANT = ("'{value}' is a Lab 5 participant account (an attendee's own Duo "
                   "login); PseudoCo Identity never acts on it")
MSG_NOT_PERSONA = "'{value}' is not an AI Trust Lab 5 persona; PseudoCo Identity only reads Lab 5 personas"
MSG_NOT_VICTIM = ("'{value}' is not this room's victim ({victim}); PseudoCo Identity only "
                  "disables the victim configured on the asset")
MSG_BAD_VICTIM = ("asset victim_username '{value}' is not a Lab 5 victim persona - a trusted "
                  "persona or a participant account can never be configured as the victim")
MSG_NOT_FOUND = "Duo has no user '{value}'"
MSG_DISABLED = "Duo account {username} disabled (was {previous})"
MSG_ALREADY = "Duo account {username} was already disabled; nothing changed"


def _now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _ts_iso(value):
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).isoformat().replace('+00:00', 'Z')
    except (TypeError, ValueError, OverflowError, OSError):
        return None


class PseudocoIdentityConnector(BaseConnector):

    def __init__(self):
        super(PseudocoIdentityConnector, self).__init__()
        self._client = None
        self._victim = None
        self._room = ''
        self._config_error = None

    # -- lifecycle -------------------------------------------------------------

    def initialize(self):
        config = self.get_config() or {}
        self._room = (config.get('room') or '').strip()
        victim = (config.get('victim_username') or '').strip().lower()
        try:
            self._client = DuoAdminClient(config.get('api_host'), config.get('ikey'),
                                          config.get('skey'))
        except DuoError as exc:
            self._config_error = str(exc)
            return phantom.APP_SUCCESS
        if victim.startswith(PARTICIPANT_PREFIX) or victim in TRUSTED_PERSONAS or \
                victim not in VICTIM_PERSONAS:
            self._config_error = MSG_BAD_VICTIM.format(value=victim)
        self._victim = victim
        return phantom.APP_SUCCESS

    def finalize(self):
        return phantom.APP_SUCCESS

    def handle_action(self, param):
        action_id = self.get_action_identifier()
        self.debug_print('action_id', action_id)
        handlers = {
            'test_connectivity': self._handle_test_connectivity,
            'get_user': self._handle_get_user,
            'disable_user': self._handle_disable_user,
        }
        handler = handlers.get(action_id)
        if handler is None:
            action_result = self.add_action_result(ActionResult(dict(param)))
            return action_result.set_status(
                phantom.APP_ERROR, 'Unknown action identifier: {}'.format(action_id))
        return handler(param)

    # -- helpers ---------------------------------------------------------------

    def _ready(self, action_result):
        if self._config_error:
            action_result.set_status(phantom.APP_ERROR, self._config_error)
            return False
        return True

    def _resolve_username(self, action_result, param):
        """Normalise the username parameter to a persona username; None after
        setting an error."""
        raw = (param.get('username') or '').strip()
        if not raw:
            action_result.set_status(phantom.APP_ERROR, MSG_USERNAME_MISSING)
            return None
        if '$' in raw or '%24' in raw.upper() or any(ch.isspace() for ch in raw):
            action_result.set_status(phantom.APP_ERROR, MSG_TOKEN_UNRESOLVED.format(value=raw))
            return None
        value = raw.lower()
        local, _, domain = value.partition('@')
        if local.startswith(PARTICIPANT_PREFIX):
            action_result.set_status(phantom.APP_ERROR, MSG_PARTICIPANT.format(value=raw))
            return None
        if (domain and domain not in PERSONA_DOMAINS) or \
                local not in (TRUSTED_PERSONAS | VICTIM_PERSONAS):
            action_result.set_status(phantom.APP_ERROR, MSG_NOT_PERSONA.format(value=raw))
            return None
        return local

    def _record(self, user):
        return {
            'username': user.get('username'),
            'user_id': user.get('user_id'),
            'email': user.get('email'),
            'status': user.get('status'),
            'is_enrolled': user.get('is_enrolled'),
            'last_login': _ts_iso(user.get('last_login')),
            'lockout_reason': user.get('lockout_reason'),
            'groups': [g.get('name') for g in user.get('groups') or [] if isinstance(g, dict)],
            'is_room_victim': str(user.get('username', '')).lower() == self._victim,
            'room': self._room,
            'source': 'duo_admin_api',
            'simulated': False,
        }

    # -- actions ---------------------------------------------------------------

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._ready(action_result):
            self.save_progress('Test Connectivity Failed')
            return action_result.get_status()
        try:
            user = self._client.find_user(self._victim)
        except DuoError as exc:
            self.save_progress('Test Connectivity Failed')
            return action_result.set_status(phantom.APP_ERROR, str(exc))
        if not user:
            self.save_progress('Test Connectivity Failed')
            return action_result.set_status(phantom.APP_ERROR,
                                            MSG_NOT_FOUND.format(value=self._victim))
        message = 'Connected to {}; room victim {} is {} in Duo{}'.format(
            self._client.host, self._victim, user.get('status'),
            ' (room {})'.format(self._room) if self._room else '')
        self.save_progress(message)
        self.save_progress('Test Connectivity Passed')
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._ready(action_result):
            return action_result.get_status()
        username = self._resolve_username(action_result, param)
        if username is None:
            return action_result.get_status()
        try:
            user = self._client.find_user(username)
        except DuoError as exc:
            return action_result.set_status(phantom.APP_ERROR, str(exc))
        if not user:
            return action_result.set_status(phantom.APP_ERROR, MSG_NOT_FOUND.format(value=username))
        record = self._record(user)
        action_result.add_data(record)
        action_result.update_summary({'username': username, 'status': record['status'],
                                      'is_room_victim': record['is_room_victim'],
                                      'simulated': False})
        return action_result.set_status(phantom.APP_SUCCESS, 'Duo user {} is {}'.format(
            username, record['status']))

    def _handle_disable_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._ready(action_result):
            return action_result.get_status()
        username = self._resolve_username(action_result, param)
        if username is None:
            return action_result.get_status()
        if username != self._victim:
            return action_result.set_status(phantom.APP_ERROR, MSG_NOT_VICTIM.format(
                value=username, victim=self._victim))
        try:
            user = self._client.find_user(username)
            if not user:
                return action_result.set_status(phantom.APP_ERROR,
                                                MSG_NOT_FOUND.format(value=username))
            previous = user.get('status')
            if previous == 'disabled':
                updated, message = user, MSG_ALREADY.format(username=username)
            else:
                updated = self._client.set_status(user['user_id'], 'disabled')
                message = MSG_DISABLED.format(username=username, previous=previous)
        except DuoError as exc:
            return action_result.set_status(phantom.APP_ERROR, str(exc))
        if not isinstance(updated, dict) or updated.get('status') != 'disabled':
            return action_result.set_status(phantom.APP_ERROR, (
                'Duo did not confirm the disable for {}: status is {}'.format(
                    username, (updated or {}).get('status'))))
        record = self._record(updated)
        record.update({'previous_status': previous, 'reason': (param.get('reason') or '').strip(),
                       'transaction_id': str(uuid.uuid4()), 'timestamp': _now_iso(),
                       'message': message})
        action_result.add_data(record)
        action_result.update_summary({'username': username, 'status': 'disabled',
                                      'previous_status': previous,
                                      'transaction_id': record['transaction_id'],
                                      'simulated': False})
        return action_result.set_status(phantom.APP_SUCCESS, message)


if __name__ == '__main__':
    import json
    import sys
    # Local smoke run against a REAL Duo tenant - it really disables the victim:
    #   python3 pseudoco_identity_connector.py <action_id> '<param json>' '<config json>'
    # (needs the phantom package on sys.path; see tools/soar/tests/phantom_shim)
    connector = PseudocoIdentityConnector()
    action = sys.argv[1] if len(sys.argv) > 1 else 'test_connectivity'
    params = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    config = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    connector._shim_prepare(config, action)
    connector.initialize()
    connector.handle_action(params)
    for result in connector.get_action_results():
        print(json.dumps({'status': result.get_status(), 'message': result.get_message(),
                          'summary': result.get_summary(), 'data': result.get_data()},
                         indent=2, default=str))
