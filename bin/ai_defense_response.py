#!/usr/bin/env python
# encoding=utf-8
"""
ai_defense_response.py - Shared logic for the AI Defense response actions.

These alert actions are SIMULATED containment steps. They do not call Cisco
AI Defense, an IdP, or any other external system. Each one records a
structured audit event in the `gen_ai_log` index under sourcetype
`ai_cim:response:action` and reports success, so that an analyst working a
finding or a response plan task sees a real, auditable "action taken" entry
without a paired SOAR instance.

Every emitted event carries `"simulated": true`. Never remove that flag: it is
the only thing distinguishing a demo containment record from a real one.

The three thin wrappers (ai_defense_suspend_user.py,
ai_defense_revoke_session.py, ai_defense_tighten_guardrail.py) import
`run_action` from here; the payload parsing, field resolution and audit
emission live in this module only.

Privacy: these actions deliberately never read or log prompt/response content
(gen_ai.input.messages / gen_ai.output.messages / response_text). Only routing
and identity fields are recorded.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import os
import sys
import json
import uuid
from datetime import datetime, timezone

# Add Splunk SDK paths - use lib directory in this app
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
lib_path = os.path.join(app_root, 'lib')
if lib_path not in sys.path:
    sys.path.insert(0, lib_path)

import splunklib.client as client


AUDIT_INDEX = 'gen_ai_log'
AUDIT_SOURCETYPE = 'ai_cim:response:action'
AUDIT_SOURCE = 'ai_defense_response'


# Field aliases, most specific first. Findings raised by the AI Governance
# detections expose the short names (nes_fields); raw gen_ai_log events and
# ad-hoc invocations expose the normalized gen_ai.* names.
FIELD_ALIASES = {
    'enduser_id': ('enduser_id', 'gen_ai.user.id', 'user', 'risk_object', 'actor'),
    'session_id': ('session_id', 'gen_ai.session.id', 'conversation_id'),
    'app_name': ('app_name', 'gen_ai.app.name', 'app', 'service_name'),
    'model_name': ('model_name', 'gen_ai.request.model', 'models', 'request_model'),
    'client_address': ('client_address', 'gen_ai.client.address', 'src'),
    'event_id': ('event_id', 'gen_ai.event.id', 'gen_ai.request.id', 'request_id'),
}


def setup_logging(log_name='ai_defense_response'):
    """Set up a named logger with its own FileHandler.

    Mirrors sync_snow_asset.setup_logging so each action can log to its own
    file without basicConfig stomping on the others.
    """
    import logging
    _logger = logging.getLogger(log_name)
    if not _logger.handlers:
        _logger.setLevel(logging.INFO)
        log_file = os.path.join(
            os.environ.get('SPLUNK_HOME', '/opt/splunk'),
            'var', 'log', 'splunk', '{}.log'.format(log_name))
        handler = logging.FileHandler(log_file, mode='a')
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        _logger.addHandler(handler)
    return _logger


def _param(value):
    """Treat empty strings, the conf-spec placeholder '<string>', and
    unresolved $result...$ tokens as unset.

    Same semantics as create_snow_case._param - the alert action UI hands back
    the literal placeholder when a param was never filled in.
    """
    if not value:
        return None
    value = str(value).strip()
    if not value or value == '<string>' or (value.startswith('$') and value.endswith('$')):
        return None
    return value


def _first(result, keys):
    """Return the first populated value in `result` among `keys`.

    Multi-value fields arrive as a list (e.g. `models` from a stats values());
    collapse those to the first element so the audit record stays scalar.
    """
    for key in keys:
        value = result.get(key)
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        value = _param(value)
        if value:
            return value
    return None


def resolve_fields(payload):
    """Pull the routing/identity fields out of the alert action payload.

    Explicit UI params win over fields from the triggering result, so an
    analyst can retarget an ad-hoc run without editing the finding.
    """
    config = payload.get('configuration', {}) or {}
    result = payload.get('result', {}) or {}

    fields = {}
    for name, aliases in FIELD_ALIASES.items():
        fields[name] = _param(config.get(name)) or _first(result, aliases)
    return fields


def emit_audit_event(session_key, event):
    """Write the audit record to gen_ai_log.

    Raises on failure so the caller can exit non-zero - a containment action
    that silently failed to record itself is worse than one that errors.
    """
    service = client.connect(
        token=session_key,
        owner='nobody',
        app='TA-gen_ai_cim'
    )

    if AUDIT_INDEX not in service.indexes:
        raise RuntimeError(
            "index '{}' does not exist on this instance; run the Show "
            "post-deploy script (or create the index) before using the "
            "AI Defense response actions".format(AUDIT_INDEX))

    service.indexes[AUDIT_INDEX].submit(
        json.dumps(event),
        sourcetype=AUDIT_SOURCETYPE,
        source=AUDIT_SOURCE,
    )


def run_action(action, action_label, target_type, target_field, summary_template):
    """Entry point shared by the three AI Defense response action wrappers.

    Args:
        action: short machine name, e.g. 'suspend_user'
        action_label: human label matching the alert_actions.conf `label`
        target_type: CIM-ish entity class ('identity', 'session', 'policy')
        target_field: which resolved field this action acts on
        summary_template: format string taking `target`, used for the message
    """
    logger = setup_logging('ai_defense_{}'.format(action))

    try:
        payload = json.loads(sys.stdin.read())
    except Exception:
        logger.error("%s: no input payload provided", action)
        print("Error: No input payload provided", file=sys.stderr)
        sys.exit(1)

    session_key = payload.get('session_key')
    if not session_key:
        logger.error("%s: no session_key in payload", action)
        print("Error: No session key provided", file=sys.stderr)
        sys.exit(2)

    fields = resolve_fields(payload)
    target = fields.get(target_field)

    if not target:
        logger.error("%s: could not resolve target field '%s' from payload",
                     action, target_field)
        print("Error: could not determine {} to act on. Set the '{}' parameter "
              "on the action, or run it from a finding that carries that field."
              .format(target_type, target_field), file=sys.stderr)
        sys.exit(2)

    execution_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    event = {
        'timestamp': now.isoformat(),
        'action': action,
        'action_label': action_label,
        'status': 'success',
        # Never remove: marks this as a demo/simulated containment record
        # rather than a real enforcement action.
        'simulated': True,
        'target_type': target_type,
        'target': target,
        'execution_id': execution_id,
        'executed_by': payload.get('owner') or payload.get('user') or 'unknown',
        'search_name': payload.get('search_name'),
        'sid': payload.get('sid'),
        'message': summary_template.format(target=target),
    }
    # Carry through whatever context the triggering result had, so the audit
    # record can be correlated back to the originating AI Defense event.
    for name, value in fields.items():
        if value:
            event[name] = value

    try:
        emit_audit_event(session_key, event)
    except Exception as exc:
        logger.error("%s: failed to write audit event: %s", action, exc)
        print("Error: failed to record response action: {}".format(exc),
              file=sys.stderr)
        sys.exit(2)

    logger.info("%s: recorded simulated action on %s '%s' (execution_id=%s)",
                action, target_type, target, execution_id)
    print("{} recorded for {} '{}' (execution_id={})".format(
        action_label, target_type, target, execution_id))
    sys.exit(0)
