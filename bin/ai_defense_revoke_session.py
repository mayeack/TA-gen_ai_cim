#!/usr/bin/env python
# encoding=utf-8
"""
ai_defense_revoke_session.py - Alert Action: Revoke Session / API Key

Simulated containment. Records an auditable "session revoked" action against
the GenAI session that carried the blocked prompts. Does not call an IdP,
token service, or Cisco AI Defense - see ai_defense_response.py for the
rationale and the `simulated` flag contract.

Usage:
    Run as an adaptive response action from a finding, or from a Containment
    task in the AI Incident Response Plan.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_defense_response import run_action


if __name__ == '__main__':
    run_action(
        action='revoke_session',
        action_label='Revoke Session / API Key',
        target_type='session',
        target_field='session_id',
        summary_template=(
            'Session {target} revoked and its API credentials rotated after '
            'Cisco AI Defense prompt injection activity.'
        ),
    )
