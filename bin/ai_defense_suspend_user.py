#!/usr/bin/env python
# encoding=utf-8
"""
ai_defense_suspend_user.py - Alert Action: Suspend User (AI Defense)

Simulated containment. Records an auditable "user suspended" action against
the identity that triggered the AI Defense policy block. Does not call an IdP
or Cisco AI Defense - see ai_defense_response.py for the rationale and the
`simulated` flag contract.

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
        action='suspend_user',
        action_label='Suspend User (AI Defense)',
        target_type='identity',
        target_field='enduser_id',
        summary_template=(
            'Account {target} suspended pending review of Cisco AI Defense '
            'prompt injection activity.'
        ),
    )
