#!/usr/bin/env python
# encoding=utf-8
"""
ai_defense_tighten_guardrail.py - Alert Action: Tighten Guardrail Policy

Simulated containment. Records an auditable "guardrail policy tightened"
action against the GenAI application that was targeted. Does not call the
Cisco AI Defense policy API - see ai_defense_response.py for the rationale
and the `simulated` flag contract.

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
        action='tighten_guardrail',
        action_label='Tighten Guardrail Policy',
        target_type='policy',
        target_field='app_name',
        summary_template=(
            'Cisco AI Defense guardrail profile for application {target} '
            'tightened to block the observed injection techniques.'
        ),
    )
