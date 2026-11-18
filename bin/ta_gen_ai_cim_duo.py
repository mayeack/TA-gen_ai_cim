# encoding=utf-8
"""
ta_gen_ai_cim_duo.py - the entry point Splunk runs for the ta_gen_ai_cim_duo
modular input scheme (Splunk resolves a scheme to bin/<scheme>.py). All of the
input's logic lives in ta_gen_ai_cim_duo_input.py.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ta_gen_ai_cim_duo_input  # noqa: E402

if __name__ == '__main__':
    sys.exit(ta_gen_ai_cim_duo_input.main())
