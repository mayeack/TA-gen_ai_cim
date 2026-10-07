# encoding=utf-8
"""
Offline test for bin/genaiseedes.py - the `| genaiseedes` command wrapper
around the seeding core.

test_seed.py covers genai_es_seed.py but never ran the command class, and the
class carried a crash that only the real dispatch hit: generate() assigned
self.logger, which splunklib's SearchCommand defines as a read-only property.
Every scheduled run of "GenAI - ES - Seed Response Plan and SOAR Binding" died
with AttributeError before writing anything, so on every stack the
"ai security incident" investigation type and the response plan were missing.
This test drives generate() end to end against the fake splunkd so that class
of bug fails here instead of on a workshop stack.

    /opt/splunk104/bin/splunk cmd python3.13 -m unittest discover -s tools/soar/tests -v
"""

import logging
import os
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, os.path.join(REPO, 'bin'))
sys.path.insert(0, HERE)

# A handler already on the logger makes _setup_logging() return early, so an
# import under `splunk cmd` never writes test runs into the real genaiseedes.log.
logging.getLogger('genaiseedes').addHandler(logging.NullHandler())

import genaiseedes  # noqa: E402
from test_seed import FakeSplunkd  # noqa: E402


def run_command(settings):
    fake = FakeSplunkd()
    cls = genaiseedes.GenaiSeedEsCommand
    with mock.patch.object(genaiseedes.seed, 'Splunkd', return_value=fake), \
            mock.patch.object(cls, '_connect', return_value=None), \
            mock.patch.object(cls, '_settings', return_value=settings):
        command = cls()
        command._metadata = SimpleNamespace(searchinfo=SimpleNamespace(
            splunkd_uri='https://127.0.0.1:8089', session_key='fake-session-key'))
        rows = list(command.generate())
    return fake, {row['step']: row['status'] for row in rows}


class GenerateTest(unittest.TestCase):

    def test_generate_seeds_the_investigation_type(self):
        fake, steps = run_command({'bind_soar_actions': 'false'})
        key = genaiseedes.seed.INVESTIGATION_TYPE
        self.assertEqual(steps.get('investigation type "{}"'.format(key)), 'OK', steps)
        self.assertIn(key, fake.live)
        self.assertEqual(fake.live[key]['response_template_ids'],
                         [fake.live['ai_incident_response_plan']['template_id']])
        self.assertNotIn('FAIL', steps.values(), steps)

    def test_generate_honours_seed_response_plan_off(self):
        fake, steps = run_command({'seed_response_plan': 'false', 'bind_soar_actions': 'false'})
        self.assertEqual(steps.get('response plan'), 'SKIP', steps)
        self.assertEqual(fake.writes, [])

    def test_route_findings_to_queue_setting_reaches_the_queue(self):
        fake, _ = run_command({'bind_soar_actions': 'false'})
        self.assertEqual(fake.live['ai_findings_queue']['rule_string'], '')
        fake, steps = run_command({'bind_soar_actions': 'false', 'route_findings_to_queue': 'true'})
        self.assertEqual(fake.live['ai_findings_queue']['rule_string'], genaiseedes.seed.QUEUE_RULE_STRING)
        self.assertEqual(steps.get('queue routing'), 'OK', steps)

    def test_command_never_assigns_the_splunklib_logger(self):
        with open(os.path.join(REPO, 'bin', 'genaiseedes.py'), encoding='utf-8') as handle:
            self.assertNotIn('self.logger =', handle.read())

    def test_no_method_is_shadowed_by_a_splunklib_instance_attribute(self):
        base = genaiseedes.GeneratingCommand()
        defined = set(vars(genaiseedes.GenaiSeedEsCommand))
        self.assertEqual(defined & set(vars(base)), set())


if __name__ == '__main__':
    unittest.main()
