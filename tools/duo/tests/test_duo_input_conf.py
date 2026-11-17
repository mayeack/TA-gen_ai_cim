# encoding=utf-8
"""
Offline checks that the Duo modular input ships OFF and that its scheme,
spec and checkpoint collection agree: default/inputs.conf,
README/inputs.conf.spec and default/collections.conf. Also that the Duo
identity source does not ship as a stanza (R-INP-002), only as a commented
example.

    python3 -m unittest discover -s tools/duo/tests -v
"""

import io
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
for _p in (os.path.join(REPO, 'bin'), os.path.join(REPO, 'lib')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import ta_gen_ai_cim_duo_input as duo_input  # noqa: E402


def read_conf(*parts):
    """{stanza: {key: value}}; comments and blank lines skipped."""
    stanzas, current = {}, None
    with io.open(os.path.join(REPO, *parts), encoding='utf-8') as handle:
        for line in handle.read().split('\n'):
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            m = re.match(r'^\[(.*)\]\s*$', line)
            if m:
                current = stanzas.setdefault(m.group(1), {})
            elif '=' in line and current is not None:
                key, value = line.split('=', 1)
                current[key.strip()] = value.strip()
    return stanzas


def read_text(*parts):
    with io.open(os.path.join(REPO, *parts), encoding='utf-8') as handle:
        return handle.read()


class InputsConfTests(unittest.TestCase):

    def setUp(self):
        self.inputs = read_conf('default', 'inputs.conf')

    def test_only_the_scheme_default_stanza_ships(self):
        self.assertEqual([s for s in self.inputs if s.startswith(duo_input.SCHEME + '://')], [])
        scheme = self.inputs[duo_input.SCHEME]
        self.assertEqual(scheme['python.version'], 'python3')
        self.assertEqual(scheme['python.required'], '3.13')
        self.assertGreaterEqual(int(scheme['interval']), duo_input.MIN_INTERVAL_SECONDS)
        self.assertEqual(int(scheme['lag_seconds']), duo_input.DEFAULT_LAG_SECONDS)
        self.assertEqual(int(scheme['initial_lookback_hours']), duo_input.DEFAULT_LOOKBACK_HOURS)
        self.assertNotIn('index', scheme)                              # instance-set, never gen_ai_log
        self.assertNotIn('gen_ai_log', str(scheme))

    def test_duo_identity_source_does_not_ship(self):
        # R-INP-002: its CSV is generated at runtime and never ships, and ES's
        # identity manager checks every identity source's file, a disabled
        # source's included (an ERROR in splunkd.log every 5 minutes). So the
        # stanza is a commented example an owner copies into local/, enabled.
        name = 'identity_manager://ta_gen_ai_cim_duo_identities'
        self.assertNotIn(name, self.inputs)
        lines = read_text('default', 'inputs.conf').split('\n')
        at = [i for i, line in enumerate(lines) if '[{}]'.format(name) in line]
        self.assertEqual(len(at), 1, at)
        example = lines[at[0]:at[0] + 6]
        self.assertEqual([line for line in example if not line.startswith('#')], [])
        self.assertEqual([line.lstrip('#').strip() for line in example],
                         ['[{}]'.format(name), 'target = identity', 'url = lookup://ta_gen_ai_cim_duo_identities',
                          'category = Cisco Duo users',
                          'description = Cisco Duo users from the Duo Admin API users snapshot '
                          '(ta_gen_ai_cim:duo:user)', 'disabled = false'])
        # The Lab 5 persona source does ship (with its CSV), disabled.
        self.assertEqual(self.inputs['identity_manager://pseudoco_identity_personas']['disabled'], 'true')

    def test_header_block(self):
        head = read_text('default', 'inputs.conf').split('\n[', 1)[0]
        self.assertIn('inputs.conf', head)
        self.assertIn('Compatible with: Splunk Enterprise 9.0+, Splunk Cloud', head)
        self.assertIn('#' * 79, head)


class SpecTests(unittest.TestCase):

    def test_spec_documents_every_scheme_argument(self):
        spec = read_text('README', 'inputs.conf.spec')
        self.assertIn('[{}://<name>]'.format(duo_input.SCHEME), spec)
        documented = set(re.findall(r'(?m)^([a-z_]+) = ', spec))
        args = set(a.get('name') for a in duo_input.DuoInput().get_scheme().to_xml().iter('arg'))
        self.assertEqual(documented, args)
        scheme = read_conf('default', 'inputs.conf')[duo_input.SCHEME]
        custom = set(scheme) - {'python.version', 'python.required', 'interval'}
        self.assertLessEqual(custom, args)
        for endpoint in duo_input.ENDPOINTS:
            self.assertIn(endpoint, spec)


class EntryPointTests(unittest.TestCase):

    def test_scheme_has_its_entry_point(self):
        # Splunk resolves the scheme ta_gen_ai_cim_duo to bin/ta_gen_ai_cim_duo.py
        # (the convention every modular input on this box follows); without it
        # the input never runs and AppInspect reports the scheme's script missing.
        shim = os.path.join(REPO, 'bin', duo_input.SCHEME + '.py')
        self.assertTrue(os.path.isfile(shim), 'add the bin/ta_gen_ai_cim_duo.py shim that calls '
                                              'ta_gen_ai_cim_duo_input.main()')
        import subprocess
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', SPLUNK_HOME=os.environ.get('TMPDIR', '/tmp'))
        # -B: isolated mode (-I) ignores PYTHONDONTWRITEBYTECODE, and the shim's
        # imports would otherwise leave __pycache__ in bin/ and lib/.
        out = subprocess.run([sys.executable, '-I', '-B', shim, '--scheme'], capture_output=True, env=env,
                             timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(b'<arg name="endpoint">', out.stdout)


class CollectionTests(unittest.TestCase):

    def test_checkpoint_collection(self):
        stanza = read_conf('default', 'collections.conf')[duo_input.COLLECTION]
        self.assertEqual(stanza, {'field.mintime_ms': 'number', 'field.maxtime_ms': 'number',
                                  'field.next_offset': 'string', 'field.backoff_until': 'number',
                                  'field.updated': 'number', 'replicate': 'true'})


if __name__ == '__main__':
    unittest.main()
