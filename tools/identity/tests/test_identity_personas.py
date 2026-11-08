# encoding=utf-8
"""
Tests for the AI Trust Lab 5 persona identities (TA-6):
lookups/pseudoco_identity_personas.csv, its generator, and the input that
registers it with ES Asset & Identity.

    python3 -m unittest discover -s tools/identity/tests -v

Set PSEUDOCO_PERSONAS to the PseudoCo Assistant repo's
scripts/identity/personas.yaml to also check the committed CSV against the real
persona file (skipped otherwise; the TA repo does not carry that file).
"""

import configparser
import csv
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
CSV_PATH = os.path.join(REPO, 'lookups', 'pseudoco_identity_personas.csv')
GEN = os.path.join(REPO, 'tools', 'identity', 'gen_identity_personas.py')
FIXTURE = os.path.join(HERE, 'personas_fixture.yaml')
REAL_PERSONAS = os.environ.get('PSEUDOCO_PERSONAS')

sys.path.insert(0, os.path.dirname(GEN))
import gen_identity_personas  # noqa: E402


def rows():
    with io.open(CSV_PATH, encoding='utf-8', newline='') as handle:
        return list(csv.DictReader(handle))


class CsvFormTests(unittest.TestCase):

    def test_identity_is_user_pipe_email(self):
        for row in rows():
            user, email = row['identity'].split('|')
            self.assertRegex(user, r'^[a-z]+(\.[a-z0-9]+)+$')
            self.assertEqual(email, user + '@pseudocoassistant.com')
            self.assertEqual(row['email'], email)
            self.assertEqual(row['nick'], user)
            self.assertEqual(row['bunit'], 'pseudoco')

    def test_categories_and_no_participant_accounts(self):
        cats = set(row['category'] for row in rows())
        self.assertEqual(cats, {'lab5_trusted', 'lab5_victim'})
        self.assertFalse([r for r in rows() if r['identity'].lower().startswith('l5-')])

    def test_cast_matches_the_lab_plan(self):
        by_cat = {}
        for row in rows():
            by_cat.setdefault(row['category'], set()).add(row['nick'])
        self.assertEqual(by_cat['lab5_trusted'], {'marcus.bell', 'elena.sousa', 'grace.lin'})
        self.assertTrue({'avery.kim', 'jordan.reyes', 'casey.wong'} <= by_cat['lab5_victim'])

    def test_disjoint_from_the_medadvice_identities(self):
        with io.open(os.path.join(REPO, 'lookups', 'medadvice_identities.csv'), encoding='utf-8') as handle:
            medadvice = set(r['identity'].lower() for r in csv.DictReader(handle))
        self.assertFalse(medadvice & set(r['nick'] for r in rows()))


class GeneratorTests(unittest.TestCase):

    def run_gen(self, *args):
        return subprocess.run([sys.executable, GEN] + list(args), capture_output=True, text=True)

    def load(self, text):
        with tempfile.NamedTemporaryFile('w', suffix='.yaml', delete=False) as handle:
            handle.write(text)
        self.addCleanup(os.unlink, handle.name)
        return gen_identity_personas.load_personas(handle.name)

    def test_committed_csv_matches_the_fixture(self):
        out = self.run_gen('--personas', FIXTURE, '--check')
        self.assertEqual(out.returncode, 0, out.stderr)

    @unittest.skipUnless(REAL_PERSONAS, 'set PSEUDOCO_PERSONAS to scripts/identity/personas.yaml')
    def test_committed_csv_matches_the_real_persona_file(self):
        out = self.run_gen('--personas', REAL_PERSONAS, '--check')
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_roles_are_the_apps(self):
        """The app's persona roles (deploy/lab5/lab5_personas.py ROLES); spike is the
        dry-run victim, so it is a lab5_victim row. Any other role fails loudly."""
        self.assertEqual(gen_identity_personas.CATEGORIES,
                         {'trusted': 'lab5_trusted', 'victim': 'lab5_victim', 'spike': 'lab5_victim'})
        with self.assertRaisesRegex(ValueError, r"nina\.osei: role must be one of \['spike', 'trusted', 'victim'\]"):
            self.load('personas:\n  - {username: nina.osei, role: dry_run}\n')

    def test_email_domain_is_read_and_domain_is_a_fallback(self):
        personas = 'personas:\n  - {username: avery.kim, role: victim}\n'
        self.assertEqual(self.load('email_domain: Example.TEST\n' + personas)[0]['domain'], 'example.test')
        self.assertEqual(self.load('domain: legacy.test\n' + personas)[0]['domain'], 'legacy.test')
        self.assertEqual(self.load(personas)[0]['domain'], 'pseudocoassistant.com')

    def test_participant_accounts_are_rejected(self):
        with tempfile.NamedTemporaryFile('w', suffix='.yaml', delete=False) as handle:
            handle.write('personas:\n  - {username: l5-ws1-03, role: victim}\n')
        try:
            out = self.run_gen('--personas', handle.name, '--check')
            self.assertNotEqual(out.returncode, 0)
            self.assertIn('participant', out.stderr)
        finally:
            os.unlink(handle.name)


class ConfTests(unittest.TestCase):

    def read(self, name):
        parser = configparser.RawConfigParser(strict=False, interpolation=None)
        parser.optionxform = str
        with io.open(os.path.join(REPO, 'default', name), encoding='utf-8') as handle:
            parser.read_string(handle.read())
        return parser

    def test_input_ships_disabled(self):
        stanza = self.read('inputs.conf')['identity_manager://pseudoco_identity_personas']
        self.assertEqual(stanza['disabled'].lower(), 'true')
        self.assertEqual(stanza['url'], 'lookup://pseudoco_identity_personas')

    def test_transform_is_case_insensitive(self):
        stanza = self.read('transforms.conf')['pseudoco_identity_personas']
        self.assertEqual(stanza['filename'], 'pseudoco_identity_personas.csv')
        self.assertEqual(stanza['case_sensitive_match'], 'false')


if __name__ == '__main__':
    unittest.main()
