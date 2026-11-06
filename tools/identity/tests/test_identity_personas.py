# encoding=utf-8
"""
Tests for the AI Trust Lab 5 persona identities (TA-6):
lookups/pseudoco_identity_personas.csv, its generator, and the input that
registers it with ES Asset & Identity.

    python3 -m unittest discover -s tools/identity/tests -v
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

    def test_committed_csv_matches_the_fixture(self):
        out = self.run_gen('--personas', FIXTURE, '--check')
        self.assertEqual(out.returncode, 0, out.stderr)

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
