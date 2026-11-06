#!/usr/bin/env python3
# encoding=utf-8
"""
gen_identity_personas.py - generate lookups/pseudoco_identity_personas.csv, the
ES identity rows for the AI Trust Lab 5 persona cast, from the persona file the
PseudoCo Assistant repo keeps (scripts/identity/personas.yaml).

The CSV feeds three things, so they never drift from the cast:
  * the ES Asset & Identity source [identity_manager://pseudoco_identity_personas]
    (inputs.conf; ships DISABLED - tools/show_postdeploy.py --lab5 enables it per
    room stack and --lab5-teardown disables it again);
  * the MedAdvice Identity Provider simulator's refusal list
    (tools/soar/gen_personas.py), so a Guided Response mis-pick fails loudly
    instead of faking containment of a real Duo account;
  * the PseudoCo Identity connector's persona lists (same generator).

Row form: identity=<user>|<user>@<domain>, bunit=pseudoco, category
lab5_trusted or lab5_victim. Participant accounts (l5-<workshop>-<nn>) are real
attendee logins, never personas: they are rejected here.

personas.yaml shape (only these keys are read):

    domain: pseudocoassistant.com      # optional
    personas:
      - username: marcus.bell
        role: trusted                  # trusted | victim | dry_run
        first: Marcus                  # optional; derived from the username
        last: Bell                     # optional

Usage:
    python3 tools/identity/gen_identity_personas.py --personas <personas.yaml>
    python3 tools/identity/gen_identity_personas.py --personas <yaml> --check

Dev-only: tools/ never ships in the TA tarball.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import argparse
import csv
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP_ROOT = os.path.dirname(os.path.dirname(HERE))
CSV_PATH = os.path.join(APP_ROOT, 'lookups', 'pseudoco_identity_personas.csv')
DEFAULT_DOMAIN = 'pseudocoassistant.com'
FIELDS = ['identity', 'first', 'last', 'nick', 'email', 'bunit', 'category', 'watchlist', 'priority']
CATEGORIES = {'trusted': 'lab5_trusted', 'victim': 'lab5_victim', 'dry_run': 'lab5_victim'}
USERNAME_RE = re.compile(r'^[a-z][a-z0-9]*(\.[a-z0-9]+)+$')
PARTICIPANT_RE = re.compile(r'^l5-', re.I)


def load_personas(path):
    import yaml  # PyYAML; dev-only tool, run on the Mac
    with io.open(path, encoding='utf-8') as handle:
        doc = yaml.safe_load(handle) or {}
    domain = str(doc.get('domain') or DEFAULT_DOMAIN).strip().lower()
    rows = []
    for item in doc.get('personas') or []:
        username = str(item.get('username') or '').strip().lower()
        role = str(item.get('role') or '').strip().lower()
        if PARTICIPANT_RE.match(username):
            raise ValueError('{}: participant accounts are not personas'.format(username))
        if not USERNAME_RE.match(username):
            raise ValueError('{}: expected first.last'.format(username))
        if role not in CATEGORIES:
            raise ValueError('{}: role must be one of {}'.format(username, sorted(CATEGORIES)))
        parts = username.split('.')
        rows.append({'username': username, 'role': role, 'domain': domain,
                     'first': str(item.get('first') or parts[0].title()),
                     'last': str(item.get('last') or parts[-1].title())})
    if not rows:
        raise ValueError('no personas in {}'.format(path))
    return rows


def render(personas):
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=FIELDS, lineterminator='\n')
    writer.writeheader()
    for p in sorted(personas, key=lambda r: (r['role'] != 'trusted', r['username'])):
        email = '{}@{}'.format(p['username'], p['domain'])
        writer.writerow({
            'identity': '{}|{}'.format(p['username'], email),
            'first': p['first'], 'last': p['last'], 'nick': p['username'], 'email': email,
            'bunit': 'pseudoco', 'category': CATEGORIES[p['role']],
            'watchlist': 'true' if p['role'] != 'trusted' else 'false',
            'priority': 'high' if p['role'] != 'trusted' else 'medium',
        })
    return out.getvalue()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--personas', required=True, help='path to scripts/identity/personas.yaml')
    parser.add_argument('--check', action='store_true', help='exit 1 if the CSV is stale')
    args = parser.parse_args(argv)
    text = render(load_personas(args.personas))
    current = ''
    if os.path.exists(CSV_PATH):
        with io.open(CSV_PATH, encoding='utf-8') as handle:
            current = handle.read()
    if args.check:
        if current != text:
            print('STALE: {} does not match {}'.format(CSV_PATH, args.personas), file=sys.stderr)
            return 1
        print('OK: {} is in sync'.format(CSV_PATH))
        return 0
    with io.open(CSV_PATH, 'w', encoding='utf-8', newline='') as handle:
        handle.write(text)
    print('Wrote {} ({} personas); now run python3 tools/soar/gen_personas.py'.format(
        CSV_PATH, text.count('\n') - 1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
