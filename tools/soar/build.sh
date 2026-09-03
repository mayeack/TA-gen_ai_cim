#!/usr/bin/env bash
# build.sh - package the MedAdvice Identity Provider SOAR stub app.
#
# Produces tools/soar/dist/medadvice_idp.tgz (gitignored). The top-level
# directory inside the tarball is the app directory; SOAR derives the install
# path from the appid in the manifest. Install with the SOAR UI (Apps -> Install
# App) or let tools/show_postdeploy.py --soar-app-tgz do it over REST.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${HERE}"
python3 gen_personas.py --check
python3 -c "import json; json.load(open('medadvice_idp/medadvice_idp.json'))"
mkdir -p dist
rm -f dist/medadvice_idp.tgz
# COPYFILE_DISABLE stops macOS tar from adding ._* AppleDouble members.
COPYFILE_DISABLE=1 tar -czf dist/medadvice_idp.tgz \
    --exclude='__pycache__' --exclude='*.pyc' --exclude='.DS_Store' \
    medadvice_idp
echo "Built: ${HERE}/dist/medadvice_idp.tgz"
tar -tzf dist/medadvice_idp.tgz
