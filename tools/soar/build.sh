#!/usr/bin/env bash
# build.sh - package the MedAdvice Identity Provider SOAR app for upload.
#
# Source of truth: soar_apps/medadvice_idp/ (top level, so the folder can be
# lifted out of a checkout and uploaded to SOAR on its own).
#
# Output: soar_apps/medadvice_idp.tgz - committed to the repo so it can be
# downloaded straight from GitHub and dropped into SOAR (Apps, then Install
# App). The TA does not read this file: bin/genai_es_seed.py packages the same
# source in memory when install_simulator is on, and tools/show_postdeploy.py
# accepts it via --soar-app-tgz only as a convenience.
#
# The top-level directory inside the tarball is the app directory; SOAR derives
# the install path from the appid in the manifest.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ROOT="$(cd "${HERE}/../.." && pwd)"
APP_SRC="${APP_ROOT}/soar_apps"
OUTPUT="${APP_SRC}/medadvice_idp.tgz"

cd "${HERE}"
python3 gen_personas.py --check
python3 -c "import json; json.load(open('${APP_SRC}/medadvice_idp/medadvice_idp.json'))"

rm -f "${OUTPUT}"
# COPYFILE_DISABLE + --no-xattrs stop macOS bsdtar adding ._* AppleDouble
# members and xattr pax headers (R-PKG-001), which GNU tar on SOAR cannot read.
TAR_XATTR_FLAG=()
if tar --no-xattrs --version >/dev/null 2>&1; then
    TAR_XATTR_FLAG=(--no-xattrs)
fi
COPYFILE_DISABLE=1 tar "${TAR_XATTR_FLAG[@]}" -czf "${OUTPUT}" \
    --exclude='__pycache__' --exclude='*.pyc' --exclude='.DS_Store' \
    -C "${APP_SRC}" medadvice_idp

echo "Built: ${OUTPUT}"
tar -tzf "${OUTPUT}"
