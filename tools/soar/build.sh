#!/usr/bin/env bash
# build.sh - package the TA's two SOAR apps for upload.
#
#   soar_apps/medadvice_idp/      -> soar_apps/medadvice_idp.tgz
#       MedAdvice Identity Provider, the Lab 4 simulator (simulated=true).
#   soar_apps/pseudoco_identity/  -> soar_apps/pseudoco_identity.tgz
#       PseudoCo Identity, the Lab 5 Duo connector (simulated=false). Its source
#       is NOT in the TA package (package.sh excludes it); tools/show_postdeploy.py
#       --lab5 installs it on a room stack's SOAR.
#
# Source of truth: the folders, at the top level so each can be lifted out of a
# checkout and uploaded to SOAR on its own. The .tgz files are committed so they
# can be downloaded straight from GitHub and dropped into SOAR (Apps, then
# Install App). bin/genai_es_seed.py packages the medadvice_idp source in memory
# when install_simulator is on, and a unit test asserts both archive shapes
# match what the in-product packager produces.
#
# The top-level directory inside each tarball is the app directory; SOAR derives
# the install path from the appid in the manifest.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ROOT="$(cd "${HERE}/../.." && pwd)"
APP_SRC="${APP_ROOT}/soar_apps"

cd "${HERE}"
python3 gen_personas.py --check

# COPYFILE_DISABLE + --no-xattrs stop macOS bsdtar adding ._* AppleDouble
# members and xattr pax headers (R-PKG-001), which GNU tar on SOAR cannot read.
TAR_XATTR_FLAG=()
if tar --no-xattrs --version >/dev/null 2>&1; then
    TAR_XATTR_FLAG=(--no-xattrs)
fi

for APP in medadvice_idp pseudoco_identity; do
    python3 -c "import json; json.load(open('${APP_SRC}/${APP}/${APP}.json'))"
    OUTPUT="${APP_SRC}/${APP}.tgz"
    rm -f "${OUTPUT}"
    COPYFILE_DISABLE=1 tar "${TAR_XATTR_FLAG[@]}" -czf "${OUTPUT}" \
        --exclude='__pycache__' --exclude='*.pyc' --exclude='.DS_Store' \
        -C "${APP_SRC}" "${APP}"
    echo "Built: ${OUTPUT}"
    tar -tzf "${OUTPUT}"
done
