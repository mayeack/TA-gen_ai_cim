#!/bin/bash
#
# package.sh - Build a Splunk Cloud / AppInspect-clean tarball of TA-gen_ai_cim.
#
# Produces TA-gen_ai_cim-<version>.tgz next to this script. Run from the
# workspace directory containing the TA folder, OR from the TA root itself
# (the script auto-detects).
#
# Excludes everything that would fail AppInspect or bloat the package:
#   - VCS / IDE / OS metadata
#   - Local overrides and credentials (local/, metadata/local.meta)
#   - Compiled Python (*.pyc, __pycache__)
#   - Runtime logs (*.log)
#   - Large training assets (lookups/*.csv, lookups/__mlspl_*.mlmodel)
#   - Internal docs, planning, and Cursor skill files
#   - The INSTALL helper (developer-only)
#
# Validate after build:
#   pip install splunk-appinspect
#   splunk-appinspect inspect TA-gen_ai_cim-<version>.tgz --included-tags cloud
#   splunk-appinspect inspect TA-gen_ai_cim-<version>.tgz --mode precert

set -euo pipefail

APP_NAME="TA-gen_ai_cim"

# Resolve the workspace dir that contains the TA folder.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(basename "${SCRIPT_DIR}")" == "${APP_NAME}" ]]; then
    WORKSPACE_DIR="$(dirname "${SCRIPT_DIR}")"
else
    WORKSPACE_DIR="${SCRIPT_DIR}"
fi

if [[ ! -d "${WORKSPACE_DIR}/${APP_NAME}" ]]; then
    echo "ERROR: ${APP_NAME} not found under ${WORKSPACE_DIR}" >&2
    exit 1
fi

VERSION=$(grep -E '^version\s*=' "${WORKSPACE_DIR}/${APP_NAME}/default/app.conf" \
    | head -n1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}')
VERSION="${VERSION:-0.0.0}"

OUTPUT="${WORKSPACE_DIR}/${APP_NAME}-${VERSION}.tgz"

echo "Building ${OUTPUT} from ${WORKSPACE_DIR}/${APP_NAME}"

cd "${WORKSPACE_DIR}"

# Strip macOS resource forks (._* AppleDouble files) before adding to the
# archive. AppInspect rejects ._* entries as prohibited.
if command -v xattr >/dev/null 2>&1; then
    xattr -rc "${WORKSPACE_DIR}/${APP_NAME}" 2>/dev/null || true
fi
export COPYFILE_DISABLE=1

# Normalize file permissions per AppInspect (Splunk Cloud is Linux):
#   - directories: 755
#   - everything outside bin/ and tools/: 644 (no execute bits)
#   - shell / python scripts in bin/ and tools/: 755 (executable)
#   - non-script files in bin/: 644
# Doing this in the build script prevents permission regressions sneaking
# back in from macOS / editor saves. We prune local/ and __pycache__/
# because they're excluded from the tarball and may be owned by the splunk
# user (chmod denied) on a live install.
find "${WORKSPACE_DIR}/${APP_NAME}" \
    \( -name local -o -name __pycache__ -o -name .git \) -prune -o \
    -type d -exec chmod 755 {} + 2>/dev/null || true
find "${WORKSPACE_DIR}/${APP_NAME}" \
    \( -name local -o -name __pycache__ -o -name .git -o -path "*/bin" -o -path "*/tools" \) -prune -o \
    -type f -exec chmod 644 {} + 2>/dev/null || true
if [[ -d "${WORKSPACE_DIR}/${APP_NAME}/bin" ]]; then
    find "${WORKSPACE_DIR}/${APP_NAME}/bin" \
        -name __pycache__ -prune -o \
        -type f -exec chmod 644 {} + 2>/dev/null || true
    find "${WORKSPACE_DIR}/${APP_NAME}/bin" \
        -name __pycache__ -prune -o \
        -type f \( -name '*.py' -o -name '*.sh' \) -exec chmod 755 {} + 2>/dev/null || true
fi
if [[ -d "${WORKSPACE_DIR}/${APP_NAME}/tools" ]]; then
    find "${WORKSPACE_DIR}/${APP_NAME}/tools" -type f -exec chmod 644 {} + 2>/dev/null || true
    find "${WORKSPACE_DIR}/${APP_NAME}/tools" -type f \
        \( -name '*.py' -o -name '*.sh' \) -exec chmod 755 {} + 2>/dev/null || true
fi

# NOTE: --exclude options must precede the path argument so this works on
# both GNU tar and BSD/macOS tar.
tar -czvf "${OUTPUT}" \
    --exclude='.git' \
    --exclude='.gitignore' \
    --exclude='.gitattributes' \
    --exclude='.cursor' \
    --exclude='.DS_Store' \
    --exclude='Thumbs.db' \
    --exclude='.idea' \
    --exclude='.vscode' \
    --exclude='*.swp' \
    --exclude='*.swo' \
    --exclude='local' \
    --exclude='local/*' \
    --exclude='metadata/local.meta' \
    --exclude='*.pyc' \
    --exclude='*.pyo' \
    --exclude='__pycache__' \
    --exclude='*.log' \
    --exclude='genaiscore_debug.log' \
    --exclude='lookups/*.csv' \
    --exclude='lookups/__mlspl_*.mlmodel' \
    --exclude='INSTALL.sh' \
    --exclude='package.sh' \
    --exclude='tools' \
    --exclude='tools/*' \
    --exclude='README/' \
    --exclude='planning/' \
    --exclude='.env' \
    --exclude='.env.*' \
    --exclude='._*' \
    --exclude='.AppleDouble' \
    "${APP_NAME}/" \
    > /dev/null

echo
echo "Built: ${OUTPUT}"
ls -lh "${OUTPUT}"

cat <<EOF

Next steps (AppInspect, per .cursor/skills/splunk-ta-development/SKILL.md):

  pip install splunk-appinspect
  splunk-appinspect inspect "${OUTPUT}" --included-tags cloud
  splunk-appinspect inspect "${OUTPUT}" --mode precert

EOF
