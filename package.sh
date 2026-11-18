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
#   - Large training assets (the 200k-row PII CSV, lookups/__mlspl_*.mlmodel).
#     Small sample CSVs (medadvice_*, prompt_injection_training_examples)
#     DO ship: transforms.conf and inputs.conf reference them.
#   - Site-generated lookups that a bundled copy would overwrite on upgrade
#     (lookups/ta_gen_ai_cim_duo_identities.csv, v1.9.0)
#   - Internal docs, planning, Dashboard Studio JSON sources (*.json.template),
#     and Cursor/Claude assistant files (.cursor, .claude, CLAUDE.md)
#   - Every README/ member except the top-level *.conf.spec files, which
#     Splunk reads from README/ and which therefore ship (v1.9.0):
#     inputs.conf.spec (the ta_gen_ai_cim_duo modular input scheme) and
#     alert_actions.conf.spec (alert action parameters)
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
#
# COPYFILE_DISABLE / --no-xattrs keep macOS metadata out of the archive. Without
# them bsdtar embeds LIBARCHIVE.xattr.com.apple.provenance headers on every
# member; GNU tar (which the Artifactory publish and mapping jobs use) then
# spews "Ignoring unknown extended header keyword" for each one. --no-xattrs is
# bsdtar-only, so probe for it rather than assuming the build host is a Mac.
TAR_XATTR_FLAG=()
if tar --no-xattrs --version >/dev/null 2>&1; then
    TAR_XATTR_FLAG=(--no-xattrs)
fi

# README/ holds internal docs, plus the top-level *.conf.spec files Splunk itself
# reads from README/: inputs.conf.spec declares the ta_gen_ai_cim_duo modular
# input scheme (without it an installed package has no scheme and the input
# never runs) and alert_actions.conf.spec the alert action parameters. tar has
# no include-after-exclude, so every OTHER top-level README/ member is excluded
# by its exact path, anchored to this app's README/ (the old bare 'README/'
# pattern also dropped bin/README). Glob metacharacters are escaped so a name
# only matches itself. check_package.sh fails the build on any README/ member
# that is not a top-level *.conf.spec (R-PKG-003 amendment of 2026-11-16).
README_EXCLUDES=()
if [[ -d "${APP_NAME}/README" ]]; then
    while IFS= read -r -d '' member; do
        member="$(printf '%s' "${member}" | sed 's/[][*?\\]/\\&/g')"
        README_EXCLUDES+=(--exclude="${member}")
    done < <(find "${APP_NAME}/README" -mindepth 1 -maxdepth 1 \
                ! \( -type f -name '*.conf.spec' \) -print0)
fi

# ${array[@]+"${array[@]}"} keeps an empty array legal under set -u on bash 3.2.
COPYFILE_DISABLE=1 tar ${TAR_XATTR_FLAG[@]+"${TAR_XATTR_FLAG[@]}"} -czvf "${OUTPUT}" \
    --exclude='.git' \
    --exclude='.gitignore' \
    --exclude='.gitattributes' \
    --exclude='.cursor' \
    --exclude='.claude' \
    --exclude='CLAUDE.md' \
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
    --exclude='lookups/llm_pii_mixed_responses_200k.csv' \
    --exclude='lookups/__mlspl_*.mlmodel' \
    --exclude='lookups/ta_gen_ai_cim_duo_identities.csv' \
    --exclude='*.json.template' \
    --exclude='soar_apps/*.tgz' \
    --exclude='soar_apps/pseudoco_identity' \
    --exclude='INSTALL.sh' \
    --exclude='package.sh' \
    --exclude='tools' \
    --exclude='tools/*' \
    ${README_EXCLUDES[@]+"${README_EXCLUDES[@]}"} \
    --exclude='elements/' \
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
