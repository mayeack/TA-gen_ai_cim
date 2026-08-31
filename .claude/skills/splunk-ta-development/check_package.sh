#!/bin/bash
#
# check_package.sh - Mechanical enforcement of the R-PKG-* rules in
# VALIDATION_RULES.md against a built Splunk TA tarball.
#
# Usage: bash check_package.sh <app>-<version>.tgz [repo_root]
#
# Exits non-zero on the first rule that fails, so it can gate a publish.

set -uo pipefail

PKG="${1:-}"
ROOT="${2:-$(pwd)}"

if [[ -z "${PKG}" || ! -f "${PKG}" ]]; then
    echo "usage: bash check_package.sh <app>-<version>.tgz [repo_root]" >&2
    exit 2
fi

FAILED=0
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILED=1; }

echo "Validating ${PKG}"
echo

# --- R-PKG-001: no macOS extended attributes ---------------------------------
XATTR_HITS=$(tar -tzvf "${PKG}" 2>&1 \
    | grep -c "LIBARCHIVE.xattr\|Ignoring unknown extended header" || true)
if [[ "${XATTR_HITS}" -eq 0 ]]; then
    pass "R-PKG-001  no macOS xattr headers"
else
    fail "R-PKG-001  ${XATTR_HITS} macOS xattr header(s) - rebuild with COPYFILE_DISABLE=1 tar --no-xattrs"
fi

# --- R-PKG-002: version consistent everywhere --------------------------------
PKG_VER=$(basename "${PKG}" .tgz | sed -E 's/.*-([0-9]+\.[0-9]+\.[0-9]+)$/\1/')
CONF_VERS=$(grep -hE '^version[[:space:]]*=' "${ROOT}/default/app.conf" 2>/dev/null \
    | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}' | sort -u)
MANIFEST_VER=$(python3 -c "import json;print(json.load(open('${ROOT}/app.manifest'))['info']['id']['version'])" 2>/dev/null || echo "")
README_VER=$(grep -m1 -E '^Version:' "${ROOT}/README.md" 2>/dev/null \
    | sed -E 's/^Version:[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+).*/\1/')

VER_SET=$(printf '%s\n%s\n%s\n%s\n' "${PKG_VER}" "${CONF_VERS}" "${MANIFEST_VER}" "${README_VER}" \
    | grep -v '^$' | sort -u)
if [[ $(printf '%s\n' "${VER_SET}" | wc -l | tr -d ' ') -eq 1 ]]; then
    pass "R-PKG-002  version consistent (${PKG_VER})"
else
    fail "R-PKG-002  version drift: filename=${PKG_VER} app.conf=$(echo ${CONF_VERS} | tr '\n' ',') app.manifest=${MANIFEST_VER} README=${README_VER}"
fi

if [[ ! "${PKG_VER}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    fail "R-PKG-002  '${PKG_VER}' is not semantic major.minor.patch"
fi

# --- R-PKG-003: no excluded content ------------------------------------------
BAD=$(tar -tzf "${PKG}" 2>/dev/null \
    | grep -E '(^|/)(local/|metadata/local\.meta|\.git|\.claude|\.cursor|CLAUDE\.md|__pycache__|\._|\.DS_Store|\.env)' || true)
if [[ -z "${BAD}" ]]; then
    pass "R-PKG-003  no excluded content"
else
    fail "R-PKG-003  package contains excluded content:"
    printf '        %s\n' ${BAD}
fi

# --- R-CONF-002: no [index::] props stanzas ----------------------------------
if [[ -f "${ROOT}/default/props.conf" ]]; then
    IDX=$(grep -c '^\[index::' "${ROOT}/default/props.conf" || true)
    if [[ "${IDX}" -eq 0 ]]; then
        pass "R-CONF-002  no [index::] props stanzas"
    else
        fail "R-CONF-002  ${IDX} [index::] stanza(s) - these parse as literal sourcetypes and never fire"
    fi
fi

# --- R-SEC-002: enabled searches need a rationale comment --------------------
if [[ -f "${ROOT}/default/savedsearches.conf" ]]; then
    ENABLED=$(grep -c '^disabled = 0' "${ROOT}/default/savedsearches.conf" || true)
    if [[ "${ENABLED}" -eq 0 ]]; then
        pass "R-SEC-002  all searches ship disabled"
    else
        printf '  NOTE  R-SEC-002  %s search(es) ship enabled - each needs a stanza rationale, read-only behavior, and R-SEC-001 compliance:\n' "${ENABLED}"
        grep -n '^disabled = 0' "${ROOT}/default/savedsearches.conf" | sed 's/^/        line /'
    fi
fi

echo
if [[ "${FAILED}" -eq 0 ]]; then
    echo "All package rules passed."
else
    echo "Package rules FAILED - see above." >&2
fi
exit "${FAILED}"
