#!/bin/bash
#
# check_package.sh - Mechanical enforcement of the R-PKG-*, R-INP-001,
# R-INP-002, R-CONF-002 and R-SEC-002 rules in VALIDATION_RULES.md against a
# built Splunk TA tarball.
#
# Usage: bash check_package.sh <app>-<version>.tgz [repo_root]
#
# Runs every check, then exits non-zero if any rule failed, so it can gate a
# publish.

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

# --- R-PKG-003 (amendment 2026-11-16): dev-only trees; README/ = *.conf.spec --
# The top-level dev-only trees never ship. README/ ships ONLY its top-level
# *.conf.spec files (Splunk reads inputs.conf.spec and alert_actions.conf.spec
# from there); any other README/ member is an internal doc leaking out.
APP=$(tar -tzf "${PKG}" 2>/dev/null | head -n1 | cut -d/ -f1)
DEV=$(tar -tzf "${PKG}" 2>/dev/null \
    | grep -E "^${APP}/((tools|elements|planning)(/|$)|package\.sh$|README/)" \
    | grep -vE "^${APP}/README/([^/]+\.conf\.spec)?$" || true)
if [[ -z "${DEV}" ]]; then
    pass "R-PKG-003  no dev-only trees; README/ holds only *.conf.spec"
else
    fail "R-PKG-003  package contains dev-only content (README/ may ship only top-level *.conf.spec):"
    printf '%s\n' "${DEV}" | sed 's/^/        /'
fi

# --- R-INP-001: modular inputs ship OFF, with their spec and entry point -----
# Schemes come from the packaged README/inputs.conf.spec ([<scheme>://<name>])
# and from plain [<scheme>] default stanzas in the packaged default/inputs.conf
# that have a bin/<scheme> entry point. Every scheme needs the spec and
# bin/<scheme>.py (or .sh / bare); default/inputs.conf may hold no
# [<scheme>://...] instance at all, enabled or not - instances live in local/.
MEMBERS=$(tar -tzf "${PKG}" 2>/dev/null)
PKG_SPEC=$(tar -xOzf "${PKG}" "${APP}/README/inputs.conf.spec" 2>/dev/null || true)
PKG_INPUTS=$(tar -xOzf "${PKG}" "${APP}/default/inputs.conf" 2>/dev/null || true)
# Here-strings, not printf | grep -q: under pipefail an early grep exit can
# SIGPIPE the writer and turn a match into a failure.
has_member() { grep -qxF "$1" <<<"${MEMBERS}"; }
entry_point() {
    local s="$1" f
    for f in "bin/${s}.py" "bin/${s}.sh" "bin/${s}"; do
        if has_member "${APP}/${f}"; then echo "${f}"; return 0; fi
    done
    return 1
}
SPEC_SCHEMES=$(printf '%s\n' "${PKG_SPEC}" \
    | sed -nE 's/^\[([A-Za-z0-9_.-]+):\/\/.*/\1/p' | sort -u)
DEFAULT_SCHEMES=""
for s in $(printf '%s\n' "${PKG_INPUTS}" | sed -nE 's/^\[([A-Za-z0-9_.-]+)\][[:space:]]*$/\1/p' | sort -u); do
    [[ "${s}" == "default" ]] && continue
    entry_point "${s}" >/dev/null && DEFAULT_SCHEMES="${DEFAULT_SCHEMES} ${s}"
done
SCHEMES=$(printf '%s\n' ${SPEC_SCHEMES} ${DEFAULT_SCHEMES} | grep -v '^$' | sort -u || true)

if [[ -f "${ROOT}/README/inputs.conf.spec" ]] && ! has_member "${APP}/README/inputs.conf.spec"; then
    fail "R-INP-001  README/inputs.conf.spec is in the repo but not in the package - the input's scheme would not exist"
fi
if [[ -z "${SCHEMES}" ]]; then
    pass "R-INP-001  no modular input schemes"
fi
for s in ${SCHEMES}; do
    if ! grep -qxF "${s}" <<<"${SPEC_SCHEMES}"; then
        fail "R-INP-001  scheme ${s}: no [${s}://<name>] in the packaged README/inputs.conf.spec"
    fi
    if ep=$(entry_point "${s}"); then
        pass "R-INP-001  scheme ${s}: entry point ${ep}"
    else
        fail "R-INP-001  scheme ${s}: no bin/${s}.py (Splunk runs a scheme from bin/<scheme>.py)"
    fi
    INSTANCES=$(printf '%s\n' "${PKG_INPUTS}" | grep -nE "^\[${s}://" || true)
    if [[ -z "${INSTANCES}" ]]; then
        pass "R-INP-001  scheme ${s}: no input instance in default/inputs.conf"
    else
        fail "R-INP-001  scheme ${s}: input instance(s) ship in default/inputs.conf - add them in local/:"
        printf '%s\n' "${INSTANCES}" | sed 's/^/        line /'
    fi
done

# --- R-INP-002: an ES identity/asset source ships only with its lookup file --
# ES's identity manager resolves the lookup file of EVERY identity_manager
# source on every pass (300 s), a disabled source's included, and splunkd logs
# "ERROR PersistentScript ... Lookup table was not found" while it is missing.
# So each [identity_manager://<name>] in the packaged default/inputs.conf must
# point (url = lookup://<definition>) at a [<definition>] in the packaged
# default/transforms.conf whose filename is in the package under lookups/. A
# source whose file is generated at runtime ships as a commented example only.
PKG_TRANSFORMS=$(tar -xOzf "${PKG}" "${APP}/default/transforms.conf" 2>/dev/null || true)
# conf_value <conf text> <stanza> <key>: the key's value in that stanza, the
# last one if it repeats; comment lines are skipped.
conf_value() {
    WANT="[$2]" KEY="$3" awk '
        /^[[:space:]]*#/ { next }
        /^\[/ { line = $0; sub(/[[:space:]]+$/, "", line); inside = (line == ENVIRON["WANT"]); next }
        inside {
            eq = index($0, "=")
            if (eq == 0) next
            k = substr($0, 1, eq - 1); v = substr($0, eq + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
            if (k == ENVIRON["KEY"]) found = v
        }
        END { print found }' <<<"$1"
}
ES_SOURCES=$(printf '%s\n' "${PKG_INPUTS}" \
    | sed -nE 's/^\[identity_manager:\/\/(.+)\][[:space:]]*$/\1/p' | sort -u)
if [[ -z "${ES_SOURCES}" ]]; then
    pass "R-INP-002  no [identity_manager://...] source in default/inputs.conf"
fi
while IFS= read -r src; do
    [[ -z "${src}" ]] && continue
    url=$(conf_value "${PKG_INPUTS}" "identity_manager://${src}" url)
    def="${url#lookup://}"
    if [[ "${url}" != lookup://* || -z "${def}" ]]; then
        fail "R-INP-002  [identity_manager://${src}]: url '${url}' is not lookup://<definition>"
        continue
    fi
    file=$(conf_value "${PKG_TRANSFORMS}" "${def}" filename)
    if [[ -z "${file}" ]]; then
        fail "R-INP-002  [identity_manager://${src}]: no [${def}] with a filename in the packaged default/transforms.conf"
    elif has_member "${APP}/lookups/${file}"; then
        pass "R-INP-002  [identity_manager://${src}]: lookups/${file} ships"
    else
        fail "R-INP-002  [identity_manager://${src}]: lookups/${file} is not in the package - ES logs 'Lookup table was not found' every 5 minutes for a source without its file, disabled or not; ship the file, or ship the stanza only as a commented example"
    fi
done <<<"${ES_SOURCES}"

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
