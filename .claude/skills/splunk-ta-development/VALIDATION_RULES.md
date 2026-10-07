# Splunk TA Validation Rules

Hard gate for any Splunk TA before it is packaged, published, or proposed in a
merge request. Every rule here was earned — each one comes from a real review
finding on a real publish MR, and each carries its provenance so the rule can be
audited back to the finding that created it.

**Contract:** no TA ships until every rule below is checked and passes, or the
exception is written down in the MR body with a reason.

---

## Maintenance protocol

These rules are refreshed on every publish MR to
`tmm/domane-unreleased-apps` (<https://cd.splunkdev.com/tmm/domane-unreleased-apps>).

After submitting an MR, harvest the review and fold it back in:

```bash
GITLAB_HOST=cd.splunkdev.com glab api \
  "projects/tmm%2Fdomane-unreleased-apps/merge_requests/<IID>/notes?per_page=100" \
  | python3 -c "import json,sys; [print('='*70,'\n',n['author']['username'],'\n',n['body']) for n in json.load(sys.stdin) if not n.get('system')]"
```

The reviewer is `codex-ai-mr-bot`. Each inline finding carries a JSON metadata
block with `finding_id`, `priority` (P0–P3), `category`, and
`confidence_score` — record all of them in the ledger.

For every finding:

1. **Fix the instance** in the TA.
2. **Generalize it into a rule** here — the rule must cover the whole class,
   not the one line that tripped it. A finding about a notable description is
   really a finding about every path that leaves the source index.
3. **Give it a mechanical check** — a command or grep with a pass condition.
   A rule nobody can run is a rule nobody follows.
4. **Add a ledger row** at the bottom.
5. Mirror this file to `.cursor/skills/splunk-ta-development/`.

Rules are append-only. Retire one only by marking it `SUPERSEDED` with a note
saying what replaced it — never delete, or the next reviewer re-files the same
finding.

---

## The gate

Run in order. Any failure stops the publish.

```bash
# 1. Python compiles under both runtimes the platform may select
/opt/splunk104/bin/splunk cmd python3.9  -m py_compile bin/*.py
/opt/splunk104/bin/splunk cmd python3.13 -m py_compile bin/*.py

# 2. Configuration parses
/opt/splunk104/bin/splunk btool check --app=<APP_NAME>

# 3. Build
bash package.sh

# 4. Package hygiene (R-PKG-*, R-CONF-002, R-SEC-002)
bash .claude/skills/splunk-ta-development/check_package.sh <APP_NAME>-<VERSION>.tgz

# 5. Data minimization (R-SEC-001)
python3 .claude/skills/splunk-ta-development/check_notable_content.py default/savedsearches.conf

# 5b. Search ownership, risk objects, custom-command collisions (R-CONF-005/006, R-PY-001)
python3 .claude/skills/splunk-ta-development/check_search_owner.py
python3 .claude/skills/splunk-ta-development/check_risk_objects.py
/opt/splunk104/bin/splunk cmd python3.13 .claude/skills/splunk-ta-development/check_command_collisions.py

# 6. Cloud certification
splunk-appinspect inspect <APP_NAME>-<VERSION>.tgz --included-tags cloud
```

---

## R-PKG — Packaging

### R-PKG-001 · No macOS extended attributes in the tarball

**Rule.** A `.tgz` must be built with `COPYFILE_DISABLE=1` *and* `tar
--no-xattrs`. Clearing attributes on the source tree (`xattr -rc`) is **not
sufficient** — macOS re-applies `com.apple.provenance` on write, so bsdtar
embeds a `LIBARCHIVE.xattr.com.apple.provenance` pax header on every member
regardless. `--no-xattrs` is bsdtar-only; probe for it rather than assuming the
build host is a Mac.

**Why.** GNU tar — which the Artifactory publish and mapping jobs run — cannot
read those headers and emits `Ignoring unknown extended header keyword` once
per archive member. Those jobs parse the archive directly, so the noise lands
in the pipeline log for every file in the app.

**Check.** Must print `0`:

```bash
tar -tzvf <pkg>.tgz 2>&1 | grep -c "LIBARCHIVE.xattr\|Ignoring unknown extended header"
```

**Pattern.**

```bash
TAR_XATTR_FLAG=()
if tar --no-xattrs --version >/dev/null 2>&1; then
    TAR_XATTR_FLAG=(--no-xattrs)
fi
COPYFILE_DISABLE=1 tar "${TAR_XATTR_FLAG[@]}" -czvf "${OUTPUT}" --exclude=... "${APP_NAME}/"
```

*Provenance: MR !171 finding `11909_171_712a7827_0`, P2, confidence 0.97,
category `bug`, 2026-08-26.*

### R-PKG-002 · Version consistent everywhere

**Rule.** One version string, identical in: the tarball filename,
`default/app.conf [launcher] version`, `default/app.conf [id] version`,
`app.manifest` `.info.id.version`, and the README version header. The publish
pipeline derives `available_versions` from the packaged `app.conf`, so a
filename that disagrees with `app.conf` publishes under the wrong version and
`unreleased_app_mappings.yaml` silently records the wrong thing.

**Check.** All lines must show the same value:

```bash
grep -E '^version\s*=' default/app.conf
python3 -c "import json;print(json.load(open('app.manifest'))['info']['id']['version'])"
grep -m1 '^Version:' README.md
```

**Note.** Semantic `major.minor.patch` only — AppInspect rejects other forms.

*Provenance: MR !171 reviewer summary check ("packaged app.conf and
app.manifest versions align with the 1.6.2 filename"), 2026-08-26.*

### R-PKG-003 · No excluded content in the archive

**Rule.** The package must never contain `local/`, `metadata/local.meta`,
`.git`, `.claude`, `.cursor`, `CLAUDE.md`, `__pycache__`, `*.pyc`, `*.log`,
`.DS_Store`, `._*` AppleDouble members, `.env*`, or dev-only trees
(`tools/`, `README/`, `elements/`, `planning/`, `package.sh`).

**Check.** Must print `0`:

```bash
tar -tzf <pkg>.tgz | grep -cE '(^|/)(local/|metadata/local\.meta|\.git|\.claude|\.cursor|CLAUDE\.md|__pycache__|\._|\.DS_Store|\.env)'
```

**Note.** Whenever a new assistant/dev file or directory is added to the repo,
add it to the `package.sh` exclude list in the *same* change.

### R-PKG-004 · AppInspect baseline is exact

**Rule.** `splunk-appinspect inspect <pkg> --included-tags cloud` must return
**0 errors / 0 failures / 0 future-failures**, with a warning set that matches
the app's documented accepted list exactly — same checks, same count.

**Why.** "Some warnings" is not a baseline. A new warning is the only early
signal that a change broke a cloud-vetting rule; if the count floats, that
signal is gone.

**Check.** Compare the warning check names against the documented list in
`CLAUDE.md`. Any warning outside the list, or a different count, is drift —
fix the underlying item or update the documented list in the same change.

---

## R-SEC — Security and data minimization

### R-SEC-001 · Never copy raw prompt or response content across a trust boundary

**Rule.** No field derived from raw model input/output may be interpolated into
anything that leaves the source index. That includes:

- `action.notable.param.rule_description` and `rule_title` (→ the notable index)
- ServiceNow case short descriptions and bodies (→ an external system)
- Email alert action subjects and bodies (→ mail)
- KV store collections and lookup writebacks (→ a different retention policy)
- Any `sendalert` / custom alert action payload (→ wherever it goes)

Emit **derived metadata** instead — a technique label, a category, a count, a
score. Point the analyst at the raw text through the drilldown, where the source
index's own access controls and retention apply.

**Why.** A notable lives in a different index with its own retention and its own
ACL. Copying an attack prompt into the description clones any PII, PHI, or
secret it contained into a store the original data-governance decision never
covered — and one that typically retains longer and is readable by more people.

**Check.** Mechanical — resolves every `$token$` in an outbound parameter back
to the `stats`/`eval` term that produces it and flags raw-content sources:

```bash
python3 .claude/skills/splunk-ta-development/check_notable_content.py default/savedsearches.conf
```

Regression-tested against the pre-fix tree, where it reproduces both the
reviewer's `$injection_prompts$` finding and the `$explanations$` one the gate
later found on its own.

Red flags it looks for: a producing term referencing `gen_ai.input.messages`,
`input_messages{}.content`, `gen_ai.output.messages`, `output_messages{}.content`,
a local `_prompt` / `_response` variable, or any `*.explanation` field.

**Note on the second class.** An LLM-authored *explanation* of a prompt is not a
copy of the prompt, but it is written about it and routinely quotes it — treat
free-text scoring rationale exactly like raw content. Widen `RAW` in the checker
whenever a new content-bearing field appears.

**Pattern.** Classify, then aggregate the *label*:

```spl
| eval injection_technique=case(
      match(_p, "<pattern-1>"), "instruction_override",
      match(_p, "<pattern-2>"), "guardrail_bypass",
      1=1, null())
| stats values(injection_technique) as techniques by actor
```

...and say so in the description, so the next reader does not "helpfully" add
the prompt back:

> `Techniques: $techniques$. Raw prompt text is deliberately NOT copied into
> this notable — use the drilldown to read it in <index>, where index-level
> access controls and retention apply.`

*Provenance: MR !171 finding `11909_171_712a7827_1`, P2, confidence 0.88,
category `security`, 2026-08-26.*

### R-SEC-002 · A search that ships enabled gets a stricter review

**Rule.** Everything ships `disabled = 1` by default; enablement is a per-
environment decision made in `local/`. Any documented exception must:

- be **read-only** — no email, no ServiceNow, no outbound call, no writeback;
- pass **R-SEC-001** with no exception, because it runs on a fresh install with
  nobody having opted in;
- carry a rationale comment **in the stanza itself**;
- carry a README changelog entry naming it as an exception.

**Why.** `disabled = 0` means the search runs on somebody's data before any
operator has read what it does. Every risk it carries is taken on their behalf.

**Check.**

```bash
grep -n "^disabled = 0" default/savedsearches.conf   # each hit needs a rationale comment above it
```

*Provenance: MR !171 — both P2 findings compounded because the affected search
shipped enabled; the reviewer led with "enabling this correlation rule makes a
fresh install run it automatically". 2026-08-26.*

**Amendment (2026-08-31, v1.6.5).** A second exception is sanctioned:
`GenAI - Tokenomics - Seed Token Cost Pricing` ships `disabled = 0` +
`run_on_startup = 1`. It does not meet the letter of "no writeback", so that
clause is narrowed rather than waived: an enabled search may write **only**
values that ship inside the app's own package (here
`lookups/genai_token_cost_seed.csv`) into the app's **own** KV collection,
insert-only and idempotent — and it may read no index and no event-derived
field, so R-SEC-001 holds vacuously. Every other clause still applies:
rationale comment in the stanza, README changelog entry naming the exception,
R-SEC-001 with no exception. Any third enabled search, or any enabled
writeback that reads from an index, needs a new amendment here first.

**Amendment (2026-09-03).** A third exception is sanctioned:
`GenAI - ES - Seed Response Plan and SOAR Binding` ships `disabled = 0` +
`run_on_startup = 1` and runs `| genaiseedes` (`bin/genaiseedes.py` over
`bin/genai_es_seed.py`). It writes **outside** the app's own namespace — the
`missioncontrol` KV collections `mc_response_templates`, `mc_incident_types`
and `queues`, and, through the ES/SOAR pairing proxy, one asset on the paired
SOAR — so the writeback clause is narrowed a second time, with these bounds:
the records are TA-owned (fixed `_key`s: `ai_incident_response_plan`,
`ai security incident`, `ai_findings_queue`, asset `medadvice_idp`); their
content ships inside the package (`default/data/response_plans/`,
`soar_apps/`); every write is update-or-create, and actions or
playbooks already attached to a plan task on the live record are preserved
unless a shipped `soar_binding` replaces them; nothing is written to SOAR
unless the simulator app is already installed there; and no index or
event-derived field is read, so R-SEC-001 holds vacuously. The two settings
that change behaviour beyond the TA's own records — `install_simulator`
(installs an app on the paired SOAR; needs a `soar` account) and
`enable_triage_agent` (ES-wide AI triage) — ship **off** in
`ta_gen_ai_cim_es.conf`. Every other clause still applies: rationale comment
in the stanza, README changelog entry naming the exception, R-SEC-001 with no
exception. Any enabled search that writes a record it does not own, or that
reads from an index, needs a new amendment here first.

### R-SEC-003 · No secrets, no content logging

**Rule.** No credentials, tokens, or API keys in conf files, code, or URLs —
API keys go in headers, secrets go in `storage/passwords`. Never log
prompt/response content at `INFO`; content logging is `DEBUG`-only and gated by
an explicit setting.

**Check.**

```bash
grep -rniE '(api[_-]?key|password|secret|token)\s*=\s*[^<$]' default/ bin/ | grep -v 'storage/passwords'
```

---

## R-CONF — Configuration correctness

### R-CONF-001 · Search-time only

Never add index-time settings (`INDEXED_EXTRACTIONS`, `TIME_FORMAT`,
`LINE_BREAKER`, `SHOULD_LINEMERGE`, …) to a search-time normalization TA's
`props.conf`. Check: `btool props list --debug` and confirm the stanza carries
only search-time keys.

### R-CONF-002 · Only valid props.conf stanza scopes

A `props.conf` stanza may only be `<sourcetype>`, `host::`, `source::`,
`rule::`, or `delayedrule::`. **There is no `index::` scope** — an
`[index::foo]` stanza parses as a literal sourcetype named `index::foo` and
silently never fires.

**Check.** Must print `0`:

```bash
grep -c '^\[index::' default/props.conf
```

### R-CONF-003 · A config that parses is not a config that fires

`btool check` passing proves syntax, not behavior. Every new extraction, alias,
eval, or macro must be confirmed to actually populate against real indexed data
before the MR is opened. Two classes of bug that pass `btool check` cleanly and
still produce nothing:

- an `[index::…]` stanza (R-CONF-002);
- a JSON-array field mapped through a `FIELDALIAS` or a `REPORT` with
  `SOURCE_KEY = <bare name>` — under `KV_MODE = json` the auto-extracted name is
  **braced** (`safety_categories{}`), so the bare name never resolves. Use an
  `EVAL` that reads the braced name with a bare-name fallback.

**Check.** For every field the change claims to populate:

```spl
index=<idx> earliest=-24h | stats count, dc(<field>) as distinct, count(<field>) as populated
```

`populated = 0` means the change did nothing, whatever `btool` said.

### R-CONF-004 · Writeback sourcetypes must be excluded from operational queries

Any event a TA writes back into its own index (scoring output, response-action
audit records) must be added to the exclusion macro in the **same change** that
introduces it. Otherwise it contaminates every inference metric and every
detection that reads the index.

**Check.** Every sourcetype the app emits appears either in the exclusion macro
or in a documented reason why it should not.

---

## R-DOC — Documentation

### R-CONF-005 · A scheduled search that calls a restricted command needs an owner

**Rule.** Any saved search shipped in `default/savedsearches.conf` that invokes
a custom command whose `[commands/<name>]` ACL excludes `nobody` — i.e. any
`read` list that is not `[ * ]` — must carry an owner stanza in
`metadata/default.meta`:

```
[savedsearches/<URL-encoded search name>]
owner = admin
```

The same applies to a search that reads an admin-only conf or writes a
restricted KV collection over REST, whatever command it uses.

**Why.** Objects shipped in `default/` are owned by `nobody`, and `nobody`
holds no roles. The scheduler runs a saved search in its owner's context, so a
nobody-owned search cannot read an admin-only command, conf, or collection: it
fails config load with *"Session is not logged in"* and, because a scheduled
search has nobody to report to, does so silently. The blast radius is worst
exactly where it is least visible — a search that ships `disabled = 0` with
`run_on_startup = 1` is supposed to make a fresh install self-configure, so a
silent no-op there means the feature never runs and nothing says why.

**Check.** Lists every enabled search, the restricted command it calls, and
whether an owner stanza exists. Matches only the `search =` value, joining conf
line-continuations, so a command named in a stanza comment is not a false hit.
Exits non-zero on any FAIL:

```bash
python3 .claude/skills/splunk-ta-development/check_search_owner.py
```

*Provenance: MR !174 finding `11909_174_489ad313_1`, P1, confidence 0.91,
category `bug`, 2026-09-03. The ten `GenAI Scoring - Pipeline N` searches
already carried `owner = admin` for this exact reason; the new
`GenAI - ES - Seed Response Plan and SOAR Binding` search was added without
one, which would have made the entire self-seeding ES integration a silent
no-op on every fresh install.*

### R-CONF-006 · A rule with configured risk objects must not emit `risk_object`

**Rule.** If `action.risk.param._risk` names its risk objects with
`risk_object_field`, the search must not put a `risk_object` (or
`risk_object_type`) field in its results — no `| eval risk_object=...`, no
`... as risk_object`. A rule that also raises a finding (`action.notable = 1`)
names the finding's entity in `action.notable.param._entities` instead.

**Why.** The ES risk action (`SA-ThreatIntelligence/bin/risk_extractor.py`)
prefers a result-level `risk_object`, and a result-level `risk_object_type`,
over **every** entry in `_risk`. A rule that declares `user` (80) and `src`
(60) and also evals `risk_object=user` writes the user risk twice and the
`src`/system risk never — with no error anywhere. All three AI Governance rules
shipped that way until v1.7.1.

The eval existed for a reason, and removing it alone causes a different bug.
Mission Control reads the finding's `risk_object` for its Entity column and
risk-score badge, and commit `4d61c09` added the eval so that column would
stop rendering `--`. `action.notable.param._entities` (SA-ThreatIntelligence
`alert_actions.conf.spec`) is the mechanism that serves both: for an
event-based detection, `notable.py` runs `parse_risk_objects(result,
'notable')` over `_entities` and puts `risk_object`/`risk_object_type` on the
finding only, while the risk action still writes every `_risk` entry. Give
`_entities` one entry: `notable.py` raises one finding per entity value.

**Check.** Exits non-zero on any FAIL. It reads only the `search =` value, and
also fails a finding-raising rule with `_risk` but no `_entities`:

```bash
python3 .claude/skills/splunk-ta-development/check_risk_objects.py
```

*Provenance: AI Trust workshop dry run (2026-10-07), finding "Detection risk";
not an MR finding. Regression-tested against the v1.7.0 tree, where it flags
all three rules.*

### R-CONF-007 · Mission Control queue rules are rule-engine syntax, not SPL

**Rule.** A `queues` record seeded into Mission Control carries a `rule_string`
in the syntax of Mission Control's vendored `rule_engine` library, plus the
matching structured `rules` (stored as a JSON string). It may only reference
fields the finding holds at queue-assignment time: the detection's notable
params (`rule_title` with its literal `$tokens$`, `investigation_type`,
`severity`, `security_domain`) and the result row. `search_name` is **not**
one of them, because `notable.py` adds it after the queue is assigned.
Generate the string with
`missioncontrol/bin/blueridge/data_models/models/queues.py`
`Queues.build_rule_string()` rather than writing it by hand.

**Why.** `rule_executor.py` evaluates every queue rule against every finding.
The SPL-style `search_name="AI Governance*"` that `| genaiseedes` seeded up to
v1.7.1 is a rule-engine syntax error (*"illegal character '='"*). It never matched,
so findings fell to the default queue, and it logged an ERROR to
`notable_modalert.log` on every finding. The obvious repair,
`search_name =~ "^AI Governance"`, parses but still never matches, for the
reason above. Both went unnoticed while the seeder itself was crashing
(R-PY-001). The rule shipped in v1.7.1 is `(rule_title =~ "^GenAI Prompt Injection")`,
and it ships **off** (`route_findings_to_queue = false`). A working routing rule
moves findings out of the default Analyst Queue, and a non-default queue is
admin-only until ES queue permissions are granted. Fixing the syntax must not
silently change where analysts find their work.

**Check.** Validates the seeded string with Mission Control's own engine and UI
builder (skips where ES is not installed):

```bash
/opt/splunk104/bin/splunk cmd python3.13 -m unittest tools.soar.tests.test_seed.QueueRuleTests -v
```

*Provenance: live verification of the v1.7.1 fixes (2026-10-07). A verifier
found the ERRORs in `notable_modalert.log` once the fixed seeder ran.*

## R-PY — Python

### R-PY-001 · A custom search command must not collide with splunklib's names

**Rule.** A class deriving from a splunklib `*Command` must not assign a
read-only `SearchCommand` property (`self.logger = ...`) and must not define a
method whose name `SearchCommand.__init__` assigns as an instance attribute
(`_service`, `_metadata`, ...). Keep loggers at module level; name helpers
something splunklib does not own (`_connect`, not `_service`). Every shipped
command also gets an offline test that drives its `generate()` / `stream()` end
to end — testing only the logic it calls is how both bugs below shipped.

**Why.** Both fail only at dispatch, after `py_compile`, `btool` and AppInspect
have passed. `| genaiseedes` did both: `self.logger = ...` raised *"property
'logger' ... has no setter"*, and behind it `self._service()` raised
*"'NoneType' object is not callable"* because `SearchCommand.__init__` sets
`self._service = None`. The enabled, `run_on_startup` seeding search therefore
wrote nothing on any stack from v1.7.0 until v1.7.1, which surfaced in the
workshop as findings with no investigation type and no response plan.

**Check.** Exits non-zero on any FAIL; run under Splunk's Python so
`lib/splunklib` resolves:

```bash
/opt/splunk104/bin/splunk cmd python3.13 .claude/skills/splunk-ta-development/check_command_collisions.py
```

*Provenance: AI Trust workshop dry run (2026-10-07), findings 6–7 ("investigation
type ai security incident does not exist"); root cause found in
`scheduler.log`, not an MR finding. Regression-tested against the v1.7.0 tree,
where it reports both collisions.*

### R-DOC-001 · Behavior changes carry a changelog entry

Every user-visible change gets a README changelog entry under the version that
ships it, labelled `ADDED` / `FIXED` / `CHANGED`. A fix that came from an MR
review finding should say what was actually wrong, so the next person does not
reintroduce it.

### R-DOC-002 · The MR body states the validation evidence

The publish MR body must state, concretely: the AppInspect result (errors /
failures / future-failures + warning count), that `btool check` is clean, that
`py_compile` passes on both Python runtimes, and that the package was installed
and verified on a real instance. Numbers, not adjectives.

---

## Finding ledger

| MR | Finding ID | Pri | Conf | Category | Finding | Rule |
|---|---|---|---|---|---|---|
| [!171](https://cd.splunkdev.com/tmm/domane-unreleased-apps/-/merge_requests/171) | `11909_171_712a7827_0` | P2 | 0.97 | bug | Tarball carried `LIBARCHIVE.xattr.com.apple.provenance` headers | R-PKG-001 |
| [!171](https://cd.splunkdev.com/tmm/domane-unreleased-apps/-/merge_requests/171) | `11909_171_712a7827_1` | P2 | 0.88 | security | Enabled correlation rule wrote raw `$injection_prompts$` into the notable description | R-SEC-001, R-SEC-002 |
| — (found by the gate, not a reviewer) | `R-SEC-001/self-1` | P3 | — | security | `AI Governance - Prompt Injection Detected (GenAI Judge) - Rule` wrote the judge's free-text `$explanations$` into the notable description; ships disabled, so opt-in | R-SEC-001 |
| — (deliberate design decision, not a finding) | `R-SEC-002/amend-1` | — | — | security | Second sanctioned `disabled = 0` exception: `GenAI - Tokenomics - Seed Token Cost Pricing`, an insert-only KV seed of shipped CSV pricing constants (reads no index, no event-derived fields) | R-SEC-002 (amended) |
| [!174](https://cd.splunkdev.com/tmm/domane-unreleased-apps/-/merge_requests/174) | `11909_174_489ad313_1` | P1 | 0.91 | bug | Enabled `run_on_startup` search calling the admin-only `genaiseedes` command had no `owner = admin` stanza, so it would run as `nobody` and silently no-op on a fresh install | R-CONF-005 |
| — (workshop dry run 2026-10-07, not a reviewer) | `dryrun-1007-risk` | — | — | bug | All three AI Governance rules evaled `risk_object` in their results, so ES wrote the first `_risk` object twice and the `src`/system risk never | R-CONF-006 |
| — (live verification 2026-10-07, not a reviewer) | `verify-1007-entity` | — | — | bug | Removing the result-level `risk_object` (R-CONF-006) without `_entities` would have reverted `4d61c09` and blanked Mission Control's Entity column | R-CONF-006 (amended) |
| — (live verification 2026-10-07, not a reviewer) | `verify-1007-queue` | — | — | bug | Seeded queue `rule_string` was SPL, a Mission Control rule-engine syntax error; the queue never matched and every finding logged an ERROR | R-CONF-007 |
| — (workshop dry run 2026-10-07, not a reviewer) | `dryrun-1007-seedes` | — | — | bug | `genaiseedes` assigned the read-only `self.logger` and called a `_service()` shadowed by splunklib's `self._service = None`; the enabled seeding search wrote nothing on any stack from v1.7.0 | R-PY-001 |
