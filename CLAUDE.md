# TA-gen_ai_cim — AI Governance Technology Add-on

Splunk TA that normalizes GenAI/LLM telemetry into a `gen_ai.*` CIM
(OTel GenAI semantic conventions), with governance alerts, dashboards,
ML detections, and a ServiceNow AI Case Management integration.

## Repo & git workflow

- This directory IS the git repo root (standalone repo, single remote
  `origin` = https://github.com/mayeack/TA-gen_ai_cim.git). There is no
  monorepo, no subtree, no `ta-cim` remote — ignore any older docs that
  describe one.
- Feature branch → PR → merge to `main`. Never commit directly to `main`.
- Never commit: `local/` (instance overrides — this is also a live dev
  Splunk instance and box-specific enablement lives there),
  `metadata/local.meta`, `.cursor/mcp.json`, `.claude/settings.local.json`,
  large/generated lookup CSVs (see `.gitignore` — the small `medadvice_*`
  and `prompt_injection_training_examples` sample CSVs ARE tracked and ship).

## Layout

- `bin/` — Python only (custom commands `aicase`, `genaiscore`; alert
  actions `create_snow_case`, `sync_snow_asset`, `pull_snow_inventory`,
  `ai_defense_suspend_user`, `ai_defense_revoke_session`,
  `ai_defense_tighten_guardrail`; REST handler
  `ta_gen_ai_cim_account_handler`; CLI `snow_setup`).
  The shared ServiceNow client (config/OAuth/HTTP) lives in
  `sync_snow_asset.py` — never duplicate it; import it. Likewise the shared
  AI Defense response logic (payload parsing, field resolution, audit
  emission) lives in `ai_defense_response.py`; the three `ai_defense_*`
  actions are thin wrappers that call `run_action`.
- `lib/splunklib/` — vendored Splunk SDK (keep ≥ 2.1.1: older versions'
  `six` shim breaks under Python 3.13, which `python.required = 3.13`
  selects on Splunk 9.4+).
- `tools/` — dev-only scripts and docs (never packaged). The MLTK model
  loaders live here, not in `bin/`, because they write into another app's
  dir. Also `show_postdeploy.py` (configures a Splunk Show stack for the
  AI Defense demo — everything the tarball structurally cannot do) plus
  `demobot-spray-attack-spec.md` and
  `splunk-show-template-integration.md`, each with a parallel
  self-contained `.html`.
- `elements/`, `README/` — internal docs, excluded from the package.
- `package.sh` — builds the shippable tarball; keep its exclude list in
  sync when adding assistant/dev files.

## Conf conventions

- **Search-time only**: never add index-time settings
  (`INDEXED_EXTRACTIONS`, `TIME_FORMAT`, `LINE_BREAKER`, …) to props.conf.
- Every `.conf` gets a header comment block (filename, app, purpose,
  "Compatible with: Splunk Enterprise 9.0+, Splunk Cloud") and
  banner-style `###` section separators.
- Primary index: `gen_ai_log`. **props.conf has NO `index::` scope** — a stanza
  may only be `<sourcetype>`, `host::`, `source::`, `rule::`, `delayedrule::`.
  An `[index::gen_ai_log]` stanza parses as a literal sourcetype name and never
  fires; one existed and was inert until v1.4.0. Normalization is keyed on the
  canonical sourcetype `[gen_ai:json]`, which owns the single copy of the alias
  set. Attach other ingest sourcetypes with `rename = gen_ai:json`
  (`[medadvice3:json]`, `[toyapp:json]` do exactly this); `[medadvice:json]`
  keeps its own stanza because its nested `event.*` schema differs.
  `FIELDALIAS-genai_*` for 1:1 renames; `EVAL` for computed/coalesced/boolean
  fields. Booleans use the two-step `*_raw` pattern: alias the source to
  `gen_ai.<x>_raw`, then `EVAL` the canonical name from the underscore source.
- Booleans normalize to lowercase string `"true"`/`"false"` via
  `EVAL ... case(...)`.
- JSON arrays → multi-value fields via `REPORT` transforms with
  `MV_ADD = true`.
- Eventtypes: base `gen_ai_inference` (priority 5) excludes scoring
  sourcetypes; provider eventtypes chain from it (priority 4); tags flow
  one direction only (eventtypes → tags.conf).
- ML scoring events are written back to `gen_ai_log` with sourcetypes
  `ai_cim:<name>:ml_scoring` / `ai_cim:<name>:gen_ai_scoring`; always
  exclude them from operational queries (`exclude_scoring_sourcetypes`
  macro). The AI Defense response actions likewise write back under
  `ai_cim:response:action`, and that pattern is excluded by the same macro —
  anything else written back into `gen_ai_log` must be added there too, or it
  contaminates every inference metric and detection.
- The AI Defense response actions are **simulated**: they call nothing
  external and every audit record they write carries `"simulated": true`.
  That flag is the only thing separating a demo containment record from a
  real one — never strip it, and never let one of these actions imply real
  enforcement.
- `default/data/response_plans/*.json` are seed assets for the ES Mission
  Control `mc_response_templates` KV collection, stored **plain text** so
  they stay reviewable in git. Mission Control stores the strings
  URL-encoded (`encodeURIComponent` semantics — parens stay literal);
  `tools/show_postdeploy.py` encodes on write. The collection declares only
  `name`/`order`/`description`/`owner` on a task — there is no structural key
  for an embedded search or action, so SPL and action references go in the
  task description.
- KV store: underscore field names (dots break REST), `replicate = true`,
  `accelerated_fields` for hot queries, typed `field.<name>` declarations.
- Macros: `genai_*` (cost/analytics) vs `gen_ai_*` (review/workflow);
  every macro gets a doc comment; always set `iseval`.
- Saved searches: `GenAI - <Category> - <Action>` naming. **Everything
  ships `disabled = 1`** — enablement is per-environment via `local/`
  (this box's enablement is in `local/savedsearches.conf`; keep the
  btool before/after diff clean when touching default enablement).
  **One documented exception (v1.6.2+):**
  `AI Governance - Prompt Injection Attack Correlation - Rule` ships
  `disabled = 0` because it is the entry-point detection for the Agentic
  Trust workshop / AI Defense demo — a fresh install must reach a Mission
  Control Finding with no manual enablement. It is read-only (no email, no
  ServiceNow, no outbound call). Do not add further exceptions without the
  same rationale comment in the stanza and a README changelog entry.
- Data models: `AI_Inference`, `AI_Safety`, `AI_Evaluation`
  (acceleration off by default).
- Custom confs (`ta_gen_ai_cim_*`) need: reload triggers in
  `app.conf [triggers]`, `conf_replication_include` in
  `default/server.conf`, a `.spec` in `default/`, and `admin, sc_admin`
  meta grants for their endpoints.
- Never modify Splunk stock roles (e.g. `[role_admin]`) in `default/`.

## ServiceNow table mapping

| ServiceNow table | Purpose | KV store | Key field |
|---|---|---|---|
| `sn_ai_case_mgmt_ai_case` | AI Case escalation | `gen_ai_snow_case_map` | `event_id` |
| `alm_ai_system_digital_asset` | AI System inventory | `gen_ai_app_asset_map` | `gen_ai_app_name` |
| `alm_ai_model_digital_asset` | AI Model inventory | `gen_ai_model_asset_map` | `gen_ai_response_model` |

Table names are configurable in `ta_gen_ai_cim_account.conf`
(`asset_discovery` stanza). Credentials live in storage/passwords under
realm `ta_gen_ai_cim_account__<account>` — written only by the
`ta_gen_ai_cim_account` REST handler (UI and `snow_setup.py` both drive it).

## Privacy

This TA processes events that may contain PII/PHI. Never log
prompt/response/event content at INFO; content logging is DEBUG-only,
gated by `debug_logging` in `ta_gen_ai_cim_genai_scoring.conf [settings]`.
Never put API keys in URLs (Gemini uses the `x-goog-api-key` header).

## Verification (run after changes)

```bash
/opt/splunk104/bin/splunk cmd python3.9 -m py_compile bin/*.py   # and python3.13
/opt/splunk104/bin/splunk btool check --app=TA-gen_ai_cim
/opt/splunk104/bin/splunk btool <conf> list --app=TA-gen_ai_cim --debug
bash package.sh   # then:
splunk-appinspect inspect TA-gen_ai_cim-<version>.tgz --included-tags cloud
```

Expected AppInspect result (`--included-tags cloud`): 0 errors / 0
failures / 0 future-failures, and only these 8 accepted warnings:

- `check_reload_trigger_for_meta` — custom-conf reload triggers, by design.
- `check_for_gratuitous_cron_scheduling` — governance searches on fixed crons.
- `check_for_datamodel_acceleration` — DMA shipped off (customer opts in).
- `check_for_splunk_js` — vendored dashboard JS.
- `check_collections_conf` — informational KV store collection review.
- `check_for_python_script_existence` — informational review of bin/ scripts.
- `check_python_sdk_version` — manual review of the vendored splunklib.
- `check_hostnames_and_ips` — public IPs in the `medadvice_*` demo lookups.

Any warning outside this list, or a count other than 8, is drift: fix the
underlying item or update this list in the same change.

Live checks on this box (Splunk MCP `splunk_run_query`; note `| rest` and
custom commands are blocked by the MCP): scheduler health via
`index=_internal sourcetype=scheduler savedsearch_name="GenAI Scoring - Pipeline 5"`
(runs every minute here) and error scan via
`index=_internal source=*scheduler.log* log_level=ERROR`.

## Skills

Project skills live in `.claude/skills/` (mirrored for Cursor in
`.cursor/skills/` — keep edits in sync): `splunk-dashboard-studio`,
`splunk-ml-detection`, `splunk-ta-development`, `splunk-workshop-design`.
