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
  actions `create_snow_case`, `sync_snow_asset`, `pull_snow_inventory`;
  REST handler `ta_gen_ai_cim_account_handler`; CLI `snow_setup`).
  The shared ServiceNow client (config/OAuth/HTTP) lives in
  `sync_snow_asset.py` — never duplicate it; import it.
- `lib/splunklib/` — vendored Splunk SDK (keep ≥ 2.1.1: older versions'
  `six` shim breaks under Python 3.13, which `python.required = 3.13`
  selects on Splunk 9.4+).
- `tools/` — dev-only scripts (never packaged). The MLTK model loaders
  live here, not in `bin/`, because they write into another app's dir.
- `elements/`, `README/` — internal docs, excluded from the package.
- `package.sh` — builds the shippable tarball; keep its exclude list in
  sync when adding assistant/dev files.

## Conf conventions

- **Search-time only**: never add index-time settings
  (`INDEXED_EXTRACTIONS`, `TIME_FORMAT`, `LINE_BREAKER`, …) to props.conf.
- Every `.conf` gets a header comment block (filename, app, purpose,
  "Compatible with: Splunk Enterprise 9.0+, Splunk Cloud") and
  banner-style `###` section separators.
- Primary index: `gen_ai_log`. Normalization: `[index::gen_ai_log]` stanza
  is the base layer; sourcetype stanzas (`[medadvice3:json]`, …) handle
  format-specific mapping. `FIELDALIAS` for 1:1 renames
  (`FIELDALIAS-idx_*` in the index stanza, `FIELDALIAS-genai_*` in
  sourcetype stanzas); `EVAL` for computed/coalesced/boolean fields.
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
  macro).
- KV store: underscore field names (dots break REST), `replicate = true`,
  `accelerated_fields` for hot queries, typed `field.<name>` declarations.
- Macros: `genai_*` (cost/analytics) vs `gen_ai_*` (review/workflow);
  every macro gets a doc comment; always set `iseval`.
- Saved searches: `GenAI - <Category> - <Action>` naming. **Everything
  ships `disabled = 1`** — enablement is per-environment via `local/`
  (this box's enablement is in `local/savedsearches.conf`; keep the
  btool before/after diff clean when touching default enablement).
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

Expected AppInspect result: 0 errors / 0 failures / 0 future-failures;
accepted warnings only (reload_trigger_for_meta, gratuitous cron,
datamodel-acceleration info, splunk_js, collections info).

Live checks on this box (Splunk MCP `splunk_run_query`; note `| rest` and
custom commands are blocked by the MCP): scheduler health via
`index=_internal sourcetype=scheduler savedsearch_name="GenAI Scoring - Pipeline 5"`
(runs every minute here) and error scan via
`index=_internal source=*scheduler.log* log_level=ERROR`.

## Skills

Project skills live in `.claude/skills/` (mirrored for Cursor in
`.cursor/skills/` — keep edits in sync): `splunk-dashboard-studio`,
`splunk-ml-detection`, `splunk-ta-development`, `splunk-workshop-design`.
