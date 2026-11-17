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
  The Cisco Duo modular input (v1.9.0): `ta_gen_ai_cim_duo.py` (the scheme
  entry point Splunk runs, a shim) -> `ta_gen_ai_cim_duo_input.py`
  (window, checkpoint, users snapshot, SHC guard) over
  `ta_gen_ai_cim_duo_api.py`, the TA's canonical read-only Duo Admin API
  client (v5 signer identical to `soar_apps/pseudoco_identity/pseudoco_identity_duo.py`,
  proven by `tools/duo/tests/test_duo_api.py`; it never imports `soar_apps/`).
- `lib/splunklib/` — vendored Splunk SDK (keep ≥ 2.1.1: older versions'
  `six` shim breaks under Python 3.13, which `python.required = 3.13`
  selects on Splunk 9.4+).
- `tools/` — dev-only scripts and docs (never packaged). The MLTK model
  loaders live here, not in `bin/`, because they write into another app's
  dir. Also `show_postdeploy.py` (configures a Splunk Show stack for the
  AI Defense demo — everything the tarball structurally cannot do) plus
  `demobot-spray-attack-spec.md`,
  `splunk-show-template-integration.md` and
  `es-guided-response-runbook.md`, each with a parallel self-contained
  `.html`. `tools/soar/` holds the build script, persona generator and offline
  tests for the SOAR app in `soar_apps/` (see below). `tools/duo/` holds
  `fake_duo.py` (in-memory and loopback-HTTP fake Duo Admin API, which returns
  logs DESCENDING by default so a missing `sort=ts:asc` fails a test, and, like
  Duo, a `next_offset` on the last page that has records; `echo_offset=True`
  models a Duo that echoes the `next_offset` it was sent) and the Duo input and
  client tests.
- `soar_apps/` — **SOAR** apps, not Splunk apps. Top level and outside
  `default/` on purpose: SOAR is a separate product, so the folder (or the
  committed `medadvice_idp.tgz` beside it) is lifted out and uploaded to the
  SOAR instance on its own. It still ships inside the TA tarball, which is what
  lets `bin/genai_es_seed.py` package it in memory for `install_simulator`;
  `package.sh` excludes only `soar_apps/*.tgz` so the archive holds no nested
  tarball. `medadvice_idp/` is a simulated identity provider (classic
  connector, stdlib only, stateless, every result `"simulated": true`) whose
  persona table is generated from `lookups/medadvice_identities.csv` by
  `tools/soar/gen_personas.py` (`--check` in `build.sh`). `build.sh` and
  `build_soar_app_tgz()` must produce the same archive shape — only the
  `build.sh` output has been verified to install on SOAR, and a unit test
  asserts the two match. `pseudoco_identity/` (v1.8.0) is the AI Trust Lab 5
  containment connector: **real**, not simulated (`simulated: false`), it
  disables the room's victim persona in Duo through the Duo Admin API (v5
  signing, stdlib only, `pseudoco_identity_duo.py`) and nothing else. Its
  source is excluded from the TA package (`package.sh`); only
  `tools/show_postdeploy.py --lab5` installs it, and the seeder never creates
  its asset. `tools/soar/build.sh` builds both apps; `gen_personas.py`
  generates both apps' persona modules (the simulator's Lab 5 refusal list and
  PseudoCo Identity's persona lists) from the lookups.
- `tools/identity/` — `gen_identity_personas.py` builds
  `lookups/pseudoco_identity_personas.csv` from the PseudoCo Assistant persona
  file (`scripts/identity/personas.yaml` in that repo). `tools/lab5_steps.py`
  holds the `show_postdeploy.py --lab5` steps; `tools/tests/` the Lab 5 conf
  tests (also the menu, the home cards and the Duo Identity Feed view), live
  SPL fixtures and the scratch-index end-to-end script, and (v1.9.0) the Duo
  conf, SPL and account tests, the packaging tests and the Identity Activity
  view's tests (`test_identity_activity.py`).
- `elements/`, `README/` — internal docs, excluded from the package, except
  `README/*.conf.spec` (top level only), which Splunk reads from there and which
  therefore ship: `README/inputs.conf.spec` (the `ta_gen_ai_cim_duo` scheme)
  and `README/alert_actions.conf.spec` (R-PKG-003 amendment of 2026-11-16).
  `bin/README` ships too.
- `package.sh` — builds the shippable tarball; keep its exclude list in
  sync when adding assistant/dev files. It excludes every top-level `README/`
  member that is not a `*.conf.spec` by exact path, and the site-generated
  `lookups/ta_gen_ai_cim_duo_identities.csv`.

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
- JSON arrays → multi-value fields via `EVAL` in props.conf reading the
  **braced** auto-extracted name (`safety_categories{}`), with a bare-name
  fallback for scalar emitters. Never `FIELDALIAS` (multivalue through an
  alias is undocumented) and never a `REPORT` with `SOURCE_KEY = <bare
  name>` — that key never resolves under `KV_MODE = json`, which left five
  CIM array fields silently null until v1.6.2.
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
  `tools/show_postdeploy.py` encodes on write, recursively, including the SPL.
  The authoritative schema is the Python model at
  `missioncontrol/bin/blueridge/data_models/models/response_template.py`, **not
  `collections.conf`** — the latter declares only scalar/indexed types and omits
  nested objects, so its silence about a field proves nothing. Tasks **do**
  support embedded SPL via `suggestions.searches[] {name, description, spl}`
  (`actions[]`/`playbooks[]` are SOAR objects, not Splunk alert actions).
  `origin` must be a `{id, name, version}` **dict** — a bare string raises
  `TypeError` in `ResponseTemplateOrigin(**origin)` and breaks every read
  through the `/response_templates` REST handler the ES UI uses.
- A response plan **never binds to a detection**. The chain is
  `action.notable.param.investigation_type` → KV `mc_incident_types`
  (`_key` = that name, `response_template_ids` = **array**) → KV
  `mc_response_templates`. Investigation type names must be **lowercase**
  (`missioncontrol/bin/blueridge/incident_types.py` rejects uppercase), and the
  conf value must match the `_key` exactly or the plan silently fails to attach.
  The TA ships and seeds only the plan: **no investigation type** and **no
  `investigation_type` on its detections** (removed in 1.7.2). Mission
  Control's investigation-type API answers `DELETE` with 405, so a seeded type
  outlives the TA, and a detection naming a type the stack lacks is flagged
  as missing. Customers bind the plan to their own type in ES; never seed
  `mc_incident_types` or reintroduce the conf key.
- The ES **Triage agent** gates on an allowlist, not on annotations, risk, or
  severity: `es_ai_settings.conf [ai_triage_detections] enabled` keyed on
  `"<search name>+<app name>"` (see `triage_agent_utils.py`), plus
  `ai_triage_enabled` and the entitlement flag `allow_ai_triage`. It needs ES
  8.6 Premier + Platform 10.1+ + AWS Cloud + paired SOAR; this dev box is ES
  8.5.1, so it cannot be verified here.
- KV store: underscore field names (dots break REST), `replicate = true`,
  `accelerated_fields` for hot queries, typed `field.<name>` declarations.
- Macros: `genai_*` (cost/analytics) vs `gen_ai_*` (review/workflow);
  every macro gets a doc comment; always set `iseval`.
- Saved searches: `GenAI - <Category> - <Action>` naming. **Everything
  ships `disabled = 1`** — enablement is per-environment via `local/`
  (this box's enablement is in `local/savedsearches.conf`; keep the
  btool before/after diff clean when touching default enablement).
  **Three documented exceptions:**
  (1) `AI Governance - Prompt Injection Attack Correlation - Rule` (v1.6.2+)
  ships `disabled = 0` because it is the entry-point detection for the
  Agentic Trust workshop / AI Defense demo — a fresh install must reach a
  Mission Control Finding with no manual enablement. It is read-only (no
  email, no ServiceNow, no outbound call).
  (2) `GenAI - Tokenomics - Seed Token Cost Pricing` (v1.6.5+) ships
  `disabled = 0` + `run_on_startup = 1` because a fresh install has an empty
  `genai_token_cost` collection and every cost panel renders $0. It writes
  only shipped CSV constants (`lookups/genai_token_cost_seed.csv`) into the
  app's own collection, insert-only and idempotent, and reads no event data.
  (3) `GenAI - ES - Seed Response Plan and SOAR Binding` (v1.7.0+) ships
  `disabled = 0` + `run_on_startup = 1` and runs `| genaiseedes`: it writes
  the TA-owned records a TA cannot ship as conf into the `missioncontrol`
  namespace (response plan, AI Findings queue; never an investigation type)
  and, via the ES/SOAR pairing proxy, the `medadvice_idp`
  asset + the plan's SOAR task actions when the simulator app is on the
  paired SOAR. Update-or-create, live task actions always preserved, triage
  allowlist merged, no event data read; `install_simulator`,
  `enable_triage_agent`, `route_findings_to_queue` and
  `seed_identity_response_plan` (the Lab 5 Compromised Identity Response Plan,
  bound to PseudoCo Identity only when its app and asset already exist) ship
  off in `ta_gen_ai_cim_es.conf`.
  Do not add further exceptions without the same stanza rationale comment, a
  README changelog entry, and an R-SEC-002 amendment in VALIDATION_RULES.md.
- **AI Trust Lab 5 content ships off** (v1.8.0): the compromised-identity
  rule `disabled = 1`, `[identity_manager://pseudoco_identity_personas]`
  `disabled = true`, `seed_identity_response_plan = false`, and the PseudoCo
  Identity connector outside the package. Lab personas must never merge into a
  customer's identities and a lab plan never lands on a customer stack;
  `show_postdeploy.py --lab5` enables them per room stack. Participant accounts
  (`l5-<workshop>-<nn>`) are never a victim or a trusted persona: the rule
  excludes them (`genai_identity_participant_filter`), the generator rejects
  them and both SOAR apps refuse them.
- CII (Cisco Identity Intelligence) events belong to the Cisco Security Cloud
  app's sourcetype, so the TA adds no props for them and reads them with
  `spath` inside `genai_cii_extract`. The field paths are provisional until a
  real `FAILED_CHECK` event is captured (Lab 5 spike S6): re-pin the macro, the
  fixtures (`tools/tests/fixtures/lab5_spl.json`) and the dashboard together.
  The rule accepts labelled backfill (`backfill=true`, `source=lab5-setup`) and
  names every finding's evidence provenance (`cii_provenance`).
- **Modular inputs ship off** (R-INP-001, v1.9.0): `default/inputs.conf` holds
  only the scheme's default stanza (never a `[<scheme>://` instance, enabled or
  not); `README/inputs.conf.spec` and the entry point `bin/<scheme>.py` ship;
  `validate_input` enforces the 120 s interval floor and the script holds it at
  runtime too (an interval set in `local/` skips validation); secrets come only
  from `storage/passwords` with the input's own session key and are never
  logged; the index is instance-set and never `gen_ai_log`. The input sets
  `_time` itself, so props stay search-time only. `app.manifest`
  `targetWorkloads` lists `_forwarders` because the Duo input may run on a
  heavy forwarder (which then needs the KV store for its checkpoint).
- **Cisco Duo content ships off** (v1.9.0): no input instance, no identity
  source stanza, the lookup gen and the Duo rule `disabled = 1`, and the
  identity CSV never tracked or packaged.
  `[identity_manager://ta_gen_ai_cim_duo_identities]` is only a commented
  example in `default/inputs.conf` (kept identical to the README's stanza by
  `tools/tests/test_duo_conf.py`); an owner adds it in `local/inputs.conf` or
  in ES once the CSV has rows. Never ship it, not even disabled, and never
  ship a header-only CSV for it: ES's identity manager (SA-IdentityManagement,
  every 300 s) checks the lookup file of every `identity_manager` source,
  disabled ones included, and logs `ERROR PersistentScript ... Lookup table
  was not found` to `splunkd.log` every 5 minutes while the file is missing
  (found live on 2026-11-16), and a bundled CSV would overwrite the generated
  one on every upgrade. R-INP-002 makes it general: an identity or asset
  source ships in `default/` only together with its lookup file.
  Two deliberate deviations from the design, both pinned
  in `tools/tests/test_duo_conf.py`: CIM 8.5.0's Authentication data model has
  **no `vendor_product` field** (`Splunk_SA_CIM/default/data/models/Authentication.json`),
  so the rule scopes `tstats` by the sourcetype through `genai_duo_auth_events`,
  which must therefore stay index/sourcetype/source/host terms with no pipe;
  and it never filters on `authentication_service=duo`, which PseudoCo
  Assistant's own Duo sign-in records also carry. Its `tstats` BY list is
  `_time, <fields> span=1s` (span last, as documented) and holds no field the
  Duo feed can leave null (`tstats` drops such rows), so fraud is read from
  `signature_id`, never `Authentication.result`. The rule's `user` is the
  identity join key (the lowercased local part of the Duo username), while the
  identity value is username|email|aliases, username first; ES keeps that pipe
  order (SA-IdentityManagement rejoins identity before its `mvsort`, which
  then sorts one value), so the canonical key is the Duo username. Where a
  tenant's Duo usernames are emails, the risk object is not an identity key
  unless the Duo identity source sets
  `dynamic_identity_spec = {"email_short": true}` (a per-source setting).
  Add that source only once its CSV has rows: ES's merge search fails for
  every identity source while an enabled source's file is missing. The TA adds
  no props for Cisco Security Cloud's `cisco:duo:*` sourcetypes.
- Data models: `AI_Inference`, `AI_Safety`, `AI_Evaluation`
  (acceleration off by default).
- Custom confs (`ta_gen_ai_cim_*`) need: reload triggers in
  `app.conf [triggers]`, `conf_replication_include` in
  `default/server.conf`, a `.spec` in `default/`, and `admin, sc_admin`
  meta grants under the conf's own name, `[ta_gen_ai_cim_<x>]` (the object
  splunkd writes as `[ta_gen_ai_cim_genai_scoring/pipeline_1]` in
  `local.meta`). Never `[conf/...]` or `[configs/conf-...]`: Splunk applies
  neither, and until v1.9.0 those names left every TA conf readable by all
  (`[]`, read `*`, export system).
- Dashboards are Dashboard Studio v2, dark. The home (`TA-gen_ai_cim_home`,
  the default view: one numbered card and one live KPI per menu dashboard,
  then the scoreboard), *Duo Identity Feed* (`ta_gen_ai_cim_duo_identity`) and
  *Identity Activity* (`ta_gen_ai_cim_identity_activity`, v1.9.0: per
  identity, Cisco Duo next to the AI application, keyed by
  `genai_identity_join_key`) are absolute layout on canvas `#171D21` with
  `#31373E` cards. The menu's Dashboards collection, the home cards and
  `DASHBOARDS` in `tools/tests/test_lab5_conf.py` move together. Rules
  `tools/tests/test_identity_activity.py` pins for Identity Activity, to
  follow in any new panel: a search reads events only through the contract
  macros (never a hard-coded index or sourcetype); a KPI's last `stats` is a
  count or carries one beside its `sum()` (a bare `sum()` over no rows is null
  and Studio draws `###`); a query holds no `$` that is not a token (Studio
  pairs any two into a token, so no regex `$` anchor beside one); an input
  token is compared only as a quoted field value
  (`| search identity_key=$identity|s$`); no prompt or response text, email
  address or phone number reaches a panel, so a user is shown as the identity
  join key, never as the raw Duo username (an email address on some tenants).
  A panel fed by Enterprise Security (`Risk.All_Risk`,
  `identity_lookup_expanded`) says "Needs Enterprise Security", and that it
  shows an error without it when the whole panel fails; those reads stay out
  of the searches that must work without ES: a `tstats` on a missing data
  model is fatal even inside `append`. Four more, each found on live data in
  the 1.9.0 review:
  - A **verified AI turn** is `genai_identity_verified_turn` (the turn's one
    chat event: provider set, operation `chat`), never "verified and not an
    audit record": PseudoCo Assistant stamps `identity_verified` on every
    event of a signed-in turn (tool calls, decisions and, on a
    single-sourcetype destination, the escalation record). The application's
    identity events are read through `genai_identity_activity_events`, whose
    raw term `identity_*` only narrows the scan; a Duo outcome is
    `genai_identity_duo_class` everywhere.
  - **ES 8's Risk data model reads the notable index too**
    (`(index=risk OR index=notable)`), so a rule that writes a risk event and
    raises a finding is two rows. Count them apart (`index` in the `tstats`
    BY list, renamed before any comparison) and keep the score as the total,
    which is ES's own entity risk. Never filter to the risk index: a detection
    that only raises a finding would vanish.
  - **An application sign-in pairs with Duo on the transaction id**: the
    `identity_signin_success` record carries `details.duo_txid`, equal to the
    Duo authentication's `txid`. Only a verified turn has no such key and is
    matched on user and time (nearest earlier successful Duo authentication
    within 10 minutes). Never write that the application does not log it.
  - **`append` keeps the first 50,000 rows of its subsearch**, silently:
    filter and aggregate inside the subsearch and sort so that a cap drops the
    least useful rows.

  In an absolute layout a card rectangle comes before the panel it frames in
  `layout.structure` (later blocks are drawn on top and the rectangles are
  opaque); `StudioLayoutMixin.assert_draw_order` pins it for all three views.
- Never modify Splunk stock roles (e.g. `[role_admin]`) in `default/`.

## ServiceNow table mapping

| ServiceNow table | Purpose | KV store | Key field |
|---|---|---|---|
| `sn_ai_case_mgmt_ai_case` | AI Case escalation | `gen_ai_snow_case_map` | `event_id` |
| `alm_ai_system_digital_asset` | AI System inventory | `gen_ai_app_asset_map` | `gen_ai_app_name` |
| `alm_ai_model_digital_asset` | AI Model inventory | `gen_ai_model_asset_map` | `gen_ai_response_model` |

Table names are configurable in `ta_gen_ai_cim_account.conf`
(`asset_discovery` stanza). Credentials live in storage/passwords under
realm `ta_gen_ai_cim_account__<account>` — written by the
`ta_gen_ai_cim_account` REST handler (the Configuration page's Cisco Duo tab
and `snow_setup.py`) and, for ServiceNow accounts, by the Configuration page's
ServiceNow tab through `configs/conf-ta_gen_ai_cim_account` +
`storage/passwords`. The conf also holds the `soar` and Cisco Duo
(`auth_type = duo_hmac`) accounts, so ServiceNow consumers pick theirs with
`sync_snow_asset.select_snow_account`, never by stanza order. Since v1.9.0
`metadata/default.meta [passwords]` limits every credential to `admin,
sc_admin` with `export = none`: a reader must connect in this app's context as
one of those roles, so a shipped search whose action reads a credential is
`owner = admin` (the five ServiceNow sync/inventory searches, R-CONF-005).

## Privacy

This TA processes events that may contain PII/PHI. Never log
prompt/response/event content at INFO; content logging is DEBUG-only,
gated by `debug_logging` in `ta_gen_ai_cim_genai_scoring.conf [settings]`.
Never put API keys in URLs (Gemini uses the `x-goog-api-key` header).

## Verification (run after changes)

The authoritative gate is
`.claude/skills/splunk-ta-development/VALIDATION_RULES.md` — packaging,
security, config, and doc rules harvested from the review findings on every
publish MR to `tmm/domane-unreleased-apps`. It is append-only: after submitting
an MR there, harvest the `codex-ai-mr-bot` findings and fold them back in
(protocol at the top of that file), then mirror it to `.cursor/skills/`.
Run `bash .claude/skills/splunk-ta-development/check_package.sh <pkg>.tgz`
after `package.sh` to enforce the mechanical rules. Offline tests:

```bash
PYTHONPATH=tools/soar/tests/phantom_shim /opt/splunk104/bin/splunk cmd python3.13 \
    -m unittest discover -s tools/soar/tests            # seeder + both SOAR apps
python3 -m unittest discover -s tools/identity/tests   # Lab 5 persona rows
python3 -m unittest discover -s tools/tests             # Lab 5 + Duo conf, Duo account, packaging (+ live SPL with SPLUNK_TEST_*)
python3 -m unittest discover -s tools/duo/tests          # Duo client + modular input vs fake Duo (also runs under splunk cmd python3.9 / python3.13)
/opt/splunk104/bin/splunk cmd python3.13 -m unittest discover -s tools/tests -p 'test_duo_account.py'  # + the real splunk.admin round trip
python3 tools/tests/fixtures/duo_spl_gen.py --check     # Duo SPL fixtures are current (like gen_personas.py --check)
```

`tools/tests` holds `test_duo_conf.py` (offline) and `test_duo_spl.py` (live,
with `SPLUNK_TEST_*`); the Duo SPL fixtures in `tools/tests/fixtures/duo_spl.json`
are generated by `tools/tests/fixtures/duo_spl_gen.py`. `test_duo_package.py`
builds the package from a scratch copy of the tree and runs `check_package.sh`
on it and on deliberately broken tarballs. `test_identity_activity.py` pins the
Identity Activity view offline and, with `SPLUNK_TEST_*`, dispatches every one
of its searches over an empty window and over the default one. Its
`SIMULATIONS` run makeresults rows through the view's own text (a branch's
eval, a search's tail, the three `genai_identity_*` macros) and compare one
answer each; `python3 tools/tests/test_identity_activity.py --simulations`
prints them with the expected answer, to paste into a search bar or the
read-only Splunk MCP (each fits its 5,000-character limit).

```bash
/opt/splunk104/bin/splunk cmd python3.9 -m py_compile bin/*.py   # and python3.13
/opt/splunk104/bin/splunk btool check --app=TA-gen_ai_cim
/opt/splunk104/bin/splunk btool <conf> list --app=TA-gen_ai_cim --debug
bash package.sh   # then:
splunk-appinspect inspect TA-gen_ai_cim-<version>.tgz --included-tags cloud
```

Expected AppInspect result (`--included-tags cloud`, AppInspect 4.2.0): 0
errors / 0 failures / 0 future-failures, and only these 9 accepted warnings:

- `check_reload_trigger_for_meta` — custom-conf reload triggers, by design.
- `check_for_gratuitous_cron_scheduling` — governance searches on fixed crons.
- `check_for_datamodel_acceleration` — DMA shipped off (customer opts in).
- `check_for_splunk_js` — vendored dashboard JS.
- `check_collections_conf` — informational KV store collection review.
- `check_for_python_script_existence` — informational review of bin/ scripts.
- `check_python_sdk_version` — manual review of the vendored splunklib.
- `check_hostnames_and_ips` — public IPs in the `medadvice_*` demo lookups.
- `check_for_modular_inputs` — informational since v1.9.0: "App contains
  modular inputs in inputs.conf.spec. No action required." (the Duo input's
  `README/inputs.conf.spec`).

Any warning outside this list, or a count other than 9, is drift: fix the
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

`splunk-ta-development/VALIDATION_RULES.md` is a hard gate rather than a
reference — read it before any TA change and run its checks before packaging.
