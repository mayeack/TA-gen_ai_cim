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
  holds the `show_postdeploy.py --lab5` steps and `tools/duo_steps.py` the
  `--duo` / `--duo-teardown` ones (below); `tools/tests/` the Lab 5 conf
  tests (also the menu, the home cards and the Duo Identity Feed view), live
  SPL fixtures and the scratch-index end-to-end script, and (v1.9.0) the Duo
  conf, SPL and account tests, the packaging tests, the Identity Activity
  view's tests (`test_identity_activity.py`) and the stack tool's tests
  (`test_duo_stack.py` against `fake_splunk_rest.py`).
- **The Duo stack tool** (`tools/duo_steps.py`, LR-09, 2026-11-17; steps D0-D8
  and DT1-DT7, one run per stack that polls Duo). Rules to keep:
  - The Duo secret key comes only from a named environment variable or a
    hidden prompt: never argv, never a file, never a printed line or an
    exception's text. It travels only in the body of the account write, which
    bypasses `Splunkd.call` (its dry run prints bodies). A Duo run verifies
    the stack's certificate; `--duo-no-tls-verify` is the only way around it
    and the run says so. A private CA comes in through `--duo-ca-file`, loaded
    explicitly into the stack's context only (`load_verify_locations`): never
    tell an operator to set `SSL_CERT_FILE` (Apple's Python on LibreSSL
    ignores it, Splunk's launcher overwrites it, and where it is read it
    replaces the roots ACS needs). No `--duo-*` option gets an argparse `type`
    or `choices` (argparse repeats a bad value), the parser has
    `allow_abbrev=False`, and `Parser.error` repeats nothing from argv but an
    option's name: a value glued to a flag (`--duo-rotate-key=<key>`) and an
    abbreviation with a value both used to be printed back.
  - **Every guard refuses on an answer it cannot read.** Only a positive
    answer is a go-ahead: a 404 for "not there" (never any other status), ACS's
    own `404-index-not-found` for a missing index (a stack ACS does not know
    answers 404 too), ACS's count of 0 before an index the search sees nothing
    in is deleted, a confirmed-gone index before its checkpoints are cleared.
    Never write `if code == 200: keep ... else: delete`. D0 also reads the
    input endpoint itself, so a stack that does not serve it is stopped before
    the index, the stored key, the role grant and the enabled rules.
  - **An index delete is asynchronous.** DT6 writes a marker
    (`PURGE_MARKER`, a document beside the checkpoints) before it asks ACS,
    and clears marker and checkpoints only once ACS answers that the index is
    gone; an unreadable answer is not a confirmation. `--duo` creates no input
    while the marker is there, and `--duo-force` does not override that. The
    index is not deleted from under an input the tool did not make
    (`other_writers`), and the teardown reports, and never changes, a role it
    was not given that still lists the index.
  - The rules are enabled BEFORE the authentication input is created, and the
    input only when the index exists and agrees with the input's checkpoint.
  - **It reads a rule's schedule only through `slot_minutes`**: the rule must
    judge by index time on a slot exactly one cron period wide. It never
    compares `dispatch.earliest_time` with the backfill; `reach_hours` reads
    that key as an event-time reach only for a search with no
    `_index_earliest` / `_index_latest` terms (a build from before LR-07).
  - A rule that reads the Duo feed goes into `DUO_DETECTIONS` and, with the
    field that names one finding, into `JUDGED_IDS`, in the change that adds
    it; `ShippedConfTests` fails otherwise. D8 dispatches a rule's own search
    ad hoc (no alert action runs) and never a text that writes
    (`WRITING_COMMANDS`: Splunk's writing commands with their aliases, `stash`,
    `summaryindex` and `sumindex` among them, and every command of
    `default/commands.conf`; a test fails when that conf gains a command that
    is missing there).
  - The users input and the identity lookup search are opt-in
    (`--duo-with-users`, `--duo-with-lookup-gen`), and every setup run prints
    what the stack will hold (`scope_lines`). The tool never adds the Duo
    identity source and never edits `cim_Authentication_indexes` (D4 and the
    data-model count in D7 are notes: the TA's rules do not read the data
    model).
  - `fake_splunk_rest.py` serves the SHIPPED saved-search stanzas and the
    shipped account handler. Never give it a schedule or a search text of its
    own: the first build's tests passed against an invented
    `dispatch.earliest_time` while the real rule would have been refused.
  - `tools/lab5-identity-runbook.html` is regenerated from the `.md`
    (`markdown.markdown(md, extensions=['tables', 'fenced_code', 'toc'])`
    inside the page's fixed head and tail), never edited by hand.
    `DocsTests.test_runbook_md_and_html_say_the_same` compares the two byte
    for byte only where Python-Markdown is installed and SKIPS elsewhere (it
    is not in Splunk's Python): a skip there is not a pass, so run the suite
    once under a Python that has it.
  - Its tests run the real entry point: `main()` with valid command lines
    against the fake (`main_on_the_fake`), a real loopback TLS handshake for
    the certificate handling, and one test per guard with the read it rests on
    made to fail (`GuardTests`, `fake.fail`). A new guard gets its failing-read
    test in the same change: flipping a `return False` to `True` must fail a
    test, and a "bad command line" test patches `seed.http_request` to raise,
    so "before any request" is asserted and not assumed.
  - Nothing in it has run against a real Splunk Cloud stack, ACS or Duo.
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
  source stanza, the lookup gen and both Duo rules (the denial-burst rule and
  the joined rule, below) `disabled = 1`, and the identity CSV never tracked
  or packaged.
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
  in `tools/tests/test_duo_conf.py`: the rule is scoped by the sourcetype
  through `genai_duo_auth_events` (CIM 8.5.0's Authentication data model has
  **no `vendor_product` field**), which must stay index/sourcetype/source/host
  terms with no pipe; and it never filters on `authentication_service=duo`,
  which PseudoCo Assistant's own Duo sign-in records also carry.
  **The rule judges by index time and counts by event time** (LR-07,
  2026-11-17). Its job time range (`-12m@m` to `-2m@m`, cron `*/10`,
  `realtime_schedule = 0`) is the slot of INDEX time one run judges, exactly one
  period wide, so runs tile; subsearches turn that range into
  `_index_earliest`/`_index_latest` terms and read the failures by EVENT time
  around the slot's events. **`dispatch.earliest_time` of this rule is an
  index-time slot edge, never an event-time reach; the event-time reach is the
  `-181d@d` in the context subsearch.** No tool or test may read it as one.
  It reads the Duo events themselves, never `tstats` on the Authentication data
  model: an accelerated data model keeps no index time (`tstats` on the data
  model returns no row for `_index_earliest` and no `_indextime`; found live).
  `tstats` on the raw index does honour `_index_earliest` and returns
  `_indextime`, so the limit is the data model, not `tstats`. A burst (a user's
  run of failures and fraud reports with no gap over 10 minutes) is raised in
  the one slot that takes it to 5 failures within 10 minutes, a fraud report in
  the slot that indexes the burst's first one. A fraud report is a fraud report
  only, never one of the 5 failures (the props map Duo's result fraud to action
  failure, so it would count twice): the two signatures are judged on disjoint
  events. Each result is dated at its Duo event and named by `burst_id`, the
  suppression key (never a blanket time throttle; `burst_id` and `burst_time`
  stay out of `nes_fields`, which only pre-selects ES's "Suppress Event" dialog).
  Dating, said one way everywhere: the risk event is dated at the Duo event; the
  finding, and its own row in `Risk.All_Risk` (index notable, same score), when
  it is raised, with the event time in `orig_time` and `burst_time`. So a
  backfilled burst adds its score to "last 24 hours" risk at the moment of the
  backfill and can trip ES's 24-hour risk threshold rule. Events are
  de-duplicated on Duo's `txid`. A time range with no end is judged up to now
  (`info_max_time` is then `+Infinity`: both subsearches guard it with
  `isnum()`). Never give the rule an event-time lookback, a `now()`, a literal
  index-time slot, `dispatch.index_*` or `allow_data_time_skew` (`allow_skew`
  alone leaves the slot on the cron tick); never change the cron without the two
  dispatch times; keep every continuation line of its search indented (the gate
  scripts end a stanza at a line starting with `[`). A failed run loses its slot
  (README, *How the rule judges Duo events*): it writes NO status row to
  `scheduler.log`, so it is found as a slot with no `status=success` row, never
  with `status!=success` (those are deferrals that completed). A catch-up run
  gets both ends of its range and never covers index time the scheduled runs
  judged: one pass does not know what they raised, and the suppression drops a
  repeat for 24 hours only. **Read the slot's start in a subsearch of its own
  (`| append [| makeresults | addinfo ...]`), never with `addinfo` in the main
  pipeline**: there it returns the event-time range the context subsearch wrote
  into the base search, so every event counts as new. Its fixtures carry a
  `window` (the slot) and an `_indextime` per row; the `rule timing:` ones name
  the lab personas nina.osei and jordan.reyes by short name, every other Duo
  fixture an invented identity. Before a change to the rule's text is
  committed, run every rule fixture through the read-only Splunk MCP over its
  `window` and record it (**The proof record**, below).
  **The joined rule** (LR-06, 2026-11-17), `AI Governance - Duo Denial Burst
  to Blocked AI Turn Correlation - Rule`, follows the same contract: a
  5-minute index-time slot (`-7m@m` to `-2m@m`, cron `*/5`,
  `realtime_schedule = 0`; its `dispatch.earliest_time` is a slot edge too,
  never a reach), the Duo rule's two index-time subsearches with the `isnum()`
  guard, and event-time context 6,000 s either side of the slot's events (10 +
  30 + 60 minutes). For one identity it needs, in event-time order, a burst (5
  failed Duo authentications within 10 minutes; **a fraud report is a failure
  here**), an application sign-in (`identity_signin_success`) under 30 minutes
  after a moment the failures stood at 5, and a blocked verified turn
  (`genai_identity_verified_turn`) within 60 minutes of that sign-in. One
  finding per sign-in: `chain_id` (`<user>:takeover:<epoch of the sign-in>`)
  is the suppression key and `_time` the first blocked turn. Every quantity is
  computed twice (indexed by the slot's end, and before the slot), so a chain
  is raised in the run that indexes its last missing step, whichever of the
  three that is. `is_new` compares index time with `slot_earliest`, read in an
  append subsearch exactly as in the Duo rule: the first build read it with
  `addinfo` in the main pipeline, got the event-time range its own finder
  writes into the base search, counted every row as new and raised a chain
  again in every later run that touched it, with all 25 fixtures green (a
  fixture's makeresults rows carry no inline time range, so `addinfo` returns
  the job's window anywhere; only a dispatch of the FULL text shows it:
  `DuoSlotEdgeTests`, `DuoChainSplitTests`). **What was raised before is
  decided per chain, by the blocked turn that completed it**: `old_turn` is an
  old turn within the hour of an old qualifying sign-in, `old_turn_n = 1` the
  first of them, and a chain that holds such a turn is not raised again, also
  when a late sign-in record re-attributes it. A chain whose turns were only
  later turns of another, judged chain IS raised (the second chain within the
  hour whose burst is indexed last, which one pass raises too); "any old turn
  within the hour" dropped it. **What a finding names is what was indexed when
  it was raised**: `chain_id`, `_time` and the risk equal a backfill's, but a
  chain raised while the burst nearest to the sign-in is still in Duo's lag
  names an earlier burst within the 30 minutes (`burst_time`,
  `duo_failures_10m`, `duo_app`, `chain_earliest`), and nothing corrects it.
  Holding the sign-in back until Duo's log has passed it is an open decision
  of the owner's, not built: do not add it, or remove the note, without one.
  **The sign-in is
  matched to Duo exactly, and the match never gates the rule**: the record's
  `details.duo_txid` and the Duo authentication's `txid` are one
  de-duplication key, so both land in one row and `signin_duo` names Duo's
  factor and application (`none indexed` while Duo's record is not in, which
  is the usual live case); the row's time and index time are the application
  record's, and a successful Duo authentication alone is never a step. The
  step `case()` reads the audit action BEFORE Duo's `action`: the
  application's sign-in record also says `action=success`, its sign-in failure
  record `action=failure`. New events are looked for among the three steps
  only (Duo successes are context). Keep the search under 4,900 characters and
  every `chain:` fixture under 5,000, so both can be pasted into the read-only
  Splunk MCP, and run every `chain:` fixture over its `window` (a 300 s slot; a
  row is indexed in the slot's first second or in the second before it) before
  a change to the text is committed. The fixture rows are written
  `offset|kind[|link]`, the kind in capitals for a row indexed in the slot and
  in lower case for one indexed before it, all of one user per fixture, to fit
  that limit; a row with no link gets the id `r<row>`, so no link starts with
  `r`. Every arrival order has a fixture that expects a finding (the burst,
  the sign-in or the blocked turn indexed last; a burst split over two slots).
  **The proof record**: the offline suite cannot run SPL, so it cannot tell a
  working rule from a dead one. `tools/tests/fixtures/duo_rule_proof.json`
  holds, for each of the two rules, the digest of the text its fixtures were
  last run against (the search and every macro it uses); `DuoRuleProofTests`
  fails while the text differs. After a change, run the fixtures (with
  `SPLUNK_TEST_*`: `python3 tools/tests/test_duo_spl.py --record-proof chain
  live "<how>"`; without: `--fixtures chain` prints each one for the read-only
  Splunk MCP, `--verify chain results.json` compares what came back,
  `--record-proof chain results.json "<how>"` records it, and only from results
  that agree with every fixture). Never edit the digest by hand to make the
  suite green. `SPLUNK_TEST_REQUIRED=1` makes every live test of
  `test_duo_spl.py` FAIL without a Splunk instead of skipping: set it for the
  run that gates a change to either rule. The live tiling tests cut index time
  where the scheduler does (`slot_grid`: the edges sit `dispatch.latest_time`
  back from the cron ticks, at minutes ending in 8 and in 3 or 8) and compare
  with `REFERENCE_BURSTS` / `REFERENCE_CHAINS`, plain event-time searches with
  no finder: a rule must never be its own oracle. `DuoContextTests` checks what
  a run READS (the finder's margins, `CONTEXT`: 3,600 s back and 601 forward
  for the Duo rule, 6,000 and 6,001 for this one) against a plain search over
  the same window; change a margin in the conf and in `CONTEXT` together. It needs the application's identity
  events in the same stack: the Duo input backfills, the application's HEC
  feed does not.
  The rule's `user` is the
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
  model is fatal even inside `append`. Five more, each found on live data in
  the 1.9.0 reviews:
  - A **verified AI turn** is `genai_identity_verified_turn` (the turn's one
    chat event: provider set, operation `chat`), never "verified and not an
    audit record": PseudoCo Assistant stamps `identity_verified` on every
    event of a signed-in turn (tool calls, decisions and, on a
    single-sourcetype destination, the escalation record). The application's
    identity events are read through `genai_identity_activity_events`, whose
    raw term `identity_*` only narrows the scan; a Duo outcome is
    `genai_identity_duo_class` everywhere. The first two macros also feed the
    joined rule (LR-06), so an override of either changes that detection, and
    `genai_identity_activity_events` stays pipe-free (the rule puts terms
    after it).
  - A **claimed, not verified AI turn** (LR-08, 2026-11-17) is
    `genai_identity_claimed_turn` (the one chat event of a turn that names a
    user with no verified identity: what a prompt-injection spray writes when
    it names a persona), read through `genai_identity_claimed_events`. It is
    counted beside the verified turns and apart from them
    (`claimed_not_verified` / `claimed_blocked` in the overview, *AI turn
    claimed, not verified* on the timeline), never added to them, never
    called a sign-in and never matched to a Duo sign-in. The name is request
    text: it only enriches an identity that a Duo sign-in or an application
    identity event already put in the view, and never creates a row, a
    dropdown entry or a bar. Keep the claimed branch out of `ds_base` and the
    sign-in chain, so the tiles and the dropdown cannot move with it, and out
    of any search but the overview and the timeline: it reads every anonymous
    chat event in the range. Its timeline colour is pale on purpose
    (`CLAIMED_COLOUR` in `test_identity_activity.py` says why). The count
    needs the application's own events in the stack and a spray that names
    the persona among them: the Duo input backfills, the application's HEC
    feed does not (README, *Identity Activity: claimed, not verified turns*;
    `tools/lab5-identity-runbook.md`, T-1).
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
python3 -m unittest discover -s tools/tests             # Lab 5 + Duo conf, Duo account, packaging, the Duo stack tool (+ live SPL with SPLUNK_TEST_*)
python3 -m unittest discover -s tools/duo/tests          # Duo client + modular input vs fake Duo (also runs under splunk cmd python3.9 / python3.13)
/opt/splunk104/bin/splunk cmd python3.13 -m unittest discover -s tools/tests -p 'test_duo_account.py'  # + the real splunk.admin round trip
python3 tools/tests/fixtures/duo_spl_gen.py --check     # Duo SPL fixtures are current (like gen_personas.py --check)
python3 tools/tests/test_duo_spl.py --fixtures chain    # each chain fixture, ready for the read-only Splunk MCP (or: rule)
SPLUNK_TEST_REQUIRED=1 python3 -m unittest discover -s tools/tests -p 'test_duo_spl.py'   # the gate for a change to a Duo rule: no skips
```

`tools/tests` holds `test_duo_conf.py` (offline) and `test_duo_spl.py` (live,
with `SPLUNK_TEST_*`; skipped without, or FAILED without when
`SPLUNK_TEST_REQUIRED=1`); the Duo SPL fixtures in `tools/tests/fixtures/duo_spl.json`
are generated by `tools/tests/fixtures/duo_spl_gen.py`, and
`tools/tests/fixtures/duo_rule_proof.json` records the text of the two Duo
rules that those fixtures were last run against (`test_duo_spl.py --fixtures`,
`--verify`, `--record-proof`; see *The proof record* above). `test_duo_conf.py`
also checks that every `$token$` of the two rules' findings names a field the
search's result carries (`unknown_tokens`). `test_duo_package.py`
builds the package from a scratch copy of the tree and runs `check_package.sh`
on it and on deliberately broken tarballs. `test_identity_activity.py` pins the
Identity Activity view offline and, with `SPLUNK_TEST_*`, dispatches every one
of its searches over an empty window and over the default one. Its
`SIMULATIONS` run makeresults rows through the view's own text (a branch's
eval, a search's tail, the five `genai_identity_*` macros) and compare one
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
