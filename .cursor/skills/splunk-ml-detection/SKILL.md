---
name: splunk-ml-detection
description: Build end-to-end Splunk ML-based detections (supervised classification, unsupervised anomaly detection, or hybrid ML+rules). Produces training saved searches, a scheduled scoring pipeline, tiered alerts, a monitoring dashboard, and a customer-ready runbook. Validates every phase via the Splunk MCP server. Use when the user wants to create a new ML detection in Splunk (e.g., PII, prompt injection, toxicity, data exfiltration, jailbreak, or any custom text/event anomaly).
---

# Splunk ML Detection

Stand up a new ML detection in Splunk end to end, without re-deriving patterns. The skill is paradigm-agnostic and works for any text or event-based detection.

## When to Use

Invoke this skill when the user says any of:

- "Build an ML model in Splunk for &lt;X&gt;"
- "Create a detection for &lt;behavior&gt; using ML"
- "Score &lt;prompts|responses|events&gt; for anomalies"
- "Train a Splunk MLTK model for &lt;category&gt;"

Do NOT use this skill for:

- Threat hunts with a specific hypothesis (use `peak-threat-hunting`).
- Parsing a new log format / building a TA (use `splunk-ta-development`).
- Building a visualization for existing data (use `splunk-dashboard-studio`).

This skill delegates Phase 6 dashboard rendering to `splunk-dashboard-studio`.

## Prerequisites

1. Splunk MCP server configured (tools named `splunk_run_query`, `splunk_get_indexes`, `splunk_get_knowledge_objects`, `splunk_get_kv_store_collections`, `splunk_get_metadata`).
2. Splunk Machine Learning Toolkit (MLTK) installed on the target Splunk instance.
3. An app context to write into. Default `TA-gen_ai_cim`; the user may override.

ALWAYS check the MCP tool schema before invoking by reading the JSON descriptor in the MCP tools folder.

## Workflow Overview

Six phases, executed sequentially. Each phase has a pass/fail gate validated via MCP before moving on.

```
Phase 1: Intake      → Phase 2: Data Survey → Phase 3: Train
                                                    ↓
Phase 6: Deliver  ← Phase 5: Alert      ← Phase 4: Score
```

Reference files (read as needed, not up-front):

- [SPL_TEMPLATES.md](SPL_TEMPLATES.md) — parameterized SPL for every saved search the skill produces.
- [DASHBOARD_TEMPLATES.md](DASHBOARD_TEMPLATES.md) — panel catalog passed to `splunk-dashboard-studio`.
- [VALIDATION_CHECKLIST.md](VALIDATION_CHECKLIST.md) — MCP queries run at each gate.
- [CONVENTIONS.md](CONVENTIONS.md) — exact naming rules. Must be followed.

---

## Phase 1 — Intake & Scope

Use `AskQuestion` to collect the intake below. Do NOT proceed without answers. If the user volunteers some answers in their first message, only ask the missing ones.

### Required intake questions

Ask these in ONE `AskQuestion` batch where possible:

1. **Detection slug** — short snake_case identifier (e.g., `toxicity`, `jailbreak`, `data_exfil`, `pii`). Drives every downstream name per [CONVENTIONS.md](CONVENTIONS.md).
2. **Detection target** — what field(s) the model scores:
   - prompt only
   - response only
   - both (score separately, combine risk)
   - arbitrary event text (provide the coalesce list)
3. **Source index + sourcetype filter** — e.g., `index=gen_ai_log`, `index=firewall`, etc.
4. **Paradigm** — three options:
   - **Supervised classification** (you have labeled data → `LogisticRegression` or `RandomForestClassifier`)
   - **Unsupervised anomaly** (you have only "normal" data → `HashingVectorizer` + `PCA` + `OneClassSVM`)
   - **Hybrid** (ML probability + regex/keyword pattern scoring combined)
5. **Training data**:
   - Supervised: lookup name, label column, positive-class value, approximate class ratio.
   - Unsupervised: baseline window (e.g., last 30 days of `index=gen_ai_log` with `exclude_scoring_sourcetypes`), plus any known-bad sourcetypes to exclude.
   - Hybrid: both of the above plus the regex/keyword pattern list.
6. **Feature families to enable** (multi-select):
   - Pattern/regex features (user supplies list of `name: regex` pairs)
   - Statistical features (length, word_count, digit_ratio, special_char_ratio, uppercase_ratio)
   - Keyword-group features (user supplies `group_name: |-joined keyword regex`)
   - TF-IDF semantic features (HashingVectorizer + PCA)
7. **Thresholds** — default risk threshold (0.5 supervised, 0.6 hybrid; unsupervised uses `isNormal < 0`) plus confidence bands.
8. **Alerts** — recipients, severity per tier, whether email action is on.
9. **App context** — default `TA-gen_ai_cim`, override allowed. All models written with `app:` prefix.

### Confirm paradigm and naming before building

After intake, restate to the user:

- The detection slug, target, paradigm, and every artifact name derived from [CONVENTIONS.md](CONVENTIONS.md) (saved searches, model names, macros, output fields, sourcetype, lookups).
- Ask for explicit approval before writing anything.

---

## Phase 2 — Data Survey via MCP

All queries in this phase are READ-ONLY. Use `splunk_run_query` through the MCP server.

### 2.1 Verify indexes and MLTK

```
Tool: splunk_get_indexes
```

Confirm the index from Phase 1 exists.

```
Tool: splunk_run_query
Query: | rest /services/apps/local | search label="Splunk Machine Learning Toolkit" | table label, version, disabled
```

MLTK must be present and enabled.

### 2.2 Verify text extraction

Build the coalesce expression from Phase 1 answer (e.g., for prompts in GenAI telemetry):

```spl
coalesce(mvjoin('input_messages{}.content', " "), 'gen_ai.input.messages', 'event.input', input_messages, input)
```

Run a 10-event probe:

```
Tool: splunk_run_query
Query: index=<idx> earliest=-24h
| head 10
| eval text=coalesce(<list>)
| where isnotnull(text) AND len(text) > 0
| stats count, avg(len(text)) as avg_len, min(len(text)) as min_len, max(len(text)) as max_len
```

Fail gate: `count=0` or `avg_len<20`. Stop and ask the user to correct the coalesce list or the index.

### 2.3 Baseline volume

```
Tool: splunk_run_query
Query: index=<idx> earliest=-7d | stats count, dc(sourcetype) as sourcetypes, min(_time) as earliest, max(_time) as latest | eval earliest=strftime(earliest,"%F"), latest=strftime(latest,"%F")
```

Check: ≥1000 events in last 7 days for supervised training on live data; ≥5000 for unsupervised baseline. If below, inform the user and recommend expanding the time range or using an included lookup.

### 2.4 Class balance (supervised only)

```
Tool: splunk_run_query
Query: | inputlookup <training_lookup> | stats count by <label_column> | eventstats sum(count) as total | eval pct=round(count/total*100, 2)
```

Warn if positive class is <5% or >50% — recommend class weighting during training.

### 2.5 Paradigm confirmation gate

Use [VALIDATION_CHECKLIST.md § Phase 2](VALIDATION_CHECKLIST.md#phase-2--data-survey). All checks must pass before Phase 3.

---

## Phase 3 — Train

Produce training saved searches using the templates in [SPL_TEMPLATES.md](SPL_TEMPLATES.md).

### Critical rules (enforced by templates)

1. `fit` and `apply` MUST NOT appear in the same search. Always split across sequential searches.
2. Models MUST be saved with `into app:<detection>_<artifact>` and applied with `apply app:<detection>_<artifact>`.
3. `OneClassSVM` MUST NOT use `gamma=scale` (string). Omit the parameter or use a float.
4. Training searches MUST include the ``exclude_scoring_sourcetypes`` macro if the source index receives scoring output, to avoid training on enriched events.
5. `HashingVectorizer` is stateless and runs inline in both training and scoring — do NOT save it.
6. Use `random_state=42` on stochastic algorithms for reproducibility.

### Step count by paradigm

| Paradigm | Steps | Artifacts |
|---|---|---|
| Supervised | 3 | `ML - <Detection> Train Step 1 - Feature Engineering`, `Train Step 2 - <Algorithm> Model`, `Train Step 3 - Validate Model Performance` |
| Unsupervised (one target) | 2 | `Train Step 1 - PCA Model`, `Train Step 2 - Anomaly Model` |
| Unsupervised (prompt + response) | 4 | Steps 1-2 for prompt, Steps 3-4 for response |
| Hybrid | 3-4 | Feature engineering, then either supervised Steps 2-3, or TF-IDF PCA + hybrid classifier + validation |

### Generation procedure

For each required saved search:

1. Pull the matching template from [SPL_TEMPLATES.md](SPL_TEMPLATES.md).
2. Substitute tokens — `<detection>`, `<Detection>` (title case), `<idx>`, `<label_column>`, `<source_text_expr>`, etc.
3. Include `enableSched = 0` and `alert.track = 0` on train/validate searches (they are run on demand).
4. Append the stanza to `$SPLUNK_HOME/etc/apps/<app>/local/savedsearches.conf`. NEVER write to `default/`. Use Splunk's layered config.

### Run each training search via MCP in order

For each step, dispatch the saved search via `splunk_run_query` using `| savedsearch "ML - <Detection> Train Step N - ..."` and wait for completion before the next step. Do not batch.

### Pass gate

- `| rest /servicesNS/-/<app>/mltk/models | search title IN (<expected_models>)` returns all expected titles.
- Validation search (final step) reports Accuracy > 0.90 / Precision > 0.75 / Recall > 0.85 / F1 > 0.80 for supervised, or non-zero anomaly count on a known-bad probe set for unsupervised.

If gates fail, consult [VALIDATION_CHECKLIST.md § Phase 3](VALIDATION_CHECKLIST.md#phase-3--train).

---

## Phase 4 — Score

Produce exactly one scoring saved search per target (`prompt`, `response`, or `event`) using the scoring template in [SPL_TEMPLATES.md](SPL_TEMPLATES.md#scoring).

### Critical rules

1. Scoring searches MUST include ``exclude_scoring_sourcetypes`` in their base filter and MUST dedup on event id BEFORE `apply`. Without this, `dedup` may pick a prior scoring event that lacks source text.
2. Feature engineering in scoring MUST be byte-identical to training (same regexes, same preprocessing). The templates encode this.
3. Scoring searches MUST emit enriched events via `| collect index=<idx> source="<detection>_ml_scoring" sourcetype="ai_cim:<detection>:ml_scoring"`.
4. `_raw` MUST be built with `json_object(...)` including every `gen_ai.<detection>.*` output field plus correlation keys (`gen_ai.event.id`, `gen_ai.request.id`, `gen_ai.session.id`, `client.address`, `trace_id`, `service.name`).
5. Schedule with `cron_schedule = * * * * *`, `dispatch.earliest_time = -1m@m`, `dispatch.latest_time = now`, `enableSched = 1`.
6. Add the new sourcetype `ai_cim:<detection>:ml_scoring` to the `exclude_scoring_sourcetypes` macro definition in `local/macros.conf` so future training/scoring ignores it.

### Output fields written by scoring

- `gen_ai.<detection>.risk_score` (float 0-1)
- `gen_ai.<detection>.ml_detected` (string "true"/"false")
- `gen_ai.<detection>.confidence` (very_high/high/medium/low/very_low)
- `gen_ai.<detection>.technique` (optional, keyword-driven classification)
- `gen_ai.<detection>.severity` (optional, critical/high/medium/low/none)
- `gen_ai.<detection>.location` (optional, prompt/response/both/none)

### Pass gate

After 2-3 minutes of scheduled runs:

```
Tool: splunk_run_query
Query: index=<idx> sourcetype="ai_cim:<detection>:ml_scoring" earliest=-15m | stats count, avg('gen_ai.<detection>.risk_score') as avg_score, dc(gen_ai.event.id) as unique_events
```

`count > 0` and `avg_score` is a real number. If zero, follow [VALIDATION_CHECKLIST.md § Phase 4](VALIDATION_CHECKLIST.md#phase-4--score).

---

## Phase 5 — Alert

Generate three alerts from [SPL_TEMPLATES.md § Alerts](SPL_TEMPLATES.md#alerts):

| Saved search | Cadence | Trigger |
|---|---|---|
| `ML - <Detection> High Risk Alert` | every 15 minutes | `risk_score > 0.7` by app/deployment |
| `ML - <Detection> Detection Alert` | hourly | any `ml_detected="true"` |
| `ML - <Detection> Rate Threshold Alert` | every 4 hours | detection rate > 5% OR avg risk > 0.4 |

All three:

- `alert.track = 1`, `alert.digest_mode = 1`, `alert.severity` per the user's Phase 1 answer (default 4).
- Email action populated from Phase 1 recipients.
- `enableSched = 1`.

### Pass gate

```
Tool: splunk_get_knowledge_objects
Type: savedsearches
Filter: name matches "ML - <Detection> .* Alert"
```

All three returned, all `disabled=0`, all `is_scheduled=1`.

---

## Phase 6 — Monitor & Deliver

### 6.1 Dashboard

Delegate to the `splunk-dashboard-studio` skill/subagent. Pass it:

- Detection slug, title, and target.
- The KPI/Trend/Breakdown/Recent panel catalog from [DASHBOARD_TEMPLATES.md](DASHBOARD_TEMPLATES.md). Each panel carries its final SPL with the detection tokens already substituted.
- Index, enriched sourcetype (`ai_cim:<detection>:ml_scoring`), risk and rate thresholds from Phase 1.
- Global inputs: time range (default Last 24 hours), app name, model.
- Target audience (default: governance/SOC analyst).

The subagent writes the dashboard view file and optionally deploys it.

### 6.2 MCP validation sweep

Run the full sweep in [VALIDATION_CHECKLIST.md § Final](VALIDATION_CHECKLIST.md#final-sweep). Every check must pass. Record results in the runbook.

### 6.3 Customer-ready runbook

Fill in and return the template below to the user as the last message of the skill:

```markdown
# <Detection Title> ML Detection — Runbook

## What it detects
<one-line description from intake>

## Where it runs
- App: <app>
- Source index: <idx>
- Enriched sourcetype: ai_cim:<detection>:ml_scoring
- Models: <list of app:<detection>_... models>

## Enable / disable
splunk enable saved-search "ML - <Detection> Scoring - <Target>" -app <app>
splunk enable saved-search "ML - <Detection> High Risk Alert" -app <app>
splunk enable saved-search "ML - <Detection> Detection Alert" -app <app>
splunk enable saved-search "ML - <Detection> Rate Threshold Alert" -app <app>

## Output fields
| Field | Type | Meaning |
| gen_ai.<detection>.risk_score | float 0-1 | ML probability |
| gen_ai.<detection>.ml_detected | string | "true" if risk_score > <threshold> |
| gen_ai.<detection>.confidence | string | very_high/high/medium/low/very_low |
<add technique/severity/location if populated>

## Threshold tuning
Run `ML - <Detection> Threshold Sweep` (from SPL_TEMPLATES.md) to compare recall/FP at 0.3/0.5/0.7.

## Retrain triggers
- Detection rate drifts >20% vs baseline for 7+ days.
- Known miss or known-good false positive reported by analysts.
- Application usage pattern changes (new app onboarded, prompt style shift).

Retrain procedure:
1. splunk dispatch "ML - <Detection> Train Step 1 - Feature Engineering" -app <app>
2. Wait for completion, then dispatch each subsequent Train Step in order.
3. Re-run this runbook's MCP validation sweep.

## Troubleshooting quick-ref
- Model not found → confirm `| rest /servicesNS/-/<app>/mltk/models | search title=<detection>_model` returns a row. Retrain if empty.
- Low recall → lower threshold by 0.1 and/or retrain with `class_weight=balanced`.
- High false positives → raise threshold, add confusing negatives to training set.
- Scoring empties → ensure `exclude_scoring_sourcetypes` macro contains `ai_cim:<detection>:ml_scoring` and scoring search dedups AFTER the exclude filter.
- No anomalies (unsupervised only) → increase `nu`, verify training baseline is clean, retrain.

## Contacts
<from Phase 1>
```

---

## Writing to Splunk — Safety Rules

- NEVER write to `$SPLUNK_HOME/etc/apps/<app>/default/`. Always use `local/`.
- NEVER commit credentials or API keys into any search, macro, or lookup.
- NEVER disable existing saved searches without explicit user approval.
- NEVER run `apply` in the same pipeline as `fit`.
- NEVER train on scoring-output sourcetypes; always use the `exclude_scoring_sourcetypes` macro.
- Use the MCP server for every read; prefer the Splunk CLI (`splunk dispatch`, `splunk enable saved-search`) only when the user's terminal is directly available.

## On Ambiguity

If the user's answer to any Phase 1 question is ambiguous, stop and re-ask via `AskQuestion` — do not guess slugs, thresholds, or labels. The slug choice in particular is permanent once written to lookups, macros, and sourcetypes.
