# Conventions

Every artifact produced by this skill MUST follow these naming rules. Uniform names make detections swappable across environments, keep MCP validation queries portable, and let dashboards/alerts generalize.

The detection slug is the only variable. Everything else derives from it.

## Slug rules

`<detection>` is:

- Lowercase, snake_case.
- Matches `^[a-z][a-z0-9_]{2,30}$`.
- Stable forever — it is baked into lookups, models, sourcetypes, and macros.
- NOT a reserved word: `model`, `train`, `test`, `score`, `genai`, `pii`, or any slug already in use within the target app (verify via `splunk_get_knowledge_objects`).

`<Detection>` is the Title Case form used only in display fields (saved-search names, descriptions, dashboard titles). Example: slug `prompt_injection` → display `Prompt Injection`.

---

## Saved searches

ALL saved-search names use the `ML - ` prefix and Title Case for the detection name. NEVER use the legacy `GenAI - ` prefix for new detections.

| Purpose | Name | Schedule | Notes |
|---|---|---|---|
| Training step 1 | `ML - <Detection> Train Step 1 - Feature Engineering` | on demand | emits `<detection>_training_data_engineered` (supervised/hybrid) or PCA input (unsupervised) |
| Training step 2 | `ML - <Detection> Train Step 2 - <Algorithm> Model` | on demand | writes `app:<detection>_model` (supervised) or `app:<detection>_<target>_pca` (unsupervised) |
| Training step 3 | `ML - <Detection> Train Step 3 - Validate Model Performance` | on demand | validation metrics, on labeled data only |
| Unsupervised Step 2 | `ML - <Detection> Train Step 2 - Anomaly Model (<target>)` | on demand | writes `app:<detection>_<target>_anomaly_model` |
| Hybrid Step 2 | `ML - <Detection> Train Step 2 - TF-IDF PCA Model` | on demand | writes `app:<detection>_tfidf_pca` |
| Hybrid Step 3 | `ML - <Detection> Train Step 3 - TF-IDF Classifier Model` | on demand | writes `app:<detection>_tfidf_model` |
| Scoring | `ML - <Detection> Scoring - <Target>` | `* * * * *` | `<Target>` is `Prompt Analysis`, `Response Analysis`, `Event Analysis`, etc. |
| High risk alert | `ML - <Detection> High Risk Alert` | `*/15 * * * *` | |
| Detection alert | `ML - <Detection> Detection Alert` | `0 * * * *` | |
| Rate threshold alert | `ML - <Detection> Rate Threshold Alert` | `0 */4 * * *` | |
| Daily summary | `ML - <Detection> Daily Summary Report` | `0 8 * * *` | optional |
| Weekly perf | `ML - <Detection> Weekly Model Performance Report` | `0 9 * * 1` | optional |
| Threshold sweep | `ML - <Detection> Threshold Sweep` | on demand | diagnostic |

### Reserved future names (do not use)

Reserved for a future feedback-loop extension (out of scope for this skill):

- `ML - <Detection> Extract Feedback from Threat Hunts`
- `ML - <Detection> Retrain Challenger Model`
- `ML - <Detection> Compare Champion vs Challenger`
- `ML - <Detection> Promote Challenger to Champion`

The skill MUST NOT create these, but MUST NOT reuse these names for any other purpose.

---

## Models

Registered in MLTK as:

| Role | Name | Notes |
|---|---|---|
| Primary classifier (supervised) | `<detection>_model` | `app:<detection>_model` when fitting/applying |
| TF-IDF dimensionality reduction | `<detection>_tfidf_pca` | hybrid only |
| Hybrid classifier | `<detection>_tfidf_model` | hybrid only |
| Unsupervised PCA (per target) | `<detection>_<target>_pca` | e.g., `<detection>_prompt_pca` |
| Unsupervised anomaly | `<detection>_<target>_anomaly_model` | |

Always save with `into app:<model_name>`. Always apply with `apply app:<model_name>`.

---

## Macros

Added to `local/macros.conf` by the skill:

| Name | Purpose |
|---|---|
| `genai_<detection>_extract_text` | coalesce → `<text_field>`; filter nulls and short text |
| `genai_<detection>_feature_engineering` | all pattern + statistical + keyword features |
| `genai_<detection>_apply_model` | `apply app:<detection>_model` + derive `risk_score`/`ml_detected` |
| `genai_<detection>_classify_techniques` | (hybrid only) keyword → technique classification |
| `genai_<detection>_score` | composition macro chaining extract → features → apply |
| `genai_<detection>_high_risk_threshold(1)` | takes threshold arg; filters on `gen_ai.<detection>.risk_score` |

The `genai_` prefix is kept (rather than `ml_`) to stay consistent with the existing `TA-gen_ai_cim` macro namespace; this is the only place the legacy prefix is used.

Skill also updates the shared macro:

```
[exclude_scoring_sourcetypes]
```

by APPENDING `ai_cim:<detection>:ml_scoring` to the NOT-IN list. Skill MUST preserve existing sourcetypes in that macro.

---

## Output fields

Emitted by the scoring pipeline, all under the `gen_ai.<detection>.` namespace:

| Field | Type | Always present? | Meaning |
|---|---|---|---|
| `gen_ai.<detection>.risk_score` | float 0–1 | yes | model probability or derived hybrid score |
| `gen_ai.<detection>.ml_detected` | string "true"/"false" | yes | `risk_score > <risk_threshold>` |
| `gen_ai.<detection>.confidence` | string | yes | `very_high`/`high`/`medium`/`low`/`very_low` |
| `gen_ai.<detection>.technique` | string | hybrid/technique-aware | keyword-derived technique |
| `gen_ai.<detection>.severity` | string | optional | `critical`/`high`/`medium`/`low`/`none` |
| `gen_ai.<detection>.location` | string | optional | `prompt`/`response`/`both`/`none` |
| `gen_ai.<detection>.anomaly_score` | float 0–1 | unsupervised only | `1/(1+exp(isNormal))` |
| `gen_ai.<detection>.is_anomaly` | string | unsupervised only | `isNormal < 0` → `"true"` |
| `gen_ai.<detection>.types` | mv string | type-tracking detections (e.g., PII) | `,`-joined detected categories |

Correlation keys preserved verbatim on every enriched event:

- `gen_ai.event.id`
- `gen_ai.request.id`
- `gen_ai.session.id`
- `gen_ai.app.name`
- `gen_ai.request.model`
- `client.address`
- `service.name`
- `trace_id`

---

## Sourcetypes

| Sourcetype | Purpose |
|---|---|
| `ai_cim:<detection>:ml_scoring` | Enriched scoring output. Emitted via `\| collect`. |

A detection MUST use exactly one scoring sourcetype regardless of how many targets are scored (prompt + response etc. collect into the same sourcetype but differ by a `target` field).

---

## Lookups

| Lookup | Purpose | Paradigm |
|---|---|---|
| `<detection>_training_data_engineered` | features + label after Step 1 | supervised / hybrid |

Reserved (future feedback loop, do NOT create):

- `<detection>_training_feedback` (KV Store)
- `<detection>_model_registry` (KV Store)
- `<detection>_threshold_results` (KV Store)

---

## Dashboards

| View file | Title |
|---|---|
| `ml_<detection>_detection.xml` | `<Detection> ML Detection` |

Tokens `$app$`, `$model$`, plus the time range picker. Stored under `default/data/ui/views/` of the target app via the `splunk-dashboard-studio` subagent.

---

## App context

Defaults to `TA-gen_ai_cim`. User may override. All writes go under `local/`:

- `$SPLUNK_HOME/etc/apps/<app>/local/savedsearches.conf`
- `$SPLUNK_HOME/etc/apps/<app>/local/macros.conf`
- `$SPLUNK_HOME/etc/apps/<app>/local/collections.conf` (only if a future extension adds KV stores; this skill creates none)
- `$SPLUNK_HOME/etc/apps/<app>/default/data/ui/views/ml_<detection>_detection.xml` — dashboard subagent handles this; if a `local/data/ui/views` copy exists, leave `default/` untouched.

NEVER write to `default/` for configs (`savedsearches.conf`, `macros.conf`, etc.). View XML files ship in `default/` by convention.

---

## Uniformity enforcement checklist

Before marking Phase 3+ complete, verify each of:

- [ ] Every saved search written has the exact `ML - <Detection> ...` prefix.
- [ ] Every model written has `<detection>_` prefix and is referenced with `app:` in every call.
- [ ] Every output field is under `gen_ai.<detection>.`.
- [ ] The scoring sourcetype is `ai_cim:<detection>:ml_scoring` (no variations).
- [ ] The training lookup is `<detection>_training_data_engineered`.
- [ ] `exclude_scoring_sourcetypes` macro contains the scoring sourcetype.
- [ ] Macros added are exactly the six names listed above, all under `genai_<detection>_` (except the shared `exclude_scoring_sourcetypes` edit).
- [ ] No reserved names from the future feedback-loop extension were used.

Run the Phase 6 final sweep in [VALIDATION_CHECKLIST.md](VALIDATION_CHECKLIST.md#final-sweep) to cross-verify.
