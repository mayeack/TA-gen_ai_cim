# Validation Checklist

Every phase has a pass/fail gate. Run the MCP queries below through the Splunk MCP server and verify the "Expected" row BEFORE moving to the next phase.

ALWAYS read the MCP tool descriptor first (`splunk_run_query.json`, `splunk_get_knowledge_objects.json`, etc.) under your MCP tools folder to confirm the exact parameter schema. Only the most common parameters are shown here.

---

## Phase 1 — Intake

No MCP validation. You must have all intake answers plus explicit user approval on naming before moving on.

Gate:

- [ ] Detection slug confirmed and used consistently in the confirmation message.
- [ ] Paradigm selected.
- [ ] All intake answers captured (or defaulted with user approval).
- [ ] User approved the planned artifact names.

---

## Phase 2 — Data Survey

### 2.1 Index exists

```
Tool: splunk_get_indexes
```

Expected: the index from intake is in the returned list.

### 2.2 MLTK installed

```
Tool: splunk_run_query
Query:
| rest /services/apps/local
| search label="Splunk Machine Learning Toolkit"
| table label version disabled
```

Expected: 1 row with `disabled=0`.

### 2.3 Source text extractable

```
Tool: splunk_run_query
Query:
index=<idx> earliest=-24h
| head 1000
| eval text=<source_text_expr>
| where isnotnull(text) AND len(text) > 0
| stats count as extractable, avg(len(text)) as avg_len, min(len(text)) as min_len
```

Expected: `extractable >= 100` and `avg_len >= 20`. Otherwise fix the coalesce list.

### 2.4 Volume

```
Tool: splunk_run_query
Query:
index=<idx> earliest=-7d | stats count
```

Expected (supervised): ≥1,000 events. Expected (unsupervised baseline): ≥5,000 events.

### 2.5 Class balance (supervised only)

```
Tool: splunk_run_query
Query:
| inputlookup <training_lookup>
| stats count by <label_column>
| eventstats sum(count) as total
| eval pct=round(count/total*100, 2)
```

Expected: positive class between 5% and 50%. Outside band → add `class_weight=balanced` to Step 2.

### 2.6 Existing name collisions

```
Tool: splunk_get_knowledge_objects
Type: savedsearches
Filter: name matches "ML - <Detection> "
```

Expected: no hits. If any come back, rename the detection slug or confirm intended overwrite with the user.

```
Tool: splunk_run_query
Query:
| rest /servicesNS/-/<app>/mltk/models
| search title IN ("<detection>_model","<detection>_pca","<detection>_anomaly_model","<detection>_tfidf_pca","<detection>_tfidf_model")
| table title
```

Expected: empty. If rows exist, confirm overwrite with the user.

---

## Phase 3 — Train

Run the saved searches in order via MCP:

```
Tool: splunk_run_query
Query: | savedsearch "ML - <Detection> Train Step 1 - Feature Engineering"
```

Repeat for each subsequent step. Confirm each completes before firing the next.

### 3.1 Training lookup populated (supervised / hybrid)

```
Tool: splunk_run_query
Query:
| inputlookup <detection>_training_data_engineered
| stats count as rows
```

Expected: `rows` matches what Step 1 reported.

### 3.2 Models registered

```
Tool: splunk_run_query
Query:
| rest /servicesNS/-/<app>/mltk/models
| search title IN (<expected_models>)
| table title updated
```

Where `<expected_models>` is:

- Supervised: `"<detection>_model"`
- Unsupervised single-target: `"<detection>_<target>_pca","<detection>_<target>_anomaly_model"`
- Unsupervised prompt+response: add both target pairs
- Hybrid: `"<detection>_tfidf_pca","<detection>_tfidf_model"` (plus `"<detection>_model"` if a dual-model hybrid)

Expected: every title present with a recent `updated` timestamp.

### 3.3 Validation metrics

Dispatch the final validation step:

```
Tool: splunk_run_query
Query: | savedsearch "ML - <Detection> Train Step 3 - Validate Model Performance"
```

Expected thresholds:

- Supervised: Accuracy ≥ 0.90, Precision ≥ 0.75, Recall ≥ 0.85, F1 ≥ 0.80.
- Hybrid: Accuracy ≥ 0.85, F1 ≥ 0.75.
- Unsupervised: use probe query in 3.4 instead.

If below thresholds:

- Recall low → reduce threshold, add class weights, add more positives.
- Precision low → add confusing negatives, raise threshold.

### 3.4 Unsupervised sanity (anomaly only)

```
Tool: splunk_run_query
Query:
index=<idx> earliest=-6h latest=now `exclude_scoring_sourcetypes`
| eval text=<source_text_expr>
| where isnotnull(text) AND len(text) > 20
| eval text_clean=trim(replace(replace(lower(text), "[^a-z0-9\s]", " "), "\s+", " "))
| head 1000
| fit HashingVectorizer text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false
| apply app:<detection>_<target>_pca
| apply app:<detection>_<target>_anomaly_model
| stats count as total, sum(eval(if(isNormal<0,1,0))) as anomalies
| eval rate=round(anomalies/total*100, 2)
```

Expected: `rate` roughly matches `nu * 100` (±5 points). Zero or >50% means retrain.

---

## Phase 4 — Score

### 4.1 Scoring search is scheduled

```
Tool: splunk_get_knowledge_objects
Type: savedsearches
Filter: name="ML - <Detection> Scoring - <Target>"
```

Expected: returned with `disabled=0`, `is_scheduled=1`, `cron_schedule="* * * * *"`.

### 4.2 Enriched events flowing

After ≥3 minutes:

```
Tool: splunk_run_query
Query:
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring" earliest=-15m
| stats count,
    dc(gen_ai.event.id) as unique_events,
    avg('gen_ai.<detection>.risk_score') as avg_score,
    min('gen_ai.<detection>.risk_score') as min_score,
    max('gen_ai.<detection>.risk_score') as max_score
```

Expected: `count > 0`, `unique_events > 0`, `avg_score` between 0 and 1.

### 4.3 No duplicate scoring (self-loop check)

```
Tool: splunk_run_query
Query:
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring" earliest=-15m
| stats count by gen_ai.event.id
| where count > 1
| stats sum(count) as dupes
```

Expected: `dupes` either empty or ≤ 1% of total events. If higher, `exclude_scoring_sourcetypes` macro is wrong.

### 4.4 Output field coverage

```
Tool: splunk_run_query
Query:
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring" earliest=-15m
| stats
    sum(eval(if(isnull('gen_ai.<detection>.risk_score'),1,0))) as missing_risk,
    sum(eval(if(isnull('gen_ai.<detection>.ml_detected'),1,0))) as missing_flag,
    sum(eval(if(isnull('gen_ai.<detection>.confidence'),1,0))) as missing_confidence,
    count as total
| eval missing_pct=round((missing_risk+missing_flag+missing_confidence)/(total*3)*100,2)
```

Expected: `missing_pct < 1`.

### 4.5 Macro list updated

```
Tool: splunk_get_knowledge_objects
Type: macros
Filter: name="exclude_scoring_sourcetypes"
```

Expected: the definition contains `ai_cim:<detection>:ml_scoring`.

---

## Phase 5 — Alert

### 5.1 All three alerts registered and enabled

```
Tool: splunk_get_knowledge_objects
Type: savedsearches
Filter: name matches "ML - <Detection> (High Risk|Detection|Rate Threshold) Alert"
```

Expected: 3 rows, each with `disabled=0`, `is_scheduled=1`, populated `cron_schedule`, non-empty `action.email.to`, `alert.digest_mode=1`.

### 5.2 Dry-run each alert

```
Tool: splunk_run_query
Query: | savedsearch "ML - <Detection> High Risk Alert"
```

Repeat for the other two. Expected: no errors. Row count may be zero if no high-risk events exist yet — that is fine.

---

## Phase 6 — Monitor & Deliver

### 6.1 Dashboard view exists

```
Tool: splunk_run_query
Query:
| rest /servicesNS/-/<app>/data/ui/views
| search title="ml_<detection>_detection"
| table title published
```

Expected: one row.

### 6.2 Dashboard panels resolve

Run each panel's SPL via `splunk_run_query` with `earliest=-1h`, `latest=now`, `app=*`, `model=*`. Expected: no errors; each returns a row or an empty table (empty is OK for new detections).

### 6.3 Model health

```
Tool: splunk_run_query
Query:
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring" earliest=-7d
| stats count as total,
    sum(eval(if('gen_ai.<detection>.ml_detected'="true", 1, 0))) as detected,
    stdev('gen_ai.<detection>.risk_score') as risk_stdev
| eval rate_pct=round(detected/total*100, 2)
| eval status=case(
    rate_pct > 25, "CRITICAL",
    rate_pct > 15, "WARNING - high rate",
    rate_pct < 0.1, "WARNING - low rate",
    risk_stdev > 0.4, "WARNING - high variance",
    1=1, "HEALTHY"
)
| table status rate_pct risk_stdev
```

Expected: `status="HEALTHY"` after 7 days of operation. For a fresh deployment, `WARNING - low rate` is acceptable; log it in the runbook.

### 6.4 KV Store collections check (if skill added any)

```
Tool: splunk_get_kv_store_collections
Filter: app=<app>
```

Expected: no unexpected collections created by this skill — it does NOT manage a feedback loop.

---

## Final Sweep

Bundle all of these into a single report included in the runbook:

| Check | Tool | Expected |
|---|---|---|
| Models exist | `splunk_run_query` `/mltk/models` | all titles present |
| Scoring search scheduled | `splunk_get_knowledge_objects` | `is_scheduled=1` |
| Alerts scheduled | `splunk_get_knowledge_objects` | 3 rows, `is_scheduled=1` |
| Dashboard exists | `splunk_run_query` `/data/ui/views` | 1 row |
| Last 15m scored events | `splunk_run_query` | `count>0`, valid avg risk |
| `exclude_scoring_sourcetypes` macro lists new sourcetype | `splunk_get_knowledge_objects` | contains `ai_cim:<detection>:ml_scoring` |
| No duplicate self-scoring | `splunk_run_query` | dupe rate < 1% |
| Model health | `splunk_run_query` | `status=HEALTHY` or documented `WARNING` |

If any row fails, STOP and hand the remediation steps back to the user before completing the runbook.

---

## Remediation Quick Reference

| Failure | Fix |
|---|---|
| Model not found | Re-check `app:` prefix on `into`/`apply`; re-run Step 2. |
| Training step errors `Could not find field "PC_*"` | Step 2 (PCA) not run — dispatch Step 1/2 in order. |
| `gamma=scale` rejected | Remove `gamma` or use a float. |
| Scoring `count=0` | Check exclude macro covers scoring sourcetype; confirm `cron_schedule`; confirm source index has recent events. |
| All events anomalous | Lower `nu`; retrain on cleaner baseline. |
| Detection rate >25% | Threshold too low; retrain with more negatives; raise threshold. |
| Detection rate ~0% | Threshold too high; verify scoring feature engineering matches training byte-for-byte. |
| Alert scheduled but never fires | Run alert SPL manually; if empty, adjust threshold; confirm `alert.digest_mode` expectations. |
| Dashboard panels blank | Check that Phase 4 produced data; confirm time range input isn't pre-scoring. |
