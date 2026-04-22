# SPL Templates

Parameterized templates for every saved search the skill produces. Substitute the tokens below before writing any stanza to `local/savedsearches.conf`.

## Token reference

| Token | Example | Notes |
|---|---|---|
| `<detection>` | `toxicity` | snake_case slug from intake |
| `<Detection>` | `Toxicity` | Title case, used in saved-search names and descriptions |
| `<app>` | `TA-gen_ai_cim` | app context |
| `<idx>` | `gen_ai_log` | source index |
| `<source_text_expr>` | `coalesce(mvjoin('input_messages{}.content'," "), 'gen_ai.input.messages')` | Full coalesce for text extraction |
| `<target>` | `Response Analysis`, `Prompt Analysis`, `Event Analysis` | human-readable target |
| `<label_column>` | `pii_label` | supervised label column name |
| `<training_lookup>` | `llm_pii_mixed_responses_200k` | lookup with labeled data |
| `<features_list>` | `output_length word_count has_ssn has_email ...` | space-separated feature list |
| `<algorithm>` | `LogisticRegression` or `RandomForestClassifier` | supervised algorithm |
| `<risk_threshold>` | `0.5` | default from intake |
| `<high_risk_threshold>` | `0.7` | alert threshold |
| `<rate_threshold>` | `5` | percent |
| `<email_recipients>` | `privacy-team@example.com, ai-governance@example.com` | |

Every template below writes into a `local/` file. Backslash-continuations are kept because `savedsearches.conf` requires them for multi-line `search = ...`.

---

## Feature Engineering (training step 1)

Use for both supervised and hybrid paradigms. Unsupervised paradigms usually go straight to PCA (see unsupervised training below) because they are trained on raw telemetry.

### Pattern features (regex)

Each regex produces one binary feature. The skill assembles these from the user-supplied `feature_patterns` list.

```conf
| rex field=<source_text_field> "(?<<feature>_match><regex>)" \
| eval has_<feature>=if(isnotnull(<feature>_match), 1, 0) \
```

### Statistical features

```conf
| eval <text>_length=len(<source_text_field>) \
| eval word_count=mvcount(split(<source_text_field>, " ")) \
| eval digit_count=len(replace(<source_text_field>, "[^\d]", "")) \
| eval digit_ratio=if(<text>_length>0, round(digit_count/<text>_length, 4), 0) \
| eval special_char_count=len(replace(<source_text_field>, "[A-Za-z0-9\s]", "")) \
| eval special_char_ratio=if(<text>_length>0, round(special_char_count/<text>_length, 4), 0) \
| eval uppercase_count=len(replace(<source_text_field>, "[^A-Z]", "")) \
| eval uppercase_ratio=if(<text>_length>0, round(uppercase_count/<text>_length, 4), 0) \
```

### Keyword-group features

For each user-supplied group (name + |-joined regex):

```conf
| eval has_<group>=if(match(<source_text_field>, "(?i)(<kw1>|<kw2>|<kw3>)"), 1, 0) \
```

### Structural features (hybrid / prompt-target detections)

```conf
| rex field=<source_text_field> max_match=100 "(?i)(don't|do not|never|not|no|none)" \
| eval negation_count=if(isnull('rex_match'), 0, mvcount('rex_match')) \
| eval negation_density=if(word_count>0, round(negation_count/word_count, 4), 0) \
| eval starts_with_command=if(match(<source_text_field>, "(?i)^(ignore|disregard|forget|reveal|show|tell|bypass|override|enable|activate)"), 1, 0) \
```

---

## Supervised Training

### Train Step 1 — Feature Engineering from Labeled Data

```conf
[ML - <Detection> Train Step 1 - Feature Engineering]
description = Step 1: Engineer features from <training_lookup>. Run BEFORE Step 2.
search = | inputlookup <training_lookup> \
| eval <source_text_field>=coalesce(<training_text_column>, "") \
| eval <label_column>=coalesce(<label_column>, 0) \
| where len(<source_text_field>) > 0 \
<pattern feature block> \
<statistical feature block> \
<keyword feature block> \
| table <source_text_field> <label_column> <features_list> \
| outputlookup <detection>_training_data_engineered \
| stats count as total_rows, \
    sum(<label_column>) as positive_examples, \
    sum(eval(if(<label_column>=0,1,0))) as negative_examples \
| eval status="SUCCESS", positive_pct=round(positive_examples/total_rows*100, 2)."%" \
| table status total_rows positive_examples negative_examples positive_pct
dispatch.earliest_time = -1m
dispatch.latest_time = now
enableSched = 0
alert.track = 0
```

### Train Step 2 — Model

```conf
[ML - <Detection> Train Step 2 - <Algorithm> Model]
description = Step 2: Train <Algorithm> classifier. Run AFTER Step 1 completes.
search = | inputlookup <detection>_training_data_engineered \
| fit <Algorithm> <label_column> \
    from <features_list> \
    probabilities=true \
    <algorithm_hyperparameters> \
    into app:<detection>_model
dispatch.earliest_time = -1m
dispatch.latest_time = now
enableSched = 0
alert.track = 0
```

Hyperparameter guidance:

- `LogisticRegression`: usually bare. Add `class_weight=balanced` if positive class <10%.
- `RandomForestClassifier`: `n_estimators=100 max_depth=15 max_features=8 random_state=42`.

### Train Step 3 — Validate Model Performance

```conf
[ML - <Detection> Train Step 3 - Validate Model Performance]
description = Step 3: Validate accuracy/precision/recall/F1 on a 10k sample.
search = | inputlookup <detection>_training_data_engineered \
| sample 10000 \
| apply app:<detection>_model \
| eval predicted_prob=coalesce('probability(<label_column>=1)', 'predicted(<label_column>)') \
| eval predicted_class=if(predicted_prob><risk_threshold>, 1, 0) \
| eval TP_flag=if(<label_column>=1 AND predicted_class=1, 1, 0) \
| eval TN_flag=if(<label_column>=0 AND predicted_class=0, 1, 0) \
| eval FP_flag=if(<label_column>=0 AND predicted_class=1, 1, 0) \
| eval FN_flag=if(<label_column>=1 AND predicted_class=0, 1, 0) \
| stats sum(TP_flag) as TP, sum(TN_flag) as TN, sum(FP_flag) as FP, sum(FN_flag) as FN \
| eval Total=TP+TN+FP+FN \
| eval Accuracy=round((TP+TN)/Total, 4) \
| eval Precision=if(TP+FP>0, round(TP/(TP+FP), 4), 0) \
| eval Recall=if(TP+FN>0, round(TP/(TP+FN), 4), 0) \
| eval F1_Score=if(Precision+Recall>0, round(2*Precision*Recall/(Precision+Recall), 4), 0) \
| eval Specificity=if(TN+FP>0, round(TN/(TN+FP), 4), 0) \
| table Accuracy Precision Recall F1_Score Specificity TP TN FP FN Total
dispatch.earliest_time = -1m
dispatch.latest_time = now
enableSched = 0
alert.track = 0
```

Target: `Accuracy>0.90, Precision>0.75, Recall>0.85, F1>0.80`. Record actuals in the runbook.

---

## Unsupervised Training (HashingVectorizer + PCA + OneClassSVM)

Use for pure anomaly detection on raw telemetry where no labels exist. If both prompt and response are targets, run the two-step pattern twice with separate model names (`<detection>_prompt_pca` + `<detection>_prompt_anomaly_model`, `<detection>_response_pca` + `<detection>_response_anomaly_model`).

### Train Step 1 — PCA

```conf
[ML - <Detection> Train Step 1 - PCA Model (<target>)]
description = Step 1: HashingVectorizer + PCA reduction. Run BEFORE Step 2.
search = index=<idx> `exclude_scoring_sourcetypes` \
| eval text=<source_text_expr> \
| where isnotnull(text) AND len(text) > 10 \
| eval text_clean=lower(text) \
| eval text_clean=replace(text_clean, "[^a-z0-9\s]", " ") \
| eval text_clean=replace(text_clean, "\s+", " ") \
| eval text_clean=trim(text_clean) \
| where len(text_clean) > 20 \
| head 50000 \
| fit HashingVectorizer text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false \
| fit PCA "text_clean_hashed_*" k=<pca_k> into app:<detection>_<target>_pca
dispatch.earliest_time = -30d@d
dispatch.latest_time = now
enableSched = 0
alert.track = 0
```

`<pca_k>` sizing:

| Events | `k` |
|---|---|
| <100 | 10-15 |
| 100-500 | 20 |
| 500-5000 | 30-50 |
| >5000 | 50-100 |

### Train Step 2 — OneClassSVM

```conf
[ML - <Detection> Train Step 2 - Anomaly Model (<target>)]
description = Step 2: OneClassSVM. Run AFTER Step 1 completes.
search = index=<idx> `exclude_scoring_sourcetypes` \
| eval text=<source_text_expr> \
| where isnotnull(text) AND len(text) > 10 \
| eval text_clean=lower(text) \
| eval text_clean=replace(text_clean, "[^a-z0-9\s]", " ") \
| eval text_clean=replace(text_clean, "\s+", " ") \
| eval text_clean=trim(text_clean) \
| where len(text_clean) > 20 \
| head 50000 \
| fit HashingVectorizer text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false \
| apply app:<detection>_<target>_pca \
| fit OneClassSVM "PC_*" kernel=rbf nu=<nu> into app:<detection>_<target>_anomaly_model
dispatch.earliest_time = -30d@d
dispatch.latest_time = now
enableSched = 0
alert.track = 0
```

`<nu>` sizing:

| Expected anomaly rate | `nu` |
|---|---|
| Low (strict baseline) | 0.1 |
| Moderate | 0.25 |
| Aggressive | 0.3 |

NEVER use `gamma=scale`. Omit `gamma` entirely or use a float like `0.1`.

---

## Hybrid Training (TF-IDF + keywords + RandomForest)

Use when you have labeled data AND a set of known-bad patterns, and want both novel-attack coverage and interpretable technique classification.

### Train Step 1 — Feature Engineering

Same as the supervised Step 1, but `<features_list>` includes BOTH the keyword-group binaries (e.g., `has_ignore_instruction`, `has_jailbreak_terms`) AND the statistical + structural features.

### Train Step 2 — TF-IDF PCA

```conf
[ML - <Detection> Train Step 2 - TF-IDF PCA Model]
description = Step 2: TF-IDF vectorization + PCA. Run AFTER Step 1.
search = | inputlookup <detection>_training_data_engineered \
| eval text_clean=lower(<source_text_field>) \
| eval text_clean=replace(text_clean, "[^a-z0-9\s]", " ") \
| eval text_clean=trim(replace(text_clean, "\s+", " ")) \
| fit HashingVectorizer text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false \
| fit PCA "text_clean_hashed_*" k=50 into app:<detection>_tfidf_pca
dispatch.earliest_time = -1m
dispatch.latest_time = now
enableSched = 0
alert.track = 0
```

### Train Step 3 — Hybrid Classifier

```conf
[ML - <Detection> Train Step 3 - TF-IDF Classifier Model]
description = Step 3: RandomForest on PCA components + keyword features. Run AFTER Step 2.
search = | inputlookup <detection>_training_data_engineered \
| eval text_clean=lower(<source_text_field>) \
| eval text_clean=replace(text_clean, "[^a-z0-9\s]", " ") \
| eval text_clean=trim(replace(text_clean, "\s+", " ")) \
| fit HashingVectorizer text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false \
| apply app:<detection>_tfidf_pca \
| fit RandomForestClassifier <label_column> \
    from PC_* <keyword_features_list> <statistical_features_list> \
    n_estimators=100 max_depth=15 max_features=8 random_state=42 \
    probabilities=true \
    into app:<detection>_tfidf_model
dispatch.earliest_time = -1m
dispatch.latest_time = now
enableSched = 0
alert.track = 0
```

### Train Step 4 — Validate

Same as supervised Step 3 but apply both models in sequence, and include the TF-IDF vectorize + PCA step before `apply app:<detection>_tfidf_model`.

---

## Scoring

Produce one saved search per scoring target. Tokens for the templates below:

- `<text_field>` → `response_text`, `input_text`, or `event_text`.
- `<text_coalesce>` → the Phase 1 coalesce expression.
- `<model_apply_block>` → one of the three blocks below.

### Scoring — Supervised

```conf
[ML - <Detection> Scoring - <Target>]
description = Score <target> events with <detection>_model every minute.
search = index=<idx> `exclude_scoring_sourcetypes` earliest=-1m@m latest=now \
| eval <text_field>=<text_coalesce> \
| where isnotnull(<text_field>) AND len(<text_field>) > <min_text_len> \
| dedup gen_ai.event.id \
<pattern feature block> \
<statistical feature block> \
<keyword feature block> \
| apply app:<detection>_model \
| eval "gen_ai.<detection>.risk_score"=round(coalesce('probability(<label_column>=1)', 'predicted(<label_column>)'), 4) \
| eval "gen_ai.<detection>.ml_detected"=if('gen_ai.<detection>.risk_score'><risk_threshold>, "true", "false") \
| eval "gen_ai.<detection>.confidence"=case( \
    'gen_ai.<detection>.risk_score'>0.9, "very_high", \
    'gen_ai.<detection>.risk_score'>0.7, "high", \
    'gen_ai.<detection>.risk_score'>0.5, "medium", \
    'gen_ai.<detection>.risk_score'>0.3, "low", \
    1=1, "very_low" \
) \
<optional technique classification block> \
| eval _raw=json_object( \
    "timestamp", strftime(_time, "%Y-%m-%dT%H:%M:%S"), \
    "source", "<detection>_ml_scoring", \
    "gen_ai.event.id", 'gen_ai.event.id', \
    "gen_ai.request.id", 'gen_ai.request.id', \
    "gen_ai.session.id", 'gen_ai.session.id', \
    "gen_ai.app.name", 'gen_ai.app.name', \
    "gen_ai.request.model", 'gen_ai.request.model', \
    "gen_ai.<detection>.risk_score", 'gen_ai.<detection>.risk_score', \
    "gen_ai.<detection>.ml_detected", 'gen_ai.<detection>.ml_detected', \
    "gen_ai.<detection>.confidence", 'gen_ai.<detection>.confidence', \
    "client.address", 'client.address', \
    "service.name", 'service.name', \
    "trace_id", 'trace_id' \
) \
| collect index=<idx> source="<detection>_ml_scoring" sourcetype="ai_cim:<detection>:ml_scoring"
dispatch.earliest_time = -1m@m
dispatch.latest_time = now
cron_schedule = * * * * *
enableSched = 1
alert.track = 0
```

Optional technique classification (hybrid detections):

```conf
| eval "gen_ai.<detection>.technique"=case( \
    has_<group_a>=1, "<technique_a>", \
    has_<group_b>=1, "<technique_b>", \
    1=1, "unknown" \
) \
```

### Scoring — Unsupervised

Replace the model-apply block with:

```conf
<preprocessing to text_clean> \
| fit HashingVectorizer text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false \
| apply app:<detection>_<target>_pca \
| apply app:<detection>_<target>_anomaly_model \
| eval "gen_ai.<detection>.anomaly_score"=1/(1+exp('isNormal')) \
| eval "gen_ai.<detection>.is_anomaly"=if('isNormal' < 0, "true", "false") \
```

Keep the `| collect` emission block.

### Scoring — Hybrid

Apply both models and combine:

```conf
<preprocessing to text_clean> \
| fit HashingVectorizer text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false \
| apply app:<detection>_tfidf_pca \
| apply app:<detection>_tfidf_model \
| eval "gen_ai.<detection>.risk_score"=round('probability(<label_column>=1)', 4) \
| eval "gen_ai.<detection>.ml_detected"=if('gen_ai.<detection>.risk_score'><risk_threshold>, "true", "false") \
<technique classification block> \
```

---

## Alerts

All three alerts share these stanzas:

```conf
alert.track = 1
alert.digest_mode = 1
alert.severity = <severity>
action.email = 1
action.email.to = <email_recipients>
counttype = number of events
relation = greater than
quantity = 0
```

### High Risk Alert (every 15 minutes)

```conf
[ML - <Detection> High Risk Alert]
description = High-risk <detection> detections (risk_score > <high_risk_threshold>).
search = index=<idx> sourcetype="ai_cim:<detection>:ml_scoring" \
    'gen_ai.<detection>.risk_score'><high_risk_threshold> \
| stats count as high_risk_count, \
    avg('gen_ai.<detection>.risk_score') as avg_risk, \
    max('gen_ai.<detection>.risk_score') as max_risk, \
    values('gen_ai.<detection>.technique') as techniques, \
    dc('gen_ai.session.id') as sessions, \
    dc('client.address') as sources \
    by 'gen_ai.deployment.id', 'gen_ai.app.name' \
| where high_risk_count >= 1
dispatch.earliest_time = -15m
dispatch.latest_time = now
cron_schedule = */15 * * * *
enableSched = 1
```

### Detection Alert (hourly)

```conf
[ML - <Detection> Detection Alert]
description = Any <detection> detection in the last hour.
search = index=<idx> sourcetype="ai_cim:<detection>:ml_scoring" \
    'gen_ai.<detection>.ml_detected'="true" \
| stats count as detections, \
    avg('gen_ai.<detection>.risk_score') as avg_risk, \
    values('gen_ai.<detection>.technique') as techniques \
    by 'gen_ai.app.name' \
| where detections > 0
dispatch.earliest_time = -1h
dispatch.latest_time = now
cron_schedule = 0 * * * *
enableSched = 1
```

### Rate Threshold Alert (every 4 hours)

```conf
[ML - <Detection> Rate Threshold Alert]
description = Overall <detection> detection rate exceeds <rate_threshold>%.
search = index=<idx> sourcetype="ai_cim:<detection>:ml_scoring" \
| stats count as total_events, \
    sum(eval(if('gen_ai.<detection>.ml_detected'="true", 1, 0))) as detected, \
    avg('gen_ai.<detection>.risk_score') as avg_risk \
    by 'gen_ai.app.name' \
| eval rate_pct=round(detected/total_events*100, 2) \
| where rate_pct > <rate_threshold> OR avg_risk > 0.4 \
| eval alert_message=case( \
    rate_pct > <rate_threshold>*2, "CRITICAL: rate ".rate_pct."% exceeds ".(<rate_threshold>*2)."%", \
    rate_pct > <rate_threshold>, "WARNING: rate ".rate_pct."% exceeds ".<rate_threshold>."%", \
    avg_risk > 0.5, "WARNING: avg risk ".round(avg_risk,2)." elevated", \
    1=1, "rate/risk above threshold" \
)
dispatch.earliest_time = -4h
dispatch.latest_time = now
cron_schedule = 0 */4 * * *
enableSched = 1
counttype = always
```

---

## Reports (optional, enable if the user wants periodic summaries)

### Daily Summary

```conf
[ML - <Detection> Daily Summary Report]
description = Daily detection volume + top techniques.
search = index=<idx> sourcetype="ai_cim:<detection>:ml_scoring" earliest=-24h latest=now \
| stats count as total_events, \
    sum(eval(if('gen_ai.<detection>.ml_detected'="true", 1, 0))) as detected, \
    avg('gen_ai.<detection>.risk_score') as avg_risk, \
    max('gen_ai.<detection>.risk_score') as max_risk \
    by 'gen_ai.app.name' \
| eval detection_rate=round(detected/total_events*100, 2)."%"
dispatch.earliest_time = -24h
dispatch.latest_time = now
cron_schedule = 0 8 * * *
enableSched = 1
alert.track = 0
```

### Weekly Model Performance

```conf
[ML - <Detection> Weekly Model Performance Report]
description = Weekly confusion-matrix-style performance on labeled sample.
search = | inputlookup <detection>_training_data_engineered \
| sample 10000 \
| apply app:<detection>_model \
| eval predicted_prob=coalesce('probability(<label_column>=1)', 'predicted(<label_column>)') \
| eval predicted_class=if(predicted_prob><risk_threshold>, 1, 0) \
| stats \
    sum(eval(if(<label_column>=1 AND predicted_class=1, 1, 0))) as TP, \
    sum(eval(if(<label_column>=0 AND predicted_class=0, 1, 0))) as TN, \
    sum(eval(if(<label_column>=0 AND predicted_class=1, 1, 0))) as FP, \
    sum(eval(if(<label_column>=1 AND predicted_class=0, 1, 0))) as FN \
| eval Accuracy=round((TP+TN)/(TP+TN+FP+FN),4) \
| eval Precision=if(TP+FP>0, round(TP/(TP+FP),4), 0) \
| eval Recall=if(TP+FN>0, round(TP/(TP+FN),4), 0) \
| eval F1=if(Precision+Recall>0, round(2*Precision*Recall/(Precision+Recall),4), 0) \
| table Accuracy Precision Recall F1 TP TN FP FN
dispatch.earliest_time = -7d
dispatch.latest_time = now
cron_schedule = 0 9 * * 1
enableSched = 1
alert.track = 0
```

---

## Threshold Sweep (diagnostic — do not schedule)

```conf
[ML - <Detection> Threshold Sweep]
description = Compare recall/FP at 0.3, 0.5, 0.7 on labeled sample.
search = | inputlookup <detection>_training_data_engineered \
| sample 5000 \
| apply app:<detection>_model \
| eval risk=coalesce('probability(<label_column>=1)', 'predicted(<label_column>)') \
| eval pred_03=if(risk>0.3,1,0), pred_05=if(risk>0.5,1,0), pred_07=if(risk>0.7,1,0) \
| stats \
    sum(eval(if(<label_column>=1 AND pred_03=1, 1, 0))) as recall_03, \
    sum(eval(if(<label_column>=1 AND pred_05=1, 1, 0))) as recall_05, \
    sum(eval(if(<label_column>=1 AND pred_07=1, 1, 0))) as recall_07, \
    sum(eval(if(<label_column>=0 AND pred_03=1, 1, 0))) as fp_03, \
    sum(eval(if(<label_column>=0 AND pred_05=1, 1, 0))) as fp_05, \
    sum(eval(if(<label_column>=0 AND pred_07=1, 1, 0))) as fp_07, \
    sum(<label_column>) as total_pos, \
    sum(eval(if(<label_column>=0,1,0))) as total_neg \
| eval "Recall@0.3"=round(recall_03/total_pos*100,1)."%", \
       "Recall@0.5"=round(recall_05/total_pos*100,1)."%", \
       "Recall@0.7"=round(recall_07/total_pos*100,1)."%", \
       "FP@0.3"=round(fp_03/total_neg*100,1)."%", \
       "FP@0.5"=round(fp_05/total_neg*100,1)."%", \
       "FP@0.7"=round(fp_07/total_neg*100,1)."%" \
| table "Recall@0.3" "Recall@0.5" "Recall@0.7" "FP@0.3" "FP@0.5" "FP@0.7"
enableSched = 0
alert.track = 0
```

---

## Macros to add to `local/macros.conf`

The skill MUST append (or update) these macros per detection:

```conf
[genai_<detection>_extract_text]
definition = eval <text_field>=<text_coalesce> | where isnotnull(<text_field>) AND len(<text_field>) > <min_text_len>
iseval = 0

[genai_<detection>_feature_engineering]
definition = <full feature engineering block as one line with no backslashes, semicolons between pipes>
iseval = 0

[genai_<detection>_apply_model]
definition = apply app:<detection>_model | eval "gen_ai.<detection>.risk_score"=round(coalesce('probability(<label_column>=1)', 'predicted(<label_column>)'), 4) | eval "gen_ai.<detection>.ml_detected"=if('gen_ai.<detection>.risk_score'><risk_threshold>, "true", "false")
iseval = 0

[genai_<detection>_score]
definition = `genai_<detection>_extract_text` | `genai_<detection>_feature_engineering` | `genai_<detection>_apply_model`
iseval = 0

[genai_<detection>_high_risk_threshold(1)]
args = threshold
definition = where 'gen_ai.<detection>.risk_score' > $threshold$
iseval = 0
```

Also update the shared macro:

```conf
[exclude_scoring_sourcetypes]
definition = NOT sourcetype IN ("ai_cim:<detection1>:ml_scoring", "ai_cim:<detection2>:ml_scoring", "ai_cim:<detection>:ml_scoring")
iseval = 0
```

Preserve existing sourcetypes in the list; append the new one.

---

## Common Pitfalls (encoded in templates)

| Pitfall | Fix |
|---|---|
| `fit` and `apply` in same search | Split into two saved searches. |
| Model not found after training | Add `app:` prefix on both `into` and `apply`. |
| `gamma=scale` rejected by MLTK | Omit `gamma` or use a float. |
| Scoring empties the prompt/response field | Add `exclude_scoring_sourcetypes` BEFORE `dedup`. |
| Training on scored data | Use `exclude_scoring_sourcetypes` in every training search. |
| PCA `n_components` error | Reduce `k` below min(samples, features). |
| All events anomalous | Lower `nu`; retrain on cleaner baseline. |
| No anomalies | Raise `nu`; verify training data has variety; confirm `isNormal` produces both `1` and `-1`. |
