# TF-IDF Anomaly Detection for GenAI Messages

This document provides complete SPL for training and deploying Splunk MLTK TF-IDF models to detect anomalous prompts (`gen_ai.input.messages`) and anomalous responses (`gen_ai.output.messages`) in GenAI telemetry.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Critical Implementation Notes](#critical-implementation-notes)
4. [Field Extraction for JSON Array Messages](#field-extraction-for-json-array-messages)
5. [Training the Models](#training-the-models)
6. [Scoring Events](#scoring-events)
7. [Governance Alerts](#governance-alerts)
8. [Dashboard Panels](#dashboard-panels)
9. [Model Maintenance](#model-maintenance)
10. [Troubleshooting Guide](#troubleshooting-guide)
11. [Parameter Reference](#parameter-reference)

---

## Overview

### What is TF-IDF Anomaly Detection?

TF-IDF (Term Frequency-Inverse Document Frequency) is a numerical statistic that reflects the importance of words in a document relative to a corpus. For anomaly detection:

1. **Training Phase:** Build a vocabulary from "normal" prompts/responses
2. **Vectorization:** Convert text to TF-IDF feature vectors
3. **Baseline:** Learn the distribution of normal text patterns
4. **Scoring:** New messages with unusual word patterns score as anomalies

### Use Cases

| Use Case | Description |
|----------|-------------|
| **Unusual Prompts** | Detect prompts that don't match normal user queries (potential attacks, misuse) |
| **Unusual Responses** | Detect model outputs that deviate from expected patterns (hallucinations, errors) |
| **Topic Drift** | Identify when users/models shift to unexpected topics |
| **Jailbreak Detection** | Catch adversarial prompts using unusual vocabulary |
| **Quality Monitoring** | Alert on responses with unexpected content patterns |

### Why TF-IDF for Anomaly Detection?

- **Language-agnostic:** Works across different prompt/response styles
- **Unsupervised:** Learns "normal" without labeled attack data
- **Interpretable:** Can identify specific unusual words/phrases
- **Efficient:** Fast vectorization suitable for real-time scoring
- **Complements Pattern-Based:** Catches anomalies that rule-based detection misses

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     TF-IDF Anomaly Detection Flow                   │
└─────────────────────────────────────────────────────────────────────┘

                    TRAINING (3 Sequential Steps)
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ Step 1: TFIDF   │────▶│ Step 2: PCA     │────▶│ Step 3: SVM     │
│ Vectorizer      │     │ Reduction       │     │ Anomaly Model   │
│ (fit + save)    │     │ (apply + fit)   │     │ (apply + fit)   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
   Model Saved            Model Saved            Model Saved

                    SCORING (Apply All 3 Models)
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ Apply TFIDF     │────▶│ Apply PCA       │────▶│ Apply SVM       │
│ Vectorizer      │     │                 │     │ (get scores)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │ Anomaly Score   │
                                               │ + Risk Level    │
                                               └─────────────────┘
```

### Prerequisites

1. **Splunk MLTK App:** Machine Learning Toolkit (version 5.3+)
2. **Python for Scientific Computing:** Splunk ML libraries installed
3. **Data in index:** Events with prompt/response text fields
4. **Minimum data:** At least 50+ events for basic training (1000+ recommended)

---

## Critical Implementation Notes

### Multi-Step Training Required

**You CANNOT fit and apply models in the same search pipeline.** MLTK models must be saved (via `fit ... into`) before they can be used (via `apply`).

**WRONG - This will fail:**
```spl
| fit TFIDF text into model_name
| apply model_name   ``` ERROR: Model does not exist
| fit PCA ...
```

**CORRECT - Run as separate searches:**
```spl
``` Search 1: Train TFIDF
| fit TFIDF text into app:model_name

``` Search 2: (run after Search 1 completes)
| apply app:model_name
| fit PCA ...
```

### Model Naming with app: Prefix

When saving models with `into app:modelname`, you MUST also use `app:` prefix when applying:

**WRONG:**
```spl
| fit TFIDF text into app:tfidf_vectorizer
| apply tfidf_vectorizer   ``` ERROR: Model does not exist
```

**CORRECT:**
```spl
| fit TFIDF text into app:tfidf_vectorizer

``` Later search:
| apply app:tfidf_vectorizer   ``` Works!
```

### OneClassSVM gamma Parameter

Splunk MLTK does not accept string values like `gamma=scale`. Either:
- Omit the parameter (uses default)
- Use a float value like `gamma=0.1`

**WRONG:**
```spl
| fit OneClassSVM "PC_*" kernel=rbf gamma=scale   ``` ERROR: Invalid value for gamma
```

**CORRECT:**
```spl
| fit OneClassSVM "PC_*" kernel=rbf nu=0.25   ``` Uses default gamma
```

---

## Field Extraction for JSON Array Messages

### Understanding Your Data Structure

GenAI telemetry often stores messages as JSON arrays:

```json
{
  "input_messages": [
    {"role": "user", "content": "What are the symptoms?"},
    {"role": "assistant", "content": "Please describe more..."},
    {"role": "user", "content": "I have a headache"}
  ],
  "output_messages": [
    {"role": "assistant", "content": "Based on your symptoms..."}
  ]
}
```

Splunk extracts these as multi-value fields:
- `input_messages{}.content` = ["What are the symptoms?", "Please describe more...", "I have a headache"]
- `input_messages{}.role` = ["user", "assistant", "user"]

### Extracting Text Content

Use `mvjoin()` to concatenate all content into a single text string:

```spl
| eval input_text=coalesce(
    mvjoin('input_messages{}.content', " "),   ``` JSON array format
    'gen_ai.input.messages',                    ``` Aliased field
    'event.input',                              ``` Nested event format
    input_messages,                             ``` Raw field
    input                                       ``` Fallback
)
```

### Verifying Field Extraction

Run this to check which fields contain your data:

```spl
index=gen_ai_log | head 1 | fieldsummary | table field
```

Then verify content extraction:

```spl
index=gen_ai_log
| eval input_text=coalesce(mvjoin('input_messages{}.content', " "), 'gen_ai.input.messages')
| where isnotnull(input_text)
| stats count
```

---

## Training the Models

### Training Overview

Training now uses **HashingVectorizer** (stateless) instead of TFIDF (which requires saving vocabulary). This simplifies the pipeline to **4 saved searches** (2 for prompts, 2 for responses), run sequentially:

| Order | Saved Search Name | Creates Model |
|-------|------------------|---------------|
| 1 | GenAI - TFIDF Train Prompt Step 1 - PCA Model | `app:tfidf_prompt_pca` |
| 2 | GenAI - TFIDF Train Prompt Step 2 - Anomaly Model | `app:prompt_anomaly_model` |
| 3 | GenAI - TFIDF Train Response Step 1 - PCA Model | `app:tfidf_response_pca` |
| 4 | GenAI - TFIDF Train Response Step 2 - Anomaly Model | `app:response_anomaly_model` |

**Note:** The old Step 3 searches are deprecated and disabled. HashingVectorizer is run inline (not saved) because it is stateless.

### Important: Training Data Filter

All training searches use the filter `sourcetype!="gen_ai:*:scoring"` to exclude ML-generated scoring events from the training data. This ensures the model trains only on original telemetry events, not on the enriched events produced by the scoring pipeline.

### Step 1: Train PCA Model (Prompts)

Uses HashingVectorizer to create features, then trains PCA for dimensionality reduction.

```spl
index=gen_ai_log sourcetype!="gen_ai:*:scoring"
| eval input_text=coalesce(mvjoin('input_messages{}.content', " "), 'gen_ai.input.messages', 'event.input', input_messages, input)
| where isnotnull(input_text) AND len(input_text) > 10
| eval input_text_clean=lower(input_text)
| eval input_text_clean=replace(input_text_clean, "[^a-z0-9\s]", " ")
| eval input_text_clean=replace(input_text_clean, "\s+", " ")
| eval input_text_clean=trim(input_text_clean)
| where len(input_text_clean) > 20
| head 50000
| fit HashingVectorizer input_text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false
| fit PCA "input_text_clean_hashed_*" k=50 into app:tfidf_prompt_pca
```

### Step 2: Train Anomaly Model (Prompts)

**Run AFTER Step 1 completes:**

```spl
index=gen_ai_log sourcetype!="gen_ai:*:scoring"
| eval input_text=coalesce(mvjoin('input_messages{}.content', " "), 'gen_ai.input.messages', 'event.input', input_messages, input)
| where isnotnull(input_text) AND len(input_text) > 10
| eval input_text_clean=lower(input_text)
| eval input_text_clean=replace(input_text_clean, "[^a-z0-9\s]", " ")
| eval input_text_clean=replace(input_text_clean, "\s+", " ")
| eval input_text_clean=trim(input_text_clean)
| where len(input_text_clean) > 20
| head 50000
| fit HashingVectorizer input_text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false
| apply app:tfidf_prompt_pca
| fit OneClassSVM "PC_*" kernel=rbf nu=0.25 into app:prompt_anomaly_model
```

### Steps 3-4: Response Model Training

Same pattern as Steps 1-2, but for responses:

**Step 3: Train PCA Model (Responses)**
```spl
index=gen_ai_log sourcetype!="gen_ai:*:scoring"
| eval output_text=coalesce(mvjoin('output_messages{}.content', " "), 'gen_ai.output.messages', 'event.output', output_messages, output)
| where isnotnull(output_text) AND len(output_text) > 20
| eval output_text_clean=lower(output_text)
| eval output_text_clean=replace(output_text_clean, "[^a-z0-9\s]", " ")
| eval output_text_clean=replace(output_text_clean, "\s+", " ")
| eval output_text_clean=trim(output_text_clean)
| where len(output_text_clean) > 50
| head 50000
| fit HashingVectorizer output_text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false
| fit PCA "output_text_clean_hashed_*" k=20 into app:tfidf_response_pca
```

**Step 4: Train Anomaly Model (Responses)** - Run after Step 3
```spl
index=gen_ai_log sourcetype!="gen_ai:*:scoring"
| eval output_text=coalesce(mvjoin('output_messages{}.content', " "), 'gen_ai.output.messages', 'event.output', output_messages, output)
| where isnotnull(output_text) AND len(output_text) > 20
| eval output_text_clean=lower(output_text)
| eval output_text_clean=replace(output_text_clean, "[^a-z0-9\s]", " ")
| eval output_text_clean=replace(output_text_clean, "\s+", " ")
| eval output_text_clean=trim(output_text_clean)
| where len(output_text_clean) > 50
| head 50000
| fit HashingVectorizer output_text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false
| apply app:tfidf_response_pca
| fit OneClassSVM "PC_*" kernel=rbf nu=0.25 into app:response_anomaly_model
```

### Verify Models Created

After training, verify models exist. Note: HashingVectorizer is stateless and runs inline, so only PCA and OneClassSVM models are saved:

```spl
| rest /servicesNS/-/TA-gen_ai_cim/mltk/models
| search title IN ("tfidf_prompt_pca", "prompt_anomaly_model", "tfidf_response_pca", "response_anomaly_model")
| table title, app
```

---

## Scoring Events

### Important: Exclude Scoring Sourcetypes

**CRITICAL:** All scoring searches MUST exclude the scoring sourcetype to prevent re-processing previously scored events. Without this filter, `dedup gen_ai.event.id` may select a scoring event (which lacks the original prompt text) instead of the original telemetry event.

```spl
sourcetype!="gen_ai:*:scoring"
```

This filter excludes:
- `gen_ai:tfidf:scoring` - TF-IDF anomaly scoring output
- `gen_ai:pii:scoring` - PII detection scoring output

### Score Prompts for Anomalies

```spl
index=gen_ai_log sourcetype!="gen_ai:*:scoring" earliest=-1h latest=now
| eval input_text=coalesce(mvjoin('input_messages{}.content', " "), 'gen_ai.input.messages', 'event.input', input_messages, input)
| where isnotnull(input_text) AND len(input_text) > 10
| eval input_text_clean=lower(input_text)
| eval input_text_clean=replace(input_text_clean, "[^a-z0-9\s]", " ")
| eval input_text_clean=replace(input_text_clean, "\s+", " ")
| eval input_text_clean=trim(input_text_clean)
| where len(input_text_clean) > 20
| fit HashingVectorizer input_text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false
| apply app:tfidf_prompt_pca
| apply app:prompt_anomaly_model
| eval "gen_ai.prompt.anomaly_score" = 'isNormal'
| eval "gen_ai.prompt.is_anomaly" = if('isNormal' < 0, "true", "false")
| table _time gen_ai.event.id gen_ai.prompt.anomaly_score gen_ai.prompt.is_anomaly input_text
```

### Score Responses for Anomalies

```spl
index=gen_ai_log sourcetype!="gen_ai:*:scoring" earliest=-1h latest=now
| eval output_text=coalesce(mvjoin('output_messages{}.content', " "), 'gen_ai.output.messages', 'event.output', output_messages, output)
| where isnotnull(output_text) AND len(output_text) > 20
| eval output_text_clean=lower(output_text)
| eval output_text_clean=replace(output_text_clean, "[^a-z0-9\s]", " ")
| eval output_text_clean=replace(output_text_clean, "\s+", " ")
| eval output_text_clean=trim(output_text_clean)
| where len(output_text_clean) > 50
| fit HashingVectorizer output_text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false
| apply app:tfidf_response_pca
| apply app:response_anomaly_model
| eval "gen_ai.response.anomaly_score" = 'isNormal'
| eval "gen_ai.response.is_anomaly" = if('isNormal' < 0, "true", "false")
| table _time gen_ai.event.id gen_ai.response.anomaly_score gen_ai.response.is_anomaly
```

### Combined Scoring with Risk Levels

```spl
index=gen_ai_log sourcetype!="gen_ai:*:scoring" earliest=-1h latest=now
| eval input_text=coalesce(mvjoin('input_messages{}.content', " "), 'gen_ai.input.messages', 'event.input', input_messages, input)
| eval output_text=coalesce(mvjoin('output_messages{}.content', " "), 'gen_ai.output.messages', 'event.output', output_messages, output)
| eval input_text_clean=lower(coalesce(input_text, ""))
| eval input_text_clean=replace(input_text_clean, "[^a-z0-9\s]", " ")
| eval input_text_clean=replace(input_text_clean, "\s+", " ")
| eval input_text_clean=trim(input_text_clean)
| eval output_text_clean=lower(coalesce(output_text, ""))
| eval output_text_clean=replace(output_text_clean, "[^a-z0-9\s]", " ")
| eval output_text_clean=replace(output_text_clean, "\s+", " ")
| eval output_text_clean=trim(output_text_clean)
| eval has_valid_prompt=if(len(input_text_clean) > 20, 1, 0)
| eval has_valid_response=if(len(output_text_clean) > 50, 1, 0)
| where has_valid_prompt=1 OR has_valid_response=1
| dedup gen_ai.event.id
| fit HashingVectorizer input_text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false
| apply app:tfidf_prompt_pca
| apply app:prompt_anomaly_model
| eval prompt_isNormal = 'isNormal'
| eval "gen_ai.prompt.anomaly_score" = if(has_valid_prompt=1, prompt_isNormal, null())
| eval "gen_ai.prompt.is_anomaly" = if(has_valid_prompt=1 AND prompt_isNormal < 0, "true", "false")
| fit HashingVectorizer output_text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false
| apply app:tfidf_response_pca
| apply app:response_anomaly_model
| eval response_isNormal = 'isNormal'
| eval "gen_ai.response.anomaly_score" = if(has_valid_response=1, response_isNormal, null())
| eval "gen_ai.response.is_anomaly" = if(has_valid_response=1 AND response_isNormal < 0, "true", "false")
| eval "gen_ai.tfidf.combined_anomaly" = case(
    'gen_ai.prompt.is_anomaly'="true" AND 'gen_ai.response.is_anomaly'="true", "both",
    'gen_ai.prompt.is_anomaly'="true", "prompt_only",
    'gen_ai.response.is_anomaly'="true", "response_only",
    1=1, "normal"
)
| eval "gen_ai.tfidf.risk_level" = case(
    'gen_ai.tfidf.combined_anomaly'="both", "HIGH",
    'gen_ai.tfidf.combined_anomaly'="prompt_only", "MEDIUM",
    'gen_ai.tfidf.combined_anomaly'="response_only", "LOW",
    1=1, "NONE"
)
```

---

## Governance Alerts

### Available Alerts (in savedsearches.conf)

| Alert Name | Description | Trigger |
|------------|-------------|---------|
| GenAI - TFIDF Anomalous Prompt Alert | Unusual prompts detected | ≥3 anomalous prompts in 15 min |
| GenAI - TFIDF Anomalous Response Alert | Unusual responses detected | ≥2 anomalous responses in 15 min |
| GenAI - TFIDF High Risk Combined Anomaly Alert | Both prompt AND response anomalous | Any HIGH risk event |
| GenAI - TFIDF Anomaly by Source IP Alert | Repeated anomalies from same source | ≥5 anomalies from one IP |
| GenAI - TFIDF Anomaly Rate Threshold Alert | Overall anomaly rate too high | >10% anomaly rate |
| GenAI - TFIDF Daily Anomaly Summary | Daily report | Daily at 8 AM |

---

## Dashboard

The TF-IDF Anomaly Detection tab in the AI Governance Overview dashboard provides visualizations for:
- Anomalous prompt/response counts and trends
- Risk level distribution (HIGH, MEDIUM, LOW, NONE)
- Top anomaly sources by client address

**Full Dashboard Documentation:** See [DASHBOARDS/TFIDF_ANOMALY_DETECTION.md](../DASHBOARDS/TFIDF_ANOMALY_DETECTION.md)

---

## Model Maintenance

### Important: When to Retrain Models

**You MUST retrain models after:**
- Changing any training parameters (nu, k, max_features, etc.)
- Modifying text preprocessing logic
- Significant changes in the types of prompts/responses in your environment

**Retraining steps:**
1. Run `GenAI - TFIDF Train Prompt Step 1 - PCA Model`, wait for completion
2. Run `GenAI - TFIDF Train Prompt Step 2 - Anomaly Model`, wait for completion
3. Run `GenAI - TFIDF Train Response Step 1 - PCA Model`, wait for completion
4. Run `GenAI - TFIDF Train Response Step 2 - Anomaly Model`, wait for completion

### Retraining Schedule

| Frequency | Trigger |
|-----------|---------|
| **Monthly** | Standard maintenance |
| **Weekly** | Anomaly rate >10% |
| **Immediate** | New app deployed, major usage change, parameter changes |

### Performance Monitoring

**Check Anomaly Rate:**
```spl
index=gen_ai_log earliest=-7d gen_ai.prompt.is_anomaly=*
| stats 
    count(eval('gen_ai.prompt.is_anomaly'="true")) as flagged,
    count as total
| eval anomaly_rate = round(flagged/total*100, 2)
| eval status = case(
    anomaly_rate > 15, "CRITICAL - Retrain immediately",
    anomaly_rate > 10, "WARNING - Consider retraining",
    1=1, "HEALTHY"
)
```

---

## Troubleshooting Guide

### Issue: "Model does not exist"

**Cause 1:** Model not yet trained
```
Error in 'apply' command: Model does not exist
```

**Solution:** Run the training saved searches in order (Step 1 for PCA, then Step 2 for OneClassSVM).

**Cause 2:** Missing `app:` prefix
```spl
| apply tfidf_prompt_pca   ``` Missing app: prefix
```

**Solution:** Use `| apply app:tfidf_prompt_pca`

**Cause 3:** Training in same search as apply

**Solution:** Split into separate searches. Each `fit` must complete before `apply` can use that model.

---

### Issue: "Invalid value for gamma"

```
Error in 'fit' command: Invalid value for gamma: must be a float
```

**Cause:** Using `gamma=scale` (string not supported)

**Solution:** Remove gamma parameter or use float value:
```spl
| fit OneClassSVM "PC_*" kernel=rbf nu=0.25   ``` Omit gamma
```

---

### Issue: "n_components must be between 0 and min(n_samples, n_features)"

**Cause:** The PCA `k` parameter exceeds the number of samples or features in your data.

**Solution:** Reduce the `k` parameter to be less than your sample count:
```spl
| fit PCA "field_tfidf_*" k=20 into app:model_name   ``` Use k < min(samples, features)
```

Recommended `k` values based on dataset size:

| Events | Recommended k |
|--------|---------------|
| <50 | 10-15 |
| 50-100 | 20 |
| 100-500 | 30-50 |
| >500 | 50-100 |

---

### Issue: Zero Events in Training

**Cause 1:** Time range excludes all data

**Solution:** Check your data's time range:
```spl
index=gen_ai_log | stats min(_time) as earliest, max(_time) as latest | eval earliest=strftime(earliest, "%Y-%m-%d"), latest=strftime(latest, "%Y-%m-%d")
```

**Cause 2:** Field extraction not matching data structure

**Solution:** Check what fields exist and use `mvjoin()` for JSON arrays.

---

### Issue: All Events Flagged as Anomalies

**Cause:** `nu` parameter too high, or trained on too few events

**Solutions:**
1. Lower `nu` from 0.25 to 0.15 or 0.1, then **retrain the models**
2. Train on more data (minimum 100+ events)
3. Increase `min_df` to filter rare terms

---

### Issue: No Anomalies Detected

**Symptoms:**
- `gen_ai.prompt.is_anomaly` is always "false"
- `gen_ai.response.is_anomaly` is always "false"
- `isNormal` field is always 1 or null

**Diagnostic Steps:**

**Step 1: Verify models exist**
```spl
| rest /servicesNS/-/TA-gen_ai_cim/mltk/models
| search title IN ("tfidf_prompt_pca", "prompt_anomaly_model", "tfidf_response_pca", "response_anomaly_model")
| table title, app, updated
```
If any models are missing, run the training saved searches (Step 1 for PCA, then Step 2 for OneClassSVM).

**Step 2: Verify scoring produces isNormal values**
```spl
index=gen_ai_log sourcetype!="gen_ai:*:scoring" earliest=-1h
| head 100
| eval input_text_clean=lower(coalesce(mvjoin('input_messages{}.content', " "), 'gen_ai.input.messages'))
| eval input_text_clean=replace(input_text_clean, "[^a-z0-9\s]", " ")
| eval input_text_clean=trim(replace(input_text_clean, "\s+", " "))
| where len(input_text_clean) > 20
| fit HashingVectorizer input_text_clean max_features=1000 ngram_range=1-2 stop_words=english reduce=false
| apply app:tfidf_prompt_pca
| apply app:prompt_anomaly_model
| stats count by isNormal
```
Expected: Mix of `isNormal=1` (normal) and `isNormal=-1` (anomaly). If all values are 1, see causes below.

**Step 3: Check anomaly rate**
```spl
index=gen_ai_log gen_ai.prompt.is_anomaly=* earliest=-7d
| stats count(eval('gen_ai.prompt.is_anomaly'="true")) as anomalies, count as total
| eval anomaly_rate=round(anomalies/total*100, 2)
| table total, anomalies, anomaly_rate
```

**Common Causes:**

1. **Model trained on anomalous data:** If the training data included anomalies, the model learns them as "normal"
   - Solution: Retrain on cleaner baseline data

2. **`nu` parameter too low:** With low `nu` values, the model expects fewer outliers
   - Solution: Increase `nu` to 0.25 or higher in the training searches, then **retrain the models**

3. **Training data too diverse:** If training data covers all patterns, nothing appears anomalous
   - Solution: Train on a more focused baseline dataset

4. **Preprocessing mismatch:** Training and scoring must use identical text preprocessing
   - Solution: Verify both use same HashingVectorizer parameters and text cleaning steps

---

### Issue: Prompt Text Extracted but Not Scored (Empty Score Fields)

**Symptoms:**
- Query for a specific `gen_ai.event.id` returns multiple rows
- One row has the prompt text but empty `gen_ai.prompt.anomaly_score`
- Another row has a score but empty `input_text`

**Cause:** The scoring search is not excluding previously created scoring events. When `dedup gen_ai.event.id` runs, it may select a scoring event (sourcetype `gen_ai:tfidf:scoring`) instead of the original telemetry event. Scoring events contain the anomaly score but not the original prompt text fields.

**Example of the problem:**
```
| Row | input_text                      | anomaly_score | is_anomaly |
|-----|--------------------------------|---------------|------------|
| 1   | "User's actual prompt..."       | (empty)       | (empty)    |  <- Original event
| 2   | (empty)                        | 1             | false      |  <- Scoring event
```

**Solution:** Add `sourcetype!="gen_ai:*:scoring"` to the search filter:

```spl
index=gen_ai_log sourcetype!="gen_ai:*:scoring" earliest=-1h latest=now
| eval input_text=...
```

This ensures only original telemetry events are processed, not ML-generated scoring output.

---

## Parameter Reference

### TFIDF Parameters

| Parameter | Default | Small Dataset | Large Dataset | Description |
|-----------|---------|---------------|---------------|-------------|
| `max_features` | 1000 | 500 | 5000 | Vocabulary size limit |
| `ngram_range` | 1-2 | 1-2 | 1-3 | N-gram range (unigrams + bigrams) |
| `stop_words` | english | english | english | Remove common words |
| `max_df` | 0.95 | 0.95 | 0.95 | Ignore terms in >95% of docs |
| `min_df` | 2 | 2 | 5 | Term must appear in ≥N docs |

### PCA Parameters

| Parameter | Default | Small Dataset | Large Dataset | Description |
|-----------|---------|---------------|---------------|-------------|
| `k` | 50 | 20 | 100 | Number of principal components |

### OneClassSVM Parameters

| Parameter | Default | Conservative | Sensitive | Description |
|-----------|---------|--------------|-----------|-------------|
| `kernel` | rbf | rbf | rbf | Kernel type |
| `nu` | 0.25 | 0.1 | 0.3 | Expected anomaly fraction |

**Important:** After changing any training parameters, you must retrain the models by running the training saved searches in order (Step 1 then Step 2 for each model type).

### Hybrid Detection Thresholds

The system uses **hybrid detection** combining ML-based anomaly detection with rule-based pattern matching. Thresholds are configurable via macros in `macros.conf`:

| Macro | Default | Description |
|-------|---------|-------------|
| `genai_tfidf_anomaly_threshold` | 0.5 | ML threshold (lower = more sensitive). Original was 0. |
| `genai_tfidf_pattern_threshold` | 2 | Pattern score threshold (triggers on 2+ pattern matches) |

**Pattern Scoring Weights (Prompts):**
| Pattern | Weight | Description |
|---------|--------|-------------|
| Injection markers | 3 | "ignore previous", "bypass safety", etc. |
| Jailbreak terms | 3 | "DAN", "jailbreak", "developer mode", etc. |
| Roleplay injection | 2 | "pretend you are", "from now on", etc. |
| Encoding tricks | 2 | base64, hex encoding, URL encoding |
| Delimiters | 1 | `[INST]`, `<<SYS>>`, `---`, etc. |
| Brackets | 1 | `[]`, `{}`, `<>` patterns |
| Repeated chars | 1 | 5+ consecutive identical characters |

**Pattern Scoring Weights (Responses):**
| Pattern | Weight | Description |
|---------|--------|-------------|
| Harmful content | 3 | Instructions for harmful activities |
| Jailbreak confirm | 3 | "I am now DAN", "entering unrestricted mode" |
| System leak | 2 | "my system prompt is", "I was instructed to" |

### Dataset Size Recommendations

| Events | max_features | k (PCA) | min_df | nu |
|--------|-------------|---------|--------|-----|
| <100 | 500 | 20 | 2 | 0.25-0.3 |
| 100-1000 | 1000 | 50 | 2 | 0.25 |
| 1000-10000 | 2000 | 100 | 3 | 0.2-0.25 |
| >10000 | 5000 | 100 | 5 | 0.15-0.2 |

---

## Output Fields

### Fields Added by Scoring

| Field | Type | Description |
|-------|------|-------------|
| `gen_ai.prompt.anomaly_score` | float | Raw score from OneClassSVM (negative = anomaly) |
| `gen_ai.prompt.is_anomaly` | string | "true" if ML OR pattern detection triggered |
| `gen_ai.prompt.anomaly_source` | string | Source: "ml_and_pattern", "ml_only", "pattern_only", "none" |
| `gen_ai.prompt.pattern_score` | int | Pattern-based score (higher = more suspicious) |
| `gen_ai.response.anomaly_score` | float | Raw score for responses |
| `gen_ai.response.is_anomaly` | string | "true" if ML OR pattern detection triggered |
| `gen_ai.response.anomaly_source` | string | Source: "ml_and_pattern", "ml_only", "pattern_only", "none" |
| `gen_ai.response.pattern_score` | int | Pattern-based score for responses |
| `gen_ai.tfidf.combined_anomaly` | string | "both", "prompt_only", "response_only", "normal" |
| `gen_ai.tfidf.risk_level` | string | "HIGH", "MEDIUM", "LOW", "NONE" |

---

## Quick Start Checklist

- [ ] Verify MLTK is installed
- [ ] Check data exists: `index=gen_ai_log | stats count`
- [ ] Verify field extraction works (see Field Extraction section)
- [ ] Run training Step 1 (TFIDF), wait for completion
- [ ] Run training Step 2 (PCA), wait for completion
- [ ] Run training Step 3 (SVM), wait for completion
- [ ] Repeat Steps 1-3 for responses
- [ ] Test scoring on sample data
- [ ] Enable scheduled scoring searches
- [ ] Enable alerts

---

## See Also

- [PII_Detection.md](PII_Detection.md) - PII and PHI detection
- [Prompt_Injection.md](Prompt_Injection.md) - Prompt injection detection

---

**Last Updated:** 2026-01-27
