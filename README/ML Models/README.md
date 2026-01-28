# Machine Learning Models for GenAI Governance

This directory contains documentation for all machine learning models used in the TA-gen_ai_cim app for AI governance, safety, and compliance monitoring.

## Overview

The TA includes four ML-based detection systems:

| Model | Purpose | Algorithm | Training Data |
|-------|---------|-----------|---------------|
| **PII Detection** | Detect PII/PHI in AI responses | RandomForestClassifier | 200k healthcare examples |
| **Prompt Injection** | Detect adversarial prompt attacks | RandomForestClassifier | 1200+ labeled attack examples |
| **TF-IDF Prompt Anomaly** | Detect unusual prompts | HashingVectorizer + PCA + OneClassSVM | Normal prompt corpus |
| **TF-IDF Response Anomaly** | Detect unusual responses | HashingVectorizer + PCA + OneClassSVM | Normal response corpus |

## Model Documentation

| Document | Description |
|----------|-------------|
| [PII_Detection.md](PII_Detection.md) | PII/PHI detection model - training, scoring, alerts, and healthcare patterns |
| [Prompt_Injection.md](Prompt_Injection.md) | Prompt injection attack detection model |
| [TFIDF_Anomaly.md](TFIDF_Anomaly.md) | TF-IDF anomaly detection for prompts and responses |
| [Feedback_Loop.md](Feedback_Loop.md) | Active learning system for continuous model improvement |

## Quick Reference

### Model Names in Splunk MLTK

| Model Name | Description |
|------------|-------------|
| `pii_detection_model` | Champion PII detection model (production) |
| `pii_detection_model_challenger` | Challenger model for A/B comparison |
| `prompt_injection_model` | Prompt injection detection |
| `tfidf_prompt_pca` | PCA dimensionality reduction for prompts |
| `prompt_anomaly_model` | OneClassSVM for prompt anomaly detection |
| `tfidf_response_pca` | PCA dimensionality reduction for responses |
| `response_anomaly_model` | OneClassSVM for response anomaly detection |

**Note:** TF-IDF vectorization uses `HashingVectorizer` which is stateless and runs inline during scoring - no saved vectorizer model required.

### Output Fields

**PII Detection:**
```
gen_ai.pii.risk_score       - ML probability (0-1)
gen_ai.pii.ml_detected      - Boolean flag ("true"/"false")
gen_ai.pii.confidence       - Level: very_high, high, medium, low, very_low
gen_ai.pii.types            - Comma-separated list of detected PII types
gen_ai.pii.severity         - Severity: critical, high, medium, low, none
```

**Prompt Injection:**
```
gen_ai.prompt_injection.risk_score    - ML probability (0-1)
gen_ai.prompt_injection.ml_detected   - Boolean flag
gen_ai.prompt_injection.technique     - Detected technique type
gen_ai.prompt_injection.confidence    - Level: very_high, high, medium, low, very_low
```

**TF-IDF Anomaly (Hybrid Detection):**
```
gen_ai.prompt.anomaly_score     - Raw SVM score (negative = anomaly)
gen_ai.prompt.is_anomaly        - Boolean flag (ML OR pattern detection)
gen_ai.prompt.anomaly_source    - Source: ml_and_pattern, ml_only, pattern_only, none
gen_ai.response.anomaly_score   - Raw SVM score
gen_ai.response.is_anomaly      - Boolean flag
gen_ai.response.anomaly_source  - Source: ml_and_pattern, ml_only, pattern_only, none
gen_ai.tfidf.combined_anomaly   - Combined: both, prompt_only, response_only, normal
gen_ai.tfidf.risk_level         - Risk level: HIGH, MEDIUM, LOW, NONE
```

## Prerequisites

### Required Apps

1. **Splunk Enterprise** 9.0+ or **Splunk Cloud**
2. **Machine Learning Toolkit (MLTK)** 5.3+ - [Splunkbase](https://splunkbase.splunk.com/app/2890)
3. **Python for Scientific Computing** add-on (required by MLTK)

### Verify Installation

```spl
| rest /services/apps/local/Splunk_ML_Toolkit
| table title, version
```

Expected output: `Splunk_ML_Toolkit` version `5.3.x` or higher

## Training Quick Start

### PII Detection (5-minute setup)

```spl
| savedsearch "GenAI - PII Train Step 1 - Feature Engineering from Initial Dataset"
| savedsearch "GenAI - PII Train Step 2 Alt - Random Forest Model"
| savedsearch "GenAI - PII Train Step 3 - Validate Model Performance"
```

### Prompt Injection Detection

```spl
| savedsearch "GenAI - Prompt Injection Train Step 1 - Feature Engineering from Initial Dataset"
| savedsearch "GenAI - Prompt Injection Train Step 2 - Random Forest Model"
| savedsearch "GenAI - Prompt Injection Train Step 3 - Validate Model Performance"
```

### TF-IDF Anomaly Detection

Run **sequentially** (wait for each to complete before running next):

**Prompt Model (2 steps):**
```spl
| savedsearch "GenAI - TFIDF Train Prompt Step 1 - PCA Model"
| savedsearch "GenAI - TFIDF Train Prompt Step 2 - Anomaly Model"
```

**Response Model (2 steps):**
```spl
| savedsearch "GenAI - TFIDF Train Response Step 1 - PCA Model"
| savedsearch "GenAI - TFIDF Train Response Step 2 - Anomaly Model"
```

See individual model documentation for detailed instructions.

## Scheduled Searches

### Scoring (Production)

| Search | Schedule | Purpose |
|--------|----------|---------|
| `GenAI - PII Scoring - Response Analysis` | Every minute | Score responses for PII |
| `GenAI - Prompt Injection Scoring - Prompt Analysis` | Every minute | Score prompts for injection |
| `GenAI - TFIDF Scoring - Combined Anomalies` | Hourly | Combined prompt+response scoring |

### Training & Maintenance

| Search | Schedule | Purpose |
|--------|----------|---------|
| `GenAI - PII Feedback Loop - Extract Training Feedback` | Daily 2 AM | Extract human labels |
| `GenAI - PII Feedback Loop - Train Challenger Model` | Weekly Sunday 4 AM | Train new model |
| `GenAI - PII Feedback Loop - Champion vs Challenger Report` | Weekly Sunday 5 AM | Compare models |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         GenAI Events                                     │
│                    (index=gen_ai_log)                                   │
└─────────────────────────┬───────────────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┬───────────────┐
          │               │               │               │
          ▼               ▼               ▼               ▼
   ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
   │    PII     │  │  Prompt    │  │   TFIDF    │  │   TFIDF    │
   │ Detection  │  │ Injection  │  │  Prompt    │  │  Response  │
   │   Model    │  │   Model    │  │  Anomaly   │  │  Anomaly   │
   │            │  │            │  │            │  │            │
   │ RandomFor. │  │ RandomFor. │  │ Hashing+   │  │ Hashing+   │
   │ Classifier │  │ Classifier │  │ PCA+SVM    │  │ PCA+SVM    │
   └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
         │               │               │               │
         │               │               │               │
         │               │         ┌─────┴───────────────┘
         │               │         │
         │               │         ▼
         │               │  ┌────────────────┐
         │               │  │ + Pattern-Based│
         │               │  │   Detection    │
         │               │  │ (Hybrid Mode)  │
         │               │  └───────┬────────┘
         │               │          │
         └───────────────┴──────────┴───────────────────┐
                                                        │
                                                        ▼
                                  ┌─────────────────────────────────┐
                                  │       Enriched Events           │
                                  │       + Risk Scores             │
                                  │       + Alerts                  │
                                  │       + Anomaly Sources         │
                                  └─────────────────────────────────┘
```

## Hybrid Detection (TF-IDF)

TF-IDF anomaly detection uses a **hybrid approach** combining:

1. **ML-Based Detection**: OneClassSVM identifies statistical anomalies based on text patterns
2. **Pattern-Based Detection**: Regex patterns catch known attack signatures

### Pattern Detection Weights

**Prompts:**
| Pattern | Weight | Examples |
|---------|--------|----------|
| Injection markers | 3 | "ignore previous", "bypass safety" |
| Jailbreak terms | 3 | "DAN", "jailbreak", "developer mode" |
| Roleplay injection | 2 | "pretend you are", "from now on" |
| Encoding tricks | 2 | base64, hex encoding, URL encoding |
| Delimiters | 1 | `[INST]`, `<<SYS>>`, `---` |

**Responses:**
| Pattern | Weight | Examples |
|---------|--------|----------|
| Harmful content | 3 | Instructions for harmful activities |
| Jailbreak confirm | 3 | "I am now DAN", "entering unrestricted mode" |
| System leak | 2 | "my system prompt is", "I was instructed to" |

### Configurable Thresholds

Thresholds are configurable via macros in `macros.conf`:

| Macro | Default | Description |
|-------|---------|-------------|
| `genai_tfidf_anomaly_threshold` | 0.5 | ML threshold (lower = more sensitive) |
| `genai_tfidf_pattern_threshold` | 2 | Pattern score threshold |

## Feedback Loop (Active Learning)

All three supervised models support active learning feedback loops:

| Model | Champion | Challenger | Registry |
|-------|----------|------------|----------|
| PII | `pii_detection_model` | `pii_detection_model_challenger` | `pii_model_registry` |
| Prompt Injection | `prompt_injection_model` | `prompt_injection_model_challenger` | `prompt_injection_model_registry` |
| TF-IDF | N/A (unsupervised) | N/A | `tfidf_model_registry` |

See [Feedback_Loop.md](Feedback_Loop.md) for complete documentation.

## Verify Models Exist

```spl
| rest /servicesNS/-/TA-gen_ai_cim/mltk/models
| search title IN (
    "pii_detection_model",
    "prompt_injection_model",
    "tfidf_prompt_pca",
    "prompt_anomaly_model",
    "tfidf_response_pca",
    "response_anomaly_model"
)
| table title, app, updated
```

## Support

- **MLTK Documentation:** https://docs.splunk.com/Documentation/MLApp
- **Splunkbase:** https://splunkbase.splunk.com/app/2890

---

**Last Updated:** 2026-01-28
