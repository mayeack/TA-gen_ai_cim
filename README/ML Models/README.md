# Machine Learning Models for GenAI Governance

This directory contains documentation for all machine learning models used in the TA-gen_ai_cim app for AI governance, safety, and compliance monitoring.

## Overview

The TA includes four ML-based detection systems:

| Model | Purpose | Algorithm | Training Data |
|-------|---------|-----------|---------------|
| **PII Detection** | Detect PII/PHI in AI responses | RandomForestClassifier | 200k healthcare examples |
| **Prompt Injection** | Detect adversarial prompt attacks | RandomForestClassifier | Labeled attack examples |
| **TF-IDF Prompt Anomaly** | Detect unusual prompts | TFIDF + PCA + OneClassSVM | Normal prompt corpus |
| **TF-IDF Response Anomaly** | Detect unusual responses | TFIDF + PCA + OneClassSVM | Normal response corpus |

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
| `tfidf_prompt_vectorizer` | TF-IDF vectorizer for prompts |
| `tfidf_prompt_pca` | PCA dimensionality reduction for prompts |
| `prompt_anomaly_model` | OneClassSVM for prompt anomaly detection |
| `tfidf_response_vectorizer` | TF-IDF vectorizer for responses |
| `tfidf_response_pca` | PCA dimensionality reduction for responses |
| `response_anomaly_model` | OneClassSVM for response anomaly detection |

### Output Fields

**PII Detection:**
```
gen_ai.pii.risk_score       - ML probability (0-1)
gen_ai.pii.ml_detected      - Boolean flag ("true"/"false")
gen_ai.pii.confidence       - Level: very_high, high, medium, low, very_low
gen_ai.pii.types            - Comma-separated list of detected PII types
```

**Prompt Injection:**
```
gen_ai.prompt_injection.risk_score    - ML probability (0-1)
gen_ai.prompt_injection.ml_detected   - Boolean flag
gen_ai.prompt_injection.technique     - Detected technique type
```

**TF-IDF Anomaly:**
```
gen_ai.prompt.anomaly_score     - Raw SVM score (negative = anomaly)
gen_ai.prompt.is_anomaly        - Boolean flag
gen_ai.response.anomaly_score   - Raw SVM score
gen_ai.response.is_anomaly      - Boolean flag
gen_ai.tfidf.risk_level         - HIGH, MEDIUM, LOW, NONE
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

### TF-IDF Anomaly Detection

Run in order (wait for each to complete):
```spl
| savedsearch "GenAI - TFIDF Train Prompt Step 1 - TFIDF Vectorizer"
| savedsearch "GenAI - TFIDF Train Prompt Step 2 - PCA"
| savedsearch "GenAI - TFIDF Train Prompt Step 3 - Anomaly Model"
```

See individual model documentation for detailed instructions.

## Scheduled Searches

### Scoring (Production)

| Search | Schedule | Purpose |
|--------|----------|---------|
| `GenAI - PII Scoring - Response Analysis` | Every minute | Score responses for PII |
| `GenAI - TFIDF Scoring - Prompt Anomalies` | Hourly | Score prompts for anomalies |
| `GenAI - TFIDF Scoring - Response Anomalies` | Hourly | Score responses for anomalies |
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
   └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
         │               │               │               │
         └───────────────┴───────────────┴───────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │    Enriched Events      │
                    │    + Risk Scores        │
                    │    + Alerts             │
                    └─────────────────────────┘
```

## Support

- **MLTK Documentation:** https://docs.splunk.com/Documentation/MLApp
- **Splunkbase:** https://splunkbase.splunk.com/app/2890

---

**Last Updated:** 2026-01-22
