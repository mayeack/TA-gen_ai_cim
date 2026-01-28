# PII Active Learning Feedback Loop

This document describes the active learning feedback loop for PII detection, which leverages human reviews to continuously improve the ML model.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Data Flow](#data-flow)
4. [Components](#components)
5. [Workflow](#workflow)
6. [KV Store Collections](#kv-store-collections)
7. [Scheduled Searches](#scheduled-searches)
8. [Dashboards](#dashboards)
9. [Model Comparison & Promotion](#model-comparison--promotion)
10. [Metrics & Monitoring](#metrics--monitoring)
11. [Quick Start Guide](#quick-start-guide)
12. [Troubleshooting](#troubleshooting)

---

## Overview

The feedback loop enables continuous improvement of PII detection by:

1. **Extracting human labels** from completed Event Reviews
2. **Splitting data** into train/validation/test sets (70/15/15)
3. **Training challenger models** with accumulated feedback
4. **Tuning thresholds** to optimize precision/recall trade-off
5. **Comparing models** (champion vs challenger)
6. **Promoting improved models** to production

### Why Active Learning?

- **Model drift**: AI applications evolve, new PII patterns emerge
- **Domain adaptation**: Customize detection for your specific use cases
- **Quality improvement**: Learn from human expert corrections
- **False positive reduction**: Train on your real-world data

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Active Learning Loop                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │   GenAI      │───►│  PII Model   │───►│   Review     │          │
│  │   Events     │    │  (Champion)  │    │    Queue     │          │
│  └──────────────┘    └──────────────┘    └──────┬───────┘          │
│                                                  │                   │
│                                                  ▼                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │   Model      │◄───│  Challenger  │◄───│   Human      │          │
│  │   Registry   │    │    Model     │    │   Labels     │          │
│  └──────────────┘    └──────────────┘    └──────────────┘          │
│         │                   ▲                   │                   │
│         │                   │                   │                   │
│         ▼                   │                   ▼                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │   Promote    │───►│   Compare    │◄───│   Training   │          │
│  │   Decision   │    │   Metrics    │    │   Feedback   │          │
│  └──────────────┘    └──────────────┘    └──────────────┘          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                  index=gen_ai_log                            │
│                              (Raw Telemetry Events)                          │
└───────────────────────────────────────┬─────────────────────────────────────┘
                                        │
                    ┌───────────────────┴───────────────────┐
                    │                                       │
                    ▼                                       ▼
    ┌───────────────────────────────┐       ┌───────────────────────────────┐
    │      Scoring Pipeline         │       │     Auto-Escalation           │
    │   (Every minute)              │       │   (Every minute)              │
    │                               │       │                               │
    │  1. Extract response text     │       │  High-risk events ──────────┐ │
    │  2. Engineer 20 features      │       │  Random sample ─────────────┤ │
    │  3. Apply champion model      │       │                             │ │
    │  4. Calculate risk score      │       │                             │ │
    └───────────────┬───────────────┘       └─────────────────────────────┼─┘
                    │                                                      │
                    ▼                                                      │
    ┌───────────────────────────────┐                                     │
    │    Enriched Events            │                                     │
    │  sourcetype=gen_ai:pii:scoring│                                     │
    └───────────────────────────────┘                                     │
                                                                           │
                                                                           ▼
                                            ┌───────────────────────────────┐
                                            │   gen_ai_review_findings      │
                                            │      (KV Store)               │
                                            └───────────────┬───────────────┘
                                                            │
                                                            │ Human Review
                                                            ▼
                                            ┌───────────────────────────────┐
                                            │    Event Review Dashboard     │
                                            │                               │
                                            │  Reviewer sets:               │
                                            │  - pii_confirmed (0/1)        │
                                            │  - status = "completed"       │
                                            └───────────────┬───────────────┘
                                                            │
                                                            │ Daily 2 AM
                                                            ▼
                                            ┌───────────────────────────────┐
                                            │   pii_training_feedback       │
                                            │      (KV Store)               │
                                            └───────────────┬───────────────┘
                                                            │
                                                            │ Weekly Sunday 4 AM
                                                            ▼
                                            ┌───────────────────────────────┐
                                            │   Challenger Model Training   │
                                            └───────────────┬───────────────┘
                                                            │
                                                            │ Weekly Sunday 5 AM
                                                            ▼
                                            ┌───────────────────────────────┐
                                            │   Champion vs Challenger      │
                                            │       Evaluation              │
                                            └───────────────┬───────────────┘
                                                            │
                                                            │ Manual Promotion
                                                            ▼
                                            ┌───────────────────────────────┐
                                            │     pii_model_registry        │
                                            │       (KV Store)              │
                                            └───────────────────────────────┘
```

---

## Components

### Champion Model (Production)

| Property | Value |
|----------|-------|
| **Model Name** | `pii_detection_model` |
| **Algorithm** | RandomForestClassifier |
| **Features** | 20 engineered features |
| **Target** | `pii_label` (0 = clean, 1 = PII) |
| **Threshold** | 0.5 (configurable) |

### Challenger Model (Candidate)

| Property | Value |
|----------|-------|
| **Model Name** | `pii_detection_model_challenger` |
| **Training Data** | Human feedback + original dataset |
| **Purpose** | Evaluated against champion for promotion |

### Auto-Escalation System

**Two escalation paths populate the review queue:**

| Path | Search | Trigger |
|------|--------|---------|
| **High-Risk Events** | `GenAI - Auto Escalate PII to Review Queue` | `gen_ai.pii.ml_detected="true"` |
| **Random Sampling** | `GenAI - Auto Escalate Random Sample to Review Queue` | Event ID matches RNG seed |

---

## Workflow

### 1. Data Collection

Human reviewers label events in the Event Review dashboard:
- **PII Confirmed**: Reviewer confirms PII/PHI is present (`pii_confirmed=1`)
- **PII Not Confirmed**: Reviewer confirms the event is clean (`pii_confirmed=0`)
- **PII Types (Reviewed)**: Reviewer selects specific PII types found (SSN, EMAIL, PHONE, etc.)

The `gen_ai_review_pii_types_reviewed` field captures the reviewer-confirmed PII types, which are used as ground truth labels for model retraining.

### 2. Feedback Extraction (Daily)

The extraction search runs daily at 2 AM:

1. Reads completed reviews from `gen_ai_review_findings`
2. Extracts `gen_ai_review_pii_types_reviewed` (reviewer-confirmed types) as ground truth
3. Generates per-type labels from reviewed types (e.g., `has_ssn_label`, `has_email_label`)
4. Joins with original event data to get full response text and ML predictions
5. Classifies feedback type by comparing ML predictions with reviewer confirmations:

| Feedback Type | Definition |
|---------------|------------|
| `confirmed_pii_exact` | Human confirmed PII, model predicted PII, and types match exactly |
| `confirmed_pii_type_mismatch` | Human confirmed PII, model predicted PII, but types differ |
| `confirmed_clean` | Human confirmed clean, model predicted clean (True Negative) |
| `false_positive` | Human confirmed clean, model predicted PII |
| `false_negative` | Human confirmed PII, model predicted clean |

6. Assigns random train/valid/test split (70/15/15)
7. Engineers all 20 features for training
8. Stores in `pii_training_feedback` collection with per-type ground truth labels

### Per-Type Ground Truth Labels

The feedback extraction generates individual labels for each PII type based on reviewer confirmations:

| Label Field | Source |
|-------------|--------|
| `has_ssn_label` | 1 if reviewer confirmed SSN in `pii_types_reviewed` |
| `has_email_label` | 1 if reviewer confirmed EMAIL |
| `has_phone_label` | 1 if reviewer confirmed PHONE |
| `has_dob_label` | 1 if reviewer confirmed DOB |
| `has_address_label` | 1 if reviewer confirmed ADDRESS |
| `has_credit_card_label` | 1 if reviewer confirmed CREDIT_CARD |
| `has_name_label` | 1 if reviewer confirmed NAME |

These per-type labels enable:
- Granular analysis of which PII types the model is missing
- Targeted improvements for specific PII categories
- Better understanding of type-specific false positive/negative rates

### 3. Model Training (Weekly)

The training search runs weekly on Sunday at 4 AM:

1. Loads feedback data (train split only)
2. Appends original training data
3. Trains RandomForestClassifier
4. Saves as `pii_detection_model_challenger`

### 4. Threshold Tuning

Evaluates thresholds 0.3-0.8 on the validation set:

| Threshold | Use Case |
|-----------|----------|
| 0.3 | High recall - catch all PII (more false positives) |
| 0.5 | Balanced - default operating point |
| 0.7-0.8 | High precision - fewer false alarms |

### 5. Model Comparison

Evaluates both models on the held-out test set:

- Accuracy, Precision, Recall, F1 Score
- Generates promotion recommendation

### 6. Model Promotion (Manual)

When challenger outperforms champion:

1. Review metrics in Model Comparison dashboard
2. Click "Promote Challenger to Champion"
3. New version registered in `pii_model_registry`

**Promotion Criteria:**
- Challenger F1 score > Champion F1 score
- Challenger recall >= Champion recall (critical for PII)
- Test set has at least 30 samples

---

## KV Store Collections

### gen_ai_review_findings

**Purpose:** Event review queue and human labels

| Field | Purpose |
|-------|---------|
| `gen_ai_event_id` | Primary key (links to original event) |
| `gen_ai_review_status` | new → in_progress → completed/rejected |
| `gen_ai_review_pii_confirmed` | Human label: 1 = PII present, 0 = clean |
| `gen_ai_review_phi_confirmed` | Human label: 1 = PHI present |
| `gen_ai_review_pii_types` | ML-detected PII types (auto-populated) |
| `gen_ai_review_pii_types_reviewed` | **Reviewer-confirmed PII types (ground truth)** |
| `gen_ai_review_reviewer` | Username who completed review |

### pii_training_feedback

**Purpose:** Human-labeled data with cached features for retraining

| Field | Purpose |
|-------|---------|
| `event_id` | Primary key |
| `response_text` | Original response text |
| `pii_label` | Human label (0/1) |
| `pii_types` | ML-detected PII types |
| `pii_types_reviewed` | **Reviewer-confirmed PII types (ground truth)** |
| `feedback_type` | confirmed_pii_exact, confirmed_pii_type_mismatch, false_positive, false_negative, confirmed_clean |
| `split_assignment` | train, valid, or test |
| `ml_predicted_score` | Original ML prediction |
| `ml_predicted_types` | ML-detected types for comparison |
| **Per-Type Labels** | |
| `has_ssn_label` | Reviewer confirmed SSN (0/1) |
| `has_email_label` | Reviewer confirmed EMAIL (0/1) |
| `has_phone_label` | Reviewer confirmed PHONE (0/1) |
| `has_dob_label` | Reviewer confirmed DOB (0/1) |
| `has_address_label` | Reviewer confirmed ADDRESS (0/1) |
| `has_credit_card_label` | Reviewer confirmed CREDIT_CARD (0/1) |
| `has_name_label` | Reviewer confirmed NAME (0/1) |
| 20 feature fields | Cached for training (has_ssn, has_email, etc.) |

### pii_model_registry

**Purpose:** Track model versions, metrics, and promotion history

| Field | Purpose |
|-------|---------|
| `model_name` | Model identifier |
| `model_version` | Version timestamp |
| `status` | champion or archived |
| `accuracy`, `precision`, `recall`, `f1_score` | Performance metrics |
| `promoted_at`, `promoted_by` | Promotion tracking |

### pii_threshold_results

**Purpose:** Store threshold tuning analysis results

| Field | Purpose |
|-------|---------|
| `threshold` | Threshold value (0.3-0.8) |
| `precision`, `recall`, `f1_score` | Metrics at this threshold |
| `true_positives`, `false_positives` | Confusion matrix values |

---

## Scheduled Searches

| Search | Schedule | Purpose |
|--------|----------|---------|
| `GenAI - PII Feedback Loop - Extract Training Feedback` | Daily 2:00 AM | Extract completed reviews |
| `GenAI - PII Feedback Loop - Assign Data Splits` | Daily 2:30 AM | Assign train/valid/test splits |
| `GenAI - PII Feedback Loop - Train Challenger Model` | Weekly Sun 4:00 AM | Train new challenger |
| `GenAI - PII Feedback Loop - Threshold Analysis` | Weekly Sun 4:30 AM | Analyze thresholds 0.3-0.8 |
| `GenAI - PII Feedback Loop - Champion vs Challenger Report` | Weekly Sun 5:00 AM | Compare models |
| `GenAI - PII Feedback Loop - Promote Model Version` | Manual | Promote challenger |
| `GenAI - PII Feedback Loop - Model Health Report` | Weekly Mon 9:00 AM | Performance summary |

---

## Dashboards

### Model Comparison Dashboard

**File:** `pii_feedback_loop_model_comparison.xml`

Features:
- Champion vs Challenger metrics side-by-side
- Threshold tuning visualization
- Precision/Recall curves
- Promote button

### Model Registry Dashboard

**File:** `pii_feedback_loop_model_registry.xml`

Features:
- Model version history
- Performance metrics over time
- Feedback statistics
- Data split distribution

---

## Model Comparison & Promotion

### Comparison Metrics

```spl
| inputlookup pii_training_feedback_lookup
| where split_assignment="test"
| apply pii_detection_model
| eval champion_pred=if('predicted(pii_label)'>0.5, 1, 0)
| apply pii_detection_model_challenger
| eval challenger_pred=if('predicted(pii_label)'>0.5, 1, 0)
| stats 
    sum(eval(if(pii_label=1 AND champion_pred=1, 1, 0))) as champion_tp,
    sum(eval(if(pii_label=1 AND challenger_pred=1, 1, 0))) as challenger_tp,
    ... (full confusion matrix) ...
| eval champion_f1=...
| eval challenger_f1=...
| eval recommendation=if(challenger_f1>champion_f1 AND challenger_recall>=champion_recall, "PROMOTE", "KEEP")
```

### Promotion Process

1. Review metrics in Model Comparison dashboard
2. Verify challenger improves on key metrics
3. Click "Promote Challenger to Champion" button
4. System registers new version in `pii_model_registry`
5. Update scoring search to use new model (if needed)

---

## Metrics & Monitoring

### Performance Metrics

| Metric | Definition | Target |
|--------|------------|--------|
| **Accuracy** | (TP + TN) / Total | > 90% |
| **Precision** | TP / (TP + FP) | > 75% |
| **Recall** | TP / (TP + FN) | > 85% |
| **F1 Score** | Harmonic mean | > 80% |

### Feedback Quality Metrics

| Metric | Definition | Warning Threshold |
|--------|------------|-------------------|
| **False Positive Rate** | FP / Total | > 30% |
| **False Negative Rate** | FN / Total | > 10% (critical) |
| **Type Mismatch Rate** | Type Mismatches / Confirmed PII | > 50% |

### Per-Type Metrics

The feedback loop now tracks per-type detection performance:

| Metric | Definition | Purpose |
|--------|------------|---------|
| **SSN Recall** | SSN detected / SSN reviewed | Catch rate for SSN |
| **Email Recall** | Email detected / Email reviewed | Catch rate for Email |
| **Phone Recall** | Phone detected / Phone reviewed | Catch rate for Phone |
| **Name Recall** | Name detected / Name reviewed | Catch rate for Names |

### Model Health Check

```spl
| inputlookup pii_training_feedback_lookup
| stats count AS total_feedback,
    sum(eval(if(feedback_type="confirmed_pii_exact" OR feedback_type="confirmed_pii_type_mismatch", 1, 0))) AS confirmed_pii,
    sum(eval(if(feedback_type="confirmed_pii_type_mismatch", 1, 0))) AS type_mismatches,
    sum(eval(if(feedback_type="false_positive", 1, 0))) AS false_positives,
    sum(eval(if(feedback_type="false_negative", 1, 0))) AS false_negatives,
    sum(has_ssn_label) AS ssn_confirmed,
    sum(has_email_label) AS email_confirmed,
    sum(has_name_label) AS name_confirmed
| eval fp_rate=round(false_positives/total_feedback*100, 2)
| eval fn_rate=round(false_negatives/total_feedback*100, 2)
| eval type_mismatch_rate=if(confirmed_pii>0, round(type_mismatches/confirmed_pii*100, 2), 0)
| eval model_health=case(
    fn_rate > 20, "CRITICAL - High false negative rate",
    fp_rate > 30, "WARNING - High false positive rate",
    type_mismatch_rate > 50, "WARNING - High type mismatch rate",
    total_feedback < 50, "WARNING - Insufficient feedback data",
    1=1, "HEALTHY"
)
```

### Per-Type Analysis

To analyze which PII types are most commonly missed or incorrectly detected:

```spl
| inputlookup pii_training_feedback_lookup
| stats 
    sum(has_ssn_label) AS ssn_reviewed,
    sum(has_ssn) AS ssn_detected,
    sum(has_email_label) AS email_reviewed,
    sum(has_email) AS email_detected,
    sum(has_phone_label) AS phone_reviewed,
    sum(has_phone) AS phone_detected,
    sum(has_name_label) AS name_reviewed,
    sum(has_patient_name) AS name_detected
| eval ssn_recall=if(ssn_reviewed>0, round(ssn_detected/ssn_reviewed*100, 1), "N/A")
| eval email_recall=if(email_reviewed>0, round(email_detected/email_reviewed*100, 1), "N/A")
| eval phone_recall=if(phone_reviewed>0, round(phone_detected/phone_reviewed*100, 1), "N/A")
| eval name_recall=if(name_reviewed>0, round(name_detected/name_reviewed*100, 1), "N/A")
| table ssn_recall, email_recall, phone_recall, name_recall
```

---

## Quick Start Guide

### Minimum Requirements

- At least **50 completed reviews** with PII labels set
- Balanced class distribution (aim for 20-40% PII samples)
- Events must exist in `gen_ai_log` index for feature extraction

### Step 1: Complete Event Reviews

1. Navigate to **Review Queue** dashboard
2. Open events and complete reviews
3. **Critical**: Set the PII confirmation field for each review

### Step 2: Extract Training Feedback

Run manually or wait for daily schedule:
```spl
| savedsearch "GenAI - PII Feedback Loop - Extract Training Feedback"
```

Verify:
```spl
| inputlookup pii_training_feedback_lookup 
| stats count by feedback_type, split_assignment
```

### Step 3: Train Challenger Model

After 50+ feedback samples:
```spl
| savedsearch "GenAI - PII Feedback Loop - Train Challenger Model"
```

### Step 4: Compare Models

```spl
| savedsearch "GenAI - PII Feedback Loop - Champion vs Challenger Report"
```

### Step 5: Promote (If Improved)

Navigate to Model Comparison dashboard and click "Promote Challenger to Champion".

---

## Troubleshooting

### No Challenger Model

**Error:** `pii_detection_model_challenger` doesn't exist

**Solutions:**
1. Run `GenAI - PII Feedback Loop - Train Challenger Model` manually
2. Ensure training feedback has > 0 samples
3. Check MLTK app is installed

### Empty Feedback

**Symptoms:** No feedback being extracted

**Solutions:**
1. Verify reviews are marked "completed"
2. Check `gen_ai_review_pii_confirmed` field is set (0 or 1)
3. Ensure original events exist in `gen_ai_log`

### Poor Model Performance

**Symptoms:** Low accuracy or high false negative rate

**Solutions:**
1. Review class balance in training data
2. Check for labeling errors
3. Consider adjusting threshold
4. Add more diverse training examples

### Feedback Data Imbalance

**Symptoms:** Too few PII examples or clean examples

**Solutions:**
1. Adjust auto-escalation criteria
2. Enable random sampling for false negatives
3. Manually escalate edge cases

---

## Best Practices

### Review Quality

- Train reviewers on PII/PHI definitions
- Use random sampling to catch false negatives
- Review borderline cases carefully
- Document labeling decisions

### Data Requirements

| Metric | Target |
|--------|--------|
| **Minimum Reviews** | 50+ |
| **Recommended Reviews** | 200+ |
| **PII Class Balance** | 20-40% PII samples |

### Monitoring Schedule

| Check | Frequency |
|-------|-----------|
| Review queue status | Daily |
| Model health metrics | Weekly |
| Champion vs Challenger | Weekly |
| Full retraining | Monthly |

---

## See Also

- [PII_Detection.md](PII_Detection.md) - PII detection model guide
- [Prompt_Injection.md](Prompt_Injection.md) - Prompt injection detection
- [TFIDF_Anomaly.md](TFIDF_Anomaly.md) - Anomaly detection

---

## Per-Type Labels Data Flow

The following diagram shows how reviewer-confirmed PII types flow through the feedback loop:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Event Review Dashboard                                │
│                                                                              │
│  Reviewer selects PII Types (Reviewed): [SSN] [EMAIL] [PHONE]               │
│                           ↓                                                  │
│  gen_ai_review_pii_types_reviewed = "SSN,EMAIL,PHONE"                       │
└───────────────────────────────────────┬─────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│            Extract Training Feedback (Daily 2 AM)                            │
│                                                                              │
│  Parse reviewed_pii_types into individual labels:                           │
│    • has_ssn_label = 1 (SSN found in reviewed types)                        │
│    • has_email_label = 1 (EMAIL found in reviewed types)                    │
│    • has_phone_label = 1 (PHONE found in reviewed types)                    │
│    • has_dob_label = 0 (DOB not in reviewed types)                          │
│    • has_address_label = 0                                                  │
│    • has_credit_card_label = 0                                              │
│    • has_name_label = 0                                                     │
│                                                                              │
│  Compare ML predictions vs reviewed types for feedback_type                 │
└───────────────────────────────────────┬─────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 pii_training_feedback (KV Store)                             │
│                                                                              │
│  Stored fields include:                                                      │
│    • pii_types_reviewed = "SSN,EMAIL,PHONE"                                 │
│    • has_ssn_label = 1                                                      │
│    • has_email_label = 1                                                    │
│    • has_phone_label = 1                                                    │
│    • feedback_type = "confirmed_pii_type_mismatch" (if ML missed PHONE)    │
└───────────────────────────────────────┬─────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Model Health Report (Weekly)                              │
│                                                                              │
│  Aggregates per-type labels to identify:                                    │
│    • Which PII types are most commonly confirmed                            │
│    • Which types have high false negative rates                             │
│    • Type-specific recall metrics                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

**Last Updated:** 2026-01-26
