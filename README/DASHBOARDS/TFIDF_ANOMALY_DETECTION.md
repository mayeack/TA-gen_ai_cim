# TF-IDF Anomaly Detection Dashboard

## Overview

The **TF-IDF Anomaly Detection** tab (within the AI Governance Overview dashboard) provides ML-based detection of anomalous prompts and responses in GenAI telemetry. It uses unsupervised learning to identify unusual patterns that may indicate jailbreak attempts, misuse, hallucinations, or quality issues.

## Purpose

This dashboard enables AI governance teams to:

- **Detect** unusual user prompts that deviate from normal patterns (potential attacks, misuse)
- **Identify** unusual AI responses that may indicate hallucinations or errors
- **Monitor** combined risk levels across both prompts and responses
- **Investigate** sources generating repeated anomalies

## File Location

This is a tab within the main AI Governance Overview dashboard:

```
default/data/ui/views/genai_governance_overview_studio.json
```

## Panels

### KPI Summary

| Panel | Description | Color Coding |
|-------|-------------|--------------|
| **Anomalous Prompts** | Count of unusual user inputs | Green (0), Yellow (1-9), Red (10+) |
| **Anomalous Responses** | Count of unusual AI outputs | Green (0), Yellow (1-9), Red (10+) |
| **High Risk Events** | Combined prompt AND response anomalies | Green (0), Red (1+) |

### Visualizations

| Panel | Type | Description |
|-------|------|-------------|
| **Risk Level Distribution** | Pie/Donut chart | Breakdown by HIGH, MEDIUM, LOW, NONE |
| **Anomaly Trend Over Time** | Line chart | Anomalous prompts/responses over time |
| **Top Anomaly Sources** | Table | Client addresses with most anomalies |
| **Recent Anomalies** | Table | Latest detected anomalies with details |

## Risk Level Classification

| Risk Level | Condition | Color |
|------------|-----------|-------|
| **HIGH** | Both prompt AND response are anomalous | Red (`#DC4E41`) |
| **MEDIUM** | Only prompt is anomalous | Yellow (`#F8BE34`) |
| **LOW** | Only response is anomalous | Blue (`#6AB7C7`) |
| **NONE** | Neither is anomalous | Green (`#53A051`) |

## Output Fields

The TF-IDF anomaly detection scoring produces these fields:

| Field | Type | Description |
|-------|------|-------------|
| `gen_ai.prompt.anomaly_score` | float | Raw score from OneClassSVM (negative = anomaly) |
| `gen_ai.prompt.is_anomaly` | string | "true" if prompt is anomalous |
| `gen_ai.response.anomaly_score` | float | Raw score for responses |
| `gen_ai.response.is_anomaly` | string | "true" if response is anomalous |
| `gen_ai.tfidf.combined_anomaly` | string | "both", "prompt_only", "response_only", "normal" |
| `gen_ai.tfidf.risk_level` | string | "HIGH", "MEDIUM", "LOW", "NONE" |

## How It Works

1. **Vectorization**: HashingVectorizer converts text to TF-IDF feature vectors
2. **Dimensionality Reduction**: PCA reduces features to 50 principal components
3. **Anomaly Detection**: OneClassSVM learns the boundary of "normal" text
4. **Classification**: New messages outside the boundary are flagged as anomalies

## Prerequisites

- **Splunk MLTK** (Machine Learning Toolkit) 5.3+
- **Python for Scientific Computing** add-on
- Trained models: `app:tfidf_prompt_pca`, `app:prompt_anomaly_model`, `app:tfidf_response_pca`, `app:response_anomaly_model`

## Related Alerts

| Alert | Trigger |
|-------|---------|
| GenAI - TFIDF Anomalous Prompt Alert | 3+ anomalous prompts in 15 min |
| GenAI - TFIDF Anomalous Response Alert | 2+ anomalous responses in 15 min |
| GenAI - TFIDF High Risk Combined Anomaly Alert | Any HIGH risk event |
| GenAI - TFIDF Anomaly by Source IP Alert | 5+ anomalies from one IP |
| GenAI - TFIDF Anomaly Rate Threshold Alert | >10% anomaly rate |

## Related Documentation

- [TF-IDF Anomaly Detection ML Model](../ML%20Models/TFIDF_Anomaly.md) - Complete training and scoring documentation
- [AI Governance Overview Dashboard](AI_GOVERNANCE_OVERVIEW.md) - Main dashboard documentation

---

**Last Updated:** 2026-01-28
