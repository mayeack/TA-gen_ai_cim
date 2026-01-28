# PII Feedback Loop - Model Comparison

## Overview

The **PII Feedback Loop - Model Comparison** dashboard enables data scientists and ML engineers to compare champion and challenger PII detection models. It provides detailed performance metrics, threshold analysis, and model promotion capabilities.

## Design

Built using **SimpleXML Form** with custom JavaScript (`pii_feedback_loop_promote.js`) for model promotion functionality.

### Layout Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│  Filters: Feedback Time Range                                        │
├─────────────────────────────────────────────────────────────────────┤
│  Summary Stats Row                                                   │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌──────────┐│
│  │Total Feedback │ │ Training Set  │ │Validation Set │ │ Test Set ││
│  │   Samples     │ │               │ │               │ │          ││
│  └───────────────┘ └───────────────┘ └───────────────┘ └──────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  Champion vs Challenger Comparison                                   │
│  ┌─────────────────────────────────┐ ┌─────────────────────────────┐│
│  │ Test Set Performance Table      │ │ Recommendation              ││
│  │ Metric|Champion|Challenger|Delta│ │ PROMOTE / KEEP              ││
│  └─────────────────────────────────┘ └─────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  Threshold Analysis - Challenger Model on Validation Set             │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ Threshold | Precision | Recall | F1                              ││
│  │ 0.3, 0.4, 0.5, 0.6, 0.7, 0.8 variations                         ││
│  └─────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  Feedback Distribution                                               │
│  ┌─────────────────────────────┐ ┌─────────────────────────────────┐│
│  │ Feedback Type Distribution  │ │ Feedback Over Time              ││
│  │ (pie chart)                 │ │ (stacked area chart)            ││
│  └─────────────────────────────┘ └─────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  Model Promotion                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ [Promote Challenger to Champion Button]                          ││
│  └─────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  Navigation: Model Registry | Review Queue                           │
└─────────────────────────────────────────────────────────────────────┘
```

## Purpose

This dashboard enables ML teams to:

- **Compare** champion vs challenger model performance
- **Analyze** precision, recall, F1, and accuracy metrics
- **Tune** decision thresholds for optimal performance
- **Monitor** feedback data quality and distribution
- **Promote** better-performing models to production

## Key Metrics

### Performance Comparison Table

| Metric | Description |
|--------|-------------|
| Accuracy | Overall correct predictions |
| Precision | True positives / (True positives + False positives) |
| Recall | True positives / (True positives + False negatives) |
| F1 Score | Harmonic mean of precision and recall |
| Delta | Challenger - Champion difference |

### Recommendation Logic

The dashboard provides an automatic recommendation:
- **PROMOTE**: If challenger F1 > champion F1 AND challenger recall >= champion recall
- **KEEP**: Otherwise

### Threshold Analysis

Evaluates challenger model at multiple thresholds (0.3, 0.4, 0.5, 0.6, 0.7, 0.8) to identify optimal decision boundary.

## Feedback Types

| Type | Description | Label |
|------|-------------|-------|
| confirmed_pii | Reviewer confirmed PII present | True Positive |
| confirmed_clean | Reviewer confirmed no PII | True Negative |
| false_positive | Model flagged, reviewer found clean | False Positive |
| false_negative | Model missed, reviewer found PII | False Negative |

## Model Promotion

Clicking "Promote Challenger to Champion":
1. Saves challenger model as new champion
2. Retires previous champion
3. Registers in model registry
4. Updates production model reference

## File Location

```
default/data/ui/views/pii_feedback_loop_model_comparison.xml
```

## Technical Details

- **Format**: SimpleXML Form
- **Theme**: Dark
- **Scripts**: `pii_feedback_loop_promote.js`
- **MLTK Models**: `pii_detection_model`, `pii_detection_model_challenger`

## Data Sources

| Lookup | Purpose |
|--------|---------|
| `pii_training_feedback_lookup` | Human feedback from reviews |
| `pii_model_registry_lookup` | Model version history |

## Related Files

- `appserver/static/pii_feedback_loop_promote.js` - Promotion logic
- `pii_feedback_loop_model_registry.xml` - Model registry view
- `savedsearches.conf` - Training searches
