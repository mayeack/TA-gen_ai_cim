# PII Feedback Loop - Model Registry

## Overview

The **PII Feedback Loop - Model Registry** dashboard provides a comprehensive view of PII detection model versions, performance history, and training data statistics. It serves as the central tracking system for model lifecycle management.

## Design

Built using **SimpleXML Form** with filtering capabilities for model status.

### Layout Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│  Filters: Status Filter (All/Champion/Challenger/Candidate/Retired)  │
├─────────────────────────────────────────────────────────────────────┤
│  Current Champion Stats                                              │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐│
│  │ Current      │ │ Champion     │ │ Champion     │ │ Total Model  ││
│  │ Champion     │ │ F1 Score     │ │ Recall       │ │ Versions     ││
│  │ Model Name   │ │              │ │              │ │              ││
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  Model Version History (sortable table)                              │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ Version | Status | Algorithm | Accuracy | Precision | Recall    ││
│  │ F1 | Threshold | Samples | Promoted | Promoted By | Notes       ││
│  └─────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  Performance Trends                                                  │
│  ┌─────────────────────────────┐ ┌─────────────────────────────────┐│
│  │ F1 Score Trend Over         │ │ Precision vs Recall Trade-off  ││
│  │ Model Versions              │ │ Over Versions                   ││
│  │ (line chart)                │ │ (line chart)                    ││
│  └─────────────────────────────┘ └─────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  Feedback Data Statistics                                            │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ Total | PII | Clean | PII% | Train | Valid | Test | Apps | etc. ││
│  └─────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  Feedback Quality                                                    │
│  ┌─────────────────────────────┐ ┌─────────────────────────────────┐│
│  │ Model Error Analysis        │ │ Feedback by Application         ││
│  │ (bar chart)                 │ │ (pie chart)                     ││
│  └─────────────────────────────┘ └─────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  Navigation: Model Comparison | Review Queue | Event Review          │
└─────────────────────────────────────────────────────────────────────┘
```

## Purpose

This dashboard enables ML operations teams to:

- **Track** all model versions and their performance
- **Monitor** the current production (champion) model
- **Analyze** performance trends over time
- **Review** training data quality and distribution
- **Audit** model promotion history

## Model Statuses

| Status | Icon | Description |
|--------|------|-------------|
| Champion | 🏆 | Current production model |
| Challenger | ⚔️ | Model under evaluation |
| Candidate | 📋 | Newly trained, not yet evaluated |
| Retired | 📦 | Previously used, now archived |

## Key Visualizations

### Current Champion Stats
- Model name and version
- F1 Score (color-coded by performance)
- Recall (color-coded by performance)
- Total model versions tracked

### Model Version History Table
| Column | Description |
|--------|-------------|
| Version | Model version identifier |
| Status | Current status with icon |
| Algorithm | ML algorithm used |
| Accuracy | Overall accuracy |
| Precision | Precision metric |
| Recall | Recall metric |
| F1 | F1 score (color-coded) |
| Threshold | Decision threshold |
| Samples | Training sample count |
| Promoted | Promotion date |
| Promoted By | User who promoted |
| Notes | Additional notes |

### Performance Trends
- **F1 Score Trend**: Line chart showing F1 improvement over versions
- **Precision vs Recall**: Trade-off visualization over versions

### Feedback Data Statistics
| Metric | Description |
|--------|-------------|
| Total | Total feedback samples |
| PII | Samples with PII |
| Clean | Samples without PII |
| PII % | Percentage of PII samples |
| Train/Valid/Test | Split distribution |
| Apps | Unique applications in feedback |
| Reviewers | Unique human reviewers |

## File Location

```
default/data/ui/views/pii_feedback_loop_model_registry.xml
```

## Technical Details

- **Format**: SimpleXML Form
- **Theme**: Dark
- **Filters**: Status filter dropdown

## Data Sources

| Lookup | Purpose |
|--------|---------|
| `pii_model_registry_lookup` | Model version history |
| `pii_training_feedback_lookup` | Human feedback data |

## KV Store Schema: Model Registry

| Field | Type | Description |
|-------|------|-------------|
| `_key` | string | Unique key |
| `model_name` | string | Model name |
| `model_version` | string | Version identifier |
| `status` | string | champion/challenger/candidate/retired |
| `algorithm` | string | ML algorithm |
| `accuracy` | number | Accuracy metric |
| `precision` | number | Precision metric |
| `recall` | number | Recall metric |
| `f1_score` | number | F1 score |
| `threshold` | number | Decision threshold |
| `training_samples` | number | Sample count |
| `created_at` | number | Unix timestamp |
| `promoted_at` | number | Promotion timestamp |
| `promoted_by` | string | Promoting user |
| `notes` | string | Additional notes |

## Related Files

- `collections.conf` - KV Store definitions
- `transforms.conf` - Lookup definitions
- `pii_feedback_loop_model_comparison.xml` - Comparison view
- `savedsearches.conf` - Training and scoring searches
