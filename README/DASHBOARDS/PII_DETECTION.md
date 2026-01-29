# PII Detection Dashboard

## Overview

The **PII Detection** dashboard provides ML-powered detection and monitoring of Personally Identifiable Information (PII) in AI responses. It enables governance teams to track PII exposure, identify high-risk events, and investigate detections.

## Purpose

This dashboard enables AI governance teams to:

- **Monitor** PII detection rates across applications and models
- **Identify** critical PII types (SSN, credit cards, medical records)
- **Analyze** PII exposure trends over time
- **Investigate** individual detections with drilldown to source events

## File Location

```
default/data/ui/views/pii_detection.xml
```

## Design

Built using **Dashboard Studio (JSON)** embedded in SimpleXML, providing modern visualizations with dark theme.

## Global Inputs

| Input | Description | Default |
|-------|-------------|---------|
| **Time Range** | Filter data by time period | Last 24 hours |
| **App Name** | Filter by AI application/service | All Apps |
| **Model** | Filter by AI model | All Models |

## Panels

### KPI Summary Row

| Panel | Description | Color Coding |
|-------|-------------|--------------|
| **PII Detections** | Total count of PII events | Green (0), Yellow (1-9), Red (10+) |
| **Total Events** | Total events scanned | Green (informational) |
| **PII Detection Rate** | Percentage of events with PII | Green (<5%), Yellow (5-15%), Red (>15%) |
| **Review Queue** | Link to governance review queue | Clickable link |

### Visualizations

| Panel | Type | Description |
|-------|------|-------------|
| **PII Detection Trend** | Line chart | PII detections vs total events over time |
| **PII by Category** | Horizontal bar chart | Breakdown by PII type (SSN, EMAIL, PHONE, etc.) |
| **Risk Level Distribution** | Pie/Donut chart | CRITICAL, HIGH, MEDIUM, NONE breakdown |
| **Detections by Service** | Table | PII count, total requests, and rate by service |
| **Recent PII Detections** | Table | Latest detections with drilldown |

## Risk Level Classification

| Risk Level | Condition | Color |
|------------|-----------|-------|
| **CRITICAL** | Risk score >= 0.8 OR SSN/Credit Card detected | Dark Red (`#9C1C1C`) |
| **HIGH** | Risk score >= 0.6 | Red (`#DC4E41`) |
| **MEDIUM** | Risk score >= 0.3 | Yellow (`#F8BE34`) |
| **NONE** | Risk score < 0.3 | Green (`#53A051`) |

## PII Types Detected

| Category | Examples |
|----------|----------|
| **SSN** | Social Security Numbers |
| **EMAIL** | Email addresses |
| **PHONE** | Phone numbers |
| **DOB** | Dates of birth |
| **ADDRESS** | Physical addresses |
| **CREDIT_CARD** | Credit card numbers |
| **NAME** | Personal names |
| **MRN** | Medical Record Numbers |
| **MEMBER_ID** | Insurance member IDs |

## Output Fields

| Field | Type | Description |
|-------|------|-------------|
| `gen_ai.pii.detected` | string | "true" if any PII detected |
| `gen_ai.pii.ml_detected` | string | "true" if ML model detected PII |
| `gen_ai.pii.risk_score` | float | ML probability score (0-1) |
| `gen_ai.pii.types` | string | Comma-separated PII types |
| `gen_ai.pii.confidence` | string | very_high, high, medium, low, very_low |
| `gen_ai.pii.severity` | string | critical, high, medium, low |

## Drilldown Behavior

Clicking any row in the **Recent PII Detections** table opens a search for the full event:

```
index=gen_ai_log source=pii_ml_scoring gen_ai.request.id="<REQUEST_ID>"
```

## Related Alerts

| Alert | Trigger |
|-------|---------|
| GenAI - PII Detection Alert | Any PII detected |
| GenAI - PII High Volume Alert | PII rate exceeds threshold |
| GenAI - MLTK PII Risk Score Alert | High ML-based PII risk |
| GenAI - PII ML Critical SSN or Credit Card Alert | Critical PII types detected |

## Related Documentation

- [PII/PHI Detection ML Model](../ML%20Models/PII_Detection.md) - Complete training and scoring documentation
- [AI Governance Overview Dashboard](AI_GOVERNANCE_OVERVIEW.md) - Main dashboard documentation
- [Review Queue Dashboard](REVIEW_QUEUE.md) - Human review workflow

---

**Last Updated:** 2026-01-28
