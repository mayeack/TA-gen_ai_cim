# AI Governance Overview Dashboard

## Overview

The **AI Governance Overview** is the default landing page and primary dashboard for the TA-gen_ai_cim application. It provides a centralized, comprehensive view of GenAI usage, cost, performance, and risk across all monitored AI services.

## File Location

```
default/data/ui/views/genai_governance_overview_studio.json
```

## Design

Built using **Dashboard Studio (JSON)**, this dashboard leverages modern visualization capabilities with a tabbed layout for organized information presentation.

### Layout Structure

```
+---------------------------------------------------------------------+
|  Global Inputs: Time Range | App Name | Model                       |
+---------------------------------------------------------------------+
|  Tab: Overview | TF-IDF Anomaly Detection | PII Detection           |
+---------------------------------------------------------------------+
|                         Tab Content Area                            |
+---------------------------------------------------------------------+
```

### Tabs

| Tab | Description |
|-----|-------------|
| **Overview** | Main operational metrics, safety/compliance KPIs, and trend analysis |
| **TF-IDF Anomaly Detection** | ML-based anomaly detection for prompts and responses |
| **PII Detection** | ML-powered PII detection metrics and recent detections |

## Global Inputs

| Input | Description | Default |
|-------|-------------|---------|
| **Time Range** | Filter data by time period | Last 24 hours |
| **App Name** | Filter by AI application/service | All Apps |
| **Model** | Filter by AI model | All Models |

## Overview Tab Panels

### Key Performance Indicators (KPIs)

| Panel | Description | Color Coding |
|-------|-------------|--------------|
| **Total AI Requests** | Count of all AI interactions | - |
| **Unique Sessions** | Distinct conversation sessions | - |
| **Total Token Usage** | Aggregate token consumption | - |
| **Total Cost** | Calculated cost using KV Store pricing | - |
| **Avg Response Latency** | Mean response time in milliseconds | Green (<2s), Yellow (2-5s), Red (>5s) |

### Safety and Compliance

| Panel | Description | Color Coding |
|-------|-------------|--------------|
| **Safety Violations** | Count of safety policy violations | Green (0), Yellow (1-4), Red (5+) |
| **PII Detected** | Events with PII identified | Green (0), Yellow (1-9), Red (10+) |
| **Policy Blocked** | Requests blocked by policy | Green (0), Yellow (1-4), Red (5+) |
| **Guardrails Triggered** | Guardrail activations | Green (0), Yellow (1-4), Red (5+) |
| **Compliance Summary** | Safety/PII compliance percentages | Red (<85%), Yellow (85-95%), Green (>95%) |

### Trend Analysis

| Panel | Visualization | Time Span |
|-------|---------------|-----------|
| **Request Volume Over Time** | Line chart | Selected time range |
| **Token Usage Over Time** | Area chart | Selected time range |
| **Cost Over Time** | Area chart | Selected time range |
| **Response Latency Over Time** | Line chart (P50/P95) | Selected time range |
| **Latency Distribution** | Histogram | Selected time range |

### Additional Visualizations

| Panel | Type | Description |
|-------|------|-------------|
| **Cost by Service** | Pie/Donut chart | Cost breakdown by application |
| **ML Detection Summary** | Bar chart | Detection counts by type |
| **Recent AI Requests** | Table | Latest requests with compliance status |

## Technical Details

| Property | Value |
|----------|-------|
| **Format** | Dashboard Studio JSON |
| **Theme** | Dark |
| **Data Sources** | 40+ SPL queries |
| **Refresh** | Manual (with time picker) |

## Color Coding Convention

The dashboard uses consistent color coding throughout:

| Color | Hex Code | Meaning |
|-------|----------|---------|
| Green | `#53A051` | Good / Safe / Normal |
| Yellow | `#F8BE34` | Warning / Medium |
| Red | `#DC4E41` | Critical / High Risk |
| Blue | `#5A9BD5` | Informational |

## Related Documentation

- [TF-IDF Anomaly Detection Dashboard](TFIDF_ANOMALY_DETECTION.md)
- [PII Detection Dashboard](PII_DETECTION.md)
- [ML Models Overview](../ML%20Models/README.md)

## Related Files

| File | Purpose |
|------|---------|
| `macros.conf` | Search macros for cost calculations |
| `transforms.conf` | KV Store lookup definitions |
| `savedsearches.conf` | Underlying alert definitions |

---

**Last Updated:** 2026-01-28
