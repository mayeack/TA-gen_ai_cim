# Navigation Menu

## Overview

The navigation menu provides the primary interface for accessing all dashboards and pages within the TA-gen_ai_cim application. It is configured in `default/data/ui/nav/default.xml`.

## Design

The navigation uses Splunk's standard `<nav>` structure with a dark color theme (`#3C444D`) to match the app's visual identity.

### Menu Structure

```
├── Search (external link to Splunk search)
├── Dashboards (collection)
│   ├── AI Governance Overview (default landing page)
│   ├── Tokenomics
│   ├── AI Asset Discovery
│   ├── PII Detection
│   └── Prompt Injection Detection
├── Configuration
├── GenAI Scoring
├── Datasets (built-in)
├── Reports (built-in)
└── Alerts (built-in)
```

Two collections are currently commented out in the nav (views still ship,
reachable by URL): **Governance Review** (Review Queue, Event Review) and
**ML Feedback Loop** (PII / TF-IDF Model Comparison and Registry), plus the
TF-IDF Anomaly Detection entry (`governance_safety`). `review_landing` and
`servicenow_case` are intentionally nav-less — they are reached via
Event Context workflow actions.

## Purpose

The navigation organizes the app's functionality into logical groups:

1. **Search**: Quick access to search the `gen_ai_log` index
2. **Dashboards**: Central monitoring for AI activity, cost, assets, and detections
3. **Configuration / GenAI Scoring**: Administrative settings and integrations
4. **Datasets/Reports/Alerts**: Standard Splunk knowledge objects

## File Location

```
default/data/ui/nav/default.xml
```

## Configuration

| Attribute | Value | Description |
|-----------|-------|-------------|
| `search_view` | `search` | Default search view |
| `color` | `#3C444D` | Navigation bar background color |
| `default` | `ai_governance_overview` | Default landing page |

## Related Files

- All view XML/JSON files in `default/data/ui/views/`
- `app.conf` for app-level settings
