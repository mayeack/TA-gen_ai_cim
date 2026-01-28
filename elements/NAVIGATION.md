# Navigation Menu

## Overview

The navigation menu provides the primary interface for accessing all dashboards and pages within the TA-gen_ai_cim application. It is configured in `default/data/ui/nav/default.xml`.

## Design

The navigation uses Splunk's standard `<nav>` structure with a dark color theme (`#3C444D`) to match the app's visual identity.

### Menu Structure

```
├── Search (external link to Splunk search)
├── AI Governance Overview (default landing page)
├── Governance Review (collection)
│   ├── Review Queue
│   └── Event Review
├── ML Feedback Loop (collection)
│   ├── PII Feedback Loop - Model Comparison
│   └── PII Feedback Loop - Model Registry
├── Configuration
├── Datasets (built-in)
├── Reports (built-in)
└── Alerts (built-in)
```

## Purpose

The navigation organizes the app's functionality into logical groups:

1. **Search**: Quick access to search the `gen_ai_log` index
2. **AI Governance Overview**: Central dashboard for monitoring all AI activity
3. **Governance Review**: Human review workflow for flagged AI events
4. **ML Feedback Loop**: Model management and continuous improvement
5. **Configuration**: Administrative settings and integrations
6. **Datasets/Reports/Alerts**: Standard Splunk knowledge objects

## File Location

```
default/data/ui/nav/default.xml
```

## Configuration

| Attribute | Value | Description |
|-----------|-------|-------------|
| `search_view` | `search` | Default search view |
| `color` | `#3C444D` | Navigation bar background color |
| `default` | `genai_governance_overview_studio` | Default landing page |

## Related Files

- All view XML/JSON files in `default/data/ui/views/`
- `app.conf` for app-level settings
