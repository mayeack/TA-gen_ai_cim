# AI Governance Overview Dashboard

## Overview

The **AI Governance Overview** is the default landing page and primary dashboard for the TA-gen_ai_cim application. It provides a centralized, comprehensive view of GenAI usage, cost, performance, and risk across all monitored AI services.

## Design

Built using **Dashboard Studio (JSON)**, this dashboard leverages modern visualization capabilities with a tabbed layout for organized information presentation.

### Layout Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│  Global Inputs: Time Range | Service | Model                        │
├─────────────────────────────────────────────────────────────────────┤
│  Tab: Overview | TF-IDF Anomaly Detection | PII Detection           │
├─────────────────────────────────────────────────────────────────────┤
│                         Tab Content Area                            │
└─────────────────────────────────────────────────────────────────────┘
```

### Tabs

1. **Overview** - Main operational metrics and trends
2. **TF-IDF Anomaly Detection** - TF-IDF anomaly detection and risk analysis
3. **PII Detection** - ML-powered PII detection metrics

## Purpose

This dashboard enables AI governance teams to:

- **Monitor** real-time AI usage across all services and models
- **Track** costs using dynamic token pricing from KV Store lookups
- **Identify** safety violations, PII detections, and policy blocks
- **Analyze** performance trends including latency and token usage
- **Detect** anomalies using TF-IDF machine learning models
- **Review** recent AI requests with compliance status

## Key Visualizations

### KPI Section
| Visualization | Description |
|---------------|-------------|
| Total AI Requests | Count of all AI interactions |
| Unique Sessions | Distinct conversation sessions |
| Total Token Usage | Aggregate token consumption |
| Total Cost | Calculated cost using KV Store pricing |
| Avg Response Latency | Mean response time (color-coded) |

### Safety & Compliance Section
| Visualization | Description |
|---------------|-------------|
| Safety Violations | Count of safety policy violations |
| PII Detected | Events with PII identified |
| Policy Blocked | Requests blocked by policy |
| Guardrails Triggered | Guardrail activations |
| Compliance Summary | Safety/PII compliance percentages |

### Trend Analysis
| Visualization | Description |
|---------------|-------------|
| Request Volume Over Time | Timechart of AI requests |
| Token Usage Over Time | Token consumption trends |
| Latency Distribution | Histogram of response times |
| Response Latency Over Time | P50/P95 latency trends |
| Cost Over Time | Hourly cost tracking |

### TF-IDF Anomaly Detection
| Visualization | Description |
|---------------|-------------|
| Anomalous Prompts | Count of unusual user inputs |
| Anomalous Responses | Count of unusual AI outputs |
| High Risk Events | Combined anomaly events |
| Risk Level Distribution | Pie chart of risk levels |
| Top Anomaly Sources | Sources generating anomalies |

### PII ML Detection
| Visualization | Description |
|---------------|-------------|
| PII Detections | Total PII events detected |
| Critical Risk Events | High-severity PII (SSN, CC) |
| PII Detection Rate | Percentage of events with PII |
| PII by Category | Breakdown by PII type |
| Recent PII Detections | Table of recent events |

## File Location

```
default/data/ui/views/genai_governance_overview_studio.json
```

## Technical Details

- **Format**: Dashboard Studio JSON
- **Theme**: Dark
- **Data Sources**: 40+ SPL queries
- **Refresh**: Manual (with time picker)
- **Filters**: Time Range, Service, Model

## Color Coding

The dashboard uses consistent color coding:
- 🟢 **Green** (`#53A051`): Good/Safe/Normal
- 🟡 **Yellow** (`#F8BE34`): Warning/Medium
- 🔴 **Red** (`#DC4E41`): Critical/High Risk
- 🔵 **Blue** (`#5A9BD5`): Informational

## Related Files

- `macros.conf` - Search macros for cost calculations
- `transforms.conf` - KV Store lookup definitions
- `savedsearches.conf` - Underlying alert definitions
