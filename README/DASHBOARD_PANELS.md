# GenAI Governance Dashboard Panels

This document provides ready-to-use dashboard definitions for AI governance monitoring in **both Dashboard Studio (JSON)** and **Classic Dashboard (XML)** formats.

**Dashboard Studio** is recommended for Splunk 9.0+ users, offering a modern, responsive interface with advanced visualization options.

**Classic Dashboards** are provided for backward compatibility or environments using Splunk < 9.0.

## Table of Contents

1. [Governance KPIs](#governance-kpis)
2. [Safety Events Timeline](#safety-events-timeline)
3. [PII Detection Dashboard](#pii-detection-dashboard)
4. [Model Drift Monitoring](#model-drift-monitoring)
5. [Cost and Performance](#cost-and-performance)
6. [Latency Analysis](#latency-analysis)
7. [MLTK Risk Scores](#mltk-risk-scores)
8. [Complete Dashboard Definitions](#complete-dashboard-definitions)
   - [Dashboard Studio JSON](#dashboard-studio-version-json) (Recommended)
   - [Classic Dashboard XML](#classic-dashboard-xml-legacy-format)

---

## Governance KPIs

### Panel: Safety Violation Rate

**SPL:**
```spl
index=gen_ai_log
    (gen_ai.safety.violated="true" OR gen_ai.safety.violated="false")
| stats count as total_requests,
    sum(eval(if('gen_ai.safety.violated'="true", 1, 0))) as safety_violations
| eval violation_rate=round((safety_violations/total_requests)*100, 2)
| fields violation_rate
```

**Visualization:** Single Value
**Time Range:** Last 24 hours

---

### Panel: PII Hit Rate by App

**SPL:**
```spl
index=gen_ai_log
| stats count as total_events,
    sum(eval(if('gen_ai.pii.detected'="true", 1, 0))) as pii_events
    by gen_ai.app.name
| eval pii_rate=round((pii_events/total_events)*100, 2)
| sort -pii_rate
| head 10
```

**Visualization:** Bar Chart
**Time Range:** Last 7 days

---

### Panel: Token Usage and Cost per Request

**SPL:**
```spl
index=gen_ai_log
    gen_ai.usage.total_tokens>0
| stats sum(gen_ai.usage.total_tokens) as total_tokens,
    sum(gen_ai.cost.total) as total_cost,
    count as request_count
    by gen_ai.request.model
| eval avg_tokens_per_request=round(total_tokens/request_count, 0)
| eval cost_per_request=round(total_cost/request_count, 4)
| eval cost_per_1k_tokens=round((total_cost/(total_tokens/1000)), 4)
| table gen_ai.request.model, request_count, total_tokens, avg_tokens_per_request, total_cost, cost_per_request, cost_per_1k_tokens
| sort -total_cost
```

**Visualization:** Table
**Time Range:** Last 30 days

---

### Panel: Guardrail Trigger Frequency

**SPL:**
```spl
index=gen_ai_log
    gen_ai.guardrail.triggered="true"
| stats count as trigger_count
    by gen_ai.guardrail.ids
| sort -trigger_count
| head 20
```

**Visualization:** Pie Chart
**Time Range:** Last 24 hours

---

## Safety Events Timeline

### Panel: Safety Violations Over Time

**SPL:**
```spl
index=gen_ai_log
    gen_ai.safety.violated="true"
| eval severity=case(
    like('gen_ai.safety.categories', "%EMERGENCY%"), "CRITICAL",
    like('gen_ai.safety.categories', "%HIGH%"), "HIGH",
    like('gen_ai.safety.categories', "%MEDIUM%"), "MEDIUM",
    1=1, "LOW"
)
| timechart span=1h count by severity
```

**Visualization:** Area Chart (stacked)
**Time Range:** Last 7 days
**Color Scheme:** CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=green

---

### Panel: Safety Categories Breakdown

**SPL:**
```spl
index=gen_ai_log
    gen_ai.safety.violated="true"
| mvexpand gen_ai.safety.categories
| stats count as occurrences by gen_ai.safety.categories
| sort -occurrences
| head 15
```

**Visualization:** Bar Chart (horizontal)
**Time Range:** Last 7 days

---

### Panel: Safety Events by Deployment

**SPL:**
```spl
index=gen_ai_log
    gen_ai.safety.violated="true"
| stats count as violations,
    dc(gen_ai.session.id) as affected_sessions,
    values(gen_ai.safety.categories) as categories
    by gen_ai.deployment.id, gen_ai.app.name
| sort -violations
```

**Visualization:** Table
**Time Range:** Last 24 hours

---

## PII Detection Dashboard

### Panel: PII Detection Events Over Time

**SPL:**
```spl
index=gen_ai_log
    gen_ai.pii.detected="true"
| timechart span=1h count as pii_detections
```

**Visualization:** Line Chart
**Time Range:** Last 7 days

---

### Panel: PII Types by Volume

**SPL:**
```spl
index=gen_ai_log
    gen_ai.pii.detected="true"
| mvexpand gen_ai.pii.types
| stats count as detections,
    dc(gen_ai.session.id) as unique_sessions
    by gen_ai.pii.types
| sort -detections
```

**Visualization:** Column Chart
**Time Range:** Last 7 days

---

### Panel: PII Detection Rate by Model

**SPL:**
```spl
index=gen_ai_log
| stats count as total_requests,
    sum(eval(if('gen_ai.pii.detected'="true", 1, 0))) as pii_events
    by gen_ai.request.model
| eval pii_rate=round((pii_events/total_requests)*100, 2)
| where pii_rate > 0
| sort -pii_rate
```

**Visualization:** Table
**Time Range:** Last 30 days

---

### Panel: MLTK PII Risk Score Distribution

**SPL:**
```spl
index=gen_ai_log
    gen_ai.pii.risk_score>0
| eval risk_bucket=case(
    'gen_ai.pii.risk_score'>=0.8, "High (0.8-1.0)",
    'gen_ai.pii.risk_score'>=0.6, "Medium (0.6-0.8)",
    'gen_ai.pii.risk_score'>=0.4, "Low (0.4-0.6)",
    1=1, "Very Low (0-0.4)"
)
| stats count by risk_bucket
| sort -count
```

**Visualization:** Pie Chart
**Time Range:** Last 24 hours

---

## Model Drift Monitoring

### Panel: Drift Status by Deployment

**SPL:**
```spl
index=gen_ai_log
    gen_ai.drift.status=*
| stats count by gen_ai.drift.status, gen_ai.deployment.id
| sort gen_ai.deployment.id, gen_ai.drift.status
```

**Visualization:** Table with color-coded status
**Time Range:** Last 24 hours

---

### Panel: Drift Metric Trend Over Time

**SPL:**
```spl
index=gen_ai_log
    gen_ai.drift.metric.value=*
| timechart span=1h avg(gen_ai.drift.metric.value) as avg_drift_value
    by gen_ai.request.model
```

**Visualization:** Line Chart (multi-series)
**Time Range:** Last 7 days

---

### Panel: Critical Drift Alerts

**SPL:**
```spl
index=gen_ai_log
    gen_ai.drift.status="critical"
| stats latest(_time) as last_alert,
    count as critical_count,
    avg(gen_ai.drift.metric.value) as avg_drift_value,
    values(gen_ai.drift.metric.name) as drift_metrics
    by gen_ai.request.model, gen_ai.deployment.id
| eval last_alert=strftime(last_alert, "%Y-%m-%d %H:%M:%S")
| sort -critical_count
```

**Visualization:** Table (with red highlighting)
**Time Range:** Last 7 days

---

## Cost and Performance

### Panel: Daily Cost Trend by Model

**SPL:**
```spl
index=gen_ai_log
    gen_ai.cost.total>0
| bucket _time span=1d
| stats sum(gen_ai.cost.total) as daily_cost
    by _time, gen_ai.request.model
| timechart span=1d sum(daily_cost) as total_cost by gen_ai.request.model
```

**Visualization:** Area Chart (stacked)
**Time Range:** Last 30 days

---

### Panel: Cost per Deployment

**SPL:**
```spl
index=gen_ai_log
    gen_ai.cost.total>0
| stats sum(gen_ai.cost.total) as total_cost,
    sum(gen_ai.usage.total_tokens) as total_tokens,
    count as request_count
    by gen_ai.deployment.id
| eval cost_per_request=round(total_cost/request_count, 4)
| eval cost_per_1M_tokens=round((total_cost/(total_tokens/1000000)), 2)
| table gen_ai.deployment.id, request_count, total_tokens, total_cost, cost_per_request, cost_per_1M_tokens
| sort -total_cost
```

**Visualization:** Table
**Time Range:** Last 30 days

---

### Panel: Top 10 Most Expensive Sessions

**SPL:**
```spl
index=gen_ai_log
    gen_ai.cost.total>0
| stats sum(gen_ai.cost.total) as session_cost,
    sum(gen_ai.usage.total_tokens) as session_tokens,
    count as turns,
    values(gen_ai.request.model) as models
    by gen_ai.session.id, gen_ai.app.name
| sort -session_cost
| head 10
| eval session_cost=round(session_cost, 4)
```

**Visualization:** Table
**Time Range:** Last 7 days

---

## Latency Analysis

### Panel: Latency Distribution by Model

**SPL:**
```spl
index=gen_ai_log
    gen_ai.client.operation.duration>0
| stats avg(gen_ai.client.operation.duration) as avg_latency,
    perc50(gen_ai.client.operation.duration) as p50,
    perc95(gen_ai.client.operation.duration) as p95,
    perc99(gen_ai.client.operation.duration) as p99,
    max(gen_ai.client.operation.duration) as max_latency
    by gen_ai.request.model
| eval avg_latency=round(avg_latency, 2)
| eval p50=round(p50, 2)
| eval p95=round(p95, 2)
| eval p99=round(p99, 2)
| eval max_latency=round(max_latency, 2)
| sort -p95
```

**Visualization:** Table
**Time Range:** Last 24 hours

---

### Panel: Latency Trend Over Time

**SPL:**
```spl
index=gen_ai_log
    gen_ai.client.operation.duration>0
| timechart span=10m
    avg(gen_ai.client.operation.duration) as avg_latency,
    perc95(gen_ai.client.operation.duration) as p95_latency
    by gen_ai.request.model
```

**Visualization:** Line Chart (multi-series)
**Time Range:** Last 24 hours

---

### Panel: Latency vs Token Count Scatter

**SPL:**
```spl
index=gen_ai_log
    gen_ai.client.operation.duration>0 gen_ai.usage.total_tokens>0
| table gen_ai.usage.total_tokens, gen_ai.client.operation.duration, gen_ai.request.model
| head 1000
```

**Visualization:** Scatter Plot
**X-axis:** gen_ai.usage.total_tokens
**Y-axis:** gen_ai.client.operation.duration
**Time Range:** Last 24 hours

---

## MLTK Risk Scores

### Panel: Prompt Injection Risk Over Time

**SPL:**
```spl
index=gen_ai_log
    gen_ai.prompt_injection.risk_score>0.5
| timechart span=1h count as high_risk_events,
    avg(gen_ai.prompt_injection.risk_score) as avg_risk_score
```

**Visualization:** Combination Chart (column + line)
**Time Range:** Last 7 days

---

### Panel: Prompt Injection Techniques Detected

**SPL:**
```spl
index=gen_ai_log
    gen_ai.prompt_injection.ml_detected="true"
| stats count as detections,
    dc(gen_ai.session.id) as unique_sessions,
    dc(client.address) as unique_sources
    by gen_ai.prompt_injection.technique
| sort -detections
```

**Visualization:** Table
**Time Range:** Last 7 days

---

### Panel: Combined Risk Heatmap (PII vs Prompt Injection)

**SPL:**
```spl
index=gen_ai_log
    (gen_ai.pii.risk_score>0 OR gen_ai.prompt_injection.risk_score>0)
| eval pii_risk_bucket=case(
    'gen_ai.pii.risk_score'>=0.7, "High",
    'gen_ai.pii.risk_score'>=0.4, "Medium",
    'gen_ai.pii.risk_score'>0, "Low",
    1=1, "None"
)
| eval injection_risk_bucket=case(
    'gen_ai.prompt_injection.risk_score'>=0.7, "High",
    'gen_ai.prompt_injection.risk_score'>=0.4, "Medium",
    'gen_ai.prompt_injection.risk_score'>0, "Low",
    1=1, "None"
)
| stats count by pii_risk_bucket, injection_risk_bucket
```

**Visualization:** Heatmap or Pivot Table
**Time Range:** Last 24 hours

---

## Complete Dashboard Definitions

Both Dashboard Studio (JSON) and Classic Dashboard (XML) formats are provided below.

### Classic Dashboard XML (Legacy Format)

For backward compatibility or Splunk versions < 9.0:

```xml
<dashboard version="1.1" theme="dark">
  <label>GenAI Governance Overview</label>
  <description>Comprehensive AI governance monitoring dashboard</description>
  
  <row>
    <panel>
      <title>Safety Violation Rate (24h)</title>
      <single>
        <search>
          <query>
index=gen_ai_log
    (gen_ai.safety.violated="true" OR gen_ai.safety.violated="false")
| stats count as total_requests,
    sum(eval(if('gen_ai.safety.violated'="true", 1, 0))) as safety_violations
| eval violation_rate=round((safety_violations/total_requests)*100, 2)
| fields violation_rate
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="numberPrecision">0.00</option>
        <option name="unit">%</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[1,5]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    
    <panel>
      <title>PII Detection Rate (24h)</title>
      <single>
        <search>
          <query>
index=gen_ai_log
| stats count as total_requests,
    sum(eval(if('gen_ai.pii.detected'="true", 1, 0))) as pii_events
| eval pii_rate=round((pii_events/total_requests)*100, 2)
| fields pii_rate
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="numberPrecision">0.00</option>
        <option name="unit">%</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[2,10]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    
    <panel>
      <title>Total Cost (30d)</title>
      <single>
        <search>
          <query>
index=gen_ai_log
    gen_ai.cost.total>0
| stats sum(gen_ai.cost.total) as total_cost
| eval total_cost=round(total_cost, 2)
          </query>
          <earliest>-30d@d</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="numberPrecision">0.00</option>
        <option name="unit">$</option>
      </single>
    </panel>
    
    <panel>
      <title>Avg Latency P95 (24h)</title>
      <single>
        <search>
          <query>
index=gen_ai_log
    gen_ai.client.operation.duration>0
| stats perc95(gen_ai.client.operation.duration) as p95_latency
| eval p95_latency=round(p95_latency, 2)
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="numberPrecision">0.00</option>
        <option name="unit">s</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[5,10]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Safety Violations Over Time</title>
      <chart>
        <search>
          <query>
index=gen_ai_log
    gen_ai.safety.violated="true"
| eval severity=case(
    like('gen_ai.safety.categories', "%EMERGENCY%"), "CRITICAL",
    like('gen_ai.safety.categories', "%HIGH%"), "HIGH",
    like('gen_ai.safety.categories', "%MEDIUM%"), "MEDIUM",
    1=1, "LOW"
)
| timechart span=1h count by severity
          </query>
          <earliest>-7d@d</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.axisTitleX.text">Time</option>
        <option name="charting.axisTitleY.text">Violations</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>
    
    <panel>
      <title>PII Detection Events Over Time</title>
      <chart>
        <search>
          <query>
index=gen_ai_log
    gen_ai.pii.detected="true"
| timechart span=1h count as pii_detections
          </query>
          <earliest>-7d@d</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">line</option>
        <option name="charting.axisTitleX.text">Time</option>
        <option name="charting.axisTitleY.text">PII Detections</option>
      </chart>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Model Drift Status</title>
      <table>
        <search>
          <query>
index=gen_ai_log
    gen_ai.drift.status=*
| stats latest(gen_ai.drift.status) as drift_status,
    latest(gen_ai.drift.metric.value) as drift_value,
    latest(_time) as last_update
    by gen_ai.request.model, gen_ai.deployment.id
| eval last_update=strftime(last_update, "%Y-%m-%d %H:%M:%S")
| eval drift_value=round(drift_value, 3)
| sort drift_status
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="count">10</option>
        <format type="color" field="drift_status">
          <colorPalette type="map">{"stable":"#53A051","warning":"#F8BE34","critical":"#DC4E41"}</colorPalette>
        </format>
      </table>
    </panel>
    
    <panel>
      <title>Prompt Injection Risk (MLTK)</title>
      <chart>
        <search>
          <query>
index=gen_ai_log
    gen_ai.prompt_injection.risk_score>0.5
| timechart span=1h count as high_risk_events,
    avg(gen_ai.prompt_injection.risk_score) as avg_risk_score
          </query>
          <earliest>-7d@d</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.overlayFields">avg_risk_score</option>
        <option name="charting.axisTitleX.text">Time</option>
        <option name="charting.axisTitleY.text">High Risk Events</option>
        <option name="charting.axisTitleY2.text">Avg Risk Score</option>
      </chart>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Cost Trend by Model (30d)</title>
      <chart>
        <search>
          <query>
index=gen_ai_log
    gen_ai.cost.total>0
| bucket _time span=1d
| stats sum(gen_ai.cost.total) as daily_cost
    by _time, gen_ai.request.model
| timechart span=1d sum(daily_cost) as total_cost by gen_ai.request.model
          </query>
          <earliest>-30d@d</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.axisTitleX.text">Date</option>
        <option name="charting.axisTitleY.text">Cost ($)</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>
    
    <panel>
      <title>Latency P95 by Model (24h)</title>
      <chart>
        <search>
          <query>
index=gen_ai_log
    gen_ai.client.operation.duration>0
| timechart span=10m perc95(gen_ai.client.operation.duration) as p95_latency
    by gen_ai.request.model
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">line</option>
        <option name="charting.axisTitleX.text">Time</option>
        <option name="charting.axisTitleY.text">P95 Latency (s)</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>
  </row>
  
</dashboard>
```

```

---

## Dashboard Studio Version (JSON)

**Recommended for Splunk 9.0+**

Dashboard Studio provides a modern, responsive interface with advanced visualization options.

```json
{
  "visualizations": {
    "viz_safety_violation_rate": {
      "type": "viz.singlevalue",
      "options": {
        "unit": "%",
        "majorValue": "> sparklineValues | lastPoint()",
        "trendValue": "> sparklineValues | delta(-2)",
        "sparklineValues": "> primary | seriesByName('violation_rate')",
        "numberPrecision": 2,
        "showSparklineAreaGraph": true,
        "trendDisplay": "off",
        "backgroundColor": "> primary | seriesByName('violation_rate') | lastPoint() | rangeValue(violationRateColorRanges)"
      },
      "dataSources": {
        "primary": "ds_safety_violation_rate"
      },
      "title": "Safety Violation Rate (24h)",
      "description": "Percentage of requests with safety violations",
      "context": {
        "violationRateColorRanges": [
          {
            "to": 1,
            "value": "#53a051"
          },
          {
            "from": 1,
            "to": 5,
            "value": "#f8be34"
          },
          {
            "from": 5,
            "value": "#dc4e41"
          }
        ]
      }
    },
    "viz_pii_detection_rate": {
      "type": "viz.singlevalue",
      "options": {
        "unit": "%",
        "majorValue": "> sparklineValues | lastPoint()",
        "sparklineValues": "> primary | seriesByName('pii_rate')",
        "numberPrecision": 2,
        "showSparklineAreaGraph": true,
        "trendDisplay": "off",
        "backgroundColor": "> primary | seriesByName('pii_rate') | lastPoint() | rangeValue(piiRateColorRanges)"
      },
      "dataSources": {
        "primary": "ds_pii_detection_rate"
      },
      "title": "PII Detection Rate (24h)",
      "description": "Percentage of requests with PII detected",
      "context": {
        "piiRateColorRanges": [
          {
            "to": 2,
            "value": "#53a051"
          },
          {
            "from": 2,
            "to": 10,
            "value": "#f8be34"
          },
          {
            "from": 10,
            "value": "#dc4e41"
          }
        ]
      }
    },
    "viz_total_cost": {
      "type": "viz.singlevalue",
      "options": {
        "unit": "$",
        "majorValue": "> sparklineValues | lastPoint()",
        "sparklineValues": "> primary | seriesByName('total_cost')",
        "numberPrecision": 2,
        "showSparklineAreaGraph": true,
        "trendDisplay": "percent"
      },
      "dataSources": {
        "primary": "ds_total_cost"
      },
      "title": "Total Cost (30d)",
      "description": "Total AI usage cost over 30 days"
    },
    "viz_latency_p95": {
      "type": "viz.singlevalue",
      "options": {
        "unit": "s",
        "majorValue": "> sparklineValues | lastPoint()",
        "sparklineValues": "> primary | seriesByName('p95_latency')",
        "numberPrecision": 2,
        "showSparklineAreaGraph": true,
        "trendDisplay": "off",
        "backgroundColor": "> primary | seriesByName('p95_latency') | lastPoint() | rangeValue(latencyColorRanges)"
      },
      "dataSources": {
        "primary": "ds_latency_p95"
      },
      "title": "Avg Latency P95 (24h)",
      "description": "95th percentile latency",
      "context": {
        "latencyColorRanges": [
          {
            "to": 5,
            "value": "#53a051"
          },
          {
            "from": 5,
            "to": 10,
            "value": "#f8be34"
          },
          {
            "from": 10,
            "value": "#dc4e41"
          }
        ]
      }
    },
    "viz_safety_violations_timeline": {
      "type": "viz.area",
      "options": {
        "stackMode": "stacked",
        "xAxisTitleText": "Time",
        "yAxisTitleText": "Violations",
        "legendDisplay": "bottom",
        "seriesColors": {
          "CRITICAL": "#dc4e41",
          "HIGH": "#f57f29",
          "MEDIUM": "#f8be34",
          "LOW": "#53a051"
        }
      },
      "dataSources": {
        "primary": "ds_safety_violations_timeline"
      },
      "title": "Safety Violations Over Time",
      "description": "Safety violations by severity over 7 days"
    },
    "viz_pii_timeline": {
      "type": "viz.line",
      "options": {
        "xAxisTitleText": "Time",
        "yAxisTitleText": "PII Detections",
        "legendDisplay": "bottom",
        "lineWidth": 2,
        "seriesColors": ["#ff8b60"]
      },
      "dataSources": {
        "primary": "ds_pii_timeline"
      },
      "title": "PII Detection Events Over Time",
      "description": "PII detection events over 7 days"
    },
    "viz_model_drift": {
      "type": "viz.table",
      "options": {
        "count": 10,
        "dataOverlayMode": "none",
        "drilldown": "none",
        "showRowNumbers": false,
        "tableFormat": {
          "rowBackgroundColors": "> table | seriesByName(\"drift_status\") | pick(matchValue(driftStatusRowColors))",
          "rowColors": "> table | seriesByName(\"drift_status\") | pick(matchValue(driftStatusTextColors))"
        }
      },
      "dataSources": {
        "primary": "ds_model_drift"
      },
      "title": "Model Drift Status",
      "description": "Current drift status by model and deployment",
      "context": {
        "driftStatusRowColors": {
          "stable": "#e8f5e9",
          "warning": "#fff3e0",
          "critical": "#ffebee"
        },
        "driftStatusTextColors": {
          "stable": "#2e7d32",
          "warning": "#f57c00",
          "critical": "#c62828"
        }
      }
    },
    "viz_prompt_injection": {
      "type": "viz.column",
      "options": {
        "xAxisTitleText": "Time",
        "y2AxisTitleText": "Avg Risk Score",
        "yAxisTitleText": "High Risk Events",
        "legendDisplay": "bottom",
        "overlayFields": ["avg_risk_score"],
        "seriesColors": {
          "high_risk_events": "#dc4e41",
          "avg_risk_score": "#ff9800"
        }
      },
      "dataSources": {
        "primary": "ds_prompt_injection"
      },
      "title": "Prompt Injection Risk (MLTK)",
      "description": "High-risk prompt injection attempts detected"
    },
    "viz_cost_trend": {
      "type": "viz.area",
      "options": {
        "stackMode": "stacked",
        "xAxisTitleText": "Date",
        "yAxisTitleText": "Cost ($)",
        "legendDisplay": "bottom"
      },
      "dataSources": {
        "primary": "ds_cost_trend"
      },
      "title": "Cost Trend by Model (30d)",
      "description": "Daily cost breakdown by model"
    },
    "viz_latency_trend": {
      "type": "viz.line",
      "options": {
        "xAxisTitleText": "Time",
        "yAxisTitleText": "P95 Latency (s)",
        "legendDisplay": "bottom",
        "lineWidth": 2
      },
      "dataSources": {
        "primary": "ds_latency_trend"
      },
      "title": "Latency P95 by Model (24h)",
      "description": "95th percentile latency by model"
    }
  },
  "dataSources": {
    "ds_safety_violation_rate": {
      "type": "ds.search",
      "options": {
        "query": "index=gen_ai_log\n    (gen_ai.safety.violated=\"true\" OR gen_ai.safety.violated=\"false\")\n| stats count as total_requests,\n    sum(eval(if('gen_ai.safety.violated'=\"true\", 1, 0))) as safety_violations\n| eval violation_rate=round((safety_violations/total_requests)*100, 2)\n| fields violation_rate",
        "queryParameters": {
          "earliest": "-24h@h",
          "latest": "now"
        }
      },
      "name": "Safety Violation Rate"
    },
    "ds_pii_detection_rate": {
      "type": "ds.search",
      "options": {
        "query": "index=gen_ai_log\n| stats count as total_requests,\n    sum(eval(if('gen_ai.pii.detected'=\"true\", 1, 0))) as pii_events\n| eval pii_rate=round((pii_events/total_requests)*100, 2)\n| fields pii_rate",
        "queryParameters": {
          "earliest": "-24h@h",
          "latest": "now"
        }
      },
      "name": "PII Detection Rate"
    },
    "ds_total_cost": {
      "type": "ds.search",
      "options": {
        "query": "index=gen_ai_log\n    gen_ai.cost.total>0\n| stats sum(gen_ai.cost.total) as total_cost\n| eval total_cost=round(total_cost, 2)",
        "queryParameters": {
          "earliest": "-30d@d",
          "latest": "now"
        }
      },
      "name": "Total Cost"
    },
    "ds_latency_p95": {
      "type": "ds.search",
      "options": {
        "query": "index=gen_ai_log\n    gen_ai.client.operation.duration>0\n| stats perc95(gen_ai.client.operation.duration) as p95_latency\n| eval p95_latency=round(p95_latency, 2)",
        "queryParameters": {
          "earliest": "-24h@h",
          "latest": "now"
        }
      },
      "name": "Latency P95"
    },
    "ds_safety_violations_timeline": {
      "type": "ds.search",
      "options": {
        "query": "index=gen_ai_log\n    gen_ai.safety.violated=\"true\"\n| eval severity=case(\n    like('gen_ai.safety.categories', \"%EMERGENCY%\"), \"CRITICAL\",\n    like('gen_ai.safety.categories', \"%HIGH%\"), \"HIGH\",\n    like('gen_ai.safety.categories', \"%MEDIUM%\"), \"MEDIUM\",\n    1=1, \"LOW\"\n)\n| timechart span=1h count by severity",
        "queryParameters": {
          "earliest": "-7d@d",
          "latest": "now"
        }
      },
      "name": "Safety Violations Timeline"
    },
    "ds_pii_timeline": {
      "type": "ds.search",
      "options": {
        "query": "index=gen_ai_log\n    gen_ai.pii.detected=\"true\"\n| timechart span=1h count as pii_detections",
        "queryParameters": {
          "earliest": "-7d@d",
          "latest": "now"
        }
      },
      "name": "PII Timeline"
    },
    "ds_model_drift": {
      "type": "ds.search",
      "options": {
        "query": "index=gen_ai_log\n    gen_ai.drift.status=*\n| stats latest(gen_ai.drift.status) as drift_status,\n    latest(gen_ai.drift.metric.value) as drift_value,\n    latest(_time) as last_update\n    by gen_ai.request.model, gen_ai.deployment.id\n| eval last_update=strftime(last_update, \"%Y-%m-%d %H:%M:%S\")\n| eval drift_value=round(drift_value, 3)\n| sort drift_status",
        "queryParameters": {
          "earliest": "-24h@h",
          "latest": "now"
        }
      },
      "name": "Model Drift Status"
    },
    "ds_prompt_injection": {
      "type": "ds.search",
      "options": {
        "query": "index=gen_ai_log\n    gen_ai.prompt_injection.risk_score>0.5\n| timechart span=1h count as high_risk_events,\n    avg(gen_ai.prompt_injection.risk_score) as avg_risk_score",
        "queryParameters": {
          "earliest": "-7d@d",
          "latest": "now"
        }
      },
      "name": "Prompt Injection Risk"
    },
    "ds_cost_trend": {
      "type": "ds.search",
      "options": {
        "query": "index=gen_ai_log\n    gen_ai.cost.total>0\n| bucket _time span=1d\n| stats sum(gen_ai.cost.total) as daily_cost\n    by _time, gen_ai.request.model\n| timechart span=1d sum(daily_cost) as total_cost by gen_ai.request.model",
        "queryParameters": {
          "earliest": "-30d@d",
          "latest": "now"
        }
      },
      "name": "Cost Trend"
    },
    "ds_latency_trend": {
      "type": "ds.search",
      "options": {
        "query": "index=gen_ai_log\n    gen_ai.client.operation.duration>0\n| timechart span=10m perc95(gen_ai.client.operation.duration) as p95_latency\n    by gen_ai.request.model",
        "queryParameters": {
          "earliest": "-24h@h",
          "latest": "now"
        }
      },
      "name": "Latency Trend"
    }
  },
  "defaults": {
    "dataSources": {
      "ds.search": {
        "options": {
          "queryParameters": {
            "latest": "now",
            "earliest": "-24h@h"
          }
        }
      }
    }
  },
  "inputs": {},
  "layout": {
    "type": "absolute",
    "options": {
      "width": 1440,
      "height": 1080,
      "display": "auto-scale"
    },
    "structure": [
      {
        "item": "viz_safety_violation_rate",
        "type": "block",
        "position": {
          "x": 0,
          "y": 0,
          "w": 360,
          "h": 150
        }
      },
      {
        "item": "viz_pii_detection_rate",
        "type": "block",
        "position": {
          "x": 360,
          "y": 0,
          "w": 360,
          "h": 150
        }
      },
      {
        "item": "viz_total_cost",
        "type": "block",
        "position": {
          "x": 720,
          "y": 0,
          "w": 360,
          "h": 150
        }
      },
      {
        "item": "viz_latency_p95",
        "type": "block",
        "position": {
          "x": 1080,
          "y": 0,
          "w": 360,
          "h": 150
        }
      },
      {
        "item": "viz_safety_violations_timeline",
        "type": "block",
        "position": {
          "x": 0,
          "y": 150,
          "w": 720,
          "h": 300
        }
      },
      {
        "item": "viz_pii_timeline",
        "type": "block",
        "position": {
          "x": 720,
          "y": 150,
          "w": 720,
          "h": 300
        }
      },
      {
        "item": "viz_model_drift",
        "type": "block",
        "position": {
          "x": 0,
          "y": 450,
          "w": 720,
          "h": 300
        }
      },
      {
        "item": "viz_prompt_injection",
        "type": "block",
        "position": {
          "x": 720,
          "y": 450,
          "w": 720,
          "h": 300
        }
      },
      {
        "item": "viz_cost_trend",
        "type": "block",
        "position": {
          "x": 0,
          "y": 750,
          "w": 720,
          "h": 300
        }
      },
      {
        "item": "viz_latency_trend",
        "type": "block",
        "position": {
          "x": 720,
          "y": 750,
          "w": 720,
          "h": 300
        }
      }
    ],
    "globalInputs": []
  },
  "description": "Comprehensive AI governance monitoring dashboard with safety violations, PII detection, model drift, cost analysis, and latency monitoring",
  "title": "GenAI Governance Overview"
}
```

---

## Installation Instructions

### Option 1: Dashboard Studio (Recommended for Splunk 9.0+)

1. **Create Dashboard in Splunk UI:**
   - Navigate to **Dashboards → Create New Dashboard**
   - Select **Dashboard Studio**
   - Choose **Grid** layout

2. **Import JSON Definition:**
   - Click **Source** (< > icon) in the top right
   - Delete the default JSON content
   - Copy and paste the Dashboard Studio JSON above

3. **Save and Configure:**
   - Click **Save**
   - Name it "GenAI Governance Overview"
   - Set appropriate permissions

4. **Customize (Optional):**
   - Update time ranges in `queryParameters` section
   - Adjust color ranges in visualization `context` sections
   - Modify layouts in the `structure` array

### Option 2: Classic Dashboard (XML)

For Splunk versions < 9.0 or if you prefer Classic Dashboards:

1. **Create Dashboard in Splunk UI:**
   - Navigate to **Dashboards → Create New Dashboard**
   - Select **Classic Dashboards**
   - Choose any starter template

2. **Import XML Definition:**
   - Click **Edit → Edit Source**
   - Replace all content with the Classic Dashboard XML (see below)

3. **Customize:**
   - Adjust `<earliest>` and `<latest>` tags based on your data volume
   - Modify colors, thresholds, and formatting in the `<option>` tags

4. **Set Permissions:**
   - Click **Edit → Edit Permissions**
   - Share dashboard with appropriate teams (AI governance, security, ML ops)

---

## Additional KPI Queries

### Request Volume by Provider
```spl
index=gen_ai_log
| stats count as requests by gen_ai.provider.name
| sort -requests
```

### Error Rate by Model
```spl
index=gen_ai_log
| stats count as total,
    sum(eval(if(gen_ai.status!="success", 1, 0))) as errors
    by gen_ai.request.model
| eval error_rate=round((errors/total)*100, 2)
| where error_rate > 0
| sort -error_rate
```

### Session Duration Analysis
```spl
index=gen_ai_log
| stats earliest(_time) as session_start,
    latest(_time) as session_end,
    count as turns
    by gen_ai.session.id
| eval session_duration_min=round((session_end-session_start)/60, 1)
| stats avg(session_duration_min) as avg_duration,
    avg(turns) as avg_turns
```

---

## Additional Resources

For a detailed comparison of Dashboard Studio vs Classic Dashboards, including:
- Feature comparison table
- Migration guide from Classic to Dashboard Studio
- Customization tips and examples
- Troubleshooting guide
- Performance optimization techniques

**See:** [Dashboard Comparison Guide](DASHBOARD_COMPARISON.md)
