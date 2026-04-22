# Dashboard Templates

Phase 6 delegates rendering to the `splunk-dashboard-studio` subagent. This file is the panel catalog — each panel has a title, a visualization hint, and SPL with detection tokens already substituted.

## How to invoke the dashboard subagent

```
Task tool
  subagent_type: splunk-dashboard-studio (or splunk-dashboard-builder if the user prefers Simple XML)
  description: "Monitoring dashboard for <Detection>"
  prompt: |
    Build a Splunk Dashboard Studio dashboard for "<Detection Title> ML Detection".

    Index: <idx>
    Enriched sourcetype: ai_cim:<detection>:ml_scoring
    Risk threshold: <risk_threshold>
    High-risk threshold: <high_risk_threshold>
    Rate threshold: <rate_threshold>%

    Global inputs (time range, app name, model):
    - time: earliest=-24h latest=now
    - app: token $app$, default *
    - model: token $model$, default *

    Panels (in order, use the SPL verbatim):
    <paste the panel SPL blocks from below>

    Audience: <from intake, default governance/SOC analyst>.
    Theme: dark.
    Deploy into app <app> as view file ml_<detection>_detection.xml.
```

If the user prefers Simple XML, delegate to `splunk-dashboard-builder` instead; the SPL and layout carry over.

---

## Layout (4 rows)

```
Row 1: KPI Summary  [Detections] [Total Events] [Detection Rate] [Avg Risk Score]
Row 2: Trend        [Detections vs Total over time]
Row 3: Breakdown    [By Category/Technique]  [By Risk Level]
Row 4: Detail       [Top Detecting Apps] [Recent Detections table with drilldown]
```

---

## Global Inputs

| Token | Type | Default | SPL fragment |
|---|---|---|---|
| `$timepicker$` | time | last 24h | via panel `earliest`/`latest` |
| `$app$` | text/dropdown | `*` | `'gen_ai.app.name'=$app$` |
| `$model$` | text/dropdown | `*` | `'gen_ai.request.model'=$model$` |

Insert both filters in every panel search.

---

## Row 1 — KPI Summary

### Panel 1.1 — Detections

- **Viz**: Single value
- **Color**: green (0) / yellow (1-9) / red (10+)

```spl
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring"
    'gen_ai.<detection>.ml_detected'="true"
    'gen_ai.app.name'=$app$ 'gen_ai.request.model'=$model$
| stats count as detections
```

### Panel 1.2 — Total Events Scored

- **Viz**: Single value

```spl
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring"
    'gen_ai.app.name'=$app$ 'gen_ai.request.model'=$model$
| stats count as total
```

### Panel 1.3 — Detection Rate

- **Viz**: Single value with trend
- **Color**: green (<5%) / yellow (5-15%) / red (>15%)

```spl
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring"
    'gen_ai.app.name'=$app$ 'gen_ai.request.model'=$model$
| stats count as total,
    sum(eval(if('gen_ai.<detection>.ml_detected'="true", 1, 0))) as detected
| eval rate_pct=round(detected/total*100, 2)
| fields rate_pct
```

### Panel 1.4 — Average Risk Score

- **Viz**: Single value
- **Color**: green (<0.3) / yellow (0.3-0.6) / red (>0.6)

```spl
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring"
    'gen_ai.app.name'=$app$ 'gen_ai.request.model'=$model$
| stats avg('gen_ai.<detection>.risk_score') as avg_risk
| eval avg_risk=round(avg_risk, 3)
```

---

## Row 2 — Trend

### Panel 2.1 — Detections vs Total Over Time

- **Viz**: Line chart (dual series) with threshold overlay at `<rate_threshold>%`

```spl
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring"
    'gen_ai.app.name'=$app$ 'gen_ai.request.model'=$model$
| timechart span=15m
    count as total,
    sum(eval(if('gen_ai.<detection>.ml_detected'="true", 1, 0))) as detections
| eval rate_pct=round(detections/total*100, 2)
```

Drilldown: set `$time$` from the clicked bucket and route to Row 4 panels.

---

## Row 3 — Breakdown

### Panel 3.1 — Detections by Category / Technique

- **Viz**: Horizontal bar chart

If the detection emits `technique`:

```spl
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring"
    'gen_ai.<detection>.ml_detected'="true"
    'gen_ai.app.name'=$app$ 'gen_ai.request.model'=$model$
| stats count as detections by 'gen_ai.<detection>.technique'
| sort -detections
| head 10
```

If the detection emits `types` (multi-value, PII-style):

```spl
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring"
    'gen_ai.<detection>.ml_detected'="true"
    'gen_ai.app.name'=$app$ 'gen_ai.request.model'=$model$
| eval type=split('gen_ai.<detection>.types', ",")
| mvexpand type
| stats count as detections by type
| sort -detections
| head 10
```

### Panel 3.2 — Risk Level Distribution

- **Viz**: Pie/donut

```spl
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring"
    'gen_ai.app.name'=$app$ 'gen_ai.request.model'=$model$
| eval risk_level=case(
    'gen_ai.<detection>.risk_score' >= 0.8, "CRITICAL",
    'gen_ai.<detection>.risk_score' >= <high_risk_threshold>, "HIGH",
    'gen_ai.<detection>.risk_score' >= <risk_threshold>, "MEDIUM",
    'gen_ai.<detection>.risk_score' >= 0.3, "LOW",
    1=1, "NONE"
)
| stats count by risk_level
```

Suggested color mapping for the studio subagent:

- CRITICAL: `#9C1C1C`
- HIGH: `#DC4E41`
- MEDIUM: `#F8BE34`
- LOW: `#A7C1E2`
- NONE: `#53A051`

---

## Row 4 — Detail

### Panel 4.1 — Top Detecting Apps

- **Viz**: Table

```spl
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring"
    'gen_ai.app.name'=$app$ 'gen_ai.request.model'=$model$
| stats count as total_events,
    sum(eval(if('gen_ai.<detection>.ml_detected'="true", 1, 0))) as detections,
    avg('gen_ai.<detection>.risk_score') as avg_risk,
    max('gen_ai.<detection>.risk_score') as max_risk
    by 'gen_ai.app.name'
| eval rate_pct=round(detections/total_events*100, 2)
| eval avg_risk=round(avg_risk, 3), max_risk=round(max_risk, 3)
| sort -detections
| head 20
| rename 'gen_ai.app.name' as "App", rate_pct as "Detection %", avg_risk as "Avg Risk", max_risk as "Max Risk"
```

Drilldown: set `$app$` to the clicked row → refreshes every panel.

### Panel 4.2 — Recent Detections

- **Viz**: Events table with drilldown to the raw event

```spl
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring"
    'gen_ai.<detection>.ml_detected'="true"
    'gen_ai.app.name'=$app$ 'gen_ai.request.model'=$model$
| sort -_time
| head 50
| table _time 'gen_ai.event.id' 'gen_ai.app.name' 'gen_ai.request.model'
    'gen_ai.<detection>.risk_score' 'gen_ai.<detection>.confidence'
    'gen_ai.<detection>.technique' 'client.address'
```

Drilldown: on click, route to the event review dashboard (if present) or run:

```spl
index=<idx> gen_ai.event.id=$row.gen_ai.event.id$
```

---

## Optional Panels (enable on request)

### Model Health Panel

- **Viz**: Single value + status indicator

```spl
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring" earliest=-7d
| stats count as total,
    sum(eval(if('gen_ai.<detection>.ml_detected'="true", 1, 0))) as detected,
    stdev('gen_ai.<detection>.risk_score') as risk_stdev
| eval rate_pct=round(detected/total*100, 2)
| eval status=case(
    rate_pct > 25, "CRITICAL - unusually high detection rate",
    rate_pct > 15, "WARNING - high detection rate",
    rate_pct < 0.1, "WARNING - near-zero detection rate",
    risk_stdev > 0.4, "WARNING - high variance",
    1=1, "HEALTHY"
)
| table status rate_pct risk_stdev total detected
```

### Top Anomalous Sources (unsupervised only)

```spl
index=<idx> sourcetype="ai_cim:<detection>:ml_scoring"
    'gen_ai.<detection>.is_anomaly'="true"
| stats count as anomalies,
    avg('gen_ai.<detection>.anomaly_score') as avg_score
    by 'client.address'
| sort -anomalies
| head 20
```

### Threshold Sweep Chart

- **Viz**: Line chart

```spl
| savedsearch "ML - <Detection> Threshold Sweep"
```

---

## Instructions to pass to the dashboard subagent

Always include, verbatim, in the subagent's prompt:

> - Do NOT modify any SPL above — the detection sourcetype, field names, and thresholds are fixed by the skill.
> - Render global inputs for time range, app, and model.
> - Apply the KPI color thresholds listed per panel.
> - Every panel must survive with zero results (no divide-by-zero): use `coalesce(...,0)` or `where total>0` defensively.
> - Save as `default/data/ui/views/ml_<detection>_detection.xml` in app `<app>` (Dashboard Studio JSON embedded in SimpleXML).
> - After writing, run `| rest /servicesNS/-/<app>/data/ui/views/ml_<detection>_detection` and confirm it returns exactly one row.
