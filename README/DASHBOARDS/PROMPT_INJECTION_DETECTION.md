# Prompt Injection Detection Dashboard

## Overview

The **Prompt Injection Detection** dashboard provides ML-based detection of adversarial prompt injection attacks targeting AI models. It monitors for jailbreak attempts, data exfiltration, and other malicious prompt manipulation techniques.

## Purpose

This dashboard enables security and AI governance teams to:

- **Detect** adversarial prompt injection attempts
- **Classify** attack techniques (jailbreak, data exfiltration, etc.)
- **Monitor** severity and confidence levels
- **Identify** repeat offenders by source IP
- **Investigate** individual attacks with drilldown

## File Location

```
default/data/ui/views/prompt_injection_detection.xml
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

Every panel reads one base search (`ds_pi_base`) that keeps one row per prompt
(`gen_ai.event.id`). A prompt is detected when any of three detectors flagged
it:

| Detector | Signal |
|----------|--------|
| **AI Defense** | Inference event with `gen_ai.policy.blocked="true"` and "Prompt Injection" in `gen_ai.safety.categories` |
| **ML model** | `ai_cim:prompt_injection:ml_scoring` event with `gen_ai.prompt_injection.ml_detected="true"` |
| **GenAI judge** | `genai_scoring` event (`genai_scoring_pipeline="prompt_injection"`) with `gen_ai.prompt_injection.genai_detected="true"` |

A prompt flagged by more than one detector counts once. Clean prompts are kept
as hourly counts, and detected prompts as one row each.

### KPI Summary Row

| Panel | Description | Color Coding |
|-------|-------------|--------------|
| **Total Scanned** | Distinct prompts in scope (non-scoring events with the selected app and model) | Green (informational) |
| **Injections Detected** | Distinct prompts flagged by any detector | Green (0), Yellow (1-9), Red (10+) |
| **Critical Severity** | Detected prompts whose highest severity is critical | Green (0), Red (1+) |
| **High Severity** | Detected prompts whose highest severity is high | Green (0), Yellow (1-4), Red (5+) |
| **Detection Rate** | Injections Detected ÷ Total Scanned | Green (<2%), Yellow (2-5%), Red (>5%) |

### Visualizations

| Panel | Type | Description |
|-------|------|-------------|
| **Detection Trend** | Line chart | Detected vs clean prompts per hour |
| **Injections by Technique** | Horizontal bar chart | ML technique, GenAI judge types and AI Defense rule names; a prompt can count under several |
| **Severity Distribution** | Pie/Donut chart | Highest severity any detector gave the prompt (critical, high, medium, low, none) |
| **Confidence Distribution** | Pie/Donut chart | ML model and GenAI judge confidence only (very_high … very_low); AI Defense blocks carry no score |
| **Top Injection Sources** | Table | Source IPs with the most detected prompts, their sessions, techniques and detectors |
| **Recent Detections** | Table | Latest 25 detected prompts with the detectors that flagged them and severity highlighting |

## Attack Techniques Detected

| Technique | Description |
|-----------|-------------|
| **Jailbreak** | Attempts to bypass safety guidelines |
| **Data Exfiltration** | Attempts to extract training data or system prompts |
| **Roleplay Injection** | "Pretend you are..." style attacks |
| **Encoding Tricks** | Base64, hex, or URL-encoded payloads |
| **Delimiter Injection** | Using `[INST]`, `<<SYS>>`, etc. to manipulate parsing |
| **Ignore Instructions** | "Ignore previous instructions" patterns |

## Severity Classification

| Severity | Condition | Color |
|----------|-----------|-------|
| **Critical** | Risk score >= 0.9 OR known dangerous technique | Dark Red (`#9C1C1C`) |
| **High** | Risk score >= 0.7 | Red (`#DC4E41`) |
| **Medium** | Risk score >= 0.5 | Yellow (`#F8BE34`) |
| **Low** | Risk score >= 0.3 | Green (`#53A051`) |
| **None** | Risk score < 0.3 | Blue (`#6AB7C7`) |

The ML model writes its own `gen_ai.prompt_injection.severity`. The GenAI
judge's severity is derived from its risk score with the thresholds above. An
AI Defense block counts as **High**. A prompt takes the highest severity among
the detectors that flagged it.

## Output Fields

| Field | Type | Description |
|-------|------|-------------|
| `gen_ai.prompt_injection.ml_detected` | string | "true" if injection detected |
| `gen_ai.prompt_injection.risk_score` | float | ML probability score (0-1) |
| `gen_ai.prompt_injection.technique` | string | Detected attack technique |
| `gen_ai.prompt_injection.severity` | string | critical, high, medium, low, none |
| `gen_ai.prompt_injection.confidence` | string | very_high, high, medium, low, very_low |

## Drilldown Behavior

Clicking any row in the **Recent Detections** table opens a search for the full event:

```
index=gen_ai_log gen_ai.request.id="<REQUEST_ID>"
```

## Related Alerts

| Alert | Trigger |
|-------|---------|
| GenAI - Prompt Injection Alert | ML-detected injection attempts |
| GenAI - Prompt Injection by Source IP | Repeated attacks from same source |

## Related Documentation

- [Prompt Injection Detection ML Model](../ML%20Models/Prompt_Injection.md) - Complete training and scoring documentation
- [AI Governance Overview Dashboard](AI_GOVERNANCE_OVERVIEW.md) - Main dashboard documentation
- [Review Queue Dashboard](REVIEW_QUEUE.md) - Human review workflow

---

**Last Updated:** 2026-10-29
