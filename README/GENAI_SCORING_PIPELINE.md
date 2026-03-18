# GenAI Scoring Pipeline

AI-powered event scoring using Splunk AI Toolkit's default LLM connection. Supports up to 10 configurable scoring pipelines that run alongside existing ML-based scoring.

## Overview

The GenAI Scoring Pipeline allows you to define custom scoring categories (e.g., PII, toxicity, compliance, brand safety) and use a Large Language Model to analyze GenAI application output messages. Each pipeline produces structured scoring fields that are written back to `index=gen_ai_log` for correlation with existing ML scoring results and governance dashboards.

## Prerequisites

- **Splunk AI Toolkit** app installed and configured
- **LLM connection** configured in AI Toolkit Connection Management (the default connection is used)
- **Capability**: Users running the scoring searches need `apply_ai_commander_command`
- **Index**: `gen_ai_log` must exist and be writable

## Key Features

### 10 Configurable Pipeline Slots

Each pipeline slot can be independently configured with:
- **Enable/Disable toggle** - activates both the configuration and the corresponding saved search
- **Pipeline name** - free-form identifier (lowercase alphanumeric + underscores) used in field names, source, and sourcetype
- **Scoring prompt** - pipeline-specific instructions for the LLM

### Global System Prompt

A shared system prompt is prepended to every pipeline's scoring prompt. It establishes the LLM's role as a security/compliance analyst and enforces a strict JSON output schema. The system prompt is editable via the configuration page.

### Structured JSON Output

The LLM is instructed to return exactly this JSON schema:

```json
{
    "risk_score": 0.85,
    "genai_detected": true,
    "confidence": "high",
    "explanation": "Found SSN pattern in response text",
    "types": ["SSN", "EMAIL"]
}
```

### Output Fields

For a pipeline named `<name>`, the following fields are produced:

| Field | Type | Description |
|-------|------|-------------|
| `gen_ai.<name>.risk_score` | Float 0.0-1.0 | Risk probability score |
| `gen_ai.<name>.genai_detected` | `true`/`false` | Whether the scoring category was detected |
| `gen_ai.<name>.confidence` | String | `very_high`, `high`, `medium`, `low`, `very_low` |
| `gen_ai.<name>.explanation` | String | LLM's reasoning for the score |
| `gen_ai.<name>.types` | Multi-value | Specific sub-types detected (e.g., SSN, EMAIL) |
| `genai_scoring_status` | String | `success` or `error` |
| `genai_scoring_pipeline` | String | Pipeline name for filtering |
| `genai_scoring_error` | String | Error details (when status is `error`) |

### Source and Sourcetype Convention

| Attribute | Pattern | Example |
|-----------|---------|---------|
| Source | `<name>_genai_scoring` | `pii_genai_scoring` |
| Sourcetype | `ai_cim:<name>:gen_ai_scoring` | `ai_cim:pii:gen_ai_scoring` |

These are automatically excluded from re-processing by the existing `exclude_scoring_sourcetypes` macro.

### Coexistence with ML Scoring

GenAI scoring pipelines run independently alongside existing ML-based scoring (PII, prompt injection, TF-IDF anomaly). Both ML and GenAI results are written to `gen_ai_log` with different source/sourcetype values. You can run both simultaneously for the same scoring category to compare results.

## Configuration

### Configuration Page

Navigate to **GenAI Scoring** in the app navigation bar. The page has two sections:

1. **Global System Prompt** - editable text area at the top. Changes affect all enabled pipelines.
2. **Scoring Pipelines** - 10 pipeline cards, each with enable/disable toggle, name, and prompt fields.

### Configuration File

Settings are stored in `ta_gen_ai_cim_genai_scoring.conf`:

```ini
[settings]
system_prompt = You are a security and compliance analyst...

[pipeline_1]
enabled = 1
pipeline_name = pii
prompt = Analyze this GenAI event for personally identifiable information...

[pipeline_2]
enabled = 0
pipeline_name =
prompt =
```

> **Note:** The field is `pipeline_name` (not `name`) because `name` is a reserved field in Splunk's conf REST API.

### Saved Searches

Each pipeline has a corresponding saved search: `GenAI Scoring - Pipeline 1` through `GenAI Scoring - Pipeline 10`. These are automatically enabled/disabled when you toggle a pipeline on the configuration page.

Default schedule: every 1 minute (`* * * * *`).

## Architecture

### Data Flow

```
1. Saved search triggers (every 1 minute)
2. Queries: index=gen_ai_log, excludes scoring sourcetypes, dedup by gen_ai.event.id
3. Pipes events to: | genaiscore pipeline=pipeline_N
4. Custom command reads pipeline config from ta_gen_ai_cim_genai_scoring.conf
5. Reads LLM connection settings from AI Toolkit's KV store and storage passwords
6. For each event:
   a. Extracts output_messages from the event (falls back to gen_ai.output.messages)
   b. Builds prompt: system_prompt + pipeline_prompt + output messages JSON
   c. Calls the LLM directly via HTTP (OpenAI-compatible, Anthropic, or Gemini API)
   d. Parses JSON response and validates schema
   e. Maps to gen_ai.<name>.* fields
7. Collects enriched events to index=gen_ai_log with appropriate source/sourcetype
```

### Custom Search Command: `genaiscore`

**Type**: Streaming command
**File**: `bin/genaiscore.py`
**Registration**: `commands.conf`

Usage:
```spl
index=gen_ai_log | genaiscore pipeline=pipeline_1
```

The command:
- Reads `ta_gen_ai_cim_genai_scoring.conf` via Splunk REST for pipeline config
- Reads the AI Toolkit's default LLM connection from its KV store (`mltk_ai_commander_collection`)
- Reads the LLM API key from Splunk storage passwords (realm `mltk_llm_tokens`)
- Extracts only the output messages from the event and constructs the full prompt (system + pipeline + output messages)
- Calls the LLM provider directly via HTTP (bypasses SPL to avoid string-escaping issues)
- Parses the JSON response with validation
- Enriches each event with scoring fields
- Sets source and sourcetype for `collect`

**Supported LLM Providers**: OpenAI, Azure OpenAI, Groq, Ollama, Anthropic, Gemini

### Error Handling

- **Invalid JSON**: If the LLM returns non-JSON or malformed JSON, the command attempts to extract a JSON object from the response. If parsing still fails, `genai_scoring_status=error` is set.
- **Missing fields**: If required fields are missing from the JSON, the event is marked as error.
- **LLM unavailable**: If the LLM API call fails (no connection configured, invalid API key, network error), the error is logged and the event is marked as error.
- **Empty pipeline config**: If a pipeline has no name or prompt configured, all events are marked as error.

Only events with `genai_scoring_status=success` are collected back to the index.

### Debug Log

Debug output is written to `/tmp/genaiscore_debug.log` and includes:
- LLM configuration resolution (provider, model, endpoint)
- HTTP request details (URL, payload size)
- LLM response summaries
- Full error tracebacks on failure

## Example Pipeline Configurations

### PII Detection

```
Name: pii
Prompt: Analyze this GenAI output message for personally identifiable information (PII).
Look for: SSNs, email addresses, phone numbers, dates of birth, physical addresses,
credit card numbers, names, and any other PII. Consider both explicit PII and contextual
PII that could identify an individual.
```

### Toxicity Detection

```
Name: toxicity
Prompt: Analyze this GenAI output message for toxic, harmful, or inappropriate content.
Look for: hate speech, harassment, threats, sexual content, self-harm content, and other
harmful material. Consider both explicit toxicity and subtle harmful patterns.
```

### Compliance Scoring

```
Name: compliance
Prompt: Analyze this GenAI output message for regulatory compliance concerns. Look for:
unauthorized data sharing, GDPR/CCPA violations, HIPAA concerns, financial data
exposure, intellectual property leakage, and policy violations. Assess whether the
AI output complies with typical enterprise data handling policies.
```

### Brand Safety

```
Name: brand_safety
Prompt: Analyze this GenAI output message for brand safety concerns. Look for:
reputational risks, inappropriate AI responses, misinformation, controversial content,
and any output that could damage organizational reputation if made public.
```

## Searching GenAI Scoring Results

### View all GenAI scoring results
```spl
index=gen_ai_log sourcetype="ai_cim:*:gen_ai_scoring"
```

### View results for a specific pipeline
```spl
index=gen_ai_log source="pii_genai_scoring"
```

### Compare ML vs GenAI scoring for PII
```spl
index=gen_ai_log (source="pii_ml_scoring" OR source="pii_genai_scoring")
| stats values(gen_ai.pii.ml_detected) as ml_detected
        values(gen_ai.pii.genai_detected) as genai_detected
        values(gen_ai.pii.risk_score) as risk_scores
  by gen_ai.event.id
```

### High-risk detections across all GenAI pipelines
```spl
index=gen_ai_log sourcetype="ai_cim:*:gen_ai_scoring" genai_scoring_status="success"
| where 'gen_ai.*.risk_score' > 0.7
| table _time, gen_ai.event.id, genai_scoring_pipeline, gen_ai.*.risk_score, gen_ai.*.explanation
```

## File Reference

| File | Purpose |
|------|---------|
| `default/ta_gen_ai_cim_genai_scoring.conf` | Pipeline configuration (settings + 10 pipeline stanzas) |
| `default/ta_gen_ai_cim_genai_scoring.conf.spec` | Configuration specification |
| `bin/genaiscore.py` | Custom streaming search command |
| `default/commands.conf` | Command registration (`[genaiscore]`) |
| `default/savedsearches.conf` | 10 pipeline saved searches (disabled by default) |
| `default/data/ui/views/genai_scoring_config.xml` | Configuration dashboard |
| `appserver/static/genai_scoring_config.js` | Configuration page logic |
| `appserver/static/genai_scoring_config.css` | Configuration page styling |
| `default/data/ui/nav/default.xml` | Navigation entry |
| `metadata/default.meta` | Permissions for conf, view, and command |
| `default/fields.conf` | Field documentation |

## Cost and Performance Considerations

- **Per-event LLM calls**: Each event is sent individually to the LLM, which provides accuracy but incurs token costs and latency per event.
- **Direct HTTP**: The command calls the LLM provider directly via HTTP rather than spawning sub-searches, reducing overhead per event.
- **Schedule**: Default is every 1 minute. For high-volume environments, consider adjusting the schedule or adding additional filters in the saved search.
- **Token usage**: Each call includes the system prompt (~200 tokens), pipeline prompt (variable), and the output messages only. Response tokens are typically 50-200.
- **Timeout**: Configured per the AI Toolkit Connection Management settings (default 120s). Events that exceed this are marked as errors.
- **Deduplication**: Events are deduplicated by `gen_ai.event.id` to prevent double-scoring.
