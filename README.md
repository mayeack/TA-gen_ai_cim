# TA-gen_ai_cim

> **⚠️ ALPHA SOFTWARE** - This Technology Add-on is in active development. Features may change, break, or be removed without notice. Use at your own risk in non-production environments. This application is currently for demonstration purposes only.

**Splunk Technology Add-on for Generative AI Common Information Model**

Version: 1.7.1  
Author: Splunk AI Governance Team  
License: Apache 2.0

---

## Overview

The **TA-gen_ai_cim** is a Splunk Technology Add-on that normalizes GenAI/LLM telemetry events from multiple providers into a unified Common Information Model (CIM) based on OpenTelemetry semantic conventions. It provides search-time field extractions, governance-ready alerts, dashboards, and ML-based detection for AI safety, privacy, and security monitoring.

### Key Features

✅ **Multi-Provider Support**
- Anthropic (Claude)
- OpenAI (GPT)
- AWS Bedrock
- Google Vertex AI
- Azure OpenAI
- Local/internal models

✅ **Unified Schema**
- 60+ normalized fields in `gen_ai.*` namespace
- Aligned with OpenTelemetry GenAI semantic conventions
- Consistent field naming across all providers

✅ **Governance & Compliance**
- Safety violation detection and alerting
- PII/PHI detection with ML models
- Prompt injection attack detection
- Policy enforcement monitoring
- Guardrail trigger tracking

✅ **Performance & Cost**
- Token usage tracking
- **Time-versioned token cost KV store** (input/output pricing by provider/model)
- Cost per request/model/deployment with dynamic pricing lookups
- Latency monitoring (P50, P95, P99)
- Model drift detection

✅ **Splunk AI Toolkit Integration**
- ML-based PII/PHI detection model
- Prompt injection detection model
- **TF-IDF anomaly detection for prompts and responses**
- Risk scoring (0-1 probability)
- Automated threat classification

✅ **Pre-Built Governance Outputs**
- 15+ ready-to-use alerts
- Complete dashboard XML
- KPI queries for governance reporting
- Correlation searches for anomaly detection

✅ **ServiceNow AI Case Management Integration**
- One-click escalation to ServiceNow AI Cases
- Auditable linkage via KV Store mapping
- Event Context menu workflow actions
- Splunk Cloud compatible alert action fallback

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  AI Telemetry Sources                                   │
│  (Anthropic, OpenAI, Bedrock, Internal Models)          │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Splunk Indexes                                         │
│  (gen_ai_log)                                           │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  TA-gen_ai_cim (Search-Time Normalization)             │
│  ┌────────────────────────────────────────────────┐    │
│  │  props.conf:  Field aliases, EVAL transforms  │    │
│  │  transforms.conf:  JSON array extractions      │    │
│  │  fields.conf:  Field definitions & types       │    │
│  └────────────────────────────────────────────────┘    │
└────────────────────┬────────────────────────────────────┘
                     │
           ┌─────────┴──────────┐
           │                    │
           ▼                    ▼
┌──────────────────────┐  ┌────────────────────────┐
│  Normalized Fields   │  │  ML Models             │
│  (gen_ai.*)          │  │  - PII Detection       │
└──────────┬───────────┘  │  - Prompt Injection    │
           │              └────────┬───────────────┘
           │                       │
           └───────────┬───────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  Governance Outputs                                     │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐│
│  │  Alerts       │  │  Dashboards   │  │  Reports    ││
│  │  - Safety     │  │  - KPIs       │  │  - Compliance││
│  │  - PII        │  │  - Trends     │  │  - Audit    ││
│  │  - Drift      │  │  - Risk Scores│  │             ││
│  └───────────────┘  └───────────────┘  └─────────────┘│
└─────────────────────────────────────────────────────────┘
```

---

## Dependencies

### Platform Requirements

| Component | Version | Required | Notes |
|-----------|---------|----------|-------|
| **Splunk Enterprise** | 9.0+ | Yes | Or Splunk Cloud |
| **Splunk AI Toolkit** | Latest | Optional | Required for ML-based detection (PII, prompt injection, TF-IDF anomaly) and AI-powered case summaries via `\| ai` command |
| **Python for Scientific Computing** | Latest | Optional | Required by Splunk AI Toolkit; provides numpy, scipy, scikit-learn |

**Splunkbase Links:**
- [Splunk AI Toolkit](https://splunkbase.splunk.com/app/6842)
- [Python for Scientific Computing](https://splunkbase.splunk.com/app/2882)

### Python Dependencies

| Package | Version | Location | Notes |
|---------|---------|----------|-------|
| `splunklib` | 2.1.1 | Bundled in `lib/` | Splunk SDK for Python - no installation required |
| Standard Library | - | Built-in | json, os, sys, time, re, ssl, base64, datetime, argparse, getpass, urllib |
| Splunk Internal | - | Splunk Platform | `splunk.admin`, `splunk.entity`, `splunk.auth` |

**Note:** All Python dependencies are either bundled with the TA or included with the Splunk platform. No external pip installation is required.

### JavaScript Dependencies (Client-Side)

| Library | Provider | Notes |
|---------|----------|-------|
| jQuery | Splunk Web Framework | Bundled with Splunk, loaded via RequireJS |
| splunkjs/mvc | Splunk Web Framework | Splunk's MVC framework components |

**Note:** All JavaScript dependencies are provided by the Splunk Web Framework. No additional installation required.

### ML Algorithms Used

The following Splunk AI Toolkit algorithms are used for ML-based detection features:

| Algorithm | Purpose | Feature |
|-----------|---------|---------|
| `HashingVectorizer` | Text-to-vector conversion | TF-IDF anomaly detection |
| `PCA` | Dimensionality reduction | TF-IDF anomaly detection |
| `OneClassSVM` | Unsupervised anomaly detection | Prompt/response anomaly detection |
| `LogisticRegression` | Supervised classification | PII detection |
| `RandomForestClassifier` | Supervised classification | Prompt injection detection |

**Note:** These algorithms are provided by the Python for Scientific Computing add-on required by Splunk AI Toolkit.

### External Service Integrations (Optional)

| Service | Purpose | Configuration |
|---------|---------|---------------|
| **ServiceNow** | AI Case Management integration | Configure via Apps > AI Governance > Configuration |
| **LLM Provider** | AI-powered case summaries | Configure via Splunk AI Toolkit Connection Management |

### Verify Dependencies

**Check Splunk Version:**
```spl
| rest /services/server/info | table version
```

**Check Splunk AI Toolkit Installation:**
```spl
| rest /services/apps/local/splunk_ai_toolkit | table title, version
```

**Check Python for Scientific Computing:**
```spl
| rest /services/apps/local/Splunk_SA_Scientific_Python_linux_x86_64 | table title, version
```

**Check splunklib Version (bundled):**
```bash
grep "__version__" $SPLUNK_HOME/etc/apps/TA-gen_ai_cim/lib/splunklib/__init__.py
```

---

## Installation

### Prerequisites

1. **Splunk Enterprise** 9.0+ or **Splunk Cloud**
2. **Splunk AI Toolkit** (for ML-based detection)
3. **Python for Scientific Computing** (for Splunk AI Toolkit)
4. AI telemetry data flowing into Splunk indexes
5. **`mltk_admin` role** assigned to the user performing ML setup (provided by the Splunk AI Toolkit)
6. **Default LLM connection** configured in the Splunk AI Toolkit (**Apps > Splunk AI Toolkit > Connection Management**) to enable generative AI capabilities such as AI-powered case summaries via the `| ai` command

### Installation Steps

#### 1. Deploy TA to Splunk

```bash
# Copy TA to Splunk apps directory
cp -r TA-gen_ai_cim $SPLUNK_HOME/etc/apps/

# Set ownership (Linux/Unix production only - skip on macOS)
# For Linux/Unix with splunk user:
# chown -R splunk:splunk $SPLUNK_HOME/etc/apps/TA-gen_ai_cim
# For macOS or single-user installs, ownership is already correct

# Restart Splunk
$SPLUNK_HOME/bin/splunk restart
```

#### 2. Verify Installation

```bash
$SPLUNK_HOME/bin/splunk display app TA-gen_ai_cim
```

Expected output:
```
TA-gen_ai_cim
  Version: 1.7.0
  Status: enabled
```

### Ingest contract: HEC (supported path for Splunk Cloud)

This TA is **search-time only** and targets search heads. It deliberately ships
no index-time parsing (`LINE_BREAKER`, `TIME_PREFIX`, `TIME_FORMAT`,
`TRUNCATE`) — on Splunk Cloud that parsing happens on the indexer tier, which
the TA does not reach.

Send events to the **`/services/collector/event`** endpoint with an explicit
`time` and the event object under `event`:

```json
{
  "time": 1785232127.977,
  "index": "gen_ai_log",
  "sourcetype": "gen_ai:json",
  "source": "demobot:hec",
  "host": "demobot-v3",
  "event": {
    "event_id": "0a05bc6a-f2f7-4d1f-8910-0492c64ed095",
    "enduser_id": "t.nguyen",
    "app_name": "demobot-v3",
    "model_name": "dolphin3:8b",
    "prompt_category": "prompt_injection",
    "policy_blocked": true,
    "policy_action": "block",
    "guardrail_triggered": true,
    "guardrail_ids": ["cisco_ai_defense"],
    "business_outcome": "blocked_by_ai_defense",
    "risk_score": 60
  }
}
```

Because the payload is a structured object with an explicit `time`, HEC needs
**no index-time settings at all**. Search-time normalization in
`default/props.conf [gen_ai:json]` then applies unchanged, and every
`gen_ai.*` field resolves as documented in [Normalized Schema](#normalized-schema).

> **Do not use `/services/collector/raw`.** The raw endpoint reintroduces the
> index-time parsing dependency this TA cannot ship, and timestamps will fall
> back to ingest time.

Create the index and a matching HEC token before sending. On Splunk Cloud
apps cannot create indexes, so both are provisioning steps — see the Show
post-deploy script in `tools/` (dev-only, not packaged).

#### 3. Configure Data Inputs

The TA normalizes on **sourcetype**, not on index. Both of these must be set by
whatever ships your telemetry:

| Setting | Required value |
|---|---|
| `index` | `gen_ai_log` |
| `sourcetype` | **`gen_ai:json`** |

> **Why the sourcetype matters.** props.conf has no `index::` scope — a stanza
> may only be `<sourcetype>`, `host::`, `source::`, `rule::`, or
> `delayedrule::`. If your events land under some other sourcetype with no
> stanza, Splunk's default `KV_MODE = auto` still parses the JSON, so flat
> fields like `provider_name` resolve and the data *looks* fine — but every
> `gen_ai.*` field is null and every dashboard renders zeros.

##### Sending via HEC

Post the flat governance event as a JSON **object** in `event` (not a
pre-serialized string):

```bash
curl -k https://<splunk-host>:8088/services/collector/event \
  -H "Authorization: Splunk <HEC_TOKEN>" \
  -d '{
        "index": "gen_ai_log",
        "sourcetype": "gen_ai:json",
        "event": {
          "timestamp": "2026-07-29T12:00:00.000000+0000",
          "event_id": "e-456",
          "operation_name": "chat",
          "provider_name": "openai",
          "request_model": "gpt-4o",
          "response_model": "gpt-4o",
          "session_id": "s-123",
          "input_messages": [{"role": "user", "content": "..."}],
          "output_messages": [{"role": "assistant", "content": "..."}],
          "usage_input_tokens": 812,
          "usage_output_tokens": 771,
          "safety_violated": false,
          "pii_detected": false,
          "service_name": "demobot",
          "enduser_id": "jdoe"
        }
      }'
```

Field names in the payload are the **raw underscore** names that the field
aliases consume (`provider_name`, `usage_input_tokens`, …). The TA maps those
to the dotted `gen_ai.*` CIM namespace — see [Normalized Schema](#normalized-schema).

##### Sending via the OpenTelemetry Collector

```yaml
exporters:
  splunk_hec/genai:
    token: "${env:SPLUNK_HEC_TOKEN}"
    endpoint: "https://<splunk-host>:8088/services/collector"
    index: "gen_ai_log"
    sourcetype: "gen_ai:json"
    source: "otel"

service:
  pipelines:
    logs/genai:
      receivers: [otlp]
      processors: [batch]
      exporters: [splunk_hec/genai]
```

The log record **body** must be the flat JSON object shown above. If you emit
the fields as OTel resource/scope attributes instead, they arrive as
`attributes.*` and none of the field aliases fire.

##### Ingest-tier settings (indexers / heavy forwarders / Cloud IDM)

This TA is **search-time only** and deliberately ships no index-time settings,
so they cannot be applied from here. Apply these on the ingest tier:

```ini
[gen_ai:json]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = "timestamp":\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%z
MAX_TIMESTAMP_LOOKAHEAD = 40
TRUNCATE = 150000
```

`TRUNCATE = 150000` matters: prompt and response payloads routinely exceed the
default 10,000-byte line limit and would otherwise be cut off.

##### Attaching an existing sourcetype

If your data already lands under a different sourcetype and you cannot change
the sender, point it at the canonical sourcetype in `local/props.conf`. This is
search-time, so it also fixes **already-indexed** events with no re-ingest:

```ini
[my_existing_sourcetype]
rename = gen_ai:json
```

Note that after a rename, `sourcetype=my_existing_sourcetype` no longer matches
in searches — use `sourcetype=gen_ai:json`, or `_sourcetype=my_existing_sourcetype`
to recover the original name.

The legacy sourcetypes `medadvice3:json` and `toyapp:json` ship with exactly
this rename applied.

##### When NOT to rename: non-inference governance events

Only rename a sourcetype onto `gen_ai:json` if its events really are **inference**
events. The `gen_ai_inference` eventtype matches on `gen_ai.provider.name=*`, so
renaming an event stream that has no provider, model, token or cost fields adds
rows that inflate every inference count and skew every per-request cost, token
and latency average.

Session-audit and human-escalation records are the common case here. They ship
with their own stanzas instead:

| Sourcetype | Contents | Eventtype |
|---|---|---|
| `demobot:audit` | Session/user lifecycle audit records | `gen_ai_session_audit` |
| `demobot:escalation` | Human-review escalation records | `gen_ai_human_escalation` |

Both normalize the shared correlation keys — `gen_ai.session.id`,
`gen_ai.request.id`, `gen_ai.event.id`, `enduser.id`, `gen_ai.user.id` — so they
join to the inference events, then add their own domain fields under
`gen_ai.audit.*` and `gen_ai.escalation.*`. Escalations also populate the
`gen_ai.review.*` namespace shared with the review-queue KV store.

Neither stanza aliases `gen_ai.provider.name`; that is precisely what keeps them
out of `gen_ai_inference`. Follow the same pattern for your own audit or
workflow streams, and verify with:

```
index=gen_ai_log eventtype=gen_ai_inference | stats count by sourcetype
```

Escalated conversation turns are exposed as `gen_ai.escalation.messages` /
`gen_ai.escalation.roles` rather than `gen_ai.input.messages` /
`gen_ai.output.messages`. The same turns already carry the inference field names
on the corresponding `gen_ai:json` events, so reusing them here would
double-count in content-based detections and copy prompt/response content
(potentially PII/PHI) into a second namespace.

Those two fields and `gen_ai.escalation.symptoms` come from JSON arrays and are
**multivalue**. They are defined with `EVAL` rather than `FIELDALIAS` on purpose:
multivalue behaviour through a field alias is not something the field-alias
documentation defines either way, and this TA ships to Splunk 9.0+ and Splunk
Cloud, so relying on undocumented behaviour is not safe. An eval assignment
preserves multivalue by definition. If you add further array-valued fields, use
`EVAL` (or a `REPORT` transform with `MV_ADD = true`), not `FIELDALIAS`.

#### 4. Test Normalization

Run this search to verify field extraction:

```spl
index=gen_ai_log earliest=-1h
| head 10
| table gen_ai.operation.name gen_ai.provider.name gen_ai.request.model gen_ai.usage.total_tokens gen_ai.safety.violated gen_ai.pii.detected
```

Expected: All `gen_ai.*` fields should be populated.

---

## Normalized Schema

The TA extracts and normalizes **60+ fields** across these categories:

### Core Operation / Model Identity
- `gen_ai.operation.name` - Operation type (chat, completion, embeddings)
- `gen_ai.provider.name` - Provider (anthropic, openai, aws.bedrock)
- `gen_ai.request.model` - Requested model name
- `gen_ai.response.model` - Actual model that served the request
- `gen_ai.response.id` - Unique response ID
- `gen_ai.conversation.id` - Conversation/session ID
- `gen_ai.deployment.id` - Deployment identifier
- `gen_ai.request.id` - Request ID for tracing
- `trace_id` - OpenTelemetry trace ID

### Input/Output Payload
- `gen_ai.input.messages` - Input chat history (JSON)
- `gen_ai.output.messages` - Model response (JSON)
- `gen_ai.system_instructions` - System/instruction messages
- `gen_ai.output.type` - Output modality (text, json, image)

### Request Parameters
- `gen_ai.request.max_tokens` - Token limit
- `gen_ai.request.temperature` - Sampling temperature
- `gen_ai.request.top_p` - Top-p sampling
- `gen_ai.response.finish_reasons` - Completion finish reasons

### Usage, Performance, Cost
- `gen_ai.usage.input_tokens` - Input token count
- `gen_ai.usage.output_tokens` - Output token count
- `gen_ai.usage.total_tokens` - Total tokens (computed)
- `gen_ai.client.operation.duration` - Latency in seconds
- `gen_ai.cost.total` - Total cost per request (from source)
- `gen_ai.cost.input` - Calculated input token cost (via KV lookup)
- `gen_ai.cost.output` - Calculated output token cost (via KV lookup)
- `gen_ai.cost.calculated_total` - Calculated total cost (via KV lookup)
- `gen_ai.cost.input_per_million` - Input cost per million tokens
- `gen_ai.cost.output_per_million` - Output cost per million tokens
- `gen_ai.cost.currency` - Currency (default: USD)

### Safety, Guardrails, Policy
- `gen_ai.safety.violated` - Safety violation flag (true/false)
- `gen_ai.safety.categories` - Violated safety categories (MV)
- `gen_ai.guardrail.triggered` - Guardrail triggered flag
- `gen_ai.guardrail.ids` - Triggered guardrail IDs (MV)
- `gen_ai.pii.detected` - PII detection flag
- `gen_ai.pii.types` - Detected PII types (MV)
- `gen_ai.policy.blocked` - Policy block flag

### Evaluation / TEVV / Drift
- `gen_ai.evaluation.score.value` - Evaluation score
- `gen_ai.evaluation.score.label` - Score label
- `gen_ai.drift.metric.name` - Drift metric name
- `gen_ai.drift.metric.value` - Drift value
- `gen_ai.drift.status` - Drift status (stable/warning/critical)

### ML-Enhanced Fields
- `gen_ai.pii.risk_score` - PII probability (0-1)
- `gen_ai.pii.ml_detected` - ML PII detection flag
- `gen_ai.prompt_injection.risk_score` - Injection probability (0-1)
- `gen_ai.prompt_injection.ml_detected` - ML injection flag
- `gen_ai.prompt_injection.technique` - Detected technique

### TF-IDF Anomaly Detection Fields
- `gen_ai.prompt.anomaly_score` - TF-IDF anomaly score for prompts
- `gen_ai.prompt.is_anomaly` - Boolean flag for anomalous prompts
- `gen_ai.response.anomaly_score` - TF-IDF anomaly score for responses
- `gen_ai.response.is_anomaly` - Boolean flag for anomalous responses
- `gen_ai.tfidf.combined_anomaly` - Combined anomaly classification
- `gen_ai.tfidf.risk_level` - Risk level (HIGH/MEDIUM/LOW/NONE)

### Error and Infrastructure
- `error.type` - Error type
- `error.message` - Error message
- `server.address` - Server address
- `server.port` - Server port

### Actor / Application Context
- `enduser.id` - End user identifier
- `service.name` - Service/app name
- `client.address` - Client IP/address

**Full schema reference:** See [Provider Examples](README/PROVIDER_EXAMPLES.md)

---

## Governance Alerts

The TA includes **15+ pre-configured alerts** in `savedsearches.conf`:

> **Shipped searches are disabled by default, with one exception.** Following
> Splunk Cloud best practice, every scheduled search, alert, report, and
> correlation rule ships with `disabled = 1` so a fresh install never sends
> email, calls ServiceNow, or consumes scheduler slots until you opt in. See
> [Enabling the shipped searches](#enabling-the-shipped-searches) below.
>
> The one exception is **AI Governance - Prompt Injection Attack Correlation -
> Rule** (label *GenAI - Prompt Injection Attack Correlation*), which ships
> `disabled = 0` as of v1.6.2 so a fresh install lights up the
> dashboard → correlation search → Mission Control Finding path with no manual
> enablement step. It is read-only — no email, no ServiceNow, no outbound call —
> runs every minute over a 24-hour window, fires only for an actor with an
> injection attempt in the last 5 minutes, and suppresses that actor for 10
> minutes, so each burst of attempts raises one finding. Turn it off in
> `local/savedsearches.conf` if you do not want it scheduled.

### Safety & Compliance
- **GenAI - Safety Violation Alert** - Detects safety policy violations
- **GenAI - Critical Safety Alert - EMERGENCY** - Immediate EMERGENCY-level alerts
- **GenAI - Guardrail Trigger Summary** - Daily guardrail activation summary

### Privacy & PII
- **GenAI - PII Detection Alert** - PII/PHI detection in responses
- **GenAI - PII High Volume Alert** - PII rate exceeds threshold
- **GenAI - ML PII Risk Score Alert** - High ML-based PII risk

### Security
- **GenAI - Prompt Injection Alert** - ML-detected injection attempts
- **GenAI - Prompt Injection by Source IP** - Repeated attacks from sources

### Model Quality & Drift
- **GenAI - Model Drift Critical Alert** - Critical drift status

### Performance
- **GenAI - Latency Outlier Alert** - P95 > 2x average
- **GenAI - Slow Response Alert** - Responses > 10 seconds

### Cost
- **GenAI - Cost Spike Alert** - Cost anomalies (2x baseline)
- **GenAI - High Token Usage Alert** - Excessive token consumption

### Errors
- **GenAI - Error Rate Alert** - Error rate > 5%
- **GenAI - Model Failure Alert** - Model failures/errors

### TF-IDF Anomaly Detection
- **GenAI - TFIDF Anomalous Prompt Alert** - Detects unusual prompts via TF-IDF
- **GenAI - TFIDF Anomalous Response Alert** - Detects unusual responses via TF-IDF
- **GenAI - TFIDF High Risk Combined Anomaly Alert** - Both prompt AND response anomalies
- **GenAI - TFIDF Anomaly by Source IP Alert** - Identifies sources with repeated anomalies
- **GenAI - TFIDF Anomaly Rate Threshold Alert** - Overall anomaly rate > 10%
- **GenAI - TFIDF Daily Anomaly Summary** - Daily summary report

### Enabling the shipped searches

Every scheduled search ships `disabled = 1` except
`AI Governance - Prompt Injection Attack Correlation - Rule` (see above).
Enable only what your environment needs — never by editing `default/`:

- **Splunk Web:** Settings → Searches, reports, and alerts → filter on the
  TA-gen_ai_cim app → Edit → Enable.
- **Configuration files** (on-prem / deployment automation): create
  `$SPLUNK_HOME/etc/apps/TA-gen_ai_cim/local/savedsearches.conf` with a
  `disabled = 0` override per search, e.g.:

  ```ini
  [GenAI - Safety Violation Alert]
  disabled = 0
  ```

- **Splunk Cloud:** use the UI, or ACS `POST /adminconfig/v2/apps` config
  workflows per your operating model.

Before enabling, review each search's cadence and actions: the ML scoring
searches run every minute, the ServiceNow sync searches make outbound API
calls hourly, most alerts send email (configure `action.email.to` first),
and the three `AI Governance - * - Rule` correlation searches require
Splunk Enterprise Security for their notable/risk actions (see
[Enterprise Security integration](#enterprise-security-integration)).

**Customize alerts:** override thresholds and actions in
`local/savedsearches.conf` (upgrade-safe) — never edit `default/`.

---

## Dashboards

Pre-built dashboards are **automatically installed** with the TA, providing comprehensive AI governance monitoring.

| Dashboard | Description | Documentation |
|-----------|-------------|---------------|
| **AI Governance Overview** | Main dashboard with KPIs, safety/compliance metrics, trends | [Details](README/DASHBOARDS/AI_GOVERNANCE_OVERVIEW.md) |
| **Tokenomics** | Token usage, cost attribution, and spend efficiency by provider, model, app, and user; pricing from the `genai_token_cost` KV store (auto-seeded v1.6.5+) | [Details](README/TOKEN_COST_ADMIN.md) |
| **TF-IDF Anomaly Detection** | ML-based detection of unusual prompts/responses | [Details](README/DASHBOARDS/TFIDF_ANOMALY_DETECTION.md) |
| **PII Detection** | ML-powered PII detection and monitoring | [Details](README/DASHBOARDS/PII_DETECTION.md) |
| **Prompt Injection Detection** | Adversarial attack detection and analysis | [Details](README/DASHBOARDS/PROMPT_INJECTION_DETECTION.md) |
| **Review Queue** | Human review workflow and triage | [Details](README/DASHBOARDS/REVIEW_QUEUE.md) |

**Access:** Navigate to **Apps → GenAI Governance** in Splunk Web after installation.

**Full documentation:** See [README/DASHBOARDS/](README/DASHBOARDS/) for detailed panel descriptions and customization options.

### Governance Review Workflow

The TA includes a complete governance review workflow for human review of AI events.

**Key Components:**

| Component | Description |
|-----------|-------------|
| **Review Queue** | Lists events escalated for human review with status tracking |
| **Event Review** | Detailed review page with prompt/response content and findings form |
| **Detection Settings** | Configure which detection types are enabled (PII, PHI, Injection, Anomaly) |

**Conditional Field Visibility:**

The Event Review page dynamically shows/hides detection fields based on Detection Settings:

| When This Setting is OFF | These Fields are Hidden |
|--------------------------|-------------------------|
| Detect PII | "PII Present (Detected)" and "PII Types" |
| Detect PHI | "PHI Present?" and "PHI Types" |
| Detect Prompt Injection | "Injection Detected?" and "Injection Type" |
| Detect Anomalies | "Anomaly Detected?" and "Anomaly Description" |

This streamlines the review interface to show only relevant fields for your monitoring requirements.

**Documentation:** See [Governance Review Workflow](README/GOVERNANCE_REVIEW.md)

---

## ML Models

The TA includes comprehensive SPL for two ML models:

### 1. PII/PHI Detection Model

**Purpose:** Detect sensitive information in AI prompts and responses using ML

**Status:** ✅ Complete training framework with 200k healthcare examples included

**Key Features:**
- **22+ PII Types:** SSN, Email, Phone, Credit Card, DOB, Address, MRN, Member ID, and more
- **Healthcare PHI:** MRN, Member ID, Claim Numbers, Medications, NPI, DEA numbers
- **ML + Rules:** Hybrid approach combining ML probability scores with regex patterns
- **Risk Scoring:** 0-1 probability score with confidence levels
- **Multi-Location:** Detects PII in prompts, responses, or both

**Quick Start (5 Minutes):**

1. **Run Feature Engineering:**
   ```spl
   | savedsearch "GenAI - PII Train Step 1 - Feature Engineering from 200k Dataset"
   ```

2. **Train the Model (choose one):**
   ```spl
   | savedsearch "GenAI - PII Train Step 2 Alt - Random Forest Model"
   ```

3. **Validate Performance:**
   ```spl
   | savedsearch "GenAI - PII Train Step 3 - Validate Model Performance"
   ```

4. **Enable Scheduled Scoring:**
   ```bash
   $SPLUNK_HOME/bin/splunk enable saved-search "GenAI - PII Scoring - Response Analysis" -app TA-gen_ai_cim
   ```

**Output Fields:**
- `gen_ai.pii.risk_score` - ML probability (0-1)
- `gen_ai.pii.ml_detected` - Boolean detection flag
- `gen_ai.pii.confidence` - Level: very_high, high, medium, low, very_low
- `gen_ai.pii.types` - Detected PII types (SSN, EMAIL, MRN, etc.)
- `gen_ai.pii.severity` - Severity: critical, high, medium, low

**Using Macros for Ad-Hoc Detection:**
```spl
index=gen_ai_log earliest=-1h
| `genai_pii_combined_score`
| where gen_ai.pii.detected="true"
| table _time gen_ai.request.id gen_ai.pii.location gen_ai.pii.types
```

**Pre-Configured Alerts:**
- `GenAI - PII ML High Risk Alert` (risk > 0.7)
- `GenAI - PII ML Critical SSN or Credit Card Alert` (immediate)
- `GenAI - PII ML Healthcare PHI Alert` (MRN, Member ID, Claims)

**📖 Complete Guide:** See [PII/PHI Detection](README/ML%20Models/PII_Detection.md)  
**Healthcare Training:** See [PII Detection Guide](README/ML%20Models/PII_Detection.md#healthcare-specific-patterns)  
**Quick Start:** See [Your Data is Ready](README/YOUR_DATA_IS_READY.md)

### 2. Prompt Injection Detection Model

**Purpose:** Detect adversarial prompt manipulation

**Features:**
- Adversarial keywords (ignore instructions, reveal prompt, jailbreak)
- Pattern detection (encoding, escape sequences)
- Statistical features (negation density, special chars)

**Training:**
```spl
| fit RandomForestClassifier injection_label 
    from prompt_length has_ignore_instruction has_jailbreak_terms ... 
    into app:prompt_injection_model
```

**Scoring:**
```spl
| apply prompt_injection_model
| eval gen_ai.prompt_injection.risk_score=round('RandomForestClassifier:probability(injection_label=1)', 3)
| eval gen_ai.prompt_injection.ml_detected=if('gen_ai.prompt_injection.risk_score'>0.6, "true", "false")
```

**Full ML documentation:** See [ML Models Overview](README/ML%20Models/README.md)

### 3. TF-IDF Anomaly Detection Models

**Purpose:** Detect anomalous prompts and responses using unsupervised learning

**Models:**
- **Prompt Anomaly Model:** Detects unusual user inputs (jailbreaks, misuse, attacks)
- **Response Anomaly Model:** Detects unusual AI outputs (hallucinations, errors, quality issues)

**How it works:**
1. TF-IDF vectorizes text into numerical features
2. PCA reduces dimensionality for efficiency
3. OneClassSVM learns the boundary of "normal" text
4. New messages outside this boundary are flagged as anomalies

**Training (run each step in order, wait for completion before next step):**
```
Prompt Model:
  Step 1: "GenAI - TFIDF Train Prompt Step 1 - TFIDF Vectorizer"
  Step 2: "GenAI - TFIDF Train Prompt Step 2 - PCA"
  Step 3: "GenAI - TFIDF Train Prompt Step 3 - Anomaly Model"

Response Model:
  Step 1: "GenAI - TFIDF Train Response Step 1 - TFIDF Vectorizer"
  Step 2: "GenAI - TFIDF Train Response Step 2 - PCA"
  Step 3: "GenAI - TFIDF Train Response Step 3 - Anomaly Model"
```

**Scoring:**
```spl
index=gen_ai_log
| `genai_tfidf_preprocess_prompt`
| `genai_tfidf_score_prompt`
| `genai_tfidf_combined_risk`
| table _time gen_ai.request.id gen_ai.prompt.is_anomaly gen_ai.tfidf.risk_level
```

**Output Fields:**
- `gen_ai.prompt.anomaly_score`: Raw anomaly score (negative = anomaly)
- `gen_ai.prompt.is_anomaly`: Boolean flag ("true"/"false")
- `gen_ai.response.anomaly_score`: Raw anomaly score for responses
- `gen_ai.response.is_anomaly`: Boolean flag for responses
- `gen_ai.tfidf.combined_anomaly`: Combined assessment ("both", "prompt_only", "response_only", "normal")
- `gen_ai.tfidf.risk_level`: Risk classification ("HIGH", "MEDIUM", "LOW", "NONE")

**Full TF-IDF documentation:** See [TF-IDF Anomaly Detection](README/ML%20Models/TFIDF_Anomaly.md)

---

## Usage Examples

### Basic Searches

#### View Normalized Events
```spl
index=gen_ai_log 
| table _time gen_ai.operation.name gen_ai.provider.name gen_ai.request.model gen_ai.usage.total_tokens
```

#### Safety Violations by Severity
```spl
index=gen_ai_log gen_ai.safety.violated="true"
| eval severity=case(
    like('gen_ai.safety.categories', "%EMERGENCY%"), "CRITICAL",
    like('gen_ai.safety.categories', "%HIGH%"), "HIGH",
    1=1, "MEDIUM"
)
| stats count by severity, gen_ai.deployment.id
```

#### Cost Analysis by Model (using source cost)
```spl
index=gen_ai_log gen_ai.cost.total>0
| stats sum(gen_ai.cost.total) as total_cost,
    sum(gen_ai.usage.total_tokens) as total_tokens,
    count as requests
    by gen_ai.request.model
| eval cost_per_1M_tokens=round((total_cost/(total_tokens/1000000)), 2)
```

#### Cost Analysis by Model (using KV store pricing)
```spl
index=gen_ai_log earliest=-7d
| `genai_token_cost_join`
| `genai_cost_by_model`
```

#### PII Detection Rate
```spl
index=gen_ai_log
| stats count as total,
    sum(eval(if('gen_ai.pii.detected'="true", 1, 0))) as pii_events
    by gen_ai.app.name
| eval pii_rate=round((pii_events/total)*100, 2)
```

### Advanced Correlation

#### Correlate Safety Violations with PII
```spl
index=gen_ai_log (gen_ai.safety.violated="true" OR gen_ai.pii.detected="true")
| stats values(gen_ai.safety.categories) as safety_cats,
    values(gen_ai.pii.types) as pii_types
    by gen_ai.session.id, gen_ai.deployment.id
| where isnotnull(safety_cats) AND isnotnull(pii_types)
```

#### Latency vs Token Count Correlation
```spl
index=gen_ai_log gen_ai.client.operation.duration>0 gen_ai.usage.total_tokens>0
| bin gen_ai.usage.total_tokens span=500 as token_bucket
| stats avg(gen_ai.client.operation.duration) as avg_latency,
    perc95(gen_ai.client.operation.duration) as p95_latency
    by token_bucket, gen_ai.request.model
```

---

## Configuration

### Customize Index / Sourcetype Mapping

Normalization is keyed on the **sourcetype** `gen_ai:json`, not on the index.
To attach data that arrives under a different sourcetype, add a rename stanza in
`local/props.conf` (never edit `default/`, and never add index-time settings such
as `INDEXED_EXTRACTIONS` — this is a search-time TA):

```ini
[my_existing_sourcetype]
rename = gen_ai:json
```

To use a different **index**, update the searches that reference it:

```
# Find and replace across default/savedsearches.conf, default/macros.conf,
# and default/eventtypes.conf:
index=gen_ai_log   ->   index=my_custom_ai_index
```

### Add Custom Provider Mappings

Edit `transforms.conf` to add provider-specific normalization:

```ini
[my_custom_provider_normalize]
SOURCE_KEY = _raw
REGEX = "model"\s*:\s*"(my-custom-model-[^"]+)"
FORMAT = gen_ai.provider.name::my_custom_provider
WRITE_META = true
```

### Adjust ML Thresholds

Edit scoring SPL to adjust risk thresholds:

```spl
# Lower PII threshold for more sensitive detection
| eval gen_ai.pii.ml_detected=if('gen_ai.pii.risk_score'>0.5, "true", "false")

# Higher prompt injection threshold to reduce false positives
| eval gen_ai.prompt_injection.ml_detected=if('risk_score'>0.8, "true", "false")
```

### Enabling Data Model Acceleration

The TA ships with the `AI_Inference`, `AI_Safety`, and `AI_Evaluation` data
models defined but **with acceleration disabled by default**. This is
required by Splunk Cloud policy: a TA must not turn on acceleration on the
customer's behalf because the storage and indexer cost is non-trivial.

To enable acceleration after installation:

1. In Splunk Web go to **Settings > Data models**.
2. Select the data model (e.g. `AI_Inference`).
3. Click **Edit > Edit Acceleration**.
4. Check **Accelerate** and pick a summary range. The TA pre-populates
   sensible defaults (`-30d` for `AI_Inference`, `-90d` for `AI_Safety` and
   `AI_Evaluation`, with a 90-day max acceleration window).
5. Click **Save**. Splunk will start building the summary index and the
   `AI Overview`, `Cost Analysis`, and `Safety` dashboards will return
   results faster as the summary fills in.

For details, see the Splunk docs on
[Accelerate data models](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Acceleratedatamodels).

---

## Troubleshooting

### Issue: No Normalized Fields Appearing

This is almost always a **sourcetype** problem: raw flat fields resolve (because
Splunk's default `KV_MODE = auto` parses JSON on its own) while every
`gen_ai.*` field is null, so dashboards render zeros and "No search results
returned".

**Diagnosis:**
```spl
index=gen_ai_log | stats count by sourcetype, _sourcetype
```

If your sourcetype is not `gen_ai:json` — and has no `rename = gen_ai:json` —
no `gen_ai.*` field will ever resolve. Confirm the raw fields are present:

```spl
index=gen_ai_log | head 1 | table provider_name request_model usage_input_tokens
```

**Resolution:**
- Set `sourcetype = gen_ai:json` on the sender (see
  [Configure Data Inputs](#3-configure-data-inputs)), or add a
  `rename = gen_ai:json` stanza for your existing sourcetype in `local/props.conf`
- Verify the index name matches the searches (`index=gen_ai_log` by default)
- Restart Splunk, or reload search-time config, after TA installation

### Issue: ML Models Not Found

**Diagnosis:**
```spl
| inputlookup mlspl_models
| search model_name="pii_response_model" OR model_name="prompt_injection_model"
```

**Resolution:**
- Ensure Splunk AI Toolkit is installed
- Run FIT commands to create models (see README/ML Models/README.md)
- Verify model storage permissions

### Issue: Alerts Not Triggering

**Diagnosis:**
```bash
$SPLUNK_HOME/bin/splunk list saved-searches -app TA-gen_ai_cim
```

**Resolution:**
- Enable scheduled searches: `enableSched = 1`
- Check alert conditions and thresholds
- Verify email/notification actions are configured

---

## ServiceNow AI Case Management

The TA includes integration with ServiceNow AI Case Management for one-click escalation.

### Quick Start

1. **Configure credentials:**
   ```bash
   $SPLUNK_HOME/bin/splunk cmd python bin/snow_setup.py --interactive
   ```

2. **Test the connection:**
   ```spl
   | makeresults | eval gen_ai.event.id="test_123" | aicase mode=lookup
   ```

3. **Create a case from an event:**
   ```spl
   index=gen_ai_log gen_ai.safety.violated="true" | head 1 | aicase
   ```

4. **Use the Event Context menu:** Right-click any event with `gen_ai.event.id` → "Open Case in ServiceNow"

**Full documentation:** See [ServiceNow Integration](README/SERVICENOW_INTEGRATION.md)

---

## AI Defense Response Actions

Three adaptive response actions for GenAI incident containment, runnable from a
finding in the ES analyst queue or from a Containment task in the **AI Incident
Response Plan**:

| Action | Acts on | Resolves from |
|---|---|---|
| Suspend User (AI Defense) | identity | `enduser_id`, `gen_ai.user.id`, `user`, `risk_object`, `actor` |
| Revoke Session / API Key | session | `session_id`, `gen_ai.session.id`, `conversation_id` |
| Tighten Guardrail Policy | application | `app_name`, `gen_ai.app.name`, `app`, `service_name` |

> **These actions are SIMULATED.** They call nothing external — no IdP, no token
> service, no Cisco AI Defense policy API. Each records a structured audit event
> in `gen_ai_log` under sourcetype `ai_cim:response:action` carrying
> `"simulated": true`, and reports success. That flag is the only thing
> distinguishing a demo containment record from a real one; never strip it.

They exist so a deployment **without a paired SOAR instance** can still show a
real adaptive-response entry and a complete audit trail. Once SOAR is paired,
replace them with the equivalent playbook actions.

Review the audit trail with:

```spl
index=gen_ai_log sourcetype=ai_cim:response:action
| table _time, action_label, target_type, target, status, simulated, executed_by, execution_id
| sort - _time
```

The `exclude_scoring_sourcetypes` macro excludes `ai_cim:response:*`, so these
records never contaminate inference metrics, dashboards, or detections.

Shared logic lives in `bin/ai_defense_response.py`; the three scripts are thin
wrappers over it. The response plan seed asset that references them ships at
`default/data/response_plans/ai_incident_response_plan.json`.

---

## File Structure

```
TA-gen_ai_cim/
├── README.md                      # Main documentation
├── QUICKSTART.md                  # Quick setup guide
├── app.manifest                   # Splunk Cloud ACS package manifest
├── package.sh                     # AppInspect-clean package builder (dev only)
├── bin/
│   ├── ai_defense_response.py     # Shared logic for the AI Defense response actions
│   ├── ai_defense_revoke_session.py    # Alert action: Revoke Session / API Key
│   ├── ai_defense_suspend_user.py      # Alert action: Suspend User (AI Defense)
│   ├── ai_defense_tighten_guardrail.py # Alert action: Tighten Guardrail Policy
│   ├── aicase.py                  # ServiceNow AI Case custom command
│   ├── create_snow_case.py        # ServiceNow case alert action
│   ├── genaiscore.py              # GenAI LLM scoring custom command
│   ├── pull_snow_inventory.py     # ServiceNow inventory pull alert action
│   ├── snow_setup.py              # ServiceNow CLI setup utility
│   ├── sync_snow_asset.py         # ServiceNow asset sync alert action + shared client
│   └── ta_gen_ai_cim_account_handler.py  # REST handler for account management
├── appserver/
│   └── static/                    # Icons, dashboard JS/CSS
├── lib/
│   └── splunklib/                 # Vendored Splunk Python SDK
├── lookups/
│   ├── medadvice_assets.csv       # Sample ES asset data (synthetic)
│   ├── medadvice_identities.csv   # Sample ES identity data (synthetic)
│   └── prompt_injection_training_examples.csv  # Seed training data
├── default/
│   ├── app.conf                   # App metadata ([id], version, reload triggers)
│   ├── alert_actions.conf         # Alert actions (ServiceNow)
│   ├── authorize.conf             # Role definitions (ai_reviewers, ml_power_user)
│   ├── collections.conf           # KV store collections
│   ├── commands.conf              # Custom search command definitions
│   ├── datamodels.conf            # AI_Inference / AI_Safety / AI_Evaluation
│   ├── eventtypes.conf / tags.conf  # CIM-style eventtypes and tags
│   ├── fields.conf                # Field definitions
│   ├── inputs.conf                # ES Asset & Identity registrations
│   ├── macros.conf                # Search macros
│   ├── props.conf                 # Field normalization (search-time only)
│   ├── restmap.conf               # REST endpoint mapping
│   ├── savedsearches.conf         # Alerts/reports/rules (ship disabled;
│   │                              #   prompt-injection correlation is the
│   │                              #   one enabled-by-default exception)
│   ├── server.conf                # SHC replication for custom confs
│   ├── ta_gen_ai_cim_*.conf(.spec)  # Custom config files and specs
│   ├── transforms.conf            # Extractions, CSV + KV store lookups
│   ├── web.conf                   # REST endpoint exposure
│   ├── workflow_actions.conf      # Event Context menu actions
│   └── data/ui/
│       ├── nav/default.xml        # Navigation menu
│       └── views/                 # 20 dashboards (Studio + Simple XML)
├── metadata/
│   └── default.meta               # Permissions (admin + sc_admin on config)
├── elements/                      # Per-dashboard design docs (dev only, not packaged)
├── tools/                         # Dev-only utilities (not packaged)
│   ├── install-dev.sh             # Copy app into a dev instance
│   ├── load_pii_model.sh          # MLTK model loader (dev only, writes to MLTK app)
│   ├── load_prompt_injection_model.sh  # MLTK model loader (dev only)
│   └── appinspect-cloud-*.{md,json}    # Last AppInspect results
└── README/                        # Extended documentation (not packaged)
    ├── AI_CIM.md                  # AI CIM field reference
    ├── DASHBOARD_PANELS.md        # Dashboard panel definitions
    ├── DASHBOARDS/                # Per-dashboard guides
    ├── DEPLOYMENT_GUIDE.md        # Installation and deployment guide
    ├── GENAI_SCORING_PIPELINE.md  # LLM scoring pipeline guide
    ├── GOVERNANCE_REVIEW.md       # Governance review workflow guide
    ├── INTEGRATIONS/              # Integration guides
    ├── ML Models/                 # ML model documentation
    ├── PROVIDER_EXAMPLES.md       # Provider-specific field mappings
    ├── SERVICENOW_INTEGRATION.md  # ServiceNow integration guide
    ├── TOKEN_COST_ADMIN.md        # Token cost administration
    └── YOUR_DATA_IS_READY.md      # Quick start for training data
```

### Runtime-generated lookups

`transforms.conf` defines several CSV lookups whose files are **not shipped**;
they are created on the search head at runtime:

| Lookup file | Created by |
|---|---|
| `pii_training_data_engineered.csv` | "ML - PII Training" saved search (`outputlookup`) |
| `prompt_injection_training_data_engineered.csv` | "ML - Prompt Injection Training" saved search |
| `pii_model_metadata.csv` / `prompt_injection_model_metadata.csv` | model-promotion feedback-loop searches |
| `tfidf_training_data_v3.csv` / `pii_training_examples.csv` | operator-curated per environment |
| `llm_pii_mixed_responses_200k.csv` | dev-only 48 MB training dataset (never packaged) |

Do not ship placeholder CSVs for these — bundled lookup files overwrite the
runtime-generated versions on every app upgrade.

### Views not in the navigation menu

`ai_cost_analysis_dashboard`, `ai_overview_dashboard`, `ai_safety_dashboard`,
and `genai_governance_overview_studio` ship with the app but are not linked
from the navigation menu (legacy/alternate views kept for reference —
removal is a candidate for a future release). `review_landing` and
`servicenow_case` are intentionally nav-less: they are reached via workflow
actions. The two `genai_governance_overview_*.json.template` files are
Dashboard Studio JSON sources for the AI Governance Overview dashboard and
are excluded from the package.

---

## Provider Examples

Detailed normalization examples for each provider:

- **Anthropic (Claude)** - medadvice_v3 format
- **OpenAI (GPT)** - Standard OpenAI API format
- **AWS Bedrock** - Bedrock service format
- **Local/Internal** - medadvice_v2 nested event format

**Full examples:** See [Provider Examples](README/PROVIDER_EXAMPLES.md)

---

## Contributing

### Reporting Issues

Please report bugs or feature requests via:
- GitHub Issues (if open-sourced)
- Internal JIRA/ticketing system
- Email: ai-governance@example.com

### Adding New Providers

1. Identify raw field names from new provider
2. Add FIELDALIAS or EVAL mappings in `props.conf`
3. Add provider detection logic in `transforms.conf`
4. Update `PROVIDER_EXAMPLES.md` with example
5. Test normalization and submit PR

---

## Governance Best Practices

### 1. Establish Baselines

Run these queries to establish normal behavior:

```spl
# Safety violation baseline (should be < 1%)
index=gen_ai_log earliest=-30d
| stats count as total,
    sum(eval(if('gen_ai.safety.violated'="true", 1, 0))) as violations
| eval violation_rate=round((violations/total)*100, 2)

# PII detection baseline (target < 2%)
# Latency baseline (P95 by model)
# Cost baseline (per 1M tokens)
```

### 2. Configure Thresholds

Adjust alert thresholds based on baselines:
- Safety violations: Alert if rate > 2x baseline
- PII detection: Alert if rate > 5% or 3x baseline
- Latency: Alert if P95 > 2x average
- Cost: Alert if hourly cost > 2x rolling 24h average

### 3. Weekly Reviews

Schedule weekly governance reviews:
- Safety violation trends
- PII detection patterns
- Model drift status
- Cost optimization opportunities
- ML model performance (precision/recall)

### 4. Incident Response

When alerts trigger:
1. **Investigate:** Review session details, user context
2. **Classify:** Determine severity (EMERGENCY, HIGH, MEDIUM, LOW)
3. **Remediate:** Block user/session, update guardrails, retrain models
4. **Document:** Log incident, root cause, resolution
5. **Improve:** Update thresholds, add new detection rules

---

## Performance Considerations

### Search Performance

- **Field extraction:** Search-time only, no index-time overhead
- **Multi-value fields:** Use `mvexpand` sparingly in large searches
- **JSON parsing:** Already optimized with `KV_MODE=json`

### ML Scoring Performance

- **Model scoring:** ~100-500 events/second per model
- **Scheduled scoring:** Run hourly or adjust based on event volume
- **Summary indexing:** Use `| collect` to write enriched events to separate index

### Scaling Recommendations

| Events/Day | Configuration |
|------------|---------------|
| < 100K | Single search head, hourly ML scoring |
| 100K - 1M | Dedicated search head, 15-min ML scoring |
| > 1M | Search head cluster, real-time ML scoring via streaming |

---

## Security & Privacy

### Data Handling

- **Search-time only:** No data modification at index time
- **PII detection:** Flags presence, does not extract/store PII values
- **Model scoring:** Scores stored separately in governance index
- **Access control:** Use Splunk RBAC to restrict access to sensitive fields

### Compliance

The TA supports compliance requirements for:
- **GDPR:** PII detection, right to erasure tracking
- **HIPAA:** PHI detection, audit trails
- **SOC 2:** Access logging, incident response
- **AI Risk Management:** Safety monitoring, drift detection, TEVV

---

## Enterprise Security integration

The three `AI Governance - * - Rule` correlation searches register themselves
with ES automatically — `action.correlationsearch.enabled = 1` plus
`export = system` in `metadata/default.meta` is all ES needs to list them under
**Configure → Content → Content Management**. No registration file is required.

Attaching the shipped **AI Incident Response Plan** to the resulting
investigation needs records that live in the `missioncontrol` app, and Splunk
conf layering is per-app — a TA physically cannot ship into another app's
namespace. So the TA writes them itself at run time: the shipped search
**GenAI - ES - Seed Response Plan and SOAR Binding** (enabled,
`run_on_startup`, hourly) runs `| genaiseedes`, which seeds the plan, the
investigation type bound to it and the AI Findings queue, and binds the plan's
Containment tasks to the simulated SOAR identity provider when that app is on
the paired SOAR. A fresh install converges with nothing to click; the finding's
next steps and recommended actions ship as conf on the detections themselves.

### How a response plan binds to a detection

It does not bind to the detection. The chain is three hops:

```
default/savedsearches.conf
  action.notable.param.investigation_type = ai security incident   <- shipped
        |
        v   KV: mc_incident_types      (_key = the investigation type name)
  response_template_ids = ["b7c3f1a2-5d84-4e97-a1c6-3f9e02d47b58"]
        |
        v   KV: mc_response_templates  (_key = ai_incident_response_plan)
  template_id = b7c3f1a2-5d84-4e97-a1c6-3f9e02d47b58
```

The TA ships hop 1 and the plan itself
(`default/data/response_plans/ai_incident_response_plan.json`); `| genaiseedes`
writes hops 2 and 3 (update-or-create, hourly and on startup).

> **Investigation type names must be lowercase.** Mission Control rejects any
> uppercase character (its Role API is case-insensitive while the collection API
> is not). If you rename the type, change it in **both** places — the value in
> `savedsearches.conf` must match the `mc_incident_types` `_key` exactly, or the
> plan silently fails to attach.

### Automatic — `| genaiseedes`

| Step | What is written | Switch (`ta_gen_ai_cim_es.conf [es_integration]`) |
|---|---|---|
| Response plan | `mc_response_templates` `_key ai_incident_response_plan` — the shipped JSON, URL-encoded on write; actions/playbooks already attached to a task in the ES UI are preserved unless a shipped `soar_binding` replaces them | `seed_response_plan = true` |
| Investigation type | `mc_incident_types` `_key ai security incident`, this plan first in `response_template_ids` (existing ids kept) | same |
| Queue | `queues` `_key ai_findings_queue` — *AI Findings*. Seeded with no routing rule, so findings stay in the default *Analyst Queue* | same |
| Queue routing | Give the queue the rule `(rule_title =~ "^GenAI Prompt Injection")` (Mission Control rule-engine syntax, not SPL) so AI Governance findings land there. Grant analyst roles access to the queue in ES first: Mission Control shows a non-default queue only to admins until then | `route_findings_to_queue = false` |
| SOAR binding | Through Mission Control's pairing proxy (`/v1/soar/...`, no SOAR credential in the TA): if the **MedAdvice Identity Provider** app is installed on the paired SOAR, create its `medadvice_idp` asset and resolve the plan's `soar_binding` entries into real task actions (`disable user`, `clear user sessions`). Otherwise skip and preserve | `bind_soar_actions = true` |
| Simulator install | Install the app itself from `soar_apps/medadvice_idp/` when missing. The proxy has no install route, so this needs a `soar` account in `ta_gen_ai_cim_account.conf` (`url`, `auth_type = token` or `basic`, secret stored as the account password) | `install_simulator = false` |
| Triage agent | `ai_triage_enabled = 1` + allowlist the primary detection (no-op without the `allow_ai_triage` entitlement) | `enable_triage_agent = false` |

Run it by hand to see the per-step report, or to test without writing:

```
| genaiseedes dry_run=true
```

Each row carries `step`, `status` (OK / SKIP / FAIL) and `detail`. The log is
`$SPLUNK_HOME/var/log/splunk/genaiseedes.log`. On the ES8 demo tenant the
demo-mock Okta / Azure AD / AD LDAP connectors must stay deselected under
*Configure → All configurations → Security AI Assistant settings* (Guided
Response connectors); the command lists them but never edits them.

### Option A — scripted, from outside the stack

`tools/show_postdeploy.py` runs the same seeding code (`bin/genai_es_seed.py`)
from a workstation with explicit credentials, plus the demo-only extras — index,
HEC token, detection enablement, demo timing, a SOAR smoke test — that nothing
in the package should do on a customer stack (the `tools/` directory is dev-only
and is not in the shipped tarball):

```bash
export SPLUNK_ADMIN_PASSWORD='...'
export SOAR_PASSWORD='...'   # optional: installs the simulator and binds the Containment tasks
python3 tools/show_postdeploy.py --stack https://<stack>.splunkcloud.com \
    --soar-url https://<tenant>.soar.splunkcloud.com --dry-run
```

With SOAR credentials the script first installs the simulated **MedAdvice
Identity Provider** app (packaged in memory from `soar_apps/`, or the committed
`soar_apps/medadvice_idp.tgz` passed with `--soar-app-tgz`), creates its
`medadvice_idp` asset, and then binds the plan's tasks with that tenant's
app/asset ids. `--soar-only` runs just the SOAR steps.

### Option B — manual, in the ES UI (fallback)

1. **Import the response plan.** *Configure → Content → Response plans →
   Create*, then transcribe the four phases and fifteen tasks from
   `default/data/response_plans/ai_incident_response_plan.json`. Seven of the
   tasks carry embedded SPL under `suggestions.searches` — add those in the
   task's **Searches** section so an analyst (or the Triage agent) can run them
   from the task itself. Publish the plan.
2. **Create the investigation type.** *Configure → Findings and investigations →
   Investigation types → Create*, named exactly `ai security incident`.
3. **Assign the plan.** On that type, *Investigation type associations →
   Response plans → Assign response plan*. Only **published** plans appear. The
   first plan in the list is the default for the type, and additions apply only
   to **newly started** investigations.

### Verify

Let the correlation search fire, open the Finding, escalate it to an
investigation, and confirm the four phases populate.

> **Repeat runs:** since v1.7.1 every spray raises its own Finding, including
> repeats against the same actor: the rule emits an actor only while their
> newest injection attempt is under 5 minutes old and throttles that actor for
> `600s`. Up to v1.7.0 it throttled for `86400s` — one Finding per actor per day
> — and the documented workaround was `alert.suppress = 0` in
> `local/savedsearches.conf`. Remove that override when you upgrade: it masks
> the new default and raises a Finding every minute.

### AI Triage agent (optional)

The Triage agent reads the response plan assigned to the investigation and uses
its task descriptions and embedded searches to ground its reasoning, which is
why the embedded SPL in step 1 above is worth the effort.

Turning it on is operator-side configuration in the `missioncontrol` app. Set
`enable_triage_agent = true` in `ta_gen_ai_cim_es.conf` and `| genaiseedes`
does it on its next run (it ships off because it changes ES-wide behaviour), or
do it by hand under *Configure → All configurations → Triage agent →
Detections*: enable **GenAI - Prompt Injection Attack Correlation**. Only
event-based detections that are already turned on are eligible; finding groups
and risk-based detections are not.

Prerequisites are strict, and on a stack that does not meet them the toggle is a
no-op rather than an error:

| Requirement | Notes |
|---|---|
| ES 8.6+, **Premier** edition | Not available on Essentials |
| Splunk Platform 10.1+ | |
| Splunk Cloud on AWS | |
| Splunk SOAR paired with ES | |
| AI Assistant turned on | Role needs `es_ai_edit_settings` |
| `gen_ai_log` is a **default** search index for `admin`, `ess_admin` and `ess_analyst` | The agent's evidence searches carry no `index=`, so they run against the role's default indexes (`main` and `os` on ES); without `gen_ai_log` they find nothing and verdicts drift to *Benign* / *False Positive*. Settings → Roles → *Indexes* → **Default**, or `tools/show_postdeploy.py` step 14. A TA must not redefine those roles in `default/authorize.conf`, so this is per stack |

Everything else in this section — the response plan, the investigation type, the
findings and the risk scoring — works on ES 8.x without the agent.

---

## Version History

### v1.7.1 (2026-10-07)

**Fixes from the AI Trust workshop dry run**

- FIXED: `| genaiseedes` crashed on every run since v1.7.0, so the shipped
  search *GenAI - ES - Seed Response Plan and SOAR Binding* never wrote
  anything: no AI Incident Response Plan, no `ai security incident`
  investigation type, no AI Findings queue and no `medadvice_idp` SOAR asset,
  on any stack. That is why the dry run's findings were all type *default*
  with 0 response plans and why the rule's investigation type "did not exist".
  Two collisions with splunklib's `SearchCommand`, the second hidden behind the
  first: `generate()` assigned `self.logger`, a read-only property
  (`AttributeError ... has no setter`), and called `self._service()`, a method
  shadowed by the `None` that `SearchCommand.__init__` stores in
  `self._service` (`'NoneType' object is not callable`). The logger is now
  module level and the method is `_connect()`. Verified on ES 8.5.1: the
  `run_on_startup` run created the plan, the investigation type and the queue
  with 0 failures. A new offline test,
  `tools/soar/tests/test_genaiseedes_command.py`, drives `generate()` end to
  end and checks that no method is shadowed by a splunklib instance attribute.
  The existing tests only covered the seeding core.
- FIXED: the correlation rule suppressed each actor for 24 hours, so repeat
  sprays under one actor produced at most one finding per day. It now emits an
  actor only while their newest injection attempt is under 5 minutes old and
  suppresses that actor for 600s. The result is one finding per spray, and a
  new one for every later spray, with the cumulative 24-hour counts. The
  `-24h` window is unchanged because the containment standard counts attempts
  over 24 hours.
- FIXED: risk (RBA) on all three AI Governance rules wrote only one of the two
  configured risk objects. Each search ended with
  `| eval risk_object=..., risk_object_type=...`, and ES `risk_extractor.py`
  uses a result-level `risk_object` in place of every `_risk` entry, so the
  `src`/system risk (score 60) was written as a duplicate of the first object.
  The evals and the matching `nes_fields` entries are removed. Mission
  Control's Entity column, which the evals were added to populate (commit
  `4d61c09`), now comes from `action.notable.param._entities`. For a
  correlation search ES applies that list to the finding only. The entity is
  `user` on the correlation rule and `app` on the other two. `src` is also
  cleared of loopback and placeholder values (`127.x`, `::1`, `null`,
  `unknown`, `-`), so those never become risk objects. Verified live with
  DemoBot sprays: each finding carries `risk_object` = the actor, and the risk
  index gets the actor at 80 plus every source address at 60.
- CHANGED (follows from the risk fix): one correlation firing now adds 80 to
  the actor, not 140. The extra 60 was the duplicate. So the actor no longer
  crosses ES's *Risk - 24 Hour Risk Threshold Exceeded* (100) on a single
  spray. It crosses on its second finding within 24 hours, for example a
  repeat spray, and each source address crosses on its second finding too.
- FIXED: the AI Findings queue never matched. `| genaiseedes` seeded the
  SPL-style rule `search_name="AI Governance*"`, but Mission Control evaluates
  queue rules with its `rule_engine` library. That string is a syntax error
  there and was logged to `notable_modalert.log` on every finding. It could
  not have matched even if valid: `notable.py` assigns the queue before the
  finding gets a `search_name`. The queue now carries
  `(rule_title =~ "^GenAI Prompt Injection")` plus the matching structured
  `rules`, both generated the way the ES UI builds them, so the queue stays
  editable. The rule matches the literal titles of all three AI Governance
  rules, and the tests check it with Mission Control's own engine
  (`tools/soar/tests/test_seed.py`, R-CONF-007). Verified live: a finding
  routed to *AI Findings*. Routing now ships **off** behind a new switch,
  `route_findings_to_queue = false` in `ta_gen_ai_cim_es.conf` (and
  `--route-findings-to-queue` in `tools/show_postdeploy.py`). A routed
  finding leaves the default *Analyst Queue*, where analysts and AI Trust Lab
  4.4 look, and Mission Control shows a non-default queue only to admins until
  roles are granted on it. Until v1.7.1 findings stayed in the Analyst Queue
  only because the rule was broken, so off preserves the behaviour everyone
  has seen. Turn it on per stack once queue permissions are set.
- FIXED: the ES Triage agent could not find the evidence. `gen_ai_log` events
  had no CIM `user`, `app` or `src`; identity lived only in `gen_ai.user.id`.
  `[gen_ai:json]` now calculates `user`, `app` and `src` with the same
  expressions as `gen_ai.user.id`, `gen_ai.app.name` and `client.address`.
  They are EVALs rather than aliases because an alias cannot read a calculated
  field. `[demobot:audit]` gains `user`/`src`, `[demobot:escalation]` gains
  `user` and `[medadvice:json]` gains `app`. The other half of that root cause
  is per stack: the agent's searches carry no `index=`, so `gen_ai_log` must
  be a default search index for `admin`, `ess_admin` and `ess_analyst`. A TA
  must not redefine those roles, so `tools/show_postdeploy.py` gains step 14,
  which appends it while keeping existing defaults and never widening
  `srchIndexesAllowed`. The README Triage agent prerequisites list it too.
- FIXED: AI Governance Overview. The *PII Detected* tile now counts events
  flagged by `gen_ai.pii.detected` (the application / AI Defense signal) as
  well as either scoring pipeline, once per `gen_ai.event.id`. Before, it read
  only scoring output and showed 0 wherever the models were not running. The
  *Retries* tile is removed: nothing in the TA maps `gen_ai.retry.count`, so it
  always read 0. The *ML Detection Summary* and *GenAI Detection Summary*
  panels are removed.
- CHANGED: `tools/show_postdeploy.py` step 8 now writes the v1.7.1 throttle
  (`actor`, `600s`, `-24h`) instead of turning suppression off with a `-15m`
  window. That old override lives in `local/` and masks the new default,
  raising a finding every minute, so re-run step 8 on any stack it configured
  before. Step 9 checks for the new values.

### v1.7.0 (2026-09-03)

- FIXED (pre-release, from MR !174 review): the new seeding search had no
  `owner = admin` stanza in `metadata/default.meta`. Objects shipped in
  `default/` are owned by `nobody`, which holds no roles, and the scheduler
  runs a saved search in its owner's context - so the search could not read
  the admin-only `genaiseedes` command, its conf, or the Mission Control
  collections, and would have failed config load silently on exactly the
  fresh installs it exists to serve. The ten `GenAI Scoring - Pipeline N`
  searches already carried the stanza for the same reason. Generalized as
  R-CONF-005 with a mechanical check
  (`.claude/skills/splunk-ta-development/check_search_owner.py`).

**The ES integration configures itself - response plan, investigation type, queue, finding next steps and the simulated SOAR identity provider ship in the package**

- NEW: `GenAI - ES - Seed Response Plan and SOAR Binding` - a shipped,
  enabled, `run_on_startup` search (hourly) that runs the new `| genaiseedes`
  command (`bin/genaiseedes.py` over `bin/genai_es_seed.py`). It seeds Mission
  Control with the AI Incident Response Plan, the `ai security incident`
  investigation type bound to it and the AI Findings queue, and - through
  Mission Control's own ES/SOAR pairing proxy, with no SOAR credential stored
  in the TA - creates the `medadvice_idp` asset and binds the plan's
  Containment tasks to the simulated SOAR actions when that app is on the
  paired SOAR. Every write is update-or-create of a TA-owned record; actions or
  playbooks attached to a plan task in the ES UI are preserved unless a shipped
  binding replaces them; no event data is read. This is the **third**
  documented exception to "everything ships disabled" (R-SEC-002 amendment
  2026-09-03). Switches in the new `ta_gen_ai_cim_es.conf [es_integration]`:
  `seed_response_plan`, `bind_soar_actions` (both on), `install_simulator`,
  `enable_triage_agent` (both off - they change something beyond this TA's
  records). `| genaiseedes dry_run=true` prints the per-step report.
- NEW: `soar_apps/` - a top-level folder, outside `default/` on purpose,
  holding SOAR apps rather than Splunk content. SOAR is a separate product,
  so the folder and the committed, ready-to-upload
  `soar_apps/medadvice_idp.tgz` can be lifted out of a checkout and
  installed on the SOAR instance on their own. The source still ships
  inside the TA tarball so `install_simulator` can package it in memory;
  `package.sh` excludes only `soar_apps/*.tgz` so the archive holds no
  nested tarball. `build_soar_app_tgz()` and `tools/soar/build.sh` now
  produce byte-identical archive structures, asserted by a unit test,
  because only the `build.sh` output has been verified to install on SOAR.
- NEW: `soar_apps/medadvice_idp/` - the source of a small Splunk
  SOAR app, **MedAdvice Identity Provider**, with `get user`,
  `list user sessions`, `disable user`, `enable user` and `clear user
  sessions` for the MedAdvice workshop personas. It is a simulator: no network
  call, no directory, no state, and every result carries `"simulated": true`.
  It exists because ES response plans and the ES 8.6 **Guided Response agent**
  can only run actions installed on the paired SOAR, and the ES8 demo tenant's
  mock Okta / Azure AD / AD LDAP assets answer *"No data found for
  app/action/parameter"* for every MedAdvice user (the Triage agent's own
  `Okta get user t.nguyen` call fails that way). The seeding core packages it
  in memory and installs it when `install_simulator = true` and a `soar`
  account (`ta_gen_ai_cim_account.conf`: url + token/password) exists, or
  `tools/show_postdeploy.py` installs it with explicit SOAR credentials. Build
  script, persona generator and 23 offline tests live in `tools/soar/`.
- NEW: `action.notable.param.next_steps` and `recommended_actions` on all
  three AI Governance rules. The correlation rule's next steps state the
  containment standard (3+ blocked attempts in 24h, no authorized-testing
  record -> inactivate the account) and name the SOAR action the Guided
  Response agent should run; `[[action|...]]` links carry the simulated
  `ai_defense_*` adaptive responses as the no-SOAR fallback.
- CHANGED: `default/data/response_plans/ai_incident_response_plan.json` -
  Containment task *Suspend the offending identity* is now *Inactivate the
  offending identity's account* (note required, containment standard stated),
  and it and *Revoke active sessions and API credentials* carry a
  `suggestions.soar_binding[]` naming the SOAR app/asset/action, resolved into
  real `suggestions.actions[]` (tenant-specific ids) at seed time; the
  task-action record shape was validated against the `missioncontrol` `Action`
  model. `origin.version` -> 2.
- CHANGED: `tools/show_postdeploy.py` now runs the shared seeding core with
  explicit credentials and keeps only the demo extras (index, HEC, detection
  enablement, demo timing, verify) plus SOAR steps 10-13 (install the app,
  create the asset, list competing identity assets read-only, optional smoke
  test on a scratch container) behind `--soar-url` + `$SOAR_PASSWORD` /
  `$SOAR_AUTH_TOKEN`; `--soar-only`, `--skip-triage`.
- NEW: `tools/es-guided-response-runbook.md` - what remains per tenant (agent
  model choice, connector selection, simulator install options, verification,
  demo timing, dry run).
- OPERATIONAL NOTE: the demo-mock `okta`, `azure_ad` and `ldap` assets stay
  installed; keep the Guided Response agent off them by deselecting those
  connectors in ES (*Security AI Assistant settings*). Nothing in the TA
  writes to foreign SOAR assets: `POST /rest/asset/<id>` re-saves the whole
  asset (absent fields reset to defaults, masked secrets are re-stored) and
  ignores `disabled`, so there is no safe REST way to switch one off.

**Prompt injection correlation now runs every minute**

- CHANGED: `AI Governance - Prompt Injection Attack Correlation - Rule` (ES
  Content Management label *GenAI - Prompt Injection Attack Correlation*) moved
  from a `*/30` cron to `*/1` — it now runs every minute instead of every 30
  minutes. The dispatch window is unchanged at `-24h`, as is
  `alert.suppress.period = 86400s` per `actor`, so an actor still produces at
  most one notable per day; the shorter cadence only shortens time-to-notable
  for a *new* actor, which is what the Agentic Trust workshop and the AI Defense
  demo need (attack → Finding in Mission Control while the audience watches).
- OPERATIONAL NOTE: this is the one detection that ships `disabled = 0`, so the
  every-minute schedule is on by default. Each run is a `-24h` search over
  `gen_ai_log`; on a busy stack that is a materially heavier scheduler and
  search load than `*/30`. Override `cron_schedule` (or `disabled`) in
  `local/savedsearches.conf` to dial it back per environment.

### v1.6.5 (2026-08-26)

**Second pass of the notable data-minimization rule; Tokenomics pricing now self-seeds**

- FIXED (privacy): `AI Governance - Prompt Injection Detected (GenAI Judge) -
  Rule` interpolated `$explanations$` into
  `action.notable.param.rule_description`. That field is
  `gen_ai.prompt_injection.explanation` — unbounded free text the scoring judge
  writes *about* the prompt, and an explanation of why a prompt is an injection
  routinely quotes the prompt verbatim. It therefore carried the same PII/PHI
  and secret exposure into ES/Mission Control notables that `$injection_prompts$`
  did in the correlation rule fixed in v1.6.4, just one indirection removed.

  The `values(pi_explanation) as explanations` aggregation and the
  `Rationale: $explanations$` clause are both gone. The notable keeps the
  structured `$techniques$` (from `gen_ai.prompt_injection.types`) and
  `$confidences$`, and the existing drilldown already lands on the judge's
  scoring events in `gen_ai_log`, where the rationale can be read under that
  index's own access controls and retention. The rule ships `disabled = 1`, so
  unlike the v1.6.4 case this was opt-in rather than on by default.
- FIXED (docs): the README version header and the sample `Status: enabled`
  output still read 1.6.2 after the 1.6.3 and 1.6.4 releases.
- ADDED (dev tooling): `.claude/skills/splunk-ta-development/VALIDATION_RULES.md`
  and `check_package.sh` — the review findings from publish MRs are now an
  append-only, mechanically-checkable gate rather than tribal knowledge. Both
  fixes above were found by running that gate, not by a reviewer.
- ADDED (tokenomics): the `genai_token_cost` KV store now self-seeds.
  `lookups/genai_token_cost_seed.csv` ships current per-1M-token USD pricing
  for 40 provider/model pairs (80 rows) — every DemoBot static-emission model
  keyed both under provider `ollama` (static emissions keep
  `provider_name="ollama"` while spoofing the model) and under its real
  vendor, the self-hosted `mistral-nemo:12b`/`dolphin3:8b` at $0, and the
  AWS Bedrock models from the provider examples. A new scheduled search
  `GenAI - Tokenomics - Seed Token Cost Pricing` copies it into the
  collection at startup and hourly. The copy is insert-only and idempotent:
  a (provider, model, direction) triple already in the KV store — seeded,
  operator-added, or operator-expired — is never touched, so operator price
  management survives re-runs and upgrades only add new triples. Seeded rows
  carry null effective windows so backfilled/historical events price
  correctly. This search is the **second documented exception** to the
  "everything ships disabled" rule (R-SEC-002, amended): it ships
  `disabled = 0` + `run_on_startup = 1` so a fresh install renders non-zero
  costs with no manual step; it reads no event data and writes only shipped
  constants into the app's own collection. Opt out in
  `local/savedsearches.conf`.
- CHANGED (docs): `README/TOKEN_COST_ADMIN.md` gains an "Automatic Seeding"
  section; the stale "as of January 2024" bulk-insert example is superseded
  (it priced gpt-4o at 5.00/15.00 — current is 2.50/10.00 — referenced
  `amazon.titan-text-express` without the `-v1` suffix the events carry, and
  its `outputlookup` lacked `append=true`, which would have replaced the
  entire collection).
- FIXED (docs): the Tokenomics dashboard was missing from the README
  Dashboards table.

### v1.6.4 (2026-08-26)

**Packaging and notable-content fixes from the publish review**

- FIXED: `package.sh` built the tarball with a bare `bsdtar`, stamping
  `LIBARCHIVE.xattr.com.apple.provenance` onto every member. GNU tar — which
  the Artifactory publish and mapping jobs use — then emitted *Ignoring unknown
  extended header keyword* for each of the 127 entries. The build now sets
  `COPYFILE_DISABLE=1` and adds `--no-xattrs`, probed for rather than assumed so
  a non-macOS build host still works.
- FIXED (privacy): `AI Governance - Prompt Injection Attack Correlation - Rule`
  interpolated `$injection_prompts$` — raw input message text — into
  `action.notable.param.rule_description`. Because the rule ships enabled, any
  PII, PHI or secret inside an attack prompt was copied into ES/Mission Control
  notables, which carry their own retention and access path. This contradicted
  the app's own rule that content is DEBUG-only and never logged at INFO.

  The search no longer carries prompt text at all. The `is_injection` OR-chain
  is now a `case()` that labels which pattern fired — `instruction_override`,
  `guardrail_bypass`, `persona_jailbreak`, `jailbreak_mode`,
  `system_prompt_disclosure`, `obfuscated_payload`, `classifier_flagged` — and
  `stats` collects that label as `techniques` instead of the prompt body. The
  notable reports techniques and points the analyst at the drilldown to read the
  prompt in `gen_ai_log`, where index-level access controls apply. `techniques`
  is added to `nes_fields`.

  **Detection behaviour is unchanged.** All six regexes are reused byte-for-byte
  and `case()` is non-null exactly when the old OR-chain was true. Verified
  across the 1,055-row labelled corpus: **0 disagreements**, precision 98.3%
  matching the documented v1.6.2 figure.

### v1.6.3 (2026-08-26)

**ES response plan now attaches to the prompt injection investigation**

- FIXED: all three `AI Governance - * - Rule` correlation searches now set
  `action.notable.param.investigation_type = ai security incident`. Without it
  a Finding escalated to an investigation opened with **no response plan
  attached** — a response plan binds through the investigation type, never
  directly to a detection, and that key was missing entirely.
- FIXED: `default/data/response_plans/ai_incident_response_plan.json` set
  `origin` to a bare string. Mission Control's `ResponseTemplate` model calls
  `ResponseTemplateOrigin(**origin)`, so a string raised `TypeError` and broke
  every read through the `/response_templates` REST handler the ES UI uses. It
  is now the `{id, name, version}` object the model expects.
- ADDED: seven response plan tasks now carry native embedded searches under
  `suggestions.searches`, lifted out of the task prose. Earlier versions
  asserted that `mc_response_templates` had no structural key for an embedded
  search; that was inferred from `collections.conf`, which only declares scalar
  types and omits nested objects. `ResponseTask.suggestions` holds
  `searches[] {name, description, spl}` and is the documented mechanism for
  grounding the ES Triage agent.
- ADDED: `action.correlationsearch.annotations` (ATLAS `AML.T0051`, OWASP
  `LLM01`) to `AI Governance - Prompt Injection Attempt Detected - Rule`,
  matching its two siblings.
- ADDED: an **Enterprise Security integration** section to this README covering
  the binding chain, the manual UI steps, the suppression foot-gun, and the
  Triage agent prerequisites. `tools/` and `README/` are excluded from the
  tarball, so this was previously undocumented for anyone installing the app.
- FIXED (dev tooling, `tools/show_postdeploy.py`): the investigation type was
  `AI Security Incident`, which Mission Control rejects for containing
  uppercase; `response_template_ids` was written as a scalar where the handler
  expects an array; and the Triage agent allowlist keyed on the bare search
  name where the agent keys on `"<search name>+<app name>"`, so the entry never
  matched. Step 7 now reports SKIP with the entitlement requirements instead of
  a green OK on stacks where the agent cannot run.

### v1.6.2 (2026-08-25)

**Prompt injection correlation detection ships enabled**

- CHANGED: `AI Governance - Prompt Injection Attack Correlation - Rule` (ES
  Content Management label *GenAI - Prompt Injection Attack Correlation*) now
  ships `disabled = 0`. It is the entry-point detection for the Agentic Trust
  workshop and the AI Defense demo: with it enabled out of the box, a fresh
  install walks dashboard → correlation search → Finding in Mission Control
  without an operator first enabling the rule by hand.
- This is a deliberate, documented exception to the "everything ships disabled"
  convention introduced in v1.2.2. The search is read-only (no email, no
  ServiceNow, no outbound call), runs on a `*/30` cron over `-24h`, and
  suppresses per `actor` for 24 hours. Its only adaptive responses are the ES
  notable and risk actions, which no-op on a stack without Enterprise Security.
- Every other search in `default/savedsearches.conf` still ships
  `disabled = 1`. Override this one in `local/savedsearches.conf` to turn it
  off.

**Prompt injection correlation regex aligned with the proven scoring patterns**

- FIX: the `is_injection` pattern fallback in `AI Governance - Prompt Injection
  Attack Correlation - Rule` was a single regex requiring a trigger verb
  followed by `\s+` and then an object noun. It missed most real injections:
  punctuation after the verb defeated it (`SYSTEM OVERRIDE:` never matched),
  it had no roleplay/persona verbs at all, and `safety`/`filter`/`restriction`
  were absent from the object group. It is now six `match()` calls, one per
  technique family, deliberately aligned with the per-technique regexes already
  proven in `GenAI - Prompt Injection Scoring - Prompt Analysis`
  (`has_ignore_instruction`, `has_bypass_request`, `has_roleplay_injection`,
  `has_jailbreak_terms`, `has_reveal_request`, `has_encoding`).
- Two deliberate departures from the scoring search's copies, because this rule
  raises a notable and RBA risk so precision matters more: the verb/object gap
  is bounded (`.{0,60}`) rather than unbounded, and the object groups that are
  ambiguous in ordinary technical or clinical English are gated.
- MEASURED against `lookups/prompt_injection_training_examples.csv` (501
  labelled injections / 554 clean prompts): recall 6.4% → **70.3%**, precision
  97.0% → **98.3%**. Validated live on the Splunk Cloud Show stack against an
  indexed DemoBot spray campaign: **8 of 8** genuine injections across all
  actors (was 3), with 0 of 6 benign / reconnaissance turns flagged.

**Fix: JSON-array CIM fields never populated (braced multi-value field names)**

- FIX: `gen_ai.safety.categories`, `gen_ai.guardrail.ids`, `gen_ai.pii.types`,
  `gen_ai.response.finish_reasons` and `gen_ai.request.stop_sequences` were
  always null for `gen_ai:json` events. Emitters send these as JSON arrays, and
  `KV_MODE = json` auto-extracts a JSON array under the **braced** field name
  (`safety_categories{}`), not the bare name. Both mapping paths targeted the
  bare name — a `FIELDALIAS` in `props.conf` and a `SOURCE_KEY` in the
  `transforms.conf` `REPORT` — so neither ever matched. All five are now `EVAL`
  calculated fields that read the braced name first and fall back to the bare
  name, so array and scalar emitters both normalize. Verified live on the
  Splunk Cloud Show stack: an event carrying
  `safety_categories{}` = "AI Defense unavailable (fail-closed): HTTP 401:
  Unauthorized" produced a null `gen_ai.safety.categories`.
- FIX: same defect on `[medadvice:json]` — `extract_guardrail_ids_alt` keyed off
  `event.guardrails_triggered` instead of `event.guardrails_triggered{}`, so
  `gen_ai.guardrail.ids` never populated there either. Replaced with an `EVAL`.
- IMPACT: `AI Governance - Prompt Injection Attack Correlation - Rule` has three
  `is_injection` branches; the `like('gen_ai.safety.categories', "%Prompt
  Injection%")` branch could never fire. Measured across 10 live spray-campaign
  events: `via_safety_categories` = 0, `via_prompt_category` = 0, `via_regex` =
  3 — the detection rested entirely on the regex branch. Also affected the
  safety-violation severity classification, the guardrail trigger summary and
  every PII-types breakdown in `savedsearches.conf` and the safety dashboard.
- CLEANUP: removed the six now-dead `transforms.conf` stanzas
  (`extract_safety_categories`, `extract_guardrail_ids`,
  `extract_guardrail_ids_alt`, `extract_pii_types`, `extract_finish_reasons`,
  `extract_stop_sequences`) and their `REPORT-` references in `props.conf`. A
  `REPORT` cannot coexist with a calculated field on the same target — the
  `EVAL` runs later and wins — and under `KV_MODE = json` there is no remaining
  case for them to handle. New array-valued fields should use `EVAL` in
  `props.conf`, not a `REPORT` transform.
- KNOWN ISSUE (not changed here): on `[medadvice:json]`,
  `FIELDALIAS-genai_guardrail_triggered` maps the *array*
  `event.guardrails_triggered` onto the *boolean* `gen_ai.guardrail.triggered`.
  It has the same bare-name problem, but fixing it means deciding that "array
  is non-empty" implies `"true"`, which is a semantic change rather than a
  mapping repair. Left for a separate change.

### v1.6.1 (2026-08-12)

**Fix: escalation array fields defined with `EVAL` so multivalue is preserved**

- FIX: the three `demobot:escalation` fields sourced from JSON arrays —
  `conversation_history{}.role`, `conversation_history{}.content` and
  `symptoms{}` — were mapped with `FIELDALIAS`. They are now `EVAL` calculated
  fields. Testing on Splunk 10.4 confirmed the alias form *did* preserve
  multivalue (`gen_ai.escalation.roles` and `.messages` both resolved as
  3-value fields), so this is not a live-defect fix on that version. The Splunk
  field-alias documentation, however, does not define multivalue behaviour
  through an alias in either direction, and this TA targets Splunk 9.0+ and
  Splunk Cloud — depending on behaviour that is neither guaranteed nor
  described is a portability risk across versions. An eval assignment preserves
  multivalue by definition.
- DOCS: `props.conf` and README both record why these three use `EVAL`, so the
  mapping is not "simplified" back into `FIELDALIAS`. For any future
  array-valued field use `EVAL`, or a `REPORT` transform with `MV_ADD = true`.

### v1.6.0 (2026-08-12)

**DemoBot session-audit and human-escalation normalization**

- NEW: search-time normalization for the `demobot:audit` (session/user
  lifecycle) and `demobot:escalation` (human review) sourcetypes. Both were
  landing raw — no `gen_ai.*` fields, no eventtypes, no tags — while the
  inference stream on the canonical `gen_ai:json` sourcetype normalized
  correctly.
- Neither sourcetype is renamed onto `gen_ai:json`, deliberately. Neither
  carries a provider, model, token or cost field, so a rename would add them to
  the `gen_ai_inference` eventtype (which gates on `gen_ai.provider.name=*`)
  and inflate every inference count and every per-request cost, token and
  latency average. **If you attach your own audit or workflow stream, do not
  rename it onto `gen_ai:json` either** — give it its own stanza and leave
  `gen_ai.provider.name` unmapped.
- Each stanza instead normalizes the shared correlation keys
  (`gen_ai.session.id`, `gen_ai.request.id`, `gen_ai.event.id`, `enduser.id`,
  `gen_ai.user.id`) so audit and escalation events **join** to the inference
  events for the same session, then adds its own fields under
  `gen_ai.audit.*` and `gen_ai.escalation.*`.
- NEW: escalations populate the `gen_ai.review.*` namespace already shared with
  the review-queue KV store (`gen_ai.review.status`, `.reviewer`, `.notes`,
  `.updated_at`), so escalations and review findings line up.
- Escalated conversation turns are exposed as `gen_ai.escalation.messages` /
  `.roles`, **not** `gen_ai.input.messages` / `.output.messages`. The same turns
  already carry the inference field names on the corresponding `gen_ai:json`
  events; reusing them would double-count in content-based detections and copy
  prompt/response content (potentially PII/PHI) into a second namespace.
- FIX: correlation keys use `mvdedup()`. Events ingested before 2026-07-31
  carry `session_id` and `enduser_id` as HEC *indexed* fields as well as in the
  JSON body, so search-time extraction resolved both copies and the key became
  a 2-value multivalue — which silently breaks `join`, `dedup` and `stats by`
  on that subset. `mvdedup` collapses it and is a no-op on single-valued
  payloads.
- NEW: eventtypes `gen_ai_session_audit`, `gen_ai_human_escalation`,
  `gen_ai_escalation_critical` (severity `emergency` or `critical`) and
  `gen_ai_escalation_pending_review`, plus matching tags. These key on the
  normalized `gen_ai.audit.*` / `gen_ai.escalation.*` fields rather than on a
  sourcetype, so any emitter that normalizes to them participates.
- DOCS: README gains a "When NOT to rename" section covering non-inference
  governance events and how to verify with
  `index=gen_ai_log eventtype=gen_ai_inference | stats count by sourcetype`.

### v1.5.0 (2026-07-31)

**AI Defense incident response: simulated containment actions + response plan**

- NEW: three adaptive response actions for GenAI incident containment —
  `ai_defense_suspend_user`, `ai_defense_revoke_session`,
  `ai_defense_tighten_guardrail`. Each records a structured audit event in
  `gen_ai_log` under sourcetype `ai_cim:response:action` and reports success.
  See [AI Defense Response Actions](#ai-defense-response-actions).
  **These are SIMULATED** — every record carries `"simulated": true` and no
  external system is called. They let a deployment with no paired SOAR
  instance still produce a real adaptive-response entry and audit trail.
- NEW: `bin/ai_defense_response.py` holds the shared payload parsing, field
  resolution and audit emission; the three action scripts are thin wrappers.
  Per repo convention the shared logic is imported, never duplicated.
- NEW: `default/data/response_plans/ai_incident_response_plan.json` — an
  **AI Incident Response Plan** seed for the Mission Control
  `mc_response_templates` collection. Four phases (Identification,
  Containment, Eradication and Recovery, Post-Incident) with embedded
  drilldown SPL and references to the actions above. Values are plain text;
  Mission Control stores them URL-encoded, so the loader encodes on write.
  This plan also grounds the ES Triage agent, which reasons against the plan
  assigned to the investigation.
- CHANGED: `exclude_scoring_sourcetypes` now also excludes
  `ai_cim:response:*`, keeping response-action audit records out of inference
  metrics, dashboards and detections. Existing exclusions are unchanged.
- NEW: documented HEC ingest contract — send to `/services/collector/event`
  with an explicit `time` and a structured `event` object, which removes any
  index-time parsing dependency. `/services/collector/raw` is explicitly
  unsupported. See "Installation → Ingest contract".

### v1.4.0 (2026-07-29)

**Fix: normalization never applied — canonical `gen_ai:json` ingest sourcetype**

- FIX: `default/props.conf` carried the primary normalization layer (`KV_MODE`,
  52 field aliases, 9 calculated fields, 5 multi-value extractions) in a stanza
  named `[index::gen_ai_log]`. **props.conf has no `index::` scope** — per
  `props.conf.spec` a stanza may only be `<sourcetype>`, `host::`, `source::`,
  `rule::`, or `delayedrule::`, so Splunk parsed `index::gen_ai_log` as a
  literal *sourcetype name* and the stanza never matched a single event.
  The failure was silent: Splunk's default `KV_MODE = auto` still parses JSON,
  so flat fields (`provider_name`, `session_id`) resolved and the data looked
  correct, while every `gen_ai.*` field was null. Because
  `[gen_ai_inference]` in `eventtypes.conf` gates on `gen_ai.provider.name=*`,
  the entire eventtype → tag → data model → dashboard chain collapsed to zero
  for any deployment whose sourcetype had no stanza of its own.
- NEW: **`gen_ai:json` is now the canonical, documented ingest sourcetype.**
  It owns the single copy of the normalization layer. Send GenAI telemetry to
  `index=gen_ai_log` with `sourcetype=gen_ai:json`; see
  "Installation → Configure Data Inputs" for HEC and OpenTelemetry Collector
  (`splunk_hec` exporter) examples, and for the ingest-tier index-time settings
  that this search-time TA deliberately does not ship.
- **BREAKING:** `medadvice3:json` and `toyapp:json` are now one-line
  `rename = gen_ai:json` stanzas, removing ~200 lines of duplicated aliases.
  Searches filtering on `sourcetype=medadvice3:json` or `sourcetype=toyapp:json`
  **no longer match** — use `sourcetype=gen_ai:json`, or `_sourcetype=` to
  recover the original name. Note that `| tstats ... by sourcetype` and
  `| metadata type=sourcetypes` read index-time metadata and continue to report
  the original names. Any site-local *search-time* config under those stanza
  names is discarded by the rename; move it to a `[gen_ai:json]` stanza.
  If you built `AI_Inference` / `AI_Safety` / `AI_Evaluation` data model
  datasets in the UI with a `sourcetype=medadvice3:json` constraint, update
  them or they will silently return no results.
- FIX: `error.message` is now mapped (`error_message AS error.message`). It was
  present only in the dead stanza, so it has always been null. Deployments that
  enable `GenAI - Model Failure Alert` will see its `error_messages` field begin
  to populate — review for PII/PHI exposure in provider error strings before
  enabling.
- IMPROVED: boolean normalization uses the two-step `*_raw` pattern (alias the
  source value to `gen_ai.<x>_raw`, then compute the canonical field from the
  underscore source) rather than an `EVAL` that reads and rewrites the field it
  defines. Values such as `"TRUE"` now normalize to `"true"` instead of null,
  so safety/guardrail/PII eventtypes may match slightly more events.
- IMPROVED: `gen_ai.user.id` and `gen_ai.app.name` now coalesce three sources
  (`enduser_id, user_id, user` and `service_name, app_name, app`) instead of
  two, so more events resolve an application name. `gen_ai.app.name` is the key
  into `gen_ai_app_asset_map`, so newly-resolving names can create additional
  ServiceNow AI System asset rows on the next inventory sync.
- FIX: removed the same dead `[index::gen_ai_log]` stanza from `local/props.conf`,
  where it additionally carried `TRUNCATE` — an index-time setting that cannot be
  scoped this way under any stanza spec.
- NEW: declared the four `gen_ai.*_raw` boolean fields in `fields.conf`.
- DOCS: README and QUICKSTART now document the required sourcetype. The previous
  QUICKSTART instruction to retarget the TA by editing `[index::gen_ai_log]` to
  `[index::your_index]` could never have worked and has been replaced;
  "Customize Index Mapping" no longer recommends `INDEXED_EXTRACTIONS` in a
  search-time TA.

### v1.3.1 (2026-07-18)

**Security hardening — custom command permissions & SPL injection (no feature changes)**
- SECURITY: the `aicase` and `genaiscore` custom search commands are no longer
  exported with `read : [ * ]`. `aicase` is now restricted to `admin`, `sc_admin`,
  and `power` (matching the `open_case_in_servicenow` workflow action and the
  `gen_ai_snow_case_map` collection); `genaiscore` is restricted to `admin` and
  `sc_admin` (its scoring pipelines are admin-owned saved searches).
  **To grant either command to a custom analyst role, add a `[commands/<name>]`
  stanza with the desired `read` ACL to `metadata/local.meta`** — do not edit
  `default.meta`.
- SECURITY: `aicase.py` now escapes `gen_ai.event.id` (via the existing
  `_escape_spl_string` helper) before interpolating it into the event-lookup
  SPL, preventing a crafted event ID from injecting additional SPL that would
  run under the invoking user's session.
- SECURITY: the `open_case_in_servicenow` workflow action now URL-encodes its
  substituted field values (`$!field$`), and the `servicenow_case` redirect
  dashboard applies the `|s` search-string token filter before `| aicase`,
  so field content containing `&`, `"`, or `|` cannot alter the target URL or
  the dashboard search.
- INTERNAL: removed the misleading `passauth = splunk-system-user` lines from
  `commands.conf`. Splunk ignores `passauth` for chunked (v2 protocol)
  commands; both commands already run under the invoking user's session.

### v1.2.2 (2026-07-12)

**Code Review Remediation — Splunk Cloud & AppInspect hardening (no feature changes)**
- FIXED: `app.conf` now carries an `[id]` stanza and matches the documented version
  (v1.2.1 shipped in docs without an app.conf bump; this release supersedes it)
- NEW: `app.manifest` for Splunk Cloud ACS / self-service installs
- NEW: `default/server.conf` `[shclustering]` replication for the TA's custom confs
- NEW: `python.required = 3.13` on all custom commands, alert actions, and the REST
  handler (Python 3.13 readiness, clears AppInspect future-failures)
- CHANGED: all shipped scheduled searches are now `disabled = 1` by default —
  enable the ones you need per environment (see "Enabling the shipped searches")
- CHANGED: stock `admin` role is no longer modified by the app (Cloud best practice);
  grant `apply_ai_commander_command` / `list_ai_commander_config` per environment
- CHANGED: `metadata/default.meta` grants `sc_admin` (Splunk Cloud admin) access to
  the configuration pages alongside `admin`
- FIXED: packaging no longer strips the small sample lookup CSVs that
  `transforms.conf`/`inputs.conf` reference; Dashboard Studio `*.json.template`
  sources and internal docs are excluded from the package
- FIXED: ServiceNow OAuth client-credentials flow now sends `grant_type=client_credentials`
- FIXED: `| aicase mode=open` no longer creates a case; case deep links no longer
  hardcode `localhost:8000`; `create_snow_aicase` alert action honors `param.request_id`
- FIXED: KV-store lookup failures abort case creation instead of silently creating duplicates
- SECURITY: Gemini API key moved from URL query string to `x-goog-api-key` header;
  prompt/response content logging demoted to opt-in debug level
- INTERNAL: ServiceNow client consolidated (aicase.py now reuses sync_snow_asset.py
  helpers); Python 2 compatibility shims removed; bundled splunklib SDK upgraded

### v1.2.1 (2026-01-21)

**Governance Review Enhancements**
- NEW: PHI detection fields on Event Review page (PHI Present?, PHI Types)
- NEW: Conditional field visibility based on Detection Settings configuration
- ENHANCED: Event Review fields now hide/show dynamically when detection types are toggled
- NEW: Dedicated full-width Reviewer Notes section for improved documentation workflow
- NEW: Comprehensive Governance Review workflow documentation
- IMPROVED: JavaScript visibility logic with multiple fallback strategies for reliability
- IMPROVED: Event Review layout with Reviewer Notes in its own row above the three-column content

### v1.2.0 (2026-01-19)

**ServiceNow AI Case Management Integration**
- NEW: `aicase` custom search command for one-click case creation
- NEW: KV Store collection `gen_ai_snow_case_map` for auditable linkage
- NEW: Event Context menu workflow actions ("Open Case in ServiceNow")
- NEW: Alert action fallback for Splunk Cloud compatibility
- NEW: Secure credential storage via Splunk passwords.conf
- NEW: Setup utility (`snow_setup.py`) and configuration dashboard
- NEW: Comprehensive ServiceNow integration documentation

### v1.1.0 (2026-01-16)

**TF-IDF Anomaly Detection**
- NEW: TF-IDF anomaly detection model for prompts (`gen_ai.input.messages`)
- NEW: TF-IDF anomaly detection model for responses (`gen_ai.output.messages`)
- NEW: Combined anomaly scoring with risk levels (HIGH/MEDIUM/LOW/NONE)
- NEW: 6+ TF-IDF anomaly alerts (anomalous prompts, responses, high-risk, source IP)
- NEW: TF-IDF macros for preprocessing and scoring
- NEW: Training data lookup (`tfidf_training_examples.csv`)
- NEW: Comprehensive TF-IDF documentation
- 6 new normalized fields for TF-IDF anomaly detection

### v1.0.0 (2026-01-15)

**Initial Release**
- Multi-provider normalization (Anthropic, OpenAI, Bedrock, local)
- 60+ normalized fields aligned with OTel GenAI conventions
- 15+ governance alerts (safety, PII, drift, cost, latency)
- Complete dashboard XML with 20+ panels
- ML PII/PHI detection model (LogisticRegression)
- ML prompt injection model (RandomForestClassifier)
- Provider-specific examples and documentation
- Search-time normalization (no index-time changes)

---

## Support

### Documentation

- **Deployment Guide:** [README/DEPLOYMENT_GUIDE.md](README/DEPLOYMENT_GUIDE.md)
- **Provider Examples:** [README/PROVIDER_EXAMPLES.md](README/PROVIDER_EXAMPLES.md)
- **Dashboards:** [README/DASHBOARDS/](README/DASHBOARDS/) (AI Governance Overview, PII Detection, Prompt Injection, TF-IDF Anomaly, Review Queue)
- **Governance Review Workflow:** [README/GOVERNANCE_REVIEW.md](README/GOVERNANCE_REVIEW.md)
- **PII/PHI Detection (Complete Guide):** [README/ML Models/PII_Detection.md](README/ML%20Models/PII_Detection.md)
- **ML Detection:** [README/ML Models/README.md](README/ML%20Models/README.md)
- **TF-IDF Anomaly Detection:** [README/ML Models/TFIDF_Anomaly.md](README/ML%20Models/TFIDF_Anomaly.md)
- **Prompt Injection Detection:** [README/ML Models/Prompt_Injection.md](README/ML%20Models/Prompt_Injection.md)
- **Your Data Quick Start:** [README/YOUR_DATA_IS_READY.md](README/YOUR_DATA_IS_READY.md)
- **Token Cost Administration:** [README/TOKEN_COST_ADMIN.md](README/TOKEN_COST_ADMIN.md)
- **ServiceNow AI Case Integration:** [README/SERVICENOW_INTEGRATION.md](README/SERVICENOW_INTEGRATION.md)

### Contact

- **AI Governance Team:** ai-governance@example.com
- **Splunk Support:** support@splunk.com
- **AI Toolkit Issues:** ml-toolkit@splunk.com

---

## License

Apache License 2.0

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

## Acknowledgments

- **OpenTelemetry GenAI Semantic Conventions:** https://opentelemetry.io/docs/specs/semconv/gen-ai/
- **Splunk AI Toolkit Documentation:** https://docs.splunk.com/Documentation/MLApp
- **AI Risk Management Framework (NIST):** https://www.nist.gov/itl/ai-risk-management-framework

---

**Built with ❤️ for AI Governance**
