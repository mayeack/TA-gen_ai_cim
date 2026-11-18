# TA-gen_ai_cim

> **⚠️ ALPHA SOFTWARE** - This Technology Add-on is in active development. Features may change, break, or be removed without notice. Use at your own risk in non-production environments. This application is currently for demonstration purposes only.

**Splunk Technology Add-on for Generative AI Common Information Model**

Version: 1.9.0  
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
| **Cisco Duo** (Admin API, read-only) | Duo authentication / activity logs and a users snapshot for CIM Authentication, ES identities and user risk (v1.9.0, off by default) | *Cisco Duo (Admin API)* tab of the Configuration page (`/app/TA-gen_ai_cim/configuration`, not in the menu), then an input instance in `local/` - see [Cisco Duo identity feed](#cisco-duo-identity-feed-v190) |

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
  Version: 1.9.0
  Status: enabled
```

### Ingest contract: HEC (supported path for Splunk Cloud)

This TA is **search-time only** and targets search heads. It deliberately ships
no index-time parsing (`LINE_BREAKER`, `TIME_PREFIX`, `TIME_FORMAT`,
`TRUNCATE`) — on Splunk Cloud that parsing happens on the indexer tier, which
the TA does not reach. Its one data input, the optional Cisco Duo modular input
(v1.9.0, no instance ships), sets each event's time itself and may also run on
a heavy forwarder; see [Cisco Duo identity feed](#cisco-duo-identity-feed-v190).

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
and the `AI Governance - * - Rule` correlation searches (five since v1.9.0)
require Splunk Enterprise Security for their notable/risk actions (see
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
| **PII Detection** | ML-powered PII detection and monitoring. Hidden since v1.8.0 (`/app/TA-gen_ai_cim/pii_detection`) | [Details](README/DASHBOARDS/PII_DETECTION.md) |
| **Prompt Injection Detection** | Adversarial attack detection and analysis | [Details](README/DASHBOARDS/PROMPT_INJECTION_DETECTION.md) |
| **Compromised Identity** | AI Trust Lab 5: CII failed checks joined with AI Defense blocks (v1.8.0) | [Lab 5 section](#ai-trust-lab-5-compromised-identity-v180) |
| **Duo Identity Feed** | Cisco Duo authentications by action and denied/fraud by user (24 h), checkpoint lag per input from the indexed events, user snapshots, Duo identities merged into ES and users with Duo risk; reads zero until the Duo input and the identity source are added and the lookup gen and the rule enabled (v1.9.0) | [Cisco Duo section](#cisco-duo-identity-feed-v190) |
| **Identity Activity** | Per identity, what Cisco Duo knows next to what the AI application saw: Duo status and sign-ins by outcome, application sign-ins, verified AI turns (one per chat request) and blocks, turns that only claimed the identity's name counted apart as claimed, not verified (never a sign-in), Identity Risk Gate verdicts, ES risk events, findings and risk score by detection, ES identity category, a Duo sign-in to AI activity chain (an application sign-in matched on Duo's transaction id, a verified turn on user and time), and the source addresses seen by Duo, by the application or by both. Time range and identity inputs; the ES tile, Identity overview, Activity timeline and Risk by detection need Enterprise Security and show an error without it (v1.9.0) | [Cisco Duo section](#cisco-duo-identity-feed-v190) |
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
│   ├── README                     # What each script does and which session it runs as
│   ├── ai_defense_response.py     # Shared logic for the AI Defense response actions
│   ├── ai_defense_revoke_session.py    # Alert action: Revoke Session / API Key
│   ├── ai_defense_suspend_user.py      # Alert action: Suspend User (AI Defense)
│   ├── ai_defense_tighten_guardrail.py # Alert action: Tighten Guardrail Policy
│   ├── aicase.py                  # ServiceNow AI Case custom command
│   ├── create_snow_case.py        # ServiceNow case alert action
│   ├── genai_es_seed.py           # ES / SOAR seeding logic behind | genaiseedes
│   ├── genaiscore.py              # GenAI LLM scoring custom command
│   ├── genaiseedes.py             # | genaiseedes custom command
│   ├── pull_snow_inventory.py     # ServiceNow inventory pull alert action
│   ├── snow_setup.py              # ServiceNow CLI setup utility
│   ├── sync_snow_asset.py         # ServiceNow asset sync alert action + shared client
│   ├── ta_gen_ai_cim_account_handler.py  # REST handler for account management
│   ├── ta_gen_ai_cim_duo.py       # Cisco Duo modular input entry point (v1.9.0)
│   ├── ta_gen_ai_cim_duo_input.py # Duo input: log window, checkpoint, users snapshot
│   └── ta_gen_ai_cim_duo_api.py   # Read-only Duo Admin API client (v5 signing)
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
│   ├── inputs.conf                # ES Asset & Identity registrations + the Duo
│   │                              #   input's scheme defaults (no instance)
│   ├── macros.conf                # Search macros
│   ├── props.conf                 # Field normalization (search-time only)
│   ├── restmap.conf               # REST endpoint mapping
│   ├── savedsearches.conf         # Alerts/reports/rules (ship disabled;
│   │                              #   three documented enabled exceptions)
│   ├── server.conf                # SHC replication for custom confs
│   ├── ta_gen_ai_cim_*.conf(.spec)  # Custom config files and specs
│   ├── transforms.conf            # Extractions, CSV + KV store lookups
│   ├── web.conf                   # REST endpoint exposure
│   ├── workflow_actions.conf      # Event Context menu actions
│   └── data/ui/
│       ├── nav/default.xml        # Navigation menu
│       └── views/                 # 23 views (Studio + Simple XML)
├── metadata/
│   └── default.meta               # Permissions (admin + sc_admin on config and credentials)
├── elements/                      # Per-dashboard design docs (dev only, not packaged)
├── tools/                         # Dev-only utilities (not packaged)
│   ├── duo/                       # Fake Duo Admin API + Duo input/client tests
│   ├── install-dev.sh             # Copy app into a dev instance
│   ├── load_pii_model.sh          # MLTK model loader (dev only, writes to MLTK app)
│   ├── load_prompt_injection_model.sh  # MLTK model loader (dev only)
│   └── appinspect-cloud-*.{md,json}    # Last AppInspect results
└── README/                        # Extended documentation (not packaged), except:
    ├── alert_actions.conf.spec    #   packaged: alert action parameters
    ├── inputs.conf.spec           #   packaged: the ta_gen_ai_cim_duo input scheme
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
| `ta_gen_ai_cim_duo_identities.csv` | "GenAI - Identity - Duo Identity Lookup Gen" (v1.9.0, ships disabled; gitignored and excluded by `package.sh`) |

Do not ship placeholder CSVs for these — bundled lookup files overwrite the
runtime-generated versions on every app upgrade. For the same reason
`default/inputs.conf` registers none of them as an ES identity or asset source
(`[identity_manager://...]`), enabled or disabled: ES checks every source's
lookup file and logs an ERROR every 5 minutes while it is missing, so a source
ships only together with its file (R-INP-002). The Duo identity source is
therefore added by the owner
([Cisco Duo identity feed](#cisco-duo-identity-feed-v190), step 6).

### Views not in the navigation menu

Since v1.8.0 four views are **hidden** but kept: they carry
`isVisible="false"`, so they appear neither in the navigation menu nor in the
Dashboards listing, and still open by URL.

| View | URL |
|---|---|
| Configuration (ServiceNow account, GenAI summary, detection settings) | `/app/TA-gen_ai_cim/configuration` |
| GenAI Scoring Configuration | `/app/TA-gen_ai_cim/genai_scoring_config` |
| AI Asset Discovery | `/app/TA-gen_ai_cim/ai_asset_discovery` |
| PII Detection | `/app/TA-gen_ai_cim/pii_detection` |

Splunk's own **Datasets** view is no longer in the menu either. To show any of
them again, uncomment its line in `default/data/ui/nav/default.xml` (or copy
the nav to `local/`) and drop `isVisible="false"` from the view.

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

The `AI Governance - * - Rule` correlation searches register themselves
with ES automatically — `action.correlationsearch.enabled = 1` plus
`export = system` in `metadata/default.meta` is all ES needs to list them under
**Configure → Content → Content Management**. No registration file is required.

Attaching the shipped **AI Incident Response Plan** to the resulting
investigation needs records that live in the `missioncontrol` app, and Splunk
conf layering is per-app — a TA physically cannot ship into another app's
namespace. So the TA writes them itself at run time: the shipped search
**GenAI - ES - Seed Response Plan and SOAR Binding** (enabled,
`run_on_startup`, hourly) runs `| genaiseedes`, which seeds the plan and the AI
Findings queue, and binds the plan's Containment tasks to the simulated SOAR
identity provider when that app is on the paired SOAR. The finding's next steps
and recommended actions ship as conf on the detections themselves.

The TA does **not** seed an investigation type, and its detections set no
`investigation_type`, so findings open as the stack's default type. Add the plan
to an investigation with **Add response plan**, or make it apply automatically
by assigning it to an investigation type of your own (below).

### How a response plan binds to a detection

It does not bind to the detection. The chain is three hops:

```
savedsearches.conf (local/, yours)
  action.notable.param.investigation_type = <your type>
        |
        v   KV: mc_incident_types      (_key = the investigation type name)
  response_template_ids = ["b7c3f1a2-5d84-4e97-a1c6-3f9e02d47b58"]
        |
        v   KV: mc_response_templates  (_key = ai_incident_response_plan)
  template_id = b7c3f1a2-5d84-4e97-a1c6-3f9e02d47b58
```

`| genaiseedes` writes only hop 3, the plan itself
(`default/data/response_plans/ai_incident_response_plan.json`, update-or-create,
hourly and on startup). Hops 1 and 2 are yours: create an investigation type,
assign the plan to it (Option B, steps 2–3), then select that type on the
detections — in the detection editor or with
`action.notable.param.investigation_type` in `local/savedsearches.conf`.

The TA leaves hops 1 and 2 alone because Mission Control's investigation-type
API refuses deletes (`DELETE` answers 405), so a type the TA created could not
be cleaned up afterwards. From v1.6.3 to v1.7.1 the detections named a type,
`ai security incident`, for the seeder to create. On a stack where it never was,
ES reported the detection's investigation type as missing.

> **Investigation type names must be lowercase.** Mission Control rejects any
> uppercase character (its Role API is case-insensitive while the collection API
> is not). The value on the detection must match the `mc_incident_types` `_key`
> exactly, or the plan silently fails to attach. Never point a detection at a
> type the stack does not have.

### Automatic — `| genaiseedes`

| Step | What is written | Switch (`ta_gen_ai_cim_es.conf [es_integration]`) |
|---|---|---|
| Response plan | `mc_response_templates` `_key ai_incident_response_plan` — the shipped JSON, URL-encoded on write; actions/playbooks already attached to a task in the ES UI are preserved unless a shipped `soar_binding` replaces them | `seed_response_plan = true` |
| Compromised Identity plan (Lab 5) | `mc_response_templates` `_key compromised_identity_response_plan`, same rules; its containment task binds the **PseudoCo Identity** app's `pseudoco_identity` asset only when both already exist (never created by the seeder) | `seed_identity_response_plan = false` |
| Queue | `queues` `_key ai_findings_queue` — *AI Findings*. Seeded with no routing rule, so findings stay in the default *Analyst Queue* | same |
| Queue routing | Give the queue the rule `(rule_title =~ "^GenAI Prompt Injection" or rule_title =~ "^GenAI Compromised Identity")` (Mission Control rule-engine syntax, not SPL) so AI Governance findings land there. Grant analyst roles access to the queue in ES first: Mission Control shows a non-default queue only to admins until then | `route_findings_to_queue = false` |
| SOAR binding | Through Mission Control's pairing proxy (`/v1/soar/...`, no SOAR credential in the TA): if the **MedAdvice Identity Provider** app is installed on the paired SOAR, create its `medadvice_idp` asset and resolve the plan's `soar_binding` entries into real task actions (`disable user`, `clear user sessions`). Otherwise skip and preserve | `bind_soar_actions = true` |
| Simulator install | Install the app itself from `soar_apps/medadvice_idp/` when missing. The proxy has no install route, so this needs a `soar` account in `ta_gen_ai_cim_account.conf` (`url`, `auth_type = token` or `basic`, secret stored as the account password) | `install_simulator = false` |
| Triage agent | `ai_triage_enabled = 1` + add the primary detection and the Lab 5 rule to the allowlist, keeping every existing entry (no-op without the `allow_ai_triage` entitlement) | `enable_triage_agent = false` |

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
2. **Create an investigation type** *(optional — makes the plan auto-apply)*.
   *Configure → Findings and investigations → Investigation types → Create*,
   with a lowercase name of your choosing.
3. **Assign the plan.** On that type, *Investigation type associations →
   Response plans → Assign response plan*. Only **published** plans appear. The
   first plan in the list is the default for the type, and additions apply only
   to **newly started** investigations.
4. **Select the type on the detections** *(with step 2)*. In the detection
   editor, or `action.notable.param.investigation_type = <your type>` on the
   `AI Governance - * - Rule` stanzas in `local/savedsearches.conf`.

Without steps 2–4, add the plan to each investigation with **Add response
plan**.

### Verify

Let the correlation search fire, open the Finding, escalate it to an
investigation, and confirm the four phases populate (after **Add response
plan**, unless you completed steps 2–4).

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

## AI Trust Lab 5: compromised identity (v1.8.0)

Lab 5 ("Verify: Cisco Identity Intelligence") shows Cisco Identity
Intelligence (CII) catching a Duo account takeover, PseudoCo Assistant 4.23.0+
refusing the compromised identity before the model runs (the Identity Risk
Gate), Splunk joining CII failed checks with Cisco AI Defense blocks for the
same user, and SOAR disabling the account in Duo. Everything here is **off on a
product install**: the rule ships disabled, the persona identity input ships
disabled, `seed_identity_response_plan` ships false and the PseudoCo Identity
connector is not in the package. `tools/show_postdeploy.py --lab5` turns it on
for one room stack and `--lab5-teardown` turns it off again
(`tools/lab5-identity-runbook.md`).

| Piece | What it is |
|---|---|
| *AI Governance - Compromised Identity AI Attack Correlation - Rule* | CII takeover-check failures (webhook, 7 d; or PseudoCo Assistant's own signed-in events, 24 h) joined with AI Defense blocks (24 h) per identity; finding "GenAI Compromised Identity: $user$" |
| `genai_cii_*` macros | read the CII webhook events (index `cisco_identity_intelligence`) with `spath`; field paths provisional until the S6 capture |
| `genai_cii_takeover_checks` | the only checks that count: `mfa-flood`, `impossible-travel` (CII check IDs, listed in `genai_cii_takeover_check_ids`: the same checks the Identity Risk Gate refuses); overridable in `local/` |
| `genai_cii_gate_failed_check_rows` | CII evidence from PseudoCo Assistant's own signed-in events: the takeover checks in `identity_failing_checks`, plus an UNTRUSTED trust level; no webhook needed |
| `cii_provenance` | `CII webhook`, `backfill (lab5-setup)`, `PseudoCo Assistant gate lookup` or `synthetic test event` - a room stack never holds synthetic events |
| Compromised Identity Response Plan | seeded when `seed_identity_response_plan = true`; containment = PseudoCo Identity -> disable user |
| PseudoCo Identity (SOAR) | real Duo Admin API containment of the room's configured victim only; `simulated: false`; no undo |
| MedAdvice Identity Provider 1.1.0 | the Lab 4 simulator; refuses every Lab 5 identity |
| `pseudoco_identity_personas` | ES identity rows for the persona cast; input ships disabled |
| Compromised Identity dashboard | sign-ins, gate verdicts, CII failed checks, AI Defense blocks, the join, session revocations |

Two findings per victim are expected: the spray at the victim also raises the
prompt-injection correlation. Work the Lab 5 one. ES's 24-hour risk threshold
(*Risk - 24 Hour Risk Threshold Exceeded - Rule*) may add a third, depending on
the stack's RBA rule and the Risk data model's lag. On the ES 8.5.1 dry run of
2026-11-06 it raised nothing, although the victim had 180 risk in 24 hours.

---

## Cisco Duo identity feed (v1.9.0)

The TA can read Cisco Duo's own authentication and activity logs and its user
list through the Duo Admin API (read-only), and turn them into CIM
Authentication / Change events, ES identities and user risk. Everything ships
**off**: no input instance and no identity source ship (an owner adds both),
and the lookup gen and the rule are `disabled = 1`. Nothing calls Duo until an
owner adds an input instance in `local/`.

| Piece | What it is | Ships |
|---|---|---|
| `ta_gen_ai_cim_duo` modular input | `bin/ta_gen_ai_cim_duo.py` (entry point) over `ta_gen_ai_cim_duo_input.py` and the client `ta_gen_ai_cim_duo_api.py`; spec `README/inputs.conf.spec`. One Duo endpoint per instance: `authentication`, `activity` (Duo public preview; opt in) or `users` | scheme defaults only, no instance |
| Cisco Duo account | `auth_type = duo_hmac` in `ta_gen_ai_cim_account.conf`: the API hostname and the integration key; the secret key only in `storage/passwords` (`[passwords]` is admin, sc_admin) | none |
| `ta_gen_ai_cim:duo:authentication` / `:activity` / `:user` | search-time CIM mapping: Authentication for the authentication log and admin logins, Change for enrollments and other activity; no `cisco:duo:*` props | on (inert without data) |
| `genai_duo_*` macros | `genai_duo_index` (`index=duo`), `genai_duo_auth_events`, `genai_duo_activity_events`, `genai_duo_user_events`, `genai_duo_identity_scope` | on |
| *GenAI - Identity - Duo Identity Lookup Gen* | daily; writes `lookups/ta_gen_ai_cim_duo_identities.csv` (never shipped) from the newest complete users snapshot | disabled |
| `[identity_manager://ta_gen_ai_cim_duo_identities]` | the ES identity source that merges that file into ES identities, category `Cisco Duo users` | **not shipped**: `default/inputs.conf` holds only a commented example; an owner adds it in `local/` or in ES once the file has rows (step 6) |
| *AI Governance - Duo Authentication Fraud or Denial Burst - Rule* | user risk 80 when a user reports a push as fraud, 40 for 5 or more failed Duo authentications in 10 minutes (a fraud report is never one of the 5); one finding per burst, judged once when its events are indexed, its risk event dated at the Duo event; suppressed per burst (`burst_id`) | disabled |
| *AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule* | the takeover story as one high finding and user risk 80: the same identity had 5 or more failed Duo authentications in 10 minutes, then signed in to the AI application within 30 minutes (the sign-in matched to Duo's own record of it on the transaction id), then had a verified AI turn blocked within 60 minutes; one finding per sign-in, judged once when its events are indexed; suppressed per sign-in (`chain_id`); needs the application's identity events in the same stack | disabled |
| *Duo Identity Feed* dashboard | authentications by action, denied/fraud by user, checkpoint lag per input (from the indexed events), user snapshots, merged identities, users with Duo risk | on (reads zero until enabled) |
| *Identity Activity* dashboard | per identity: Duo status and sign-ins beside the AI application's sign-ins, verified turns and blocks, claimed, not verified turns counted apart, with ES risk events, findings, risk score and identity category; a time range and an identity input | on (the Duo columns read zero until the input runs; the ES tile, Identity overview, Activity timeline and Risk by detection need Enterprise Security and show an error without it) |
| `genai_identity_activity_events`, `genai_identity_verified_turn`, `genai_identity_claimed_events`, `genai_identity_claimed_turn`, `genai_identity_duo_class` | the five macros behind *Identity Activity* (the first two also behind home card 06 and the joined rule, so an override of either changes that detection too): the AI application's identity events (the raw term `identity_*` narrows the scan, the field filter decides), the one chat event that stands for a verified AI turn, the chat events of turns with no verified identity and the one of them that stands for a claimed, not verified AI turn (it names a user, and is never a sign-in), and the outcome of a Duo authentication (success, denied, fraud, other) | on |

### Turning it on

Run the input on **one** standalone search head or heavy forwarder. Its
checkpoint is a KV store collection, so a heavy forwarder needs the KV store
enabled.

1. In Duo, create an Admin API application with only **Grant read log** and
   **Grant resource - Read**.
2. Open `/app/TA-gen_ai_cim/configuration` (not in the menu), tab
   **Cisco Duo (Admin API)**, and add the account: a name, the API hostname
   (`api-<id>.duosecurity.com` or `.duofederal.com`), the integration key and
   the secret key. The tab saves through the account REST handler, which
   `default/web.conf` exposes to Splunk Web; Splunk Web reads that at startup.
3. Create the index (`duo` is what the macros assume; never `gen_ai_log`). If
   ES's accelerated Authentication searches (`summariesonly=t`) find no Duo
   events, add the index to `cim_Authentication_indexes`.
4. Enable the rule first (step 7): it judges Duo events as they are indexed,
   so it has to be running when the first poll brings the history in. Then add
   one instance per endpoint in `local/inputs.conf` and restart Splunk
   once, which registers the new scheme and starts the instances:

   ```ini
   [ta_gen_ai_cim_duo://duo_authentication]
   account = duo
   endpoint = authentication
   index = duo
   interval = 300

   [ta_gen_ai_cim_duo://duo_users]
   account = duo
   endpoint = users
   index = duo
   interval = 86400
   ```

   On Splunk Cloud, where `local/` cannot be edited, add each instance in
   Splunk Web instead: **Settings > Data inputs > Cisco Duo (AI Governance) >
   New**. The form asks for a name, Account, Endpoint, Lag and Initial
   lookback; tick **More settings** for the interval and the index. Steps 5
   and 7 are likewise done under **Settings > Searches, reports, and alerts**.

5. Enable *GenAI - Identity - Duo Identity Lookup Gen* in `local/`, but do
   **not yet add the identity source**. Wait until the users input has written
   a complete snapshot (the *Duo Identity Feed* snapshot panel shows it), run
   the lookup gen once by hand, and confirm that
   `| inputlookup ta_gen_ai_cim_duo_identities | stats count` returns more
   than 0.
6. Only then add the identity source. The TA does not ship its stanza: ES's
   identity manager checks the lookup file of every identity source every 5
   minutes, a disabled source's included, and logs
   `ERROR PersistentScript ... Lookup table was not found` to `splunkd.log`
   each time while the file is missing, which would be forever on an install
   that never turns Duo on. The order matters for a second reason: ES merges
   every enabled identity source in one search with no check that a source's
   file exists, so a missing CSV makes that search fail for every source, Duo
   or not, and ES retries it on every pass until the file appears. Add the
   source in one of two ways:

   - In `local/inputs.conf`, then restart Splunk or reload the inputs:

     ```ini
     [identity_manager://ta_gen_ai_cim_duo_identities]
     target = identity
     url = lookup://ta_gen_ai_cim_duo_identities
     category = Cisco Duo users
     description = Cisco Duo users from the Duo Admin API users snapshot (ta_gen_ai_cim:duo:user)
     disabled = false
     ```

   - In Enterprise Security (8.5): **Configure > All configurations**, in the
     **Data** section **Assets and identities**, the **Identity lookups** tab,
     then **New > New configuration**. In the *New identity manager* dialog
     choose the lookup definition `ta_gen_ai_cim_duo_identities` as the
     **Source**, give it the same **Name** (the *Duo Identity Feed* dashboard
     finds the merged rows by that source name), the **Category**
     `Cisco Duo users` and a **Description**, and save.

   Do not add it on a stack where `genai_duo_identity_scope` leaves no rows,
   for example a room stack that polls only the lab tenant.
7. Enable the rule. Do it before step 4 where you can: it judges what is
   indexed from 12 minutes before its first run, and nothing older. If the
   authentication input has already run, see *Judging history that is already
   indexed* below. Where this stack also receives the AI application's
   identity events, enable *AI Governance - Duo Denial Burst to Blocked AI Turn
   Correlation - Rule* at the same time (*The joined rule* below).

**Scripted, on a Splunk Cloud stack.** `tools/show_postdeploy.py --duo` does
steps 2, 3, 4 and 7 from a workstation, in the order a backfill needs: the
index through ACS (waited for), the account through the account handler,
search access to the index for the attendee role, both rules enabled, and only
then the authentication input, whose first poll reads the last 30 days.
`--duo-with-users` adds the users input and `--duo-with-lookup-gen` the search
of step 5; both are off unless asked for, because on a stack that polls only a
lab tenant they put the tenant owner's own record where the room can read it.
`--duo-teardown` undoes all of it, for the roles it is given: pass it the same
`--duo-attendee-role` as the setup (it reports any other role that still lists
the index, and removes no grant it was not asked to). It is dev-only tooling,
not in the package.
The Duo secret key is read from a named environment variable or a hidden
prompt, never from the command line, and the stack's certificate is verified
before anything is sent (`--duo-ca-file PATH` adds the CA of a stack whose
certificate no public root signed; the `SSL_CERT_FILE` variable is not read).
Every guard in it refuses on an answer it cannot read: nothing is created or
deleted because a check came back with an error. It never adds the identity
source (step 6). How often
the stack polls has no default: `--duo-auth-interval`, or `--duo-poll-slot K/N`
when N stacks poll one tenant. Its last step compares the bursts and chains the
rules should have raised from what is indexed with their risk events, so
history that was indexed while a rule was off is reported, not assumed. See
`tools/lab5-identity-runbook.md`, "`--duo` (per stack that polls Duo)".

### How the rule judges Duo events

- **Once, by index time.** Every 10 minutes the rule judges the Duo events
  that were indexed in one 10-minute slot (from 12 to 2 minutes before the
  run). Its time range is that slot of index time, not a window of event
  time, the slots follow each other with no gap and no overlap, and
  continuous scheduling (`realtime_schedule = 0`) runs every one, also after
  downtime (24 hours back by default). So it does not matter how late Duo
  delivers an event: `lag_seconds`, a slow poll or a 30-day first backfill.
  `dispatch.earliest_time` of this rule is therefore an edge of that slot,
  never how far back it reads events; it reads events up to 181 days back
  (Duo keeps 180).
- **Counted by event time.** Around the slot's events the rule reads the
  failures by when they happened, whenever they were indexed. A burst is a
  user's run of failures and fraud reports with no gap over 10 minutes. It
  raises *Duo authentication denial burst* in the one run that takes it to 5
  failures within 10 minutes, and *Duo user marked fraud* in the run that
  indexes its first fraud report. A fraud report counts as a fraud report
  only, never as one of the 5 failures: five fraud reports raise one finding
  (80), and a burst of other failures that also holds a fraud report raises
  both (40 and 80). More failures of a burst that was already judged raise
  nothing.
- **The risk event is dated at the Duo event, the finding when it is
  raised.** The result's time is the 5th failure, or the first fraud report,
  so a backfill gives each result the time a live run would have. The risk
  event keeps that time (ES's default; **Intermediate finding time source**
  changes it). ES stamps the finding itself with the time it was created and
  keeps the event time in `orig_time`, and the finding's own row in
  `Risk.All_Risk` (index `notable`, same score) carries the creation time
  too. So a backfilled burst adds its score to "last 24 hours" risk at the
  moment of the backfill, and can trip ES's 24-hour risk threshold rule then,
  even when the burst is days old. The description names the event time
  (`burst_time`), and the drill-down reads 10 minutes either side of the
  burst, not around the finding.
- **Suppressed per burst.** `burst_id` is `<user>:<burst|fraud>:<epoch of the
  event>`; the rule suppresses on it for 24 hours, so only a second judgement
  of the same burst is dropped. A new burst a minute later has a new id.
- **A page sent twice counts once.** Events are de-duplicated on Duo's
  `txid`, keeping the copy indexed first.
- **A run that fails loses its slot.** The slots do not overlap, so nothing
  judges a slot a second time: after a run that failed, or whose search was
  cut short, that slot's events count as already judged. Such a run is not in
  `scheduler.log` under a status of its own: a scheduled run whose search
  fails writes no `status` row at all, and the `status=continued` rows of a
  continuously scheduled search are deferrals of runs that then complete (on
  the dev instance, of 13 scheduled runs that failed in 30 days, 7 had no row
  for their slot and 6 only `continued` rows; `status!=success` found none of
  them and listed thousands of slots that were judged normally). So look for
  the slots that have NO successful run:

  ```spl
  index=_internal sourcetype=scheduler status=success
      savedsearch_name="AI Governance - Duo Authentication Fraud or Denial Burst - Rule"
  | stats count by scheduled_time
  | sort 0 scheduled_time
  | streamstats current=f last(scheduled_time) as previous
  | eval missed_slots=(scheduled_time-previous)/600-1
  | where missed_slots>=1
  | eval after=strftime(previous, "%F %T"), before=strftime(scheduled_time, "%F %T")
  | table after, before, missed_slots, previous, scheduled_time
  ```

  (divide by 300 for the joined rule). Each row is a gap: the runs scheduled
  after `previous` and before `scheduled_time` did not succeed, also while
  the rule was switched off. Why a run failed is in the audit log:
  `index=_audit action=search savedsearch_name="<rule>" (info=failed OR
  info=bad_request)` (a search error is logged as `bad_request` there). A run
  that was cut short, by a subsearch that hit its time limit for one, still
  logs `success` and is in neither: only comparing what should have been
  raised with what was catches it, which step D8 of
  `tools/show_postdeploy.py --duo` does by `burst_id`. Judge a lost slot again
  as described under *Judging history that is already indexed*, over exactly
  that slot.
- Do not switch the detection to ES's "index time" option, give it another
  time range, set `allow_data_time_skew`, or change its cron without the two
  dispatch times: the slot must stay exactly one period wide and on the cron
  tick.

### Judging history that is already indexed

The rule never looks back past its first slot. Where Duo history was indexed
before the rule was enabled, or a run lost its slot, judge that index time
once, by hand, and only that index time. A range that also covers index time
the scheduled runs have already judged raises their findings a second time:
one pass does not know what earlier runs raised, only the per-burst
suppression does, and it drops a repeat for 24 hours and no longer. A finding
raised more than 24 hours earlier comes back, under the same `burst_id`, and
adds its 40 or 80 to the user's risk again. So the one-off range needs BOTH
ends, as epoch times:

- **History from before the rule was enabled:** from `0` up to the START of
  the first slot a scheduled run judged, which is the rule's first
  `scheduled_time` minus 12 minutes (minus 7 for the joined rule):

  ```spl
  index=_internal sourcetype=scheduler status=success
      savedsearch_name="AI Governance - Duo Authentication Fraud or Denial Burst - Rule"
  | stats min(scheduled_time) as first_run
  | eval judge_from=0, judge_up_to=first_run-720
  ```

- **A lost slot:** exactly its two edges, the lost run's `scheduled_time`
  minus 12 minutes and minus 2 minutes (minus 7 and minus 2 for the joined
  rule).

In Splunk Web (edit the search's time range) or in `local/`, set
`dispatch.earliest_time` and `dispatch.latest_time` to those two values, let
one scheduled run finish (a `status=success` row for the rule in
`index=_internal sourcetype=scheduler`), and set them back to `-12m@m` and
`-2m@m`. Leave the one-off range in and the same findings are raised again
each time the suppression expires.

A stack set up with `tools/show_postdeploy.py --duo` does not need this for
its backfill: the rules are enabled before the input exists, so the first
poll is judged by the scheduled runs. The tool's step D8 says which bursts or
chains, if any, were never raised; treat a `never raised` there as a lost
slot, and find the slot with the search above.

### The joined rule: Duo burst, sign-in, blocked AI turn

*AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule*
(ships disabled) raises the takeover story as one finding. For one identity
(the same join key as above), in event-time order:

1. a Duo denial burst: 5 or more failed Duo authentications within 10 minutes
   (the Duo rule's threshold; here a fraud report counts as a failure);
2. then a sign-in to the AI application (`identity_signin_success`) less than
   30 minutes after a moment the failures stood at 5 or more;
3. then a blocked verified AI turn within 60 minutes of that sign-in. Any
   guardrail's block counts and is named; a turn that only claims the
   identity's name never does.

A burst that comes after the sign-in raises nothing.

- **One finding per sign-in**, high severity, user risk 80. `chain_id` is
  `<user>:takeover:<epoch of the sign-in>`, and the rule suppresses on it for
  24 hours. More blocked turns of a sign-in that was already judged raise
  nothing; a second sign-in with its own blocked turn is a second finding,
  also when the second chain follows within the hour and its burst is the
  step that is indexed last (live, the usual order). Its blocked turn was
  then first counted as one more turn of the first sign-in; it did not
  complete that chain, so it still completes its own. What is never raised
  again is a chain that holds the blocked turn that completed an earlier one.
- **Matched to Duo on the transaction id.** The application's sign-in record
  carries `details.duo_txid`, equal to the `txid` of the Duo authentication it
  rode on. The rule joins the two on it, exactly, and `signin_duo` names what
  Duo recorded for that sign-in (the factor and the Duo application). The
  match never decides whether the rule fires: a record with no transaction
  id, or whose Duo event is not indexed yet, still counts, and `signin_duo`
  then reads `none indexed`. On a live stack that is the usual case, because
  Duo's log trails the application by minutes and the rule does not wait for
  it; a chain that arrives in one backfill has it. A successful Duo
  authentication alone is never the sign-in step.
- **Judged once by index time, correlated by event time**, like the Duo rule:
  every 5 minutes it judges what was indexed in one 5-minute slot (from 7 to
  2 minutes before the run, `realtime_schedule = 0`) and reads the three
  steps 100 minutes either side of the slot's events, whenever they were
  indexed. A chain is raised by the run that indexes its last missing step.
  Live that is usually the Duo burst, 3 to 5 minutes after the blocked turn;
  on a stack that gets its history late it is whichever feed lands last, the
  sign-in or the blocked turn as well. The don'ts of the Duo rule apply
  unchanged, a run that fails loses its slot in the same way, and history
  indexed before the rule was enabled, or a lost slot, is judged with the same
  one-off time range, both ends given (*Judging history that is already
  indexed*; set them back to `-7m@m` and `-2m@m`).
- **Dated like the Duo rule.** The result's time is the first blocked turn of
  the sign-in, so a backfill dates it as a live run would have; the risk
  event keeps that time and the finding is dated when it is raised. The
  description names `burst_time`, `signin_time` and `blocked_time`, and the
  drill-down reads from 10 minutes before the burst to the last blocked turn.
- **What a finding names is what was indexed when it was raised.** The
  finding itself (its `chain_id`, its time, its risk) is the same from a live
  run and from a backfill. What it says about the burst is not always:
  `burst_time` is the last moment before the sign-in at which the failures
  stood at 5 or more among the failures indexed by then, and
  `duo_failures_10m`, the Duo applications, the start of the drill-down and
  `signin_duo` follow it. Live, the sign-in and the blocked turn are indexed
  minutes before Duo's log catches up. If an EARLIER burst lies within the 30
  minutes, the chain is complete without the nearer one, is raised, and names
  the earlier burst; one pass over the same events names the nearer one. On
  the dev instance, an index-time slot ending between the blocked turn and
  the burst (21:37 on 2026-11-16) named the first staged pass's burst of
  21:08:53, where a backfill names 21:34:09. Nothing corrects the finding
  afterwards: the chain is raised once. Holding a sign-in back until Duo's
  log has passed it would make the two agree, at the price of a delay on
  every finding; that is an open decision and is not built.
- **It needs both feeds in the stack.** The Duo input backfills its history;
  the application's HEC feed does not. On a stack created after the activity
  the rule raises nothing until the application's identity events are sent
  again with their original time and event ids (a second copy of an event is
  de-duplicated on its event id, a sign-in also on its transaction id).
- **Limits.** The order of burst and sign-in is judged on the application's
  time for the sign-in, so clocks that disagree by more than the seconds
  between a burst's fifth failure and the sign-in can misorder them. The two
  windows (30 and 60 minutes) are fixed in the search. Its alert actions and
  its suppression have not run on a schedule yet.

### Identity Activity: claimed, not verified turns

*Identity Activity* counts two kinds of AI turn for an identity, side by side,
and never adds them:

- **Verified** (`ai_turns`, `ai_blocked`; *AI turn allowed* and *AI turn
  blocked* on the timeline): the one chat event of a turn made under a
  verified identity session (`genai_identity_verified_turn`).
- **Claimed, not verified** (`claimed_not_verified`, `claimed_blocked`; *AI
  turn claimed, not verified* on the timeline): the one chat event of a turn
  that names the user with no verified session behind it
  (`genai_identity_claimed_turn`, read through
  `genai_identity_claimed_events`). A prompt-injection spray that names a
  persona writes these, and so does every anonymous turn. The name is only
  what the request carried: such a turn is never a sign-in, is never matched
  to a Duo sign-in, and never counts for the joined rule above.

A claimed name only adds to an identity that is already in the view. A name
with no Duo sign-in and no application identity event in the time range gets
no row, no dropdown entry and no bar, so text sent in a request cannot put
itself on the page. The price: a persona that was idle in the chosen range
does not show a spray that named it (widen the range).

**What a staged lab needs.** The claimed count is read from the AI
application's own events, like `ai_turns` and `app_signins`. For a review to
show it above 0 for the persona, on the stack the attendee looks at:

1. The staged scenario includes a prompt-injection spray that names the
   persona. Sign-ins and signed-in turns alone leave `claimed_not_verified`
   at 0: the two staged passes of 2026-11-16 on the dev instance held no
   spray and read 0.
2. The application's events for the staging are in that stack. The Duo input
   backfills its history into a new stack; the application's HEC feed does
   not. On a stack created after the staging, `claimed_not_verified`,
   `ai_turns` and `app_signins` all read 0 for the staged days unless those
   events are sent to that stack as well (nothing in the TA does that). Send
   each event once, with its original time: unlike the joined rule, the view
   counts events and does not drop a second copy.
3. The spray, and a Duo sign-in or an application identity event of the
   persona, fall inside the time range of the view (default: the last 14
   days).

A read-only check, over the time range the review will use. 0 means the stack
holds no such turn in that range: no spray named the persona, the
application's events never reached this stack, or the spray is outside the
range.

```spl
`genai_identity_claimed_events`
| where `genai_identity_claimed_turn`
| eval identity_key=`genai_identity_join_key(user)`
| search identity_key="<persona>"
| stats count as claimed_not_verified, count(eval('gen_ai.policy.blocked'=="true")) as claimed_blocked,
    min(_time) as first, max(_time) as last
| eval first=strftime(first, "%F %T"), last=strftime(last, "%F %T")
```

### How the input reads Duo

- Every log request sends `sort=ts:asc`; each run makes one Duo log call (up
  to 1000 records), which is what Duo asks for ("no more than once per
  minute"). At `interval = 300` that caps one log input at about 288,000
  records a day: a tenant that writes more falls behind, and records that
  reach Duo's 180-day retention before they are read are lost. The interval
  floor is 120 s: the input rejects less, and a run that starts under 115 s
  after the last checkpoint write is skipped, so an interval set lower
  directly in `local/` cannot poll faster.
- The checkpoint (KV `ta_gen_ai_cim_duo_checkpoint`, one row per instance:
  `mintime_ms`, `maxtime_ms`, `next_offset`, `backoff_until`, `updated`) is
  saved after each page. Duo returns a `next_offset` on the last page that has
  records too, and only the call after it comes back without one, so a saved
  `next_offset` is a cursor, not a sign of more records: the next run resumes
  after it with `mintime` = the cursor's timestamp and `maxtime` = now minus
  `lag_seconds` (default 180, at least 120: Duo delays its logs about two
  minutes), as Duo's own duo_log_sync resumes. A page with no records, or with
  no `next_offset`, completes the window, and the next window starts at that
  call's `maxtime` + 1 ms; a `next_offset` equal to the one sent completes it
  too (WARN). A run whose window would be empty is skipped.
- A window is never abandoned while Duo still holds records it has not read.
  When Duo's retention floor (180 days less an hour) passes the cursor, the
  window resumes at the floor (WARN), so only records Duo no longer has are
  missed; `initial_lookback_hours = 4320` backfills everything Duo still holds,
  1000 records a run.
- **Two known windows.** A run killed after writing a page but before saving
  its checkpoint sends that page again, so deduplicate on `txid`. Events still
  in splunkd's pipeline when splunkd crashes are not read again (at most once).
- HTTP 429 / Duo code 42901 backs off for 120 s, doubling per consecutive 429
  up to an hour.
- A users snapshot reads every page in one run and writes an allowlist of
  fields (no phones, tokens, WebAuthn or desktop-authenticator records, no
  notes) plus `snapshot_id`, `snapshot_total` and `snapshot_seq`. A page that
  answers 429 or fails transiently (Duo unreachable, HTTP 5xx) is retried in
  the same run up to 6 times, waiting 1 s doubling to 32 s plus jitter and at
  least `Retry-After`, with at most 120 s of waiting per snapshot, as
  duo_client_python retries. Only a page still failing after that, or the page
  cap, leaves the run without a snapshot, and then it writes nothing.
- On a search head cluster only the captain polls. This guard is best effort
  and has not been tested on a real cluster.

### Identities and risk

- identity is the user's lowercased, de-duplicated username|email|aliases,
  username first, and ES keeps that order: SA-IdentityManagement rejoins
  identity into one pipe-delimited value (`mvdedup`, then `mvjoin`) before the
  merge's `mvsort`, which therefore sorts a single value, and the merge splits
  it again in order. So the canonical key (the first `normalized_identity`
  value, which UEBA reads) is the Duo username, whatever sorts first. The
  lookup gen's fixture "the newest COMPLETE snapshot wins over a newer
  incomplete one" (`tools/tests/fixtures/duo_spl.json`, run live by
  `test_duo_spl.py`) pins that order; Splunk documents `mvdedup` only as
  removing duplicates.
- The rule's risk object is `genai_identity_join_key(user)`, the lowercased
  local part of the Duo username, the same key the Lab 5 rule uses. Where a
  tenant's Duo usernames are emails, that local part is not one of the
  identity's keys, so ES matches the risk to the identity only when the Duo
  identity source sets `dynamic_identity_spec = {"email_short": true}` (on the
  `[identity_manager://ta_gen_ai_cim_duo_identities]` stanza you add in
  `local/inputs.conf`, or the **Email Short** convention in the ES dialog;
  ES then adds each email's local part as a key). That is a per-source
  setting, not a global Assets & Identities one. Two users who share a local
  part in different domains share one risk object.
- `genai_duo_identity_scope` keeps Lab 5 participant accounts (`l5-*`) out,
  and every Lab 5 persona (`pseudoco_identity_personas`): a user whose keys
  include a persona email, or a persona's short name with no Duo email (a
  persona whose Duo email is empty). A customer user who only shares a
  persona's short name, with an email of their own, stays in.
- On ES Essentials the risk feeds Entity Risk Scoring; the UEBA screens need
  ES Premier.

### Scope and coexistence

- The rule reads the Duo authentication events themselves, scoped by
  `genai_duo_auth_events` (index and sourcetype), and uses the CIM fields the
  props set (`user`, `action`, `signature_id`, `src`, `app`). It does not read
  the CIM Authentication data model: an accelerated data model keeps no index
  time, so `tstats` on it cannot say which events are new. It does not filter on
  `authentication_service=duo`, because PseudoCo Assistant's own Duo sign-in
  records carry that value too and would be counted twice (the Duo sourcetypes
  still set `vendor_product = "Cisco Duo"` for raw searches). Keep
  `genai_duo_auth_events` to index, sourcetype, source or host terms with no
  pipe: the rule puts more search terms and subsearches after it.
- The TA ships no props, eventtypes or tags for Cisco Security Cloud's
  `cisco:duo:*` sourcetypes. Do not run both inputs against one tenant, or
  every Duo event is indexed twice. The macros can point at Security Cloud
  data, but the TA's CIM mapping and the lookup gen's snapshot fields do not
  come with it, and the rule counts that data only if its own mapping sets the
  same `action` and `signature_id` values.
- No `user_agent` is synthesized: Duo sends a browser and a version, not a
  user agent string.

---

## Version History

### v1.9.0 (2026-11-17)

**Cisco Duo identity feed for ES and UEBA** (everything new ships off; see
[Cisco Duo identity feed](#cisco-duo-identity-feed-v190))

- ADDED: Cisco Duo modular input `ta_gen_ai_cim_duo` (entry point
  `bin/ta_gen_ai_cim_duo.py` over `bin/ta_gen_ai_cim_duo_input.py`, spec
  `README/inputs.conf.spec`), off by default with no instance shipped. One
  endpoint per instance: `authentication`, `activity` (Duo public preview, opt
  in) or `users`. Every log request sends `sort=ts:asc`; `mintime`, `maxtime`
  and `next_offset` are checkpointed together after each page in the KV
  collection `ta_gen_ai_cim_duo_checkpoint`. A saved `next_offset` is a cursor
  the next run resumes after, with `maxtime` = now minus the lag (Duo returns a
  `next_offset` on its last page with records too); a page with no records or
  no `next_offset`, or a `next_offset` echoing the one sent, completes the
  window, and the next one starts at `maxtime` + 1 ms; empty windows are
  skipped; a window is never abandoned while Duo still holds unread records,
  and resumes at the retention floor once the floor passes its cursor. One Duo
  log call per run, up to 1000 records. HTTP 429 / code 42901 backs off
  exponentially (120 s doubling to 1 h); the 120 s interval floor is validated
  and also held at runtime. The users snapshot writes an allowlist of fields
  with `snapshot_id` / `snapshot_total` / `snapshot_seq`, and retries a page
  that answers 429 or a transient error up to 6 times in the run (1-32 s with
  jitter, at least `Retry-After`, at most 120 s in all). Best-effort search
  head cluster guard: only the captain polls (untested on a real cluster).
  Known windows: one page may repeat after a run is killed (deduplicate on
  `txid`), and events still in splunkd's pipeline when splunkd crashes are not
  read again (at most once). As first built (review, 2026-11-16) the window
  kept `maxtime` fixed until Duo returned no `next_offset`, which cost an empty
  extra run per window against a real Duo, stalled for good on a Duo that
  echoes the `next_offset` it was sent, and abandoned an unfinished window
  once the retention floor passed its start (with `initial_lookback_hours =
  4320`, all but the first 1000 records of the backfill); a 429 on any users
  page discarded the snapshot.
- ADDED: `bin/ta_gen_ai_cim_duo_api.py`, the canonical read-only Duo Admin API
  client (v5 HMAC-SHA512, verified TLS, 20 s timeout, `next_offset` / offset
  paging; HTTP 5xx and an unreachable Duo raise `DuoUnavailable`). Its v5
  signer is proven identical to the Lab 5 SOAR connector's
  (`tools/duo/tests/test_duo_api.py`); it never imports `soar_apps/`. A
  rejected account `url` is never echoed in an error: the input logs that
  error at ERROR, and a `url` written by hand skips the handler's validation,
  so it may hold a pasted secret.
- ADDED: Cisco Duo (Admin API) accounts: `auth_type = duo_hmac` in the account
  REST handler, plus a *Cisco Duo (Admin API)* tab on the Configuration page
  that saves only through the handler. The API hostname is validated and
  normalized to `https://api-<id>.duosecurity.com` or `.duofederal.com`. The
  integration key goes in the conf; the secret key goes only to
  `storage/passwords` (realm `ta_gen_ai_cim_account__<name>`, `client_secret`)
  and is never returned, logged or echoed.
- ADDED: sourcetypes `ta_gen_ai_cim:duo:authentication`, `:activity` and
  `:user` (search-time CIM Authentication and Change mapping), eventtypes
  `ta_gen_ai_cim_duo_authentication`, `_enrollment`, `_admin_login` and
  `_activity` with their tags, macros `genai_duo_index`,
  `genai_duo_auth_events`, `genai_duo_activity_events`,
  `genai_duo_user_events` and `genai_duo_identity_scope`, and the lookup
  definition `ta_gen_ai_cim_duo_identities`. No props for any `cisco:duo:*`
  sourcetype, so nothing clashes with Cisco Security Cloud.
- ADDED: *GenAI - Identity - Duo Identity Lookup Gen* (ships **disabled**,
  owner = admin): the newest complete users snapshot into
  `lookups/ta_gen_ai_cim_duo_identities.csv` (gitignored, never packaged), the
  file behind the ES identity source
  `[identity_manager://ta_gen_ai_cim_duo_identities]` (category
  `Cisco Duo users`). That source does **not** ship as a stanza:
  `default/inputs.conf` holds it only as a commented example, and an owner
  adds it in `local/inputs.conf` or in ES (the FIXED entry below says why).
  identity is the lowercased username|email|aliases, username first (ES keeps
  the order, so the Duo username is the canonical key); Lab 5 participants and
  personas stay out by key. A persona's bare short name drops a user only when
  that user has no Duo email, so a customer user who shares one (`grace.lin`
  with an email of their own) is kept. Add the identity source only once the
  lookup has rows: ES's merge search fails for every identity source while an
  enabled source's file is missing.
- FIXED (found live on ES 8.5.1, 2026-11-16): the Duo identity source first
  shipped as a `default/inputs.conf` stanza with `disabled = true`. Its CSV is
  generated at runtime and never ships, and ES's identity manager
  (SA-IdentityManagement, every 300 s) checks the lookup file of **every**
  `identity_manager` source, a disabled one included. `splunkd.log` therefore
  got `ERROR PersistentScript ... Lookup table was not found: [HTTP 404]
  .../data/lookup-table-files/ta_gen_ai_cim_duo_identities.csv` every 5
  minutes for as long as the file did not exist, which is forever on an
  install that never turns Duo on (the identity merge itself still ran). The
  stanza no longer ships. A header-only CSV was not an option: a bundled
  lookup file overwrites the generated one on every upgrade.
- ADDED: *AI Governance - Duo Authentication Fraud or Denial Burst - Rule*
  (ships **disabled**): user risk 80 for a push the user marked as fraud, 40
  for 5 or more failed Duo authentications in 10 minutes, on the identity join
  key, with `_entities` and no `risk_object` (R-CONF-006) and no raw content
  (R-SEC-001). It is scoped by the sourcetype through `genai_duo_auth_events`,
  not by `Authentication.vendor_product` as designed: CIM 8.5.0's
  Authentication data model has no `vendor_product` field, so that filter
  would match nothing. The scope also keeps PseudoCo Assistant's own Duo
  sign-in records (`authentication_service=duo`) from being counted twice.
- CHANGED before release (review decision LR-07, 2026-11-17): the rule judges
  each Duo event once, by index time, and counts by event time. As first
  built it ran every 10 minutes over the last 30 minutes of EVENT time,
  throttled per user and signature for 30 minutes, which had two flaws, both
  seen on the dev instance: Duo events indexed more than 30 minutes late
  never raised risk (the first poll's 30-day backfill was indexed at 15:02
  and the 15:10 run returned nothing), and because the throttle equalled the
  window a second burst soon after a finding could be missed (a burst 25
  minutes after a finding was suppressed at the next run and raised only one
  second after the throttle expired). Now the time range is a 10-minute slot
  of index time, bursts are counted by event time around the slot's events,
  each result is dated at its Duo event (the risk event keeps that time; ES
  dates the finding when it is raised), suppression is per burst (`burst_id`,
  24 hours), events are de-duplicated on `txid`, and the drill-down reads the
  burst's own time range. A fraud report is judged as a fraud report only and
  no longer also counts as one of the 5 failures of a burst, so the two
  signatures are judged on disjoint events and a backfill raises exactly what
  live runs would have. The rule no longer reads the Authentication data
  model: accelerated summaries keep no index time (`tstats` on the data model
  with `_index_earliest` returned no row and `_indextime` no value on ES
  8.5.1). See *How the rule judges Duo events*.
- ADDED (review decision LR-06, 2026-11-17): *AI Governance - Duo Denial Burst
  to Blocked AI Turn Correlation - Rule* (ships **disabled**), the first
  search of the TA that reads both feeds. For one identity it joins a Duo
  denial burst (5 or more failed Duo authentications within 10 minutes), then
  an application sign-in less than 30 minutes later, then a blocked verified
  AI turn within 60 minutes of that sign-in, into one high finding and user
  risk 80, with `_entities` and no `risk_object` (R-CONF-006) and no raw
  content or transaction id outbound (R-SEC-001). The sign-in is matched to
  Duo's own record of it on the transaction id (`details.duo_txid`) when that
  record is indexed (`signin_duo`); the match never gates the rule. It judges
  by index time and correlates by event time like the Duo rule (a 5-minute
  slot, 100 minutes of context either side), raises a chain once, in the run
  that indexes its last missing step, dates the result at the first blocked
  turn and suppresses per sign-in (`chain_id`, 24 hours). It needs the
  application's identity events in the same stack: the Duo input backfills,
  the application's HEC feed does not. See *The joined rule*.
- ADDED: *Duo Identity Feed* dashboard (`ta_gen_ai_cim_duo_identity`,
  Dashboard Studio, absolute layout, dark): Duo authentications by action and
  denied/fraud by user (last 24 h; the user is the identity join key, never
  the raw Duo username, which is an email address on some tenants);
  checkpoint lag per input instance from the
  indexed events (`tstats` on the `genai_duo_*` macros, never REST or the
  checkpoint collection); Duo user snapshots judged like the lookup gen
  (complete = event count equals `snapshot_total`, same -3d window); Duo
  identities merged into `identity_lookup_expanded` (first key as the
  identity join key, no email column); users with Duo risk from
  `Risk.All_Risk`, risk events and findings counted apart (see the *Risk*
  note under *Identity Activity* below). Home card 05 (KPI *Duo
  authentications, last 24h*) and a Dashboards menu entry; the scoreboard
  moves down one card, unchanged.
- ADDED: *Identity Activity* dashboard (`ta_gen_ai_cim_identity_activity`,
  Dashboard Studio, absolute layout, dark): per identity, what Cisco Duo knows
  next to what the AI application saw. The identity is the lowercased local
  part of the login (`genai_identity_join_key`), so a Duo username and the
  user of a verified AI turn line up. A time range input (default last 14
  days) and an identity dropdown fed by the identities of either feed apply to
  every panel. Six KPI tiles (identities with Duo sign-ins, Duo sign-ins
  succeeded, denied or marked fraud, identities with verified AI turns,
  verified AI turns blocked, identities with ES user risk); an *Identity
  overview* table (Duo status and enrolment from the newest complete users
  snapshot in the range, Duo success / denied / fraud / other, last Duo
  sign-in and factor, application sign-ins, verified AI turns and blocks,
  Identity Risk Gate verdicts, ES risk events, findings and score, ES identity
  category); an *Activity timeline*; *Duo sign-in to AI activity*; *Source
  addresses by identity* (Duo only, application only, both); *Risk by
  detection*. Events are read only through `genai_duo_auth_events`,
  `genai_duo_user_events` and the new `genai_identity_activity_events` (over
  `genai_identity_ai_events`; its raw term `identity_*` only narrows the scan,
  the field filter decides). Four things the first build got wrong, found in
  review on live data (2026-11-16) and corrected before release:
  - *Sign-in chain.* The application's `identity_signin_success` record
    carries Duo's transaction id (`details.duo_txid`, equal to the `txid` of
    the Duo authentication), so an application sign-in is matched on that id,
    whatever the two clocks say. Only a verified turn carries no such id: the
    first verified turn after each application sign-in, and a sign-in whose id
    is not in the range, are matched on user and time, not on a session key
    (the nearest earlier *successful* Duo authentication of the identity
    within 10 minutes, to any Duo-protected application). `matched_on` says
    which, and `duo_denied_10m` counts the identity's denied or fraud Duo
    authentications in the 10 minutes before. The first build stated that the
    application does not log Duo's transaction id, matched everything on
    time, and so could pair a sign-in with a denial from another address a
    second earlier. A row under 15 minutes old with no match reads *Duo log
    may not be in yet* (Duo's log lags by the input's lag plus its poll
    interval) and the panel re-runs every 5 minutes.
  - *A verified AI turn* is the turn's one chat event
    (`genai_identity_verified_turn`: provider set, operation `chat`).
    PseudoCo Assistant stamps `identity_verified` on every event of a
    signed-in turn (tool calls, decisions and, on a single-sourcetype HEC
    destination, the escalation record), so "verified and not an audit
    record" counted a turn with a record lookup two or three times and a
    blocked tool call as a blocked turn.
  - *Duo outcomes* come from one macro (`genai_identity_duo_class`): success,
    denied (Duo result denied or failure), fraud, and other (error or anything
    else). The tiles, the overview and the timeline add up to the same total;
    before, a result of failure or error counted in no tile and as a failure
    in the timeline.
  - *Risk.* ES 8's Risk data model reads the notable index as well as the
    risk index, so one firing of a rule that writes a risk event and raises a
    finding is two rows. The overview shows `risk_events` and `findings` apart
    and the timeline draws them as two series; `risk_score` and *Risk by
    detection* stay the total of both, which is ES's own entity risk. The risk
    subsearches filter on the chosen identity and return the newest (or the
    riskiest) rows first, because `append` keeps only 50,000; the timeline
    reads risk in 5-minute buckets up to a 2-day range and hourly beyond.

  The ES tile, *Identity overview*, *Activity timeline* and *Risk by
  detection* read `Risk.All_Risk` (user risk) and `identity_lookup_expanded`
  and need Enterprise Security: without it they show an error, the overview
  and the timeline included, although their Duo and application content needs
  none (a `tstats` on a missing data model is fatal even inside `append`). The
  five Duo and application tiles, the sign-in chain and the address table do
  not depend on it. No prompt or response text, email address or phone number
  is shown. Home card 06 (KPI *identities active, last 24h*: distinct
  identities with a Duo sign-in or a verified AI turn) and a Dashboards menu
  entry after *Duo Identity Feed*; the scoreboard moves down one more card,
  unchanged.
- ADDED (*Identity Activity*, lab-readiness review 2026-11-17): claimed, not
  verified AI turns (review decision LR-08). The view counted only
  Duo-verified turns, so a prompt-injection spray that merely names a
  persona, with no identity session, read as 0 AI turns for that persona
  while Enterprise Security showed the spray's risk on the same name.
  *Identity overview* now has `claimed_not_verified` and `claimed_blocked`
  after `gate_verdicts`, and the *Activity timeline* one more series, *AI
  turn claimed, not verified*, drawn pale so it is told apart from the two
  sign-in series by lightness as well as by name. A claimed turn is the one
  chat event of a turn that names a user with no verified identity
  (`genai_identity_claimed_turn`, read through
  `genai_identity_claimed_events`). The name is only what the request
  carried, so a claimed turn is never a sign-in, never part of `ai_turns` and
  never matched to a Duo sign-in, and the two counts are never added. A name
  that is only claimed, with no Duo sign-in and no application identity event
  in the time range, gets no row, no dropdown entry and no bar: text sent in
  a request cannot put itself on the page, and a persona that was idle in the
  chosen range does not show a spray that named it (widen the range). The six
  tiles, the dropdown, the sign-in chain, the address table and *Risk by
  detection* do not read claimed turns, and every number the view showed
  before is unchanged. The claimed count needs the application's own events
  in the index, and a spray that names the persona among them: the Duo input
  backfills 30 days on a new stack, the application's HEC feed does not. See
  *Identity Activity: claimed, not verified turns*.
- ADDED (dev tooling, review decision LR-09, 2026-11-17):
  `tools/show_postdeploy.py --duo` / `--duo-teardown` (`tools/duo_steps.py`),
  one run per stack that polls Duo. Setup, each step reading the stack first
  and writing only a difference: index `duo` through ACS (waited for), the Duo
  account through the account handler, the attendee role's search access, the
  Duo rule and the joined rule enabled, then the authentication input; a
  teardown removes all of it, the secret key included, and deletes the index
  and the input checkpoints together or not at all. The secret key comes only
  from a named environment variable or a hidden prompt (never argv, never a
  file), no part of it is printed, and a Duo run verifies the stack's
  certificate unless `--duo-no-tls-verify` is passed, which the run then
  states. The polling interval is a required parameter (`--duo-auth-interval`,
  or `--duo-poll-slot K/N` for N stacks on one tenant, written as a list of
  minutes). What a stack holds is explicit: every run prints it, and the users
  snapshot (`--duo-with-users`) and the identity lookup search
  (`--duo-with-lookup-gen`) are off unless asked for. The rules are enabled
  before the input exists and are checked as they ship: each must judge by
  index time on a slot exactly one cron period wide (its
  `dispatch.earliest_time` is never read as an event-time reach), and the input
  is created only when the index exists, keeps the backfill and agrees with
  the input's checkpoint, so a stack created after the sign-ins were staged
  indexes them once, with the rules already on. A last, read-only step
  dispatches each rule's own search in one pass over what is indexed and
  compares its `burst_id`s and `chain_id`s with the rule's risk events (`N of N
  raised`, or which were never raised). Tested against a loopback stand-in for
  the splunkd and ACS endpoints (`tools/tests/fake_splunk_rest.py`; its account
  endpoint is the shipped handler and its saved searches are the shipped
  stanzas); **not yet run against a Splunk Cloud stack**.
- FIXED before release (review of LR-06, 2026-11-17): the joined rule judged
  nothing by index time. It read its slot's start with `addinfo` in the main
  pipeline, where `addinfo` returns the event-time range the rule's own finder
  subsearch writes into the base search, not the job's slot. Every row counted
  as new, the "before the slot" half of the search never ran, and a chain was
  raised again by every later run that indexed any step within 100 minutes of
  it; only the 24-hour suppression on `chain_id` stood between that and a
  second finding, and it could not drop a repeat under another `chain_id` or
  after 24 hours. On the dev data the 5-minute slot after the one that raised
  the staged chain returned it a second time. The slot's start is now read in
  an append subsearch, as the Duo rule reads it. The 25 fixtures had passed
  throughout: their rows are makeresults rows, which carry no inline time
  range, so `addinfo` gives the job's window anywhere.
- FIXED before release (review of LR-06, 2026-11-17): the joined rule dropped a
  second chain that followed the first within the hour when its Duo burst was
  the step indexed last, which is the usual live order. Any blocked turn that
  had been counted with an earlier, judged sign-in marked the new chain as
  already raised, so a live run raised one finding where a backfill raises
  two. "Already raised" is now decided per chain, by the blocked turn that
  completed it: a chain is not raised again when it holds the first blocked
  turn of a chain that was complete before the slot, and is raised when its
  turns were only later turns of another sign-in's chain.
- CHANGED before release (review of LR-06, 2026-11-17): the joined rule's
  description, comment and docs now say that what a finding NAMES (the burst,
  its count, the Duo applications, the start of the drill-down and Duo's
  record of the sign-in) is what was indexed when it was raised. A chain
  raised while the burst nearest to the sign-in is still in Duo's lag names an
  earlier burst within the 30 minutes; `chain_id`, the finding's time and the
  risk are the same as from a backfill. Holding a sign-in back until Duo's log
  has passed it would remove the difference at the price of a delay; that is
  left as an open decision and is not built.
- FIXED before release (review of LR-07, 2026-11-17, documentation only; the
  Duo rule's search is unchanged): the search this README gave for a run that
  lost its slot (`status!=success` in `scheduler.log`) could not find one. A
  scheduled run whose search fails writes no status row, and the rows that do
  match are deferrals of runs that completed. It now looks for the slots that
  have no successful run, names the audit log for the reason, and says that a
  run that was cut short is found only by comparing ids. And the catch-up
  advice widened only `dispatch.earliest_time` (for example `-31d@m`), a range
  that also covers index time the scheduled runs have judged: every finding
  older than the 24-hour suppression would have been raised a second time.
  The one-off range now has both ends, up to the start of the first judged
  slot, or exactly the lost slot.
- FIXED before release (review of LR-09, 2026-11-17, dev tooling):
  `tools/show_postdeploy.py --duo` / `--duo-teardown`.
  - A stack certificate that no public root signed had one remedy short of
    switching verification off, "point `SSL_CERT_FILE` at the CA", and it does
    nothing under the Python the runbook's command uses on a Mac (Apple's
    Python on LibreSSL ignores the variable; Splunk's launcher overwrites it).
    `--duo-ca-file PATH` loads the CA into the stack's TLS context explicitly,
    under any Python, and leaves ACS on the default roots.
  - Guards that deleted or created on an answer they could not read now
    refuse: the lookup file is deleted only when the identity source is
    confirmed absent (404), an index the search sees nothing in only when ACS
    says it holds 0 events, the checkpoints only once the index is confirmed
    gone. "No such index" from the stack while the step's own search counts
    events keeps everything; an ACS 404 means "the index is missing" only
    with ACS's own code for that; a rule, a checkpoint or an event count that
    cannot be read never lets the authentication input be created.
  - An index delete that ACS has accepted but not yet carried out no longer
    ends in "checkpoints cleared" and an OK. A marker stays beside the
    checkpoints until ACS confirms the index is gone, and `--duo` creates no
    input while it is there. The index is not deleted from under an input the
    tool did not make.
  - `--duo-teardown` reports, as a failure, any role it was not given that
    still lists index `duo` (a setup run with `--duo-attendee-role X` is undone
    only by a teardown that names X).
  - A value typed where none belongs is no longer printed back:
    `--duo-rotate-key=<key>` used to return "ignored explicit argument
    '<key>'" and `--duo-p=<key>` "ambiguous option: --duo-p=<key> ...".
    Option abbreviations are off for the whole script.
  - D0 reads the endpoint the inputs are created through before anything is
    written, and calls a refused read a refused read (a 403 used to read "the
    TA is not installed" or "restart the stack").
  - D8 no longer dispatches a rule text that holds `stash`, `summaryindex`,
    `sumindex`, `dump` or one of this TA's own writing commands.
- CHANGED before release (review of the tests, 2026-11-17, dev only): the
  offline suite could not tell a working Duo rule from a dead one (a `max`
  changed to `min`, a misspelt command and an inserted filter all passed it).
  `tools/tests/fixtures/duo_rule_proof.json` now records, for each of the two
  rules, the digest of the text its fixtures were last run against, and the
  suite fails while the text differs; `test_duo_spl.py --fixtures`, `--verify`
  and `--record-proof` run and record the fixtures through the read-only
  Splunk MCP where no credentials are at hand, and `SPLUNK_TEST_REQUIRED=1`
  turns every skipped live test into a failure. The chain fixtures went from
  25 to 40 (every arrival order, the second chain, the edges of the 60-minute
  window, what a finding names) and compare the drill-down's two ends. The
  live tests cut index time where the scheduler does (the slot edges sit 2
  minutes back from the cron ticks), compare each rule with a plain event-time
  reference search instead of with itself, read the edge each rule compares
  index time with, check that a run reads the events around its new ones (the
  finder's look-back, which no test exercised), and cut index time at every
  second at which an event of a burst or chain was indexed. Every `$token$` of
  the two rules' findings must
  name a field of the search's result. The stack tool's tests run `main()`
  itself and one failing read per guard.
- CHANGED: `metadata/default.meta` `[passwords]` limits every credential the
  TA stores (ServiceNow, soar, Cisco Duo) to `admin, sc_admin`, `export = none`.
  They used to inherit `[]` (read `*`, export system), so any role holding
  `list_storage_passwords` could read them from any app. Every reader runs in
  this app's context as a role that passes: the five ServiceNow sync and
  inventory searches are now `owner = admin` (R-CONF-005), `| genaiseedes`
  already was, `| aicase` runs as the invoking user (`power` may run it but
  holds no `list_storage_passwords`, so it never could read them), and the Duo
  input runs as splunk-system-user. The Duo checkpoint collection is
  admin-only as well.
- FIXED: the ACLs for `ta_gen_ai_cim_account.conf`, `ta_gen_ai_cim_es.conf`
  and `ta_gen_ai_cim_genai_scoring.conf` were written under `[conf/<name>]`
  and `[configs/conf-<name>]`, names Splunk never applies (a conf's metadata
  object is `[<name>]`, the way splunkd writes
  `[ta_gen_ai_cim_genai_scoring/pipeline_1]` into `local.meta`). All three
  confs therefore inherited `[]`: any user could read every account's url,
  username and client id, from 1.9.0 every Duo integration key and API
  hostname too. They are now `[ta_gen_ai_cim_account]`, `[ta_gen_ai_cim_es]`
  and `[ta_gen_ai_cim_genai_scoring]`, `admin, sc_admin`, `export = none`;
  every reader already runs in this app's context as a role that passes (see
  the `[passwords]` entry above).
- FIXED: the account handler declared `redirect_url`, `access_token` and
  `refresh_token` but never stored them, so a posted OAuth token was dropped
  and then echoed unmasked in the reply splunkd receives
  (`MConfigHandler.toXml` serializes every caller arg). They are no longer
  declared, so splunkd rejects them, and the reply masks them anyway.
- CHANGED (packaging, R-PKG-003 amendment): `README/*.conf.spec` now ship:
  `README/inputs.conf.spec`, without which an installed package has no Duo
  scheme, and `README/alert_actions.conf.spec`, which the old `README/` exclude
  had been dropping from every package. Every other `README/` member is still
  excluded, now by exact path. `bin/README` also ships: the old bare `README/`
  pattern matched it too.
- CHANGED: `app.manifest` `targetWorkloads` adds `_forwarders`, since the Duo
  input may run on a heavy forwarder.
- FIXED: `default/web.conf` exposed `TA-gen_ai_cim/*`, which matched no
  endpoint the app serves, so Splunk Web's proxy refused the account handler.
  It now exposes `ta_gen_ai_cim_account/ta_gen_ai_cim_account` and `/*`, which
  the Cisco Duo tab saves through; Splunk Web picks this up at startup.
- FIXED: `bin/snow_setup.py` called
  `/servicesNS/nobody/TA-gen_ai_cim/ta_gen_ai_cim_account` without the
  handler's `members` segment, so its lookups 404'd and its creates missed the
  handler.
- FIXED: `get_snow_config` and the Configuration page used the first account
  stanza, so a `duo` or `soar` account (both sort ahead of most ServiceNow
  names) would divert the ServiceNow syncs. Both now pick ServiceNow accounts
  only, a `*.service-now.com` / `*.servicenow.com` host first
  (`sync_snow_asset.select_snow_account`).
- FIXED: the account handler's create silently updated an existing stanza
  (`splunk.entity` `setEntity`'s update path); it now refuses an existing name.
  The ServiceNow form no longer turns a 409 into an update of another account.
  The handler also dropped the soar account's token on create
  (`auth_type = token`).
- CHANGED: the account handler persists through `configs/conf` +
  `storage/passwords`, updates a secret in place (never delete-then-create),
  rolls back a create whose secret write fails, refuses unknown auth types and
  switches between `duo_hmac` and another type, and masks secrets in the reply
  it sends back to splunkd.
- FIXED (found live, 2026-11-16): the Configuration page read the first
  `splunkweb_csrf_token_*` cookie it found. A browser that has used two Splunk
  instances on one host (cookies are scoped by host, not port) then sent the
  wrong token, the write failed CSRF validation with a 401, and Splunk Web
  silently reloaded the page without saving. `getCSRFToken` now takes this
  Splunk Web's own cookie (`splunkweb_csrf_token_<port>`, the port from
  `$C.MRSPARKLE_PORT_NUMBER` or the page URL) through the pure function
  `pickCsrfToken`, pinned by a node test in `tools/tests/test_duo_account.py`.
- FIXED (found live, 2026-11-16): home card 02 (Tokenomics) showed `###`
  instead of 0 whenever the last 24 hours held no inference event, because a
  bare `stats sum()` returns no row on an empty window. Its search now carries a
  count beside the sum and fills the null. The same fix went into the Duo
  Identity Feed tiles before release, and `tools/tests/test_lab5_conf.py` now
  requires every home tile's search to return a row on an empty window.
- ADDED (VALIDATION_RULES.md): R-INP-001 (modular inputs ship off, with their
  spec and `bin/<scheme>.py`; 120 s floor; secrets only in `storage/passwords`;
  never `gen_ai_log`) and a dated R-PKG-003 amendment for `README/*.conf.spec`.
  `check_package.sh` enforces both, plus the dev-only trees R-PKG-003 already
  named (`tools/`, `elements/`, `planning/`, `package.sh`). Also R-INP-002,
  from the Duo identity source fix above: an ES identity or asset source
  (`[identity_manager://...]`) ships in `default/inputs.conf` only together
  with its lookup file, enabled or not. `check_package.sh` checks it on the
  built package and `tools/tests/test_duo_conf.py` on the tree.
- Validation: AppInspect 4.2.0 `--included-tags cloud`: 0 errors, 0 failures,
  0 future-failures, 9 warnings (the 8 accepted ones plus
  `check_for_modular_inputs`, "App contains modular inputs in inputs.conf.spec.
  No action required."). On 2026-11-16 the branch was loaded on a live Splunk
  10.4.3 with Enterprise Security 8.5.1, and these were verified there against
  a real Duo tenant:
  - the modular input registered and pulled the tenant's authentication log
    (57 events at the first check; it has kept polling since) and a complete
    8-user snapshot;
  - resuming from a saved `next_offset` with a later `maxtime` works;
  - the identity lookup gen wrote 8 identities, and the ES identity manager
    merged them (7 into existing identities, 1 new);
  - the Authentication data model returns the Duo events;
  - the risk rule as first built (an event-time window, before LR-07),
    enabled in that instance's `local/`, ran on its 10-minute schedule: one
    run over a 14-day window returned 4 users and wrote their user risk and
    findings, and a later run over the default 30-minute window raised user
    risk and a finding for a fresh denial burst, with the next run throttled;
  - the Cisco Duo tab created, listed and deleted a test account;
  - ES Entity Risk Scoring scored that risk on its next 20-minute run, on one
    user together with the Prompt Injection rule's;
  - end to end with the application: a Duo sign-in to PseudoCo Assistant
    matched the application's own sign-in record on the transaction id, 3
    seconds apart; verified AI turns followed, one blocked by Cisco AI Defense;
    and a failed sign-in burst sent before that sign-in showed on *Identity
    Activity* as 6 denials in the 10 minutes before it;
  - the index-time rule (LR-07), read-only on that data on 2026-11-17, as
    ad hoc searches of its final text (no scheduled run): over the index-time
    slot that holds the first poll's 30-day backfill it returned the four
    findings that backfill held, each dated at its Duo event (three denial
    bursts, and one fraud finding for the user with five fraud reports and
    one other failure); over the slots of the three bursts sent on 2026-11-16
    one finding each (the third 25 minutes after the second), and none over
    the slot that indexed a burst's late sixth failure or over an idle slot;
    and one pass over all time, with no end, returned the same seven findings
    with the same `burst_id`s. Each of the 28 rule fixtures in
    `tools/tests/fixtures/duo_spl.json` returned its expected rows over its
    own slot. Its alert actions, suppression and continuous schedule have
    not run yet;
  - the joined rule (LR-06) as first built, read-only on that data on
    2026-11-17, as ad hoc searches (the rule is disabled; no scheduled run).
    These runs did not show that the rule raised the same chain again in the
    next slot; the review bullet below is the search as it ships: over
    all time, with no end, it returned one finding, for the persona whose
    second staged pass ran in the rule's order (six failed Duo
    authentications within the 10 minutes to 21:34:09, the application
    sign-in at 21:35:49 matched to Duo's own record of it on the transaction
    id, one turn blocked by Cisco AI Defense at 21:36:44), and none for the
    first pass, where the burst came three minutes after the sign-in and its
    turns; over the 5-minute index-time slot that indexed that burst it
    returned the same finding, with `signin_duo` reading `none indexed`
    because Duo's record of the sign-in was indexed two minutes later; and
    over that next slot, over the index time of the first pass and over the
    scheduler's current slot it returned nothing. The drill-down, with the
    finding's bounds inline, returned the chain's 11 events from a job whose
    own time range held none. Each of the 25 `chain:` fixtures in
    `tools/tests/fixtures/duo_spl.json` returned its expected rows over its
    own slot. Its alert actions and suppression have not run yet;
  - every search of *Identity Activity*, and home card 06, ran on that data
    over an empty window and over its default one; the three *Duo Identity
    Feed* searches changed in review (denied and fraud by user, merged
    identities, users with Duo risk) ran over their own windows; and the
    Identity Activity logic (one event per turn, Duo outcomes, the sign-in
    chain, risk events against findings) also ran on synthetic rows through
    the view's own text (`SIMULATIONS` in
    `tools/tests/test_identity_activity.py`);
  - claimed, not verified turns on *Identity Activity* (LR-08), read-only on
    that data on 2026-11-17, as ad hoc searches of the view's final text
    with the two new macros by name: over a fixed 14-day window the overview
    returned the same eight identities as before, the 17 columns it already
    had equal row for row (one digest over them, before and after), and the
    timeline's eight earlier series were equal in all 15 daily rows. The new
    columns read 7 claimed turns (5 blocked) for a persona a spray had named
    on 2026-11-06, 4 (2 blocked) for a second persona named on 2026-11-12,
    whose AI turns had read 0, and 0 for the two staged passes of 2026-11-16,
    which held no spray. The ES tile, which counts the overview's rows, read
    5; over a two-hour window in which the second persona had no Duo or
    application event, the spray that named that persona was not drawn; an
    empty window returned 0 and no error. Of the 743 governance events in
    the window 343 were claimed turns under 53 names, none of them also a
    verified turn, and only the two personas' showed. Each of the two
    searches scanned 485 events instead of 115 and ran in under 2 seconds.
    The two simulations added to `SIMULATIONS` returned their expected
    answers. The edited view has not been opened in a browser.
  - the stack tool's own searches (LR-09), read-only on that data on
    2026-11-17, as ad hoc searches (the tool itself was not run against this
    or any Splunk): the count by sourcetype it starts from returned the
    authentication and the user events and no other sourcetype; step D8's one
    pass of the Duo rule's own search over all index time up to 20 minutes
    before now returned the seven `burst_id`s, and of the joined rule's (up
    to 15 minutes) its one `chain_id`; the risk-index search D8 compares them
    with returned the Duo rule's seven risk events with no id, because the
    first build of the rule raised them and they carry none, which D8 reports
    as not comparable instead of advising a catch-up, and no risk event for
    the joined rule, which has never run there, so D8 would name its one
    chain as never raised; and the five T-1 searches
    of `tools/lab5-identity-runbook.md` returned, for the staged persona,
    eight ten-minute buckets of Duo sign-ins (the three staged bursts with six
    denials each), four findings of the Duo rule, no joined finding (that
    rule has not run on a schedule) and the application's two sign-ins, four
    allowed and three blocked verified turns.
  - the joined rule as fixed in review, read-only on that data on 2026-11-17,
    as ad hoc searches of its final text (4,684 characters; no scheduled
    run). Over two adjacent 5-minute index-time slots that part the staged
    chain's steps (the sign-in and the blocked turn in the first, the burst
    nearest to the sign-in in the second), the first returned the chain and
    the second returned nothing, where the first build returned the chain in
    both. That first slot named the earlier burst of 21:08:53 (the nearer one
    was not indexed yet), as documented under *The joined rule*. Over the
    scheduler's own slot of 21:33 to 21:38 it returned the chain naming the
    burst of 21:34:09, with `signin_duo` reading `none indexed`; over the next
    slot nothing; over all time one chain, the one the plain event-time
    reference search of `tools/tests/test_duo_spl.py` finds. The edge each of
    the two rules compares index time with read as the job's own earliest
    (the joined rule's had read 99 minutes earlier, the start of the
    event-time range its finder writes). What a run reads was compared with a
    plain search over the same event-time window: the Duo rule's run over the
    slot that indexed a burst's late sixth failure read 6 events (1 without
    the look-back), the joined rule's run over the 21:33 slot 19 (9 without).
    All 40 `chain:` fixtures returned
    their expected rows, each run verbatim over its own slot, and the result
    is recorded in `tools/tests/fixtures/duo_rule_proof.json`. The Duo rule's
    search is unchanged; its reference search returned the same seven
    `burst_id`s as the rule's one pass, and on the scheduler's grid (edges at
    minutes ending in 8) its events fall into five slots, one of which parts a
    burst's sixth failure from the other five. The live Python tests
    (`SPLUNK_TEST_*`) were not run: no credentials were at hand.
  - the stack tool as fixed in review: nothing was run against a Splunk. Its
    tests (127, against the loopback stand-in) include a real TLS handshake
    with a certificate no default root knows, refused without `--duo-ca-file`
    and verified with it, under Apple's Python 3.9 on LibreSSL and under
    Splunk's Python 3.13; `main()` with valid command lines; and one failing
    read per guard. In a scratch copy, each of 37 mutations of the guards, the
    routing and the TLS handling failed at least one test.

  Not exercised: the UEBA pages (the instance runs ES Essentials), a search
  head cluster, and `tools/show_postdeploy.py --duo` against any real stack.

### v1.8.0 (2026-11-07; never tagged, first released in v1.9.0)

**AI Trust Lab 5: "Verify: Cisco Identity Intelligence"**

- ADDED (2026-11-16, Lab 5 backlog row 3): the Lab 5 rule reads CII evidence
  from PseudoCo Assistant's own events, so it no longer needs a CII webhook.
  The Identity Risk Gate looks the user up on every signed-in turn and every
  event carries the answer (`identity_failing_checks`, `identity_trust_level`).
  A fourth multisearch branch (last 24 hours, `gen_ai.identity.verified=true`)
  runs the new macro `genai_cii_gate_failed_check_rows`: one row per takeover
  check, names normalized to CII's check-ID form, plus an UNTRUSTED trust level
  as the check `trust-level-untrusted`; `cii_provenance` reads
  `PseudoCo Assistant gate lookup`. The rule now fires while the newest AI
  Defense block **or** the newest CII evidence is under 5 minutes old, so a
  flag that lands after the blocks still raises it. Severity is critical for
  UNTRUSTED, or for an "Unblock me" override within 10 minutes of an AI Defense
  block (the join now emits `lastOverrideTime`). Checked on the Mac's Splunk
  10.4.3 with makeresults rows: the branch keeps MFA Flood and UNTRUSTED and
  drops handout-code checks, `multisearch` accepts it, and the freshness and
  severity clauses behave as described. Not yet run against a real flagged
  user's events.
- CHANGED (2026-11-16, Lab 5 decision D1): `duo-sign-in-threat-detected` no
  longer counts as takeover evidence. The takeover IDs now live in
  `genai_cii_takeover_check_ids` (`mfa-flood`, `impossible-travel`), the same
  CII checks PseudoCo Assistant's Identity Risk Gate refuses a turn for, and
  `test_lab5_conf.py` fails if the two drift.
- ADDED: *AI Governance - Compromised Identity AI Attack Correlation - Rule*
  (ships **disabled**). Joins Cisco Identity Intelligence (CII) `FAILED_CHECK`
  events for a takeover check (MFA Flood, Impossible Travel, Duo Sign In Threat
  Detected; last 7 days) with Cisco AI Defense blocks (last 24 hours) for the same
  identity, keyed on the lowercased local part of the login (CII reports the
  Duo email, PseudoCo Assistant the short username). Fires while the newest AI
  Defense block is under 5 minutes old and throttles each user for 600 s - the
  prompt-injection correlation's fixed values. Finding "GenAI Compromised
  Identity: $user$", risk and entity on `user` only (100), no prompt text,
  annotations ATT&CK T1078/T1621 and ATLAS AML.T0012/AML.T0051, next steps that
  name the PseudoCo Identity connector. Identity Risk Gate blocks and "Unblock
  me" overrides are reported as context. CII evidence may be the webhook or a
  labelled backfill re-created from the CII API (`backfill=true`,
  `source=lab5-setup`; the Lab 5 setup tool command that writes it is planned,
  not built); the finding names it in `cii_provenance`. Lab 5
  participant accounts (`l5-*`) never raise it.
- ADDED: macros `genai_cii_index`, `genai_cii_events`, `genai_cii_extract`,
  `genai_cii_failed_checks`, `genai_cii_failed_check_rows`,
  `genai_cii_takeover_checks`, `genai_identity_join_key(1)`, `genai_identity_ai_events`,
  `genai_identity_participant_filter`, `genai_identity_ai_attack_join` and the
  tuning hook `genai_identity_ai_attack_filter`. The CII field paths follow
  CII's published webhook payload and are **provisional** until the Lab 5 spike
  captures a real event (S6); the index is `cisco_identity_intelligence`.
- FIXED: *AI Governance - Prompt Injection Attack Correlation - Rule* now drops
  Identity Risk Gate blocks (`gen_ai.guardrail.ids=cisco_identity_intelligence`)
  right after its base search. The gate refuses whatever a compromised
  identity's attendee types, so those turns counted as policy blocks and their
  typed text matched the injection patterns: every signed-in victim would have
  raised a prompt-injection finding. Regex and corpus numbers are unchanged.
  Re-validated on a scratch index (Splunk 10.4, labelled sample events): the
  1.7.2 rule raised a finding for a victim whose only injection text was a gate
  block and counted the gate block as an extra attempt and policy block for the
  sprayed victim; the 1.8.0 rule does neither.
- ADDED: *Compromised Identity Response Plan* (`_key`
  `compromised_identity_response_plan`, its own `template_id`), seeded by
  `| genaiseedes` when `seed_identity_response_plan = true` (ships **false**) and
  by `tools/show_postdeploy.py --lab5`. Its containment task binds the
  **PseudoCo Identity** app's `pseudoco_identity` asset only when both already
  exist on the paired SOAR - the seeder never creates that asset, which holds
  real Duo credentials. Still no investigation type.
- FIXED: the hourly reseed dropped actions attached to plan tasks in the ES UI
  whenever no binding had been dropped (a task with no `soar_binding`, or a run
  where every binding resolved). Live actions are now always merged back.
- FIXED: with `enable_triage_agent = true` the reseed **replaced** the ES triage
  allowlist with this TA's one entry. It now merges, keeping every other entry,
  and adds the Lab 5 rule. With `route_findings_to_queue = true` the AI Findings
  queue rule also matches "GenAI Compromised Identity".
- ADDED: **PseudoCo Identity** SOAR connector (`soar_apps/pseudoco_identity/`,
  `soar_apps/pseudoco_identity.tgz`): `test connectivity`, `get user` (Duo
  status) and `disable user` (contain, no undo) through the Duo Admin API
  (v5/HMAC-SHA512 signing, TLS verified, standard library only). Not a
  simulator: results carry `simulated: false`. It disables only the asset's
  configured victim, refuses trusted personas, participant accounts and
  unresolved `$`/`%24` tokens. Its source is excluded from the TA package;
  `tools/show_postdeploy.py --lab5` installs it. Both TA SOAR apps are left out
  of the "competing identity assets" report.
- CHANGED: the **MedAdvice Identity Provider** simulator (1.1.0) refuses AI
  Trust Lab 5 identities - the persona cast in username or email form, the
  `pseudocoassistant.com` domain and `l5-*` participant accounts - with an app
  error naming PseudoCo Identity, so a Guided Response mis-pick fails loudly
  instead of faking containment of a real Duo account.
- ADDED: ES identity rows for the Lab 5 personas
  (`lookups/pseudoco_identity_personas.csv`, `identity=<user>|<user>@pseudocoassistant.com`,
  `bunit=pseudoco`, category `lab5_trusted` / `lab5_victim`), generated from the
  PseudoCo Assistant persona file by `tools/identity/gen_identity_personas.py`.
  The `[identity_manager://pseudoco_identity_personas]` input ships
  **disabled**; `show_postdeploy.py --lab5` enables it per room stack.
- ADDED: normalization for PseudoCo Assistant 4.23.0 identity events on
  `gen_ai:json`: `gen_ai.audit.action` / `gen_ai.audit.actor` for audit records
  that arrive on the canonical sourcetype (gated on `audit_id`; until now only
  `demobot:audit` had them, so `gen_ai_session_audit` missed every Show box);
  CIM Authentication for `identity_signin_success` / `_failure` (`action`
  success/failure, `authentication_service=duo`, `dest` = the instance's HEC
  host) through the new eventtype `gen_ai_identity_authentication`, tagged
  `authentication`; `gen_ai.identity.verified`, `.source`, `.check`
  (`unavailable` when Duo or CII could not be asked and the gate failed open),
  `.override` (the attendee pressed "Unblock me") and `gen_ai.identity.risk.*`
  from the app's flat fields: `.verdict` from `identity_risk`, `.reasons` from
  `identity_risk_reasons`, `.duo_status` from `identity_duo_status`,
  `.trust_level` from `identity_trust_level` and `.failing_checks` from
  `identity_failing_checks` (braced arrays); eventtypes
  `gen_ai_identity_session` and `gen_ai_identity_block`.
- FIXED (Lab 5 dry run, 2026-11-06): `gen_ai.identity.risk.duo_status`,
  `.trust_level`, `.reasons` and `.failing_checks` were empty on every real
  event, and so were the Compromised Identity dashboard's gate-verdict columns.
  The TA read them from a nested `identity_risk` object
  (`identity_risk.duo_status`, `identity_risk.failing_checks{}`, ...), but
  PseudoCo Assistant 4.23.0 writes flat fields (`identity_risk` is the verdict
  string). The scratch-index test passed only because its samples used the
  nested shape. The flat names are now read first and the nested object only
  as a fallback; the scratch samples and the SPL fixtures
  (`tools/tests/fixtures/lab5_spl.json`) use the shape the app writes,
  including the identity fields of a real fail-open turn and the shape of a
  real revocation record from the dev copy. `test_lab5_spl.py` now runs the
  TA's own props.conf EVAL text on those rows (`<<props:KEY>>` tokens).
  Verified on the Mac's Splunk 10.4.3 after a props reload: both identity
  turns the dev copy sent (`host=l5-dev`) read
  `gen_ai.identity.risk.duo_status=active`, `.verdict`, `.check` and
  `.override` (2 of 2 each), and the `identity_session_revoked`
  record maps to `gen_ai_identity_session` with `dest=l5-dev`. `.trust_level`,
  `.reasons` and `.failing_checks` had no source values on those turns (CII
  could not be asked), so they still wait on a CII-answered turn (R-CONF-003).
- FIXED: the Lab 5 rule counted every CII `FAILED_CHECK`. A backfill or a
  *Send notification* re-send can carry *A Bypass Code Was Used To Successfully
  Sign In* (`is-bypass-code-used`) or *Weak MFA Was Used To Successfully Sign
  In* (`is-weak-mfa-used`), which every persona fails after signing in with a
  handout bypass code, so a trusted persona that tripped AI Defense would have
  raised "GenAI Compromised Identity". The new macro
  `genai_cii_takeover_checks` keeps only `mfa-flood`, `impossible-travel` and
  `duo-sign-in-threat-detected` (CII check IDs, case-insensitive; override it
  in `local/`). `genai_cii_failed_check_rows` applies it, so the rule, the
  dashboard and the runbook's T-1 query all see takeover checks only.
- FIXED: the scratch samples used the check ID `bypass-code-used`. CII's ID is
  `is-bypass-code-used` (CII `listCheckMetadata`, 2026-11-06, which also
  confirms `mfa-flood`, `impossible-travel` and `duo-sign-in-threat-detected`).
- CHANGED: the docs and conf comments said PseudoCo Assistant 4.22.0+. The
  Identity Risk Gate ships in 4.23.0; 4.22.0 has no gate.
- CHANGED: `tools/lab5-identity-runbook.md` no longer promises a labelled
  backfill from the Lab 5 setup tool (`lab5-setup` has no such command; it is
  planned as spike S1's last option) or three findings on lab day: the ES
  24-hour risk-threshold finding depends on the stack's RBA rule and lag, and
  it did not fire on the ES 8.5.1 dry run.
- FIXED: `tools/identity/gen_identity_personas.py` could not read the real
  persona file. PseudoCo Assistant's `scripts/identity/personas.yaml` gives the
  dry-run victim `role: spike` (the app's roles are `trusted`, `victim` and
  `spike`) and names the domain `email_domain`. The generator accepted only
  `dry_run` for that role and read `domain`. It now uses the app's roles
  (`spike` -> `lab5_victim`, like a room victim) and reads `email_domain`, with
  `domain` as a fallback. The committed CSV is unchanged and now matches the
  real file (`--check`, 2026-11-07), not only the TA's fixture. To repeat
  that check in `tools/identity/tests`, set `PSEUDOCO_PERSONAS` to the file.
- ADDED: *Compromised Identity* dashboard (Dashboard Studio, dark) and a home
  dashboard (`TA-gen_ai_cim_home`, now the app's default view) with one card
  and a live count per dashboard in the menu and a five-number scoreboard.
- CHANGED: the navigation menu no longer shows *Configuration*, *GenAI Scoring
  Configuration*, *Datasets*, *AI Asset Discovery* or *PII Detection*. Nothing
  is removed: the four TA views get `isVisible="false"` (also out of the
  Dashboards listing) and still open by URL; their nav lines are commented out
  (README, "Views not in the navigation menu").
- ADDED: `tools/show_postdeploy.py --lab5 / --lab5-teardown / --out` (one run
  per room stack; see `tools/lab5-identity-runbook.md`).
- CHANGED (R-SEC-002): the seeding search's sanctioned writes widen to a
  second TA-owned plan and a second bound app, both behind
  `seed_identity_response_plan = false`; amendment of 2026-11-05 in
  `VALIDATION_RULES.md`.

### v1.7.2 (2026-10-29)

**Follow-ups to the AI Trust workshop dry run**

- CHANGED: the TA no longer creates the `ai security incident` investigation
  type, and the three AI Governance rules no longer set
  `action.notable.param.investigation_type`. Neither `| genaiseedes` nor
  `tools/show_postdeploy.py` writes `mc_incident_types` (step 5 now reports
  SKIP). Mission Control's investigation-type API refuses deletes (`DELETE`
  answers 405), so a type the TA seeded could not be removed afterwards.
  Findings now open as the stack's default type. The AI Incident Response Plan
  is still seeded; an analyst adds it to an investigation with **Add response
  plan**. To have it apply automatically, assign it to an investigation type of
  your own and select that type on the detections (*Enterprise Security
  integration → Option B*). Until then the ES AI triage settings list no
  response plan for these detections, because they resolve plans through the
  detection's investigation type. A stack that ran v1.7.1 or
  `tools/show_postdeploy.py` keeps its `ai security incident` record until
  someone deletes it from the KV store:
  `DELETE /servicesNS/nobody/missioncontrol/storage/collections/data/mc_incident_types/ai%20security%20incident`.
- FIXED: Prompt Injection Detection. The tiles disagreed: *Total Scanned* and
  *Injections Detected* counted detector output rows, and AI Defense
  contributed only the prompts it blocked, so where only AI Defense ran the
  two always matched (for example 19 and 19). *Detection Rate* divided by
  every prompt instead (5%). A prompt flagged by both AI Defense and the GenAI
  judge also counted twice (186 detections for 138 prompts over 30 days on the
  dev stack). The dashboard now has one base search that keeps one row per
  `gen_ai.event.id`, so every tile, the trend and the tables count distinct
  prompts from the same total. *Clean prompts* on the trend was always 0 and
  is now plotted. *Sessions* in *Top Injection Sources* was always 0 and is
  now counted. AI Defense injections are now recognised by its own
  `gen_ai.safety.categories` verdict ("Prompt Injection") rather than
  DemoBot's `prompt_category` label, which other emitters do not set. Their
  technique is now the AI Defense rule names, not a fixed `ai_defense_block`.
  An AI Defense block counts as *high* severity and is left out of
  *Confidence Distribution*, because a block carries no score. Before, both
  donuts read DemoBot's `evaluation_score_label`.
- FIXED: the SOAR simulator's upload steps only worked from a git checkout.
  `package.sh` leaves `soar_apps/medadvice_idp.tgz` out of the TA package and
  never packages `tools/`, yet `soar_apps/README.md` said to upload that
  tarball, and `| genaiseedes`, when it could not install the app, pointed at
  the tarball and `tools/show_postdeploy.py`. The README now builds the
  tarball from the shipped `soar_apps/medadvice_idp/` source (a checkout can
  still use the prebuilt one), and the skip message points at
  `soar_apps/README.md`.

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
