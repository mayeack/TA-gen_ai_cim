# TA-gen_ai_cim

> **⚠️ ALPHA SOFTWARE** - This Technology Add-on is in active development. Features may change, break, or be removed without notice. Use at your own risk in non-production environments. This application is currently for demonstration purposes only.

**Splunk Technology Add-on for Generative AI Common Information Model**

Version: 1.2.0-alpha  
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
| `splunklib` | 2.0.2 | Bundled in `lib/` | Splunk SDK for Python - no installation required |
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
  Version: 1.2.0
  Status: enabled
```

#### 3. Configure Data Inputs

Ensure your AI telemetry is flowing into the designated index:
- `index=gen_ai_log`

Or update `props.conf` stanzas to match your index naming.

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

**Enable alerts:**
```bash
# Enable all governance alerts
$SPLUNK_HOME/bin/splunk search "| savedsearch \"GenAI - *\""
```

**Customize alerts:** Edit `$SPLUNK_HOME/etc/apps/TA-gen_ai_cim/default/savedsearches.conf`

---

## Dashboards

Pre-built dashboards are **automatically installed** with the TA, providing comprehensive AI governance monitoring.

| Dashboard | Description | Documentation |
|-----------|-------------|---------------|
| **AI Governance Overview** | Main dashboard with KPIs, safety/compliance metrics, trends | [Details](README/DASHBOARDS/AI_GOVERNANCE_OVERVIEW.md) |
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

### Customize Index Mapping

Edit `$SPLUNK_HOME/etc/apps/TA-gen_ai_cim/default/props.conf`:

```ini
# Add your custom index
[source::*/my_custom_ai_index/*]
KV_MODE = json
INDEXED_EXTRACTIONS = json
# ... (rest of configuration)
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

---

## Troubleshooting

### Issue: No Normalized Fields Appearing

**Diagnosis:**
```spl
index=gen_ai_log | head 1 | table *
```

Check if raw fields (e.g., `operation_name`, `provider_name`) exist.

**Resolution:**
- Verify index name matches props.conf stanzas
- Check `KV_MODE = json` is set
- Restart Splunk after TA installation

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
   | makeresults | eval gen_ai.request.id="test_123" | aicase mode=lookup
   ```

3. **Create a case from an event:**
   ```spl
   index=gen_ai_log gen_ai.safety.violated="true" | head 1 | aicase
   ```

4. **Use the Event Context menu:** Right-click any event with `gen_ai.request.id` → "Open Case in ServiceNow"

**Full documentation:** See [ServiceNow Integration](README/SERVICENOW_INTEGRATION.md)

---

## File Structure

```
TA-gen_ai_cim/
├── README.md                      # Main documentation
├── QUICKSTART.md                  # Quick setup guide
├── INSTALL.sh                     # Quick install script
├── bin/
│   ├── aicase.py                  # ServiceNow AI Case custom command
│   ├── create_snow_case.py        # ServiceNow alert action script
│   ├── load_pii_model.sh          # ML model loader script
│   ├── snow_setup.py              # ServiceNow CLI setup utility
│   └── ta_gen_ai_cim_account_handler.py  # REST handler for account management
├── appserver/
│   └── static/
│       ├── config_config.js       # Configuration page JavaScript
│       ├── event_review.css       # Event review form styling
│       ├── review_landing.js      # Review landing page handler
│       ├── review_save.js         # Review save handler
│       ├── servicenow_case.js     # ServiceNow case redirect handler
│       ├── servicenow_config.css  # Configuration page styling
│       └── servicenow_setup.css   # Setup page styling
├── lookups/                       # Lookup files (user-provided, not in git)
│   └── (training data CSVs)       # PII training data, etc.
├── mlspl/
│   └── README.md                  # ML models directory info
├── default/
│   ├── app.conf                   # App metadata
│   ├── alert_actions.conf         # Alert actions (ServiceNow)
│   ├── authorize.conf             # Role definitions (ai_reviewers)
│   ├── collections.conf           # KV store collections
│   ├── commands.conf              # Custom search command definitions
│   ├── fields.conf                # Field definitions
│   ├── macros.conf                # Search macros
│   ├── props.conf                 # Field normalization logic
│   ├── restmap.conf               # REST endpoint mapping
│   ├── savedsearches.conf         # Governance alerts
│   ├── ta_gen_ai_cim_account.conf         # ServiceNow account config
│   ├── ta_gen_ai_cim_account.conf.spec    # Account config spec
│   ├── ta_gen_ai_cim_detection.conf       # Detection settings
│   ├── ta_gen_ai_cim_detection.conf.spec  # Detection config spec
│   ├── ta_gen_ai_cim_llm.conf             # GenAI LLM settings
│   ├── ta_gen_ai_cim_llm.conf.spec        # LLM config spec
│   ├── ta_gen_ai_cim_servicenow.conf      # ServiceNow settings
│   ├── ta_gen_ai_cim_servicenow.conf.spec # ServiceNow config spec
│   ├── transforms.conf            # JSON extractions, lookups
│   ├── web.conf                   # Web server configuration
│   ├── workflow_actions.conf      # Event Context menu actions
│   └── data/
│       └── ui/
│           ├── nav/
│           │   └── default.xml    # Navigation menu
│           └── views/
│               ├── configuration.xml                  # Configuration dashboard
│               ├── event_review.xml                   # Event review form
│               ├── genai_governance_overview_studio.json  # Main dashboard (Studio)
│               ├── review_landing.xml                 # Review landing page
│               ├── review_queue.xml                   # Review queue dashboard
│               └── servicenow_case.xml                # ServiceNow case redirect
├── metadata/
│   └── default.meta               # Permissions
└── README/
    ├── AI_CIM.md                  # AI CIM field reference
    ├── DASHBOARD_COMPARISON.md    # Dashboard Studio vs Classic comparison
    ├── DASHBOARD_PANELS.md        # Dashboard panel definitions
    ├── DEPLOYMENT_GUIDE.md        # Installation and deployment guide
    ├── DOCUMENTATION_CLEANUP.md   # Documentation maintenance notes
    ├── GOVERNANCE_REVIEW.md       # Governance review workflow guide
    ├── ML Models/                 # Machine Learning model documentation
    │   ├── Feedback_Loop.md       # Active learning feedback loop
    │   ├── PII_Detection.md       # PII/PHI detection (includes healthcare training)
    │   ├── Prompt_Injection.md    # Prompt injection detection
    │   ├── README.md              # ML models overview
    │   └── TFIDF_Anomaly.md       # TF-IDF anomaly detection
    ├── PROVIDER_EXAMPLES.md       # Provider-specific field mappings
    ├── SERVICENOW_INTEGRATION.md  # ServiceNow integration guide
    ├── TOKEN_COST_ADMIN.md        # Token cost administration
    └── YOUR_DATA_IS_READY.md      # Quick start for training data

```

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

## Version History

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
