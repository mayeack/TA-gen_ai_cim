# Quick Start Guide

Get TA-gen_ai_cim up and running in 10 minutes.

---

## Prerequisites

### Required

| Component | Version | Notes |
|-----------|---------|-------|
| **Splunk Enterprise** | 9.0+ | Or Splunk Cloud |
| **AI Telemetry Data** | - | GenAI/LLM events flowing into Splunk |

### Optional (for ML Features)

| Component | Version | Splunkbase | Notes |
|-----------|---------|------------|-------|
| **Machine Learning Toolkit (MLTK)** | 5.3+ | [Download](https://splunkbase.splunk.com/app/2890) | Required for PII detection, prompt injection, TF-IDF anomaly |
| **Python for Scientific Computing** | Latest | [Download](https://splunkbase.splunk.com/app/2882) | Required by MLTK |
| **Splunk AI Toolkit** | Latest | [Download](https://splunkbase.splunk.com/app/6842) | For AI-powered case summaries |

### Optional (for Integrations)

| Service | Purpose |
|---------|---------|
| **ServiceNow Instance** | AI Case Management escalation |

### Bundled Dependencies (No Action Required)

The TA includes all necessary Python libraries in the `lib/` directory:
- `splunklib` SDK v2.0.2 - Splunk SDK for Python

### Verify Prerequisites

Run these searches to verify your environment:

```spl
# Check Splunk version (should be 9.0+)
| rest /services/server/info | table version

# Check MLTK installation (optional)
| rest /services/apps/local/Splunk_ML_Toolkit | table title, version
```

---

## Step 1: Install the TA

```bash
# Copy TA to Splunk apps directory
cp -r TA-gen_ai_cim $SPLUNK_HOME/etc/apps/

# Restart Splunk
$SPLUNK_HOME/bin/splunk restart
```

Or use the included install script:

```bash
./INSTALL.sh
```

---

## Step 2: Configure Your Index

**Important:** The app assumes the index `gen_ai_log` exists.

### Option A: Create the Index (Recommended)

```bash
# Create the index
$SPLUNK_HOME/bin/splunk add index gen_ai_log
```

### Option B: Use Your Existing Index

If your AI telemetry is in a different index, update `default/props.conf`:

```ini
# Change from:
[index::gen_ai_log]

# To your index name:
[index::your_ai_index_name]
```

Then update the saved searches in `default/savedsearches.conf`:

```
# Find and replace all occurrences of:
index=gen_ai_log

# With your index name:
index=your_ai_index_name
```

---

## Step 3: Verify Field Extraction

Run this search to verify normalization is working:

```spl
index=gen_ai_log earliest=-1h
| head 10
| table gen_ai.operation.name gen_ai.provider.name gen_ai.request.model gen_ai.usage.total_tokens
```

You should see populated `gen_ai.*` fields.

---

## Step 4: Configure ServiceNow Integration (Optional)

If you want to create ServiceNow AI Cases from Splunk:

1. Navigate to **Apps > AI Governance > Configuration**
2. Click **Add** to create a new ServiceNow account
3. Enter your ServiceNow instance URL and credentials
4. Save the configuration

Test with:

```spl
| makeresults | eval gen_ai.request.id="test_123" | aicase mode=lookup
```

---

## Step 5: Configure GenAI Summary (Optional)

To enable AI-powered summaries in ServiceNow cases:

1. Navigate to **Apps > AI Governance > Configuration**
2. Click the **GenAI Summary** tab
3. Enable the feature and enter your Anthropic API key
4. Save settings

---

## Step 6: Train ML Models (Optional)

For ML-based PII detection and anomaly detection:

### PII Detection Model

1. Prepare training data in `lookups/pii_training_examples.csv`
2. Run the training saved searches in order:
   - `GenAI - PII Train Step 1 - Feature Engineering from Initial Dataset`
   - `GenAI - PII Train Step 2 - Logistic Regression Model`
   - `GenAI - PII Train Step 3 - Validate Model Performance`

### TF-IDF Anomaly Detection

1. Run the prompt model training:
   - `GenAI - TFIDF Train Prompt Step 1 - TFIDF Vectorizer`
   - `GenAI - TFIDF Train Prompt Step 2 - PCA`
   - `GenAI - TFIDF Train Prompt Step 3 - Anomaly Model`

2. Run the response model training:
   - `GenAI - TFIDF Train Response Step 1 - TFIDF Vectorizer`
   - `GenAI - TFIDF Train Response Step 2 - PCA`
   - `GenAI - TFIDF Train Response Step 3 - Anomaly Model`

**Important:** Wait for each step to complete before running the next.

---

## Step 7: Enable Alerts

Enable the governance alerts:

```bash
# Enable all GenAI alerts
$SPLUNK_HOME/bin/splunk enable saved-search "GenAI - Safety Violation Alert" -app TA-gen_ai_cim
$SPLUNK_HOME/bin/splunk enable saved-search "GenAI - PII Detection Alert" -app TA-gen_ai_cim
# ... enable other alerts as needed
```

Or enable via Splunk Web:
1. Navigate to **Settings > Searches, Reports, and Alerts**
2. Filter by App: `TA-gen_ai_cim`
3. Enable the alerts you want to use

---

## Common Configuration Options

### Token Cost Tracking

Add pricing data to the KV store:

```spl
| makeresults 
| eval provider="openai", model="gpt-4", direction="input", cost_per_million=30.00, effective_start=now(), currency="USD"
| outputlookup append=true genai_token_cost_lookup
```

### Custom Provider Mappings

Add custom provider normalization in `transforms.conf`:

```ini
[my_custom_provider_normalize]
SOURCE_KEY = _raw
REGEX = "model"\s*:\s*"(my-custom-model-[^"]+)"
FORMAT = gen_ai.provider.name::my_custom_provider
WRITE_META = true
```

---

## Troubleshooting

### No Normalized Fields Appearing

1. Verify your data is in the correct index
2. Check that `KV_MODE = json` is set for your sourcetype
3. Restart Splunk after making configuration changes

```bash
$SPLUNK_HOME/bin/splunk restart
```

### MLTK Models Not Found

1. Verify MLTK is installed
2. Run the training saved searches
3. Check model existence:

```spl
| inputlookup mlspl_models | search model_name="pii_detection_model"
```

### ServiceNow Connection Errors

1. Verify credentials in Configuration page
2. Test network connectivity to ServiceNow instance
3. Check Splunk's `_internal` index for error logs

---

## Next Steps

- Review the full [README.md](README.md) for detailed documentation
- See [README/DEPLOYMENT_GUIDE.md](README/DEPLOYMENT_GUIDE.md) for production deployment
- Check [README/SERVICENOW_INTEGRATION.md](README/SERVICENOW_INTEGRATION.md) for ServiceNow setup

---

## Support

- **Documentation:** [README/](README/) folder contains detailed guides
- **Issues:** Check Splunk's internal logs at `index=_internal sourcetype=splunkd`
