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
| **Splunk AI Toolkit** | Latest | [app 6842](https://splunkbase.splunk.com/app/6842) | Required for PII detection, prompt injection, TF-IDF anomaly, AI-powered case summaries, **and the LLM Connections UI** |
| **Python for Scientific Computing (PSC)** | Latest | platform-specific ↓ | **Required** by the AI Toolkit. Must match your Splunk host's **OS + CPU architecture** |

**Pick the PSC build that matches your platform** — the AI Toolkit loads `Splunk_SA_Scientific_Python_<platform>` and its Connections UI *and* ML engine fail if the matching build is absent:

| Platform | Splunkbase |
|----------|------------|
| Linux x86-64 | [app 2882](https://splunkbase.splunk.com/app/2882) |
| macOS Apple Silicon (arm64) | [app 6785](https://splunkbase.splunk.com/app/6785) |
| macOS Intel (x86-64) | [app 2881](https://splunkbase.splunk.com/app/2881) |
| Windows x86-64 | search Splunkbase: "Python for Scientific Computing for Windows" |

After installing PSC, **restart Splunk**, then verify it is present: `ls $SPLUNK_HOME/etc/apps | grep Scientific_Python`.

> **Role Requirement:** The user must have the **`mltk_admin`** role (provided by the AI Toolkit). It grants ML training/management **and** the `edit_ai_commander_config` + `edit_storage_passwords` capabilities required to **create LLM connections**. A plain `admin` role is **not** sufficient to create connections — also assign `mltk_admin` (or `sc_admin` / `mltk_model_admin`).

> **LLM Connection:** To use generative AI capabilities (e.g., AI-powered case summaries via the `| ai` command), configure a **default LLM connection** in the Splunk AI Toolkit under **Apps > Splunk AI Toolkit > Connection Management**.

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

# Check Splunk AI Toolkit installation (optional)
| rest /services/apps/local/splunk_ai_toolkit | table title, version
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

### AI Toolkit LLM Connection Fails (SSL/Certificate Error)

Splunk's Python expects a CA certificate bundle at `$SPLUNK_HOME/openssl/cert.pem`, but this file does not ship with Splunk. Without it, outbound HTTPS to LLM APIs (OpenAI, Anthropic, etc.) will fail.

**Quick fix:**
```bash
# macOS
cp /etc/ssl/cert.pem $SPLUNK_HOME/openssl/cert.pem

# Linux (RHEL/CentOS)
cp /etc/pki/tls/certs/ca-bundle.crt $SPLUNK_HOME/openssl/cert.pem

# Linux (Debian/Ubuntu)
cp /etc/ssl/certs/ca-certificates.crt $SPLUNK_HOME/openssl/cert.pem
```

If behind a corporate TLS inspection proxy (Cisco Secure Access, Zscaler, etc.), the system CA bundle alone is **not** enough — Splunk will reject the proxy-issued cert with `CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`. Detect it by inspecting the chain the LLM host presents (proxy issuer instead of a public CA):

```bash
echo | openssl s_client -connect api.anthropic.com:443 -servername api.anthropic.com -showcerts 2>/dev/null \
  | grep -E '^ *[0-9]+ s:|^ *[0-9]+ i:'   # issuer "Cisco Secure Access"/"Zscaler" => proxy in path
```

Then append the proxy's **root CA** to **both** bundles — the AI Toolkit's Python HTTP client verifies against PSC's `certifi`, not only `openssl/cert.pem`:

```bash
# 1) Splunk's openssl bundle
security find-certificate -a -c "Cisco Secure Access Root CA" -p /Library/Keychains/System.keychain >> $SPLUNK_HOME/openssl/cert.pem
# 2) PSC certifi bundle (the one the AI Toolkit actually uses)
PSC_CERTIFI=$(find $SPLUNK_HOME/etc/apps/Splunk_SA_Scientific_Python_*/bin/*/lib/python*/site-packages/certifi/cacert.pem 2>/dev/null | head -1)
security find-certificate -a -c "Cisco Secure Access Root CA" -p /Library/Keychains/System.keychain >> "$PSC_CERTIFI"
```

See [DEPLOYMENT_GUIDE.md](README/DEPLOYMENT_GUIDE.md#ssl-certificate-setup-for-outbound-https) for full instructions and non-macOS sources.

### AI Toolkit Connections Page Is Blank, "No providers found", or `fit` Fails

These three are the **same root cause: Python for Scientific Computing (PSC) is missing, or the wrong platform build is installed.** The AI Toolkit's connection-management backend *and* its ML engine both require PSC.

Symptoms:
- The **Connection settings** section of the *Custom/Anthropic LLM connection* form renders empty (no Endpoint / API-key fields), or **Test connection** fails before any network call.
- Searching providers under **+ Connection** returns *"No providers found."*
- ML searches error with `Failed to find Python for Scientific Computing Add-on (Splunk_SA_Scientific_Python_<platform>)` — check `index=_internal source=*mlspl.log`.

Fix: install the **platform-correct** PSC package (see Prerequisites), then **restart Splunk**:

```bash
ls $SPLUNK_HOME/etc/apps | grep Scientific_Python   # the build must match your OS + arch
$SPLUNK_HOME/bin/splunk restart
```

### LLM Test Fails "Unable to connect to Anthropic" — but TLS/cert config is correct (macOS / endpoint security)

If the SSL and proxy steps above are correct but **Test connection** still fails with *"Unable to connect to Anthropic"*, and `splunkd.log` / `index=_internal source=*mlspl.log` shows a `json.JSONDecodeError: Expecting value` from `py_executable_bouncer.py`, the cause is the **PSC Python interpreter binary**, not the network. The connection test shells out to it (`.../Splunk_SA_Scientific_Python_<platform>/bin/<arch>/<ver>/bin/python`); ML `fit` does **not**, which is why `fit` can succeed while the connection test fails.

Two macOS gotchas, both seen on Cisco-managed Macs:

1. **The interpreter binary is missing.** `tar -xzf` can silently drop the ~6 MB `python` binary (leaving only `python3-config`). Check, and re-extract just that file — do **not** re-extract the whole app, which would wipe any proxy CA you appended to PSC's certifi:
   ```bash
   PSC=$SPLUNK_HOME/etc/apps/Splunk_SA_Scientific_Python_darwin_arm64
   ls -la "$PSC"/bin/*/*/bin/python    # expect a ~6 MB binary, not just python3-config
   tar -xzf <psc-package>.tgz -C $SPLUNK_HOME/etc/apps/ \
     Splunk_SA_Scientific_Python_darwin_arm64/bin/<arch>/<ver>/bin/python
   ```

2. **Endpoint security quarantines/deletes the binary on execution.** A freshly extracted binary carries `com.apple.quarantine`; Gatekeeper or an EDR agent (e.g. **Cisco Secure Endpoint / AMP**) blocks and removes it on first `exec` — the binary vanishes the moment it runs. Clear quarantine so it matches a normal install:
   ```bash
   xattr -dr com.apple.quarantine "$PSC"
   SPLUNK_HOME=$SPLUNK_HOME "$PSC"/bin/*/*/bin/python --version   # should print Python 3.x and persist
   ```

No Splunk restart is needed — the test spawns the interpreter fresh each time. **Re-apply both after any PSC reinstall/upgrade.**

> Note: the AI Toolkit's LLM calls use `httpx` + `litellm` with `httpx.Client(verify=True)`, which verifies against **`certifi`** (`certifi.where()`) and ignores `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`. Behind a TLS-inspection proxy, the proxy root must be appended to the **certifi `cacert.pem` bundles** (core python *and* PSC), not only `openssl/cert.pem`.

### No Normalized Fields Appearing

1. Verify your data is in the correct index
2. Check that `KV_MODE = json` is set for your sourcetype
3. Restart Splunk after making configuration changes

```bash
$SPLUNK_HOME/bin/splunk restart
```

### ML Models Not Found

1. Verify Splunk AI Toolkit is installed
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
