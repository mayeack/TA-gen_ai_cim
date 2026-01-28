# Quick Deployment Guide

## Pre-Deployment Checklist

- [ ] Splunk Enterprise 9.0+ or Splunk Cloud
- [ ] MLTK 5.3+ installed (for ML models)
- [ ] AI telemetry flowing into Splunk indexes
- [ ] Admin/power user access to Splunk

---

## 5-Minute Quick Start

### 1. Deploy TA
```bash
cd $SPLUNK_HOME/etc/apps
cp -r /path/to/TA-gen_ai_cim .

# Set ownership (Linux/Unix production only)
# On Linux/Unix with splunk user: chown -R splunk:splunk TA-gen_ai_cim
# On macOS or single-user installs: skip this step

$SPLUNK_HOME/bin/splunk restart
```

### 2. Verify Normalization
```spl
index=gen_ai_log earliest=-1h
| head 10
| table gen_ai.operation.name gen_ai.provider.name gen_ai.request.model gen_ai.safety.violated gen_ai.pii.detected
```

**Expected:** All `gen_ai.*` fields populated.

### 3. Enable Alerts
```bash
# Via Splunk Web: Settings > Searches, reports, and alerts > Enable GenAI alerts
# Or via CLI:
$SPLUNK_HOME/bin/splunk edit saved-search "GenAI - Safety Violation Alert" -app TA-gen_ai_cim -action.email.to your-team@example.com
```

### 4. Access the Dashboard

The **GenAI Governance Overview** dashboard is automatically installed!

**Access it:**
1. Navigate to **Apps → GenAI Governance** in Splunk Web
2. The dashboard opens by default
3. Or go to **Dashboards** and search for "GenAI Governance Overview"

**Customization (optional):**
- Edit the installed dashboard: **Settings → User Interface → Views → genai_governance_overview**
- Create Dashboard Studio version: See `README/DASHBOARD_PANELS.md` for JSON template
- Clone and modify: Create custom versions for different teams

### 5. (Optional) Train MLTK Models

**Create training data (if not exists):**
```spl
index=gen_ai_log earliest=-90d
| eval pii_label=if('gen_ai.pii.detected'="true", 1, 0)
| ... (feature engineering) ...
| outputlookup pii_training_data.csv
```

**Train models:**
```spl
# PII Detection Model
| inputlookup pii_training_data.csv
| fit LogisticRegression pii_label from output_length has_ssn has_email ... into app:pii_response_model

# Prompt Injection Model
| inputlookup prompt_injection_training_data.csv
| fit RandomForestClassifier injection_label from prompt_length has_ignore_instruction ... into app:prompt_injection_model
```

**Enable scheduled scoring:**
```spl
# Edit savedsearches.conf to enable:
[GenAI - MLTK Scoring - PII and Prompt Injection]
enableSched = 1
cron_schedule = 5 * * * *
```

---

## Post-Deployment Validation

### Test 1: Field Extraction
```spl
| rest /services/configs/conf-props | search title="gen_ai*" | table title, FIELDALIAS*, EVAL*, REPORT*
```

### Test 2: Alert Functionality
```spl
| savedsearch "GenAI - Safety Violation Alert" earliest=-24h
```

### Test 3: MLTK Models (if trained)
```spl
| inputlookup mlspl_models | search model_name IN ("pii_response_model", "prompt_injection_model")
```

### Test 4: Dashboard Rendering
- Open "GenAI Governance Overview" dashboard
- Verify all panels load (no errors)
- Check KPI values are reasonable

---

## Common Issues & Resolutions

### Issue: No data in dashboards
**Resolution:**
- Verify index names in searches match your data
- Adjust time ranges (`earliest=-24h` → `earliest=-7d`)
- Check permissions on source indexes

### Issue: Alerts not sending
**Resolution:**
- Configure SMTP in Splunk: `Settings > System Settings > Email Settings`
- Update `action.email.to` in savedsearches.conf
- Test: `| sendemail to="test@example.com" subject="Test"`

### Issue: MLTK models fail to train
**Resolution:**
- Ensure training data has balanced classes (50/50 split)
- Check for null/missing values in features
- Verify Python for Scientific Computing is installed
- Review `_internal` logs: `index=_internal source=*mlspl*`

---

## Performance Tuning

### For High-Volume Environments (>1M events/day)

**1. Accelerate Common Searches**
```spl
# Create data model for acceleration
Settings > Data Models > New Data Model > GenAI_CIM
```

**2. Use Summary Indexing**
```spl
# Add to savedsearches.conf
[GenAI - Hourly Summary]
search = index=gen_ai_log | stats count by gen_ai.provider.name, gen_ai.request.model, gen_ai.safety.violated | collect index=summary
cron_schedule = 0 * * * *
```

**3. Adjust MLTK Scoring Frequency**
```ini
# For real-time scoring, use alert-based trigger instead of cron
[GenAI - MLTK Real-Time Scoring]
search = index=gen_ai_log earliest=rt-5m latest=rt | ... | apply pii_response_model | ...
enableSched = 1
cron_schedule = */5 * * * *
```

---

## Security Hardening

### 1. Restrict Field Access
Create role with limited field visibility:
```bash
$SPLUNK_HOME/bin/splunk add role genai_viewer -auth admin:<password>
$SPLUNK_HOME/bin/splunk edit role genai_viewer -srchFilter 'index=gen_ai_log | fields - gen_ai.input.messages, gen_ai.output.messages'
```

### 2. Mask PII in Dashboards
Update dashboard searches:
```spl
| eval gen_ai.output.messages=if(len('gen_ai.output.messages')>100, substr('gen_ai.output.messages', 1, 100)."...[REDACTED]", 'gen_ai.output.messages')
```

### 3. Audit Access to Governance Data
```spl
index=_audit action=search search="*gen_ai_log*" OR search="*pii*"
| stats count by user, search
| sort -count
```

---

## Maintenance Schedule

### Daily
- Review critical alerts (EMERGENCY safety violations, high PII risk)
- Check dashboard for anomalies

### Weekly
- Review all alert summaries
- Analyze cost trends
- Check MLTK model performance (precision/recall)

### Monthly
- Retrain MLTK models with new data
- Update alert thresholds based on baselines
- Review and archive old governance data

### Quarterly
- Full governance report for stakeholders
- Update documentation with new providers/fields
- Conduct tabletop exercise for incident response

---

## Scaling to Multi-Tenant

For environments with multiple teams/deployments:

**1. Add tenant field to events**
```spl
| eval tenant=coalesce('gen_ai.deployment.id', 'service.name', "unknown")
```

**2. Create tenant-specific alerts**
```spl
[GenAI - Safety Violation - Tenant A]
search = index=gen_ai_log gen_ai.deployment.id="tenant-a-*" gen_ai.safety.violated="true" | ...
action.email.to = tenant-a-team@example.com
```

**3. Use RBAC to isolate tenant data**
```bash
$SPLUNK_HOME/bin/splunk add role tenant_a_admin -auth admin:<password>
$SPLUNK_HOME/bin/splunk edit role tenant_a_admin -srchFilter 'index=gen_ai_log gen_ai.deployment.id="tenant-a-*"'
```

---

## Integration with External Systems

### ServiceNow Incident Creation
```spl
# In alert action
| sendalert servicenow 
    param.short_description="GenAI Safety Violation Detected"
    param.severity="2"
    param.assignment_group="AI Governance Team"
```

### Slack Notifications
```spl
# In alert action
| sendalert slack
    param.webhook_url="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    param.message="🚨 GenAI Safety Violation: $result.gen_ai.deployment.id$"
```

### JIRA Ticket Creation
```spl
# Using Splunk Add-on for JIRA
| sendalert jira
    param.project="AIGOVERN"
    param.issue_type="Incident"
    param.summary="PII Detection Alert - $result.gen_ai.app.name$"
```

---

## Next Steps

After successful deployment:

1. **Baseline Establishment (Week 1)**
   - Run 7 days to establish normal patterns
   - Document baseline metrics (safety rate, PII rate, latency, cost)

2. **Threshold Tuning (Week 2)**
   - Adjust alert thresholds based on baselines
   - Reduce false positives

3. **MLTK Training (Week 3-4)**
   - Collect labeled training data
   - Train and validate models
   - Deploy scoring searches

4. **Team Training (Week 4)**
   - Train AI governance team on dashboards and alerts
   - Document incident response procedures
   - Conduct first tabletop exercise

5. **Production Go-Live (Week 5)**
   - Enable all alerts
   - Set up on-call rotation
   - Begin regular governance reviews

---

## Support Contacts

- **TA Issues:** ai-governance-ops@example.com
- **MLTK Support:** ml-platform-team@example.com
- **Splunk Admin:** splunk-admins@example.com
- **Emergency (Safety/Privacy):** ai-safety-oncall@example.com

---

## Additional Resources

- **Splunk MLTK Docs:** https://docs.splunk.com/Documentation/MLApp
- **OpenTelemetry GenAI Conventions:** https://opentelemetry.io/docs/specs/semconv/gen-ai/
- **NIST AI RMF:** https://www.nist.gov/itl/ai-risk-management-framework
- **Splunk Security Best Practices:** https://docs.splunk.com/Documentation/Splunk/latest/Security/
