# AI Governance Review Workflow

This document describes the AI Governance Review workflow, including the Event Review page, Detection Settings configuration, and how they interact.

## Table of Contents

1. [Overview](#overview)
2. [Review Queue](#review-queue)
3. [Event Review Page](#event-review-page)
4. [Detection Settings](#detection-settings)
5. [Field Visibility Configuration](#field-visibility-configuration)
6. [Review Findings Fields](#review-findings-fields)
7. [Workflow Actions](#workflow-actions)
8. [KV Store Data](#kv-store-data)

---

## Overview

The AI Governance Review workflow enables security and compliance teams to:

- **Monitor** AI events escalated for human review
- **Investigate** prompts and responses for policy violations
- **Document** findings including PII, PHI, prompt injection, and anomalies
- **Track** review status and assignments

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Detection Alerts (Scheduled Searches)                                  │
│  ├── PII Detection Alert                                                │
│  ├── PHI Detection Alert                                                │
│  ├── Prompt Injection Alert                                             │
│  ├── Anomaly Detection Alert                                            │
│  └── Random Escalation (configurable)                                   │
└────────────────────┬────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Review Queue (KV Store: gen_ai_review_findings)                        │
│  Events with status: new, assigned, in_review                           │
└────────────────────┬────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Event Review Page                                                      │
│  ├── Event ID / Status / Save (top row)                                 │
│  ├── Reviewer Notes (dedicated full-width section)                      │
│  ├── Review Findings (left panel)                                       │
│  ├── Prompt Content (middle panel)                                      │
│  └── Response Content (right panel)                                     │
└────────────────────┬────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Completed Reviews                                                      │
│  ├── Findings stored in KV Store                                        │
│  ├── Audit trail maintained                                             │
│  └── ServiceNow integration (optional)                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Review Queue

The **Review Queue** (`review_queue.xml`) displays all events pending human review.

### Accessing the Review Queue

1. Navigate to **Apps → GenAI Governance**
2. Click **Governance Review** in the navigation
3. Select **Review Queue**

### Queue Features

| Feature | Description |
|---------|-------------|
| Status Filter | Filter by New, Assigned, In Review, Completed |
| Priority Sort | Sort by Critical, High, Medium, Low priority |
| Assignee Filter | Filter by assigned reviewer |
| Event ID Link | Click to open Event Review page |

### Event Statuses

| Status | Description |
|--------|-------------|
| `new` | Newly escalated, not yet reviewed |
| `assigned` | Assigned to a reviewer |
| `in_review` | Currently being reviewed |
| `completed` | Review finished |
| `rejected` | Event rejected (false positive, etc.) |

---

## Event Review Page

The **Event Review** page (`event_review.xml`) provides a detailed view for reviewing individual AI events.

### Layout

The page uses a multi-row layout:

```
┌───────────────────────────────────────────────────────────────────────────┐
│  Event ID: [Dropdown]                        [Status]         [Save]      │
└───────────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────────┐
│  Reviewer Notes                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  [Large textarea for reviewer notes]                                 │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────┘

┌─────────────────┬─────────────────────┬─────────────────────┐
│ Review Findings │   Prompt (Input)    │  Response (Output)  │
│                 │                     │                     │
│ - Priority      │   User's prompt     │   AI's response     │
│ - Assignee      │   to the AI model   │   to the user       │
│ - PII Present?  │                     │                     │
│ - PII Types     │                     │                     │
│ - PHI Present?  │                     │                     │
│ - PHI Types     │                     │                     │
│ - Injection?    │                     │                     │
│ - Injection Type│                     │                     │
│ - Anomaly?      │                     │                     │
│ - Anomaly Desc  │                     │                     │
└─────────────────┴─────────────────────┴─────────────────────┘
```

**Key Layout Features:**
- **Row 1:** Event selection with status and save button
- **Row 2:** Dedicated full-width Reviewer Notes section for detailed documentation
- **Row 3:** Three-column layout for Review Findings, Prompt, and Response content

### Accessing the Event Review Page

1. From the Review Queue, click an Event ID
2. Or navigate directly: `/app/TA-gen_ai_cim/event_review?form.event_id=<EVENT_ID>`

### Review Workflow

1. **Select Event** - Choose an event from the dropdown in the top row
2. **Review Content** - Examine the prompt and response panels in the three-column layout
3. **Document Notes** - Add detailed findings in the dedicated Reviewer Notes section
4. **Record Findings** - Complete detection fields in the Review Findings panel
5. **Save** - Click the Save button to persist all findings

---

## Detection Settings

Detection Settings control which detection types are enabled for AI governance monitoring. These settings are configured on the **Configuration** page.

### Accessing Detection Settings

1. Navigate to **Apps → GenAI Governance**
2. Click **Configuration** in the navigation
3. Select the **Detection Settings** tab

### Available Settings

| Setting | Description | Default |
|---------|-------------|---------|
| **Detect PII** | Enable PII (Personally Identifiable Information) detection | Enabled |
| **Detect PHI** | Enable PHI (Protected Health Information) detection | Enabled |
| **Detect Prompt Injection** | Enable prompt injection attack detection | Enabled |
| **Detect Anomalies** | Enable anomaly detection for unusual patterns | Enabled |
| **Random Escalation** | Randomly escalate events for review based on RNG seed | Disabled |
| **RNG Seed** | Alphanumeric pattern for random escalation matching | (empty) |

### Configuration Storage

Detection settings are stored in `ta_gen_ai_cim_detection.conf`:

```ini
[settings]
detect_pii = 1
detect_phi = 1
detect_prompt_injection = 1
detect_anomalies = 1
random_escalation = 0
rng_seed =
```

---

## Field Visibility Configuration

The Event Review page dynamically shows or hides detection-related fields based on the Detection Settings configuration.

### How It Works

When a detection type is **disabled** in Detection Settings, the corresponding fields are **hidden** on the Event Review page. This streamlines the review interface to show only relevant fields.

### Field Visibility Mapping

| Detection Setting | When Disabled, Hides Fields |
|-------------------|----------------------------|
| **Detect PII** OFF | "PII Present?" and "PII Types" |
| **Detect PHI** OFF | "PHI Present?" and "PHI Types" |
| **Detect Prompt Injection** OFF | "Injection Detected?" and "Injection Type" |
| **Detect Anomalies** OFF | "Anomaly Detected?" and "Anomaly Description" |

### Example Scenarios

**Scenario 1: PII-Only Environment**
- Enable: Detect PII
- Disable: Detect PHI, Detect Prompt Injection, Detect Anomalies
- Result: Event Review shows only PII fields

**Scenario 2: Healthcare Environment**
- Enable: Detect PII, Detect PHI
- Disable: Detect Prompt Injection, Detect Anomalies
- Result: Event Review shows PII and PHI fields

**Scenario 3: Full Security Monitoring**
- Enable: All detection types
- Result: Event Review shows all detection fields

### Technical Implementation

Field visibility is controlled by JavaScript in `review_save.js`:

1. On page load, the script fetches detection settings via REST API
2. For each detection type, it shows/hides corresponding input fields
3. Uses CSS classes (`detection-hidden`, `detection-visible`) for reliable toggling
4. Re-applies visibility when the event selection changes

```javascript
// Detection settings are loaded from:
// /splunkd/__raw/servicesNS/nobody/TA-gen_ai_cim/configs/conf-ta_gen_ai_cim_detection/settings

// Field mapping:
// 'pii' → ['input_pii_confirmed', 'input_pii_types']
// 'phi' → ['input_phi_confirmed', 'input_phi_types']
// 'injection' → ['input_injection_confirmed', 'input_injection_type']
// 'anomaly' → ['input_anomaly_confirmed', 'input_anomaly_type']
```

---

## Review Findings Fields

### Reviewer Notes (Dedicated Section)

| Field | Type | Description |
|-------|------|-------------|
| **Reviewer Notes** | Textarea | Full-width section for detailed investigation notes, evidence, and recommendations |

The Reviewer Notes field has its own dedicated row to provide ample space for thorough documentation of review findings.

### Standard Fields (Review Findings Panel)

| Field | Type | Description |
|-------|------|-------------|
| **Status** | Dropdown | Review status (new, assigned, in_review, completed, rejected) |
| **Priority** | Dropdown | Priority level (low, medium, high, critical) |
| **Assignee** | Dropdown | User assigned to review (from Splunk users) |

### PII Detection Fields

| Field | Type | Description | Visible When |
|-------|------|-------------|--------------|
| **PII Present?** | Dropdown | Whether PII was confirmed (Yes/No) | Detect PII = ON |
| **PII Types** | Multi-select | Types of PII found | Detect PII = ON |

**PII Types Options:**
- SSN
- EMAIL
- PHONE
- DOB
- ADDRESS
- CREDIT_CARD
- NAME

### PHI Detection Fields

| Field | Type | Description | Visible When |
|-------|------|-------------|--------------|
| **PHI Present?** | Dropdown | Whether PHI was confirmed (Yes/No) | Detect PHI = ON |
| **PHI Types** | Multi-select | Types of PHI found | Detect PHI = ON |

**PHI Types Options:**
- Medical Record
- Diagnosis
- Treatment
- Medication
- Health Insurance
- Provider Info

### Prompt Injection Fields

| Field | Type | Description | Visible When |
|-------|------|-------------|--------------|
| **Injection Detected?** | Dropdown | Whether injection was confirmed (Yes/No) | Detect Prompt Injection = ON |
| **Injection Type** | Dropdown | Type of injection attack | Detect Prompt Injection = ON |

**Injection Type Options:**
- N/A
- Jailbreak
- Data Exfiltration
- Other

### Anomaly Detection Fields

| Field | Type | Description | Visible When |
|-------|------|-------------|--------------|
| **Anomaly Detected?** | Dropdown | Whether anomaly was confirmed (Yes/No) | Detect Anomalies = ON |
| **Anomaly Description** | Text | Description of the anomaly | Detect Anomalies = ON |

---

## Workflow Actions

### Save Review

Clicking **Save** persists the review findings to the KV Store:

1. Validates that an event is selected
2. Collects all form field values
3. Updates or creates record in `gen_ai_review_findings` collection
4. Shows success/error feedback
5. Reloads the page to refresh state

### ServiceNow Integration

If ServiceNow integration is configured, completed reviews can be escalated:

1. From the Event Context menu, select "Open Case in ServiceNow"
2. Or use the `aicase` search command

See [ServiceNow Integration](SERVICENOW_INTEGRATION.md) for details.

---

## KV Store Data

### Collection: gen_ai_review_findings

Stores all review findings for auditing and tracking.

| Field | Type | Description |
|-------|------|-------------|
| `_key` | string | Unique key (event ID) |
| `gen_ai_event_id` | string | GenAI event ID |
| `gen_ai_review_status` | string | Review status |
| `gen_ai_review_priority` | string | Priority level |
| `gen_ai_review_assignee` | string | Assigned reviewer |
| `gen_ai_review_reviewer` | string | User who completed review |
| `gen_ai_review_pii_confirmed` | string | PII confirmation (true/false) |
| `gen_ai_review_pii_types` | string | Comma-separated PII types |
| `gen_ai_review_phi_confirmed` | string | PHI confirmation (true/false) |
| `gen_ai_review_phi_types` | string | Comma-separated PHI types |
| `gen_ai_review_prompt_injection_confirmed` | string | Injection confirmation |
| `gen_ai_review_prompt_injection_type` | string | Injection type |
| `gen_ai_review_anomaly_confirmed` | string | Anomaly confirmation |
| `gen_ai_review_anomaly_type` | string | Anomaly description |
| `gen_ai_review_notes` | string | Reviewer notes |
| `gen_ai_review_created_at` | number | Unix timestamp of creation |
| `gen_ai_review_updated_at` | number | Unix timestamp of last update |

### Querying Review Data

```spl
| inputlookup gen_ai_review_findings_lookup
| search gen_ai_review_status="completed"
| table gen_ai_event_id, gen_ai_review_priority, gen_ai_review_pii_confirmed, gen_ai_review_phi_confirmed
```

### Review Statistics

```spl
| inputlookup gen_ai_review_findings_lookup
| stats count by gen_ai_review_status
| eval percentage=round(count/sum(count)*100, 1)
```

---

## Best Practices

### 1. Configure Detection Settings First

Before using the Event Review page, configure Detection Settings to match your organization's monitoring requirements.

### 2. Use Appropriate Priorities

| Priority | Use For |
|----------|---------|
| Critical | SSN, Credit Card, Medical Records, Active Attacks |
| High | PII confirmed, PHI confirmed, Injection attempts |
| Medium | Suspected violations requiring investigation |
| Low | Minor anomalies, informational review |

### 3. Document Findings Thoroughly

Use the dedicated Reviewer Notes section (full-width area above the three-column layout) to document:
- Investigation steps taken
- Evidence found
- Remediation recommendations
- Follow-up actions needed

### 4. Regular Queue Review

- Review the queue daily for new high-priority events
- Clear completed reviews weekly
- Generate summary reports monthly

### 5. Integrate with Incident Response

For critical findings:
1. Complete the Event Review
2. Create ServiceNow case (if integrated)
3. Follow incident response procedures
4. Update review notes with resolution

---

## Troubleshooting

### Fields Not Hiding/Showing

**Issue:** Detection fields remain visible even when detection type is disabled.

**Resolution:**
1. Clear browser cache
2. Verify detection settings are saved correctly:
   ```spl
   | rest /servicesNS/nobody/TA-gen_ai_cim/configs/conf-ta_gen_ai_cim_detection/settings
   | table detect_pii, detect_phi, detect_prompt_injection, detect_anomalies
   ```
3. Check browser console for JavaScript errors
4. Reload the Event Review page

### Save Button Not Working

**Issue:** Clicking Save does not persist findings.

**Resolution:**
1. Ensure an Event ID is selected
2. Check browser console for errors
3. Verify KV Store collection exists:
   ```spl
   | rest /servicesNS/nobody/TA-gen_ai_cim/storage/collections/config
   | search name="gen_ai_review_findings"
   ```

### No Events in Dropdown

**Issue:** Event ID dropdown is empty.

**Resolution:**
1. Verify events exist in the review queue:
   ```spl
   | inputlookup gen_ai_review_findings_lookup
   | search gen_ai_review_status IN ("new", "assigned", "in_review")
   ```
2. Check that detection alerts are running and escalating events

---

## Related Documentation

- **Detection Settings Config:** `default/ta_gen_ai_cim_detection.conf`
- **Event Review Dashboard:** `default/data/ui/views/event_review.xml`
- **Review JavaScript:** `appserver/static/review_save.js`
- **Review Styling:** `appserver/static/event_review.css`
- **PII/PHI Detection:** [ML Models/PII_Detection.md](ML%20Models/PII_Detection.md)
- **ServiceNow Integration:** [SERVICENOW_INTEGRATION.md](SERVICENOW_INTEGRATION.md)

---

**Last Updated:** 2026-01-21
**Version:** 1.2.1
