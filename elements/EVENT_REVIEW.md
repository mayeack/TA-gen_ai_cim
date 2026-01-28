# Event Review Page

## Overview

The **Event Review** page is the detailed investigation interface for examining individual AI events. It provides side-by-side views of prompt and response content alongside a comprehensive findings form for documenting review results.

## Design

Built using **SimpleXML (Form)** with custom JavaScript (`review_save.js`) and CSS (`event_review.css`) for enhanced functionality and styling.

### Layout Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│  Row 1: Event ID [Dropdown] │ Status │ [Save Button]               │
├─────────────────────────────────────────────────────────────────────┤
│  Row 2: Reviewer Notes (full-width textarea)                        │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │  [Large textarea for detailed documentation]                    ││
│  └─────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  Row 3: Three-Column Layout                                         │
│  ┌─────────────────┬─────────────────────┬─────────────────────┐   │
│  │ Review Findings │   Prompt (Input)    │  Response (Output)  │   │
│  │                 │                     │                     │   │
│  │ - Priority      │   User's prompt     │   AI's response     │   │
│  │ - Assignee      │   to the AI model   │   to the user       │   │
│  │ - PII Present?  │                     │                     │   │
│  │ - PII Types     │                     │                     │   │
│  │ - PHI Present?  │                     │                     │   │
│  │ - PHI Types     │                     │                     │   │
│  │ - Injection?    │                     │                     │   │
│  │ - Injection Type│                     │                     │   │
│  │ - Anomaly?      │                     │                     │   │
│  │ - Anomaly Desc  │                     │                     │   │
│  └─────────────────┴─────────────────────┴─────────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│  Row 4: Event Context (service, model, user metadata)               │
├─────────────────────────────────────────────────────────────────────┤
│  Row 5: ← Back to Review Queue                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Purpose

The Event Review page enables reviewers to:

- **Examine** full prompt and response content
- **Document** findings for PII, PHI, injection, and anomalies
- **Classify** event priority and status
- **Assign** reviewers for follow-up
- **Record** detailed notes and observations
- **Save** findings to KV Store for audit trail

## Key Features

### Conditional Field Visibility

Detection fields are dynamically shown/hidden based on **Detection Settings** in the Configuration page:

| Detection Setting OFF | Fields Hidden |
|-----------------------|---------------|
| Detect PII | "PII Present?", "PII Types" |
| Detect PHI | "PHI Present?", "PHI Types" |
| Detect Prompt Injection | "Injection Detected?", "Injection Type" |
| Detect Anomalies | "Anomaly Detected?", "Anomaly Description" |

### Dedicated Reviewer Notes Section

A full-width textarea provides ample space for detailed documentation:
- Investigation steps taken
- Evidence found
- Remediation recommendations
- Follow-up actions needed

### Auto-Load Existing Findings

When an event is selected, any existing review findings are automatically loaded from the KV Store.

## Form Fields

### Standard Fields
| Field | Type | Options |
|-------|------|---------|
| Status | Dropdown | New, Assigned, In Review, Completed, Rejected |
| Priority | Dropdown | Low, Medium, High, Critical |
| Assignee | Dropdown | Splunk users |

### PII Detection Fields
| Field | Type | Options |
|-------|------|---------|
| PII Present? | Dropdown | Yes, No |
| PII Types | Multi-select | SSN, EMAIL, PHONE, DOB, ADDRESS, CREDIT_CARD, NAME |

### PHI Detection Fields
| Field | Type | Options |
|-------|------|---------|
| PHI Present? | Dropdown | Yes, No |
| PHI Types | Multi-select | Medical Record, Diagnosis, Treatment, Medication, Health Insurance, Provider Info |

### Prompt Injection Fields
| Field | Type | Options |
|-------|------|---------|
| Injection Detected? | Dropdown | Yes, No |
| Injection Type | Dropdown | N/A, Jailbreak, Data Exfiltration, Other |

### Anomaly Detection Fields
| Field | Type | Options |
|-------|------|---------|
| Anomaly Detected? | Dropdown | Yes, No |
| Anomaly Description | Text | Free-form description |

## File Location

```
default/data/ui/views/event_review.xml
```

## Technical Details

- **Format**: SimpleXML Form
- **Theme**: Dark
- **Scripts**: `review_save.js`
- **Stylesheets**: `event_review.css`
- **Data Storage**: `gen_ai_review_findings` KV Store

## JavaScript Functionality (`review_save.js`)

1. **Save Handler**: Persists form data to KV Store via REST API
2. **Field Visibility**: Dynamically shows/hides detection fields
3. **Notes Sync**: Syncs textarea with Splunk tokens
4. **Existing Data Load**: Populates form when event is selected

## CSS Styling (`event_review.css`)

- Save button styling (green, matches Configuration page)
- Detection field visibility classes
- Reviewer Notes textarea sizing
- Conditional dropdown coloring (red/green)

## Related Files

- `appserver/static/review_save.js` - JavaScript logic
- `appserver/static/event_review.css` - Custom styling
- `collections.conf` - KV Store definition
- `review_queue.xml` - Source of events
