# Review Queue Dashboard

## Overview

The **Review Queue** dashboard displays all AI events that have been flagged for human review. It serves as the central triage point for the governance review workflow, allowing reviewers to prioritize and select events for detailed examination.

## Purpose

This dashboard enables governance teams to:

- **Triage** events by priority, service, and model
- **Track** review progress with status indicators
- **Monitor** review workload with summary statistics
- **Navigate** directly to detailed event review
- **Analyze** trends in escalated events

## File Location

```
default/data/ui/views/review_queue.xml
```

## Design

Built using **SimpleXML (Classic Dashboard)**, this dashboard provides a filterable, sortable queue of events requiring attention.

### Layout Structure

```
+---------------------------------------------------------------------+
|  Filters: Priority | App Name | Model                    [Submit]   |
+---------------------------------------------------------------------+
|  +----------------+  +----------------+  +------------------+       |
|  | In Progress    |  | Completed      |  | Confirmed Issues |       |
|  |     (n)        |  |     (n)        |  |       (n)        |       |
|  +----------------+  +----------------+  +------------------+       |
+---------------------------------------------------------------------+
|  Events Pending Review (clickable table)                            |
|  +---------------------------------------------------------------+  |
|  | # | Event ID | Event Date | Status | Priority | Assignee     |  |
|  +---------------------------------------------------------------+  |
+---------------------------------------------------------------------+
|  +---------------------------+  +-----------------------------+     |
|  | Events by Service         |  | Reviews Over Time           |     |
|  | (column chart)            |  | (line chart)                |     |
|  +---------------------------+  +-----------------------------+     |
+---------------------------------------------------------------------+
```

## Filters

| Filter | Description | Default |
|--------|-------------|---------|
| **Priority** | Filter by priority level | All |
| **App Name** | Filter by AI application/service | All Apps |
| **Model** | Filter by AI model | All Models |

## Panels

### Status Summary Cards

| Card | Color | Description |
|------|-------|-------------|
| **In Progress** | Blue (`#5A9BD5`) | Events with status: new, assigned, in_review |
| **Review Completed** | Green (`#53A051`) | Events with status: completed, rejected |
| **Confirmed Issues** | Red (`#DC4E41`) | Completed reviews with confirmed findings (PII, PHI, injection, anomaly) |

### Events Pending Review Table

| Column | Description |
|--------|-------------|
| **Event ID** | Unique identifier (clickable to open Event Review) |
| **Event Date** | Timestamp of the original event |
| **Status** | Visual status indicator with emoji |
| **Priority** | Color-coded priority level |
| **Assignee** | Assigned reviewer |

### Status Indicators

| Status | Display | Color |
|--------|---------|-------|
| New | "New" | Orange (`#F8BE34`) |
| Assigned | "Assigned" | Yellow (`#F1D357`) |
| In Review | "In Review" | Blue (`#5A9BD5`) |

### Priority Indicators

| Priority | Display | Color |
|----------|---------|-------|
| Critical | "Critical" | Red (`#DC4E41`) |
| High | "High" | Orange (`#F8BE34`) |
| Medium | "Medium" | Yellow (`#F1D357`) |
| Low | "Low" | Green (`#53A051`) |

### Charts

| Panel | Type | Description |
|-------|------|-------------|
| **Events by Service/App** | Column chart | Distribution of review events by service |
| **Event Reviews Initiated** | Line chart | Daily count of new reviews over 30 days |

## Drilldown Behavior

Clicking any row in the **Events Pending Review** table opens the **Event Review** page with the selected event pre-loaded:

```
/app/TA-gen_ai_cim/event_review?form.event_id=<EVENT_ID>
```

## Data Source

| Property | Value |
|----------|-------|
| **KV Store Collection** | `gen_ai_review_findings` |
| **Lookup** | `gen_ai_review_findings_lookup` |
| **Time Range** | Last 90 days (configurable) |

## Event Review Workflow

1. **Detection alerts** escalate events to the review queue
2. **Reviewers** triage events by priority in this dashboard
3. **Click** an event to open the detailed Event Review page
4. **Document** findings and update status
5. **Optionally** escalate to ServiceNow for case management

## Related Documentation

- [AI Governance Review Workflow](../GOVERNANCE_REVIEW.md) - Complete workflow documentation
- [Event Review Page](../GOVERNANCE_REVIEW.md#event-review-page) - Detailed review interface
- [ServiceNow Integration](../SERVICENOW_INTEGRATION.md) - Case escalation

## Related Files

| File | Purpose |
|------|---------|
| `collections.conf` | KV Store collection definition |
| `transforms.conf` | Lookup definition |
| `event_review.xml` | Detailed review page |
| `review_save.js` | Save handler JavaScript |

---

**Last Updated:** 2026-01-28
