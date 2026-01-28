# Review Queue Dashboard

## Overview

The **Review Queue** dashboard displays all AI events that have been flagged for human review. It serves as the central triage point for the governance review workflow, allowing reviewers to prioritize and select events for detailed examination.

## Design

Built using **SimpleXML (Classic Dashboard)**, this dashboard provides a filterable, sortable queue of events requiring attention.

### Layout Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│  Filters: Priority | Service/App | Model           [Submit]          │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │ In Progress  │  │ Completed    │  │ Confirmed    │              │
│  │     (n)      │  │     (n)      │  │ Issues (n)   │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
├─────────────────────────────────────────────────────────────────────┤
│  Events Pending Review (clickable table)                            │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ # │ Event ID │ Status │ Priority │ Assignee                     ││
│  ├───┼──────────┼────────┼──────────┼────────────────────────────────│
│  │ 1 │ abc123.. │ 🟠 New │ 🔴 Crit  │ user@example.com             ││
│  └─────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐  ┌──────────────────────┐                 │
│  │ Events by Service   │  │ Reviews Over Time    │                 │
│  │ (column chart)      │  │ (line chart)         │                 │
│  └─────────────────────┘  └──────────────────────┘                 │
└─────────────────────────────────────────────────────────────────────┘
```

## Purpose

The Review Queue enables governance teams to:

- **Triage** events by priority, service, and model
- **Track** review progress with status indicators
- **Monitor** review workload with summary statistics
- **Navigate** directly to detailed event review
- **Analyze** trends in escalated events

## Key Components

### Status Summary Cards

| Card | Color | Description |
|------|-------|-------------|
| In Progress | Blue | Events with status: new, assigned, in_review |
| Review Completed | Green | Events with status: completed, rejected |
| Confirmed Issues | Red | Completed reviews with confirmed findings |

### Events Pending Review Table

| Column | Description |
|--------|-------------|
| Event ID | Unique identifier (clickable to open Event Review) |
| Status | Visual status indicator with emoji |
| Priority | Color-coded priority level |
| Assignee | Assigned reviewer |

### Status Indicators

| Status | Display | Color |
|--------|---------|-------|
| New | 🟠 New | Orange |
| Assigned | 🟡 Assigned | Yellow |
| In Review | 🔵 In Review | Blue |

### Priority Indicators

| Priority | Display | Color |
|----------|---------|-------|
| Critical | 🔴 Critical | Red |
| High | 🟠 High | Orange |
| Medium | 🟡 Medium | Yellow |
| Low | 🟢 Low | Green |

## Filters

| Filter | Description | Default |
|--------|-------------|---------|
| Priority | Filter by priority level | All |
| Service/App | Filter by AI service | All Services |
| Model | Filter by AI model | All Models |

## Drilldown Behavior

Clicking any row in the "Events Pending Review" table opens the **Event Review** page with the selected event pre-loaded:

```
/app/TA-gen_ai_cim/event_review?form.event_id=<EVENT_ID>
```

## File Location

```
default/data/ui/views/review_queue.xml
```

## Technical Details

- **Format**: SimpleXML (Classic Dashboard)
- **Data Source**: `gen_ai_review_findings` KV Store collection
- **Lookup**: `gen_ai_review_findings_lookup`
- **Time Range**: Last 90 days (configurable)

## Related Files

- `collections.conf` - KV Store collection definition
- `transforms.conf` - Lookup definition
- `event_review.xml` - Detailed review page
