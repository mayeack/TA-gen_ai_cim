# ServiceNow Case Page

## Overview

The **ServiceNow Case** page is a helper/redirect page that handles ServiceNow AI Case creation or lookup. It processes requests from workflow actions and redirects users to the appropriate ServiceNow case URL.

## Design

Built using **SimpleXML Dashboard** with custom JavaScript (`servicenow_case.js`) for case creation logic.

### Layout Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│  Status Display                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ Loading Message: "Processing request..."                         ││
│  │ "Creating or finding ServiceNow AI Case"                         ││
│  │ OR                                                               ││
│  │ Error Message: "Error: <error details>"                          ││
│  │ OR                                                               ││
│  │ Success Message: "Redirecting to ServiceNow..."                  ││
│  │ [Click here if not redirected]                                   ││
│  └─────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  Case Results Table (for JavaScript access)                          │
└─────────────────────────────────────────────────────────────────────┘
```

## Purpose

This page:

1. **Receives** ServiceNow case requests (via URL parameters)
2. **Executes** the `aicase` custom search command
3. **Creates** a new ServiceNow AI Case (or finds existing one)
4. **Stores** the case mapping in KV Store
5. **Redirects** to the ServiceNow case URL

## Workflow

```
User clicks "Open Case in              ┌─────────────────┐
ServiceNow" from Event      ──────────▶│ servicenow_case │
Context Menu                           │ ?event_id=xyz   │
                                       └────────┬────────┘
                                                │
                                       ┌────────▼────────┐
                                       │ Run aicase      │
                                       │ command         │
                                       └────────┬────────┘
                                                │
                             ┌──────────────────┴──────────────────┐
                             │                                     │
                    ┌────────▼────────┐                 ┌──────────▼─────────┐
                    │ Existing case   │                 │ Create new case    │
                    │ found in KV     │                 │ via ServiceNow API │
                    └────────┬────────┘                 └──────────┬─────────┘
                             │                                     │
                             └──────────────────┬──────────────────┘
                                                │
                                       ┌────────▼────────┐
                                       │ Redirect to     │
                                       │ ServiceNow URL  │
                                       └─────────────────┘
```

## URL Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `event_id` | Yes | The `gen_ai.event.id` to create case for |
| `service_name` | No | Service name for case context |

## Search Query

The page runs the `aicase` custom command:

```spl
| makeresults 
| eval gen_ai.event.id="$event_id$", "gen_ai.service.name"="$service_name$" 
| aicase 
| table snow_case_url snow_case_sys_id snow_case_status snow_case_message
```

## Result Fields

| Field | Description |
|-------|-------------|
| `snow_case_url` | Full URL to the ServiceNow case |
| `snow_case_sys_id` | ServiceNow case sys_id |
| `snow_case_status` | "created", "found", or "error" |
| `snow_case_message` | Status message or error details |

## File Location

```
default/data/ui/views/servicenow_case.xml
```

## Technical Details

- **Format**: SimpleXML Dashboard
- **Theme**: Light
- **Scripts**: `servicenow_case.js`
- **Hidden**: Edit and Export buttons
- **Time Range**: Last 1 minute (for command execution)

## JavaScript Functionality (`servicenow_case.js`)

1. **Parse** URL parameters
2. **Wait** for search completion
3. **Extract** ServiceNow case URL from results
4. **Redirect** to ServiceNow (opens in new tab)
5. **Handle** errors with user feedback

## Prerequisites

For this page to function correctly:

1. ServiceNow account must be configured in Configuration page
2. `aicase` custom command must be available
3. ServiceNow credentials must have API access
4. Network connectivity to ServiceNow instance

## Related Files

- `appserver/static/servicenow_case.js` - Redirect logic
- `bin/aicase.py` - Custom search command
- `workflow_actions.conf` - "Open Case in ServiceNow" action
- `collections.conf` - Case mapping KV Store
- `ta_gen_ai_cim_servicenow.conf` - ServiceNow settings
