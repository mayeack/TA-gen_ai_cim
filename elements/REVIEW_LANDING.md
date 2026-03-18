# Review Landing Page

## Overview

The **Review Landing** page is a helper/redirect page that processes event escalation requests and creates entries in the review queue before redirecting to the Event Review page. It is not directly accessed by users but serves as an intermediary for workflow actions.

## Design

Built using **SimpleXML Dashboard** with custom JavaScript (`review_landing.js`) for processing logic.

### Layout Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│  Status Display                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ Loading Message: "Processing request..."                         ││
│  │ OR                                                               ││
│  │ Error Message: "Error: <error details>"                          ││
│  │ OR                                                               ││
│  │ Success Message: "Redirecting to Event Review..."                ││
│  │ [Click here if not redirected]                                   ││
│  └─────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  Hidden Results Table (for JavaScript access)                        │
└─────────────────────────────────────────────────────────────────────┘
```

## Purpose

This page:

1. **Receives** event escalation requests (via URL parameter `event_id`)
2. **Fetches** event metadata from the gen_ai_log index
3. **Creates** a new entry in the review queue KV Store
4. **Redirects** to the Event Review page with the event pre-loaded

## Workflow

```
User clicks "Open AI Review"           ┌─────────────────┐
from Event Context Menu     ──────────▶│ review_landing  │
                                       │ ?event_id=xyz   │
                                       └────────┬────────┘
                                                │
                                       ┌────────▼────────┐
                                       │ Fetch event     │
                                       │ metadata        │
                                       └────────┬────────┘
                                                │
                                       ┌────────▼────────┐
                                       │ Create KV Store │
                                       │ entry           │
                                       └────────┬────────┘
                                                │
                                       ┌────────▼────────┐
                                       │ Redirect to     │
                                       │ event_review    │
                                       └─────────────────┘
```

## URL Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `event_id` | Yes | The `gen_ai.event.id` to escalate |

## Search Query

The page runs a search to fetch event metadata:

```spl
index=gen_ai_log gen_ai.event.id="$event_id$" 
| head 1 
| eval event_id='gen_ai.event.id',
    trace_id=coalesce('gen_ai.trace.id', trace_id, ""),
    event_time=_time,
    app=coalesce('gen_ai.app.name', service_name, "Unknown"),
    model=coalesce('gen_ai.request.model', request_model, "Unknown"),
    prompt_preview=substr(coalesce('gen_ai.input.messages', ""), 1, 200),
    response_preview=substr(coalesce('gen_ai.output.messages', ""), 1, 200)
| table event_id, trace_id, event_time, app, model, prompt_preview, response_preview
```

## File Location

```
default/data/ui/views/review_landing.xml
```

## Technical Details

- **Format**: SimpleXML Dashboard
- **Theme**: Dark
- **Scripts**: `review_landing.js`
- **Hidden**: Edit and Export buttons
- **Time Range**: Last 90 days

## JavaScript Functionality (`review_landing.js`)

1. **Parse** URL parameter for event_id
2. **Wait** for search results
3. **Create** KV Store entry via REST API
4. **Redirect** to Event Review page
5. **Handle** errors with user feedback

## Related Files

- `appserver/static/review_landing.js` - Processing logic
- `workflow_actions.conf` - "Open AI Review" action
- `event_review.xml` - Target destination
- `collections.conf` - KV Store definition
