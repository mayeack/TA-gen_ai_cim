# TA-gen_ai_cim UI Elements Documentation

This directory contains detailed documentation for each page and UI element in the TA-gen_ai_cim application.

## Navigation

- [NAVIGATION.md](NAVIGATION.md) - Application navigation menu structure

## Main Dashboards

| Page | File | Description |
|------|------|-------------|
| AI Governance Overview | [AI_GOVERNANCE_OVERVIEW.md](AI_GOVERNANCE_OVERVIEW.md) | Default landing page with comprehensive AI monitoring |
| Review Queue | [REVIEW_QUEUE.md](REVIEW_QUEUE.md) | Triage queue for events requiring human review |
| Event Review | [EVENT_REVIEW.md](EVENT_REVIEW.md) | Detailed event investigation and findings form |
| Configuration | [CONFIGURATION.md](CONFIGURATION.md) | Administrative settings and integrations |

## ML Feedback Loop

| Page | File | Description |
|------|------|-------------|
| Model Comparison | [PII_FEEDBACK_LOOP_MODEL_COMPARISON.md](PII_FEEDBACK_LOOP_MODEL_COMPARISON.md) | Champion vs Challenger model comparison |
| Model Registry | [PII_FEEDBACK_LOOP_MODEL_REGISTRY.md](PII_FEEDBACK_LOOP_MODEL_REGISTRY.md) | Model version history and tracking |

## Helper Pages

| Page | File | Description |
|------|------|-------------|
| Review Landing | [REVIEW_LANDING.md](REVIEW_LANDING.md) | Redirect page for event escalation |
| ServiceNow Case | [SERVICENOW_CASE.md](SERVICENOW_CASE.md) | Redirect page for ServiceNow integration |

## Quick Reference

### User-Facing Pages

These are the primary pages users interact with:

1. **AI Governance Overview** - Start here for overall monitoring
2. **Review Queue** - Check for events requiring review
3. **Event Review** - Investigate and document findings
4. **Configuration** - Administrative settings

### Workflow Pages

These pages support specific workflows:

1. **Review Landing** - Entry point from "Open AI Review" action
2. **ServiceNow Case** - Entry point from "Open Case in ServiceNow" action

### ML Operations Pages

These pages support ML model management:

1. **Model Comparison** - Evaluate model improvements
2. **Model Registry** - Track model versions and history

## File Structure

```
elements/
├── INDEX.md                              # This file
├── NAVIGATION.md                         # Navigation menu
├── AI_GOVERNANCE_OVERVIEW.md             # Main dashboard
├── REVIEW_QUEUE.md                       # Review queue
├── EVENT_REVIEW.md                       # Event review form
├── CONFIGURATION.md                      # Configuration page
├── PII_FEEDBACK_LOOP_MODEL_COMPARISON.md # ML model comparison
├── PII_FEEDBACK_LOOP_MODEL_REGISTRY.md   # ML model registry
├── REVIEW_LANDING.md                     # Review redirect helper
└── SERVICENOW_CASE.md                    # ServiceNow redirect helper
```

## Related Documentation

- [README.md](../README.md) - Main application documentation
- [README/GOVERNANCE_REVIEW.md](../README/GOVERNANCE_REVIEW.md) - Governance workflow guide
- [README/SERVICENOW_INTEGRATION.md](../README/SERVICENOW_INTEGRATION.md) - ServiceNow integration guide
- [README/ML Models/PII_Detection.md](../README/ML%20Models/PII_Detection.md) - PII/PHI detection guide
