# Dashboard Panels Reference

This document provides a quick reference to all dashboard panels available in the TA-gen_ai_cim application.

## Dashboard Documentation

For detailed documentation on each dashboard including panel descriptions, purpose, and customization options, see the dedicated documentation:

| Dashboard | Documentation |
|-----------|---------------|
| **AI Governance Overview** | [DASHBOARDS/AI_GOVERNANCE_OVERVIEW.md](DASHBOARDS/AI_GOVERNANCE_OVERVIEW.md) |
| **TF-IDF Anomaly Detection** | [DASHBOARDS/TFIDF_ANOMALY_DETECTION.md](DASHBOARDS/TFIDF_ANOMALY_DETECTION.md) |
| **PII Detection** | [DASHBOARDS/PII_DETECTION.md](DASHBOARDS/PII_DETECTION.md) |
| **Prompt Injection Detection** | [DASHBOARDS/PROMPT_INJECTION_DETECTION.md](DASHBOARDS/PROMPT_INJECTION_DETECTION.md) |
| **Review Queue** | [DASHBOARDS/REVIEW_QUEUE.md](DASHBOARDS/REVIEW_QUEUE.md) |

## Dashboard File Locations

| Dashboard | File |
|-----------|------|
| AI Governance Overview | `default/data/ui/views/genai_governance_overview_studio.json` |
| PII Detection | `default/data/ui/views/pii_detection.xml` |
| Prompt Injection Detection | `default/data/ui/views/prompt_injection_detection.xml` |
| Review Queue | `default/data/ui/views/review_queue.xml` |
| Event Review | `default/data/ui/views/event_review.xml` |

## Dashboard Formats

The TA provides dashboards in two formats:

| Format | File Extension | Splunk Version | Notes |
|--------|---------------|----------------|-------|
| **Dashboard Studio** | `.json` | 9.0+ | Recommended for modern Splunk installations |
| **Classic Dashboard** | `.xml` | 8.x+ | For backward compatibility |

## Customization

To customize dashboards:

1. **Via Splunk Web:**
   - Navigate to **Settings → User Interface → Views**
   - Find the dashboard and click **Edit**
   - Or clone it to create a custom version

2. **Via File System:**
   - Copy the dashboard file to `local/data/ui/views/`
   - Modify the copy (preserves upgrade path)

## Related Documentation

- [ML Models Overview](ML%20Models/README.md) - Training and scoring documentation
- [Governance Review Workflow](GOVERNANCE_REVIEW.md) - Human review process

---

**Last Updated:** 2026-01-28
