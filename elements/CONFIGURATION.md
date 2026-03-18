# Configuration Page

## Overview

The **Configuration** page provides administrative settings for the TA-gen_ai_cim application. It uses a tabbed interface to organize ServiceNow integration, GenAI summary settings, and detection toggles.

## Design

Built using a **SimpleXML Dashboard** with embedded HTML and custom JavaScript (`config_config.js`) and CSS (`config_config.css`) for a rich, interactive configuration experience.

### Layout Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│  Tab Navigation                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │
│  │ ServiceNow      │  │ GenAI Summary   │  │ Detection       │     │
│  │ Account         │  │                 │  │ Settings        │     │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘     │
├─────────────────────────────────────────────────────────────────────┤
│  Tab Content Area (changes based on selected tab)                   │
│                                                                     │
│  ServiceNow Account:                                                │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ [Search] [Add Account]                                          ││
│  │ Account Table: Name | Auth Type | Actions                       ││
│  └─────────────────────────────────────────────────────────────────┘│
│                                                                     │
│  GenAI Summary:                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ Enable GenAI Summary: [Toggle]                                  ││
│  │ API Key: [Password Input]                                       ││
│  │ Model: [Dropdown]                                               ││
│  │ Max Tokens: [Number Input]                                      ││
│  │ [Save Settings] [Test Connection]                               ││
│  └─────────────────────────────────────────────────────────────────┘│
│                                                                     │
│  Detection Settings:                                                │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ Detect PII: [Toggle]                                            ││
│  │ Detect PHI: [Toggle]                                            ││
│  │ Detect Prompt Injection: [Toggle]                               ││
│  │ Detect Anomalies: [Toggle]                                      ││
│  │ Random Escalation: [Toggle]                                     ││
│  │ RNG Seed: [Text Input]                                          ││
│  │ [Save Settings]                                                 ││
│  └─────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
```

## Purpose

The Configuration page enables administrators to:

- **Manage** ServiceNow account connections
- **Configure** AI-powered summary generation
- **Control** which detection types are active
- **Set up** random escalation for quality sampling

## Tab 1: ServiceNow Account

Manages ServiceNow integration credentials for case escalation.

### Features
- Add/Edit/Delete ServiceNow accounts
- Support for Basic Authentication and OAuth 2.0
- Secure credential storage via Splunk passwords.conf
- Account table with sorting and search

### Form Fields
| Field | Required | Description |
|-------|----------|-------------|
| Account Name | Yes | Unique identifier for the account |
| URL | Yes | ServiceNow instance URL |
| Auth Type | Yes | Basic Authentication or OAuth 2.0 |
| Username | Yes* | For Basic Auth |
| Password | Yes* | For Basic Auth |
| Client ID | Yes* | For OAuth 2.0 |
| Client Secret | Yes* | For OAuth 2.0 |

## Tab 2: GenAI Summary

Configures AI-powered summary generation for ServiceNow cases.

### Features
- Enable/disable AI summary generation
- Anthropic API configuration
- Model selection (Claude Sonnet 4, Claude 3.5 Sonnet, Claude 3.5 Haiku)
- Connection testing

### Settings
| Setting | Default | Description |
|---------|---------|-------------|
| Enable GenAI Summary | Off | Toggle AI summary feature |
| API Key | - | Anthropic API key |
| Model | Claude Sonnet 4 | AI model for summaries |
| Max Tokens | 300 | Maximum response length |

## Tab 3: Detection Settings

Controls which content detection types are enabled for AI governance monitoring.

### Detection Toggles
| Setting | Default | Description |
|---------|---------|-------------|
| Detect PII | On | Personal Information detection |
| Detect PHI | On | Protected Health Information detection |
| Detect Prompt Injection | On | Attack pattern detection |
| Detect Anomalies | On | Unusual pattern detection |
| Random Escalation | Off | Quality sampling escalation |
| RNG Seed | - | Pattern for random escalation |

### Impact on Event Review

When a detection type is **disabled**:
- Related fields are hidden on the Event Review page
- Corresponding alerts may be disabled
- Review workflow is streamlined to relevant fields only

## File Location

```
default/data/ui/views/configuration.xml
```

## Technical Details

- **Format**: SimpleXML Dashboard with embedded HTML
- **Scripts**: `config_config.js`
- **Stylesheets**: `config_config.css`
- **Theme**: Light

## Configuration Storage

| Setting Type | Storage Location |
|--------------|------------------|
| ServiceNow Accounts | `ta_gen_ai_cim_account.conf` |
| GenAI Summary | `ta_gen_ai_cim_llm.conf` |
| Detection Settings | `ta_gen_ai_cim_detection.conf` |
| Credentials | `passwords.conf` (encrypted) |

## REST Endpoints

The JavaScript interacts with Splunk REST APIs:

- `/servicesNS/nobody/TA-gen_ai_cim/configs/conf-ta_gen_ai_cim_account/`
- `/servicesNS/nobody/TA-gen_ai_cim/configs/conf-ta_gen_ai_cim_llm/`
- `/servicesNS/nobody/TA-gen_ai_cim/configs/conf-ta_gen_ai_cim_detection/`
- `/servicesNS/nobody/TA-gen_ai_cim/storage/passwords/`

## Related Files

- `appserver/static/config_config.js` - JavaScript logic
- `appserver/static/config_config.css` - Styling
- `ta_gen_ai_cim_account.conf.spec` - Account config spec
- `ta_gen_ai_cim_llm.conf.spec` - LLM config spec
- `ta_gen_ai_cim_detection.conf.spec` - Detection config spec
