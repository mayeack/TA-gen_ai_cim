# ServiceNow AI Case Management Integration

## Overview

The TA-gen_ai_cim now includes one-click escalation of AI events into ServiceNow AI Case Management with auditable linkage. This integration allows you to:

- **Create AI Cases** in ServiceNow directly from Splunk events
- **Track linkages** between `gen_ai.request.id` and ServiceNow `sys_id` via KV Store
- **Prevent duplicates** by checking existing mappings before case creation
- **Access cases** via URL redirect from the Event Context menu

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Splunk Event (gen_ai.request.id)                                   │
└────────────────────┬────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  aicase Command / Workflow Action / Alert Action                    │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  1. Check KV Store (gen_ai_snow_case_map)                      │ │
│  │     - If mapping exists → Return existing case URL             │ │
│  │     - If no mapping → Continue to step 2                       │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  2. Create ServiceNow AI Case                                  │ │
│  │     - POST to sn_ai_case_mgmt_ai_case                          │ │
│  │     - Store sys_id mapping in KV Store                         │ │
│  │     - Return new case URL                                      │ │
│  └────────────────────────────────────────────────────────────────┘ │
└────────────────────┬────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  ServiceNow (ciscoaidfsir.service-now.com)                          │
│  Table: sn_ai_case_mgmt_ai_case                                     │
│  Fields: Name, Type, Date of Discovery                              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Setup Instructions

### Prerequisites

1. **Splunk Enterprise 9.0+** or **Splunk Cloud**
2. **ServiceNow instance** with AI Case Management module (`sn_ai_case_mgmt`)
3. **ServiceNow service account** with appropriate permissions

### Step 1: Create ServiceNow Service Account

In ServiceNow, create a dedicated service account with these roles:

| Role | Purpose |
|------|---------|
| `sn_ai_case_mgmt.ai_case_manager` | Access to AI Case Management module |
| `rest_api_explorer` | REST API access |
| `itil` | (optional) Standard incident/case management |

**Required Table Permissions:**

| Table | Access |
|-------|--------|
| `sn_ai_case_mgmt_ai_case` | Create, Read |
| `sys_user` | Read (for connection testing) |

### Step 2: Configure ServiceNow Credentials in Splunk

#### Option A: Using the Setup Script (Recommended)

```bash
cd $SPLUNK_HOME/etc/apps/TA-gen_ai_cim

# Interactive mode
$SPLUNK_HOME/bin/splunk cmd python bin/snow_setup.py --interactive

# Or command-line mode
$SPLUNK_HOME/bin/splunk cmd python bin/snow_setup.py \
    --instance ciscoaidfsir \
    --username svc_splunk_snow \
    --password '<your-password>' \
    --test
```

#### Option B: Using Splunk REST API (CLI)

```bash
# Store ServiceNow instance name
curl -k -u admin:<password> -X POST \
    https://localhost:8089/servicesNS/nobody/TA-gen_ai_cim/storage/passwords \
    -d "name=ta_gen_ai_cim_snow" \
    -d "password=ciscoaidfsir" \
    -d "realm=servicenow_instance"

# Store ServiceNow credentials
curl -k -u admin:<password> -X POST \
    https://localhost:8089/servicesNS/nobody/TA-gen_ai_cim/storage/passwords \
    -d "name=svc_splunk_snow" \
    -d "password=<your-servicenow-password>" \
    -d "realm=servicenow_credentials"
```

#### Option C: Using Splunk Web UI

1. Navigate to **GenAI Governance** app
2. Click **Configuration** → **ServiceNow Setup**
3. Enter your ServiceNow instance name (e.g., `ciscoaidfsir`)
4. Enter the service account username and password
5. Click **Test Connection** to verify
6. Click **Save Configuration**

### Step 3: Verify Installation

```spl
# Test the aicase command
| makeresults 
| eval gen_ai.request.id="test_" . now() 
| aicase mode=lookup
| table snow_case_status snow_case_message
```

Expected output:
```
snow_case_status    snow_case_message
not_found           No existing case for request_id=test_1737312000
```

---

## Usage

### Custom Search Command: `aicase`

The `aicase` command is a streaming command that processes events and creates/retrieves ServiceNow AI Cases.

#### Syntax

```
| aicase [request_id=<value>] [mode=create|lookup|open]
```

#### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `request_id` | No | from event | Override `gen_ai.request.id` from the event |
| `mode` | No | `create` | Operation mode (see below) |

#### Modes

| Mode | Behavior |
|------|----------|
| `create` | Check for existing case; create new if not found |
| `lookup` | Check for existing case only; do not create |
| `open` | Same as create, but optimized for URL retrieval |

#### Output Fields

| Field | Description |
|-------|-------------|
| `snow_case_url` | Full URL to the ServiceNow AI Case |
| `snow_case_sys_id` | ServiceNow sys_id of the case |
| `snow_case_number` | Case number (if available) |
| `snow_case_status` | `created`, `existing`, `not_found`, `error` |
| `snow_case_message` | Human-readable status message |

#### Examples

**Create/open case for recent events:**
```spl
index=gen_ai_log earliest=-1h
| head 10
| aicase
| table _time gen_ai.request.id snow_case_url snow_case_status
```

**Create case with explicit request_id:**
```spl
| makeresults 
| eval gen_ai.request.id="abc123-def456" 
| aicase request_id=abc123-def456
| table snow_case_url snow_case_status
```

**Lookup existing cases only (no creation):**
```spl
index=gen_ai_log gen_ai.safety.violated="true" earliest=-24h
| aicase mode=lookup
| where snow_case_status="existing"
| table gen_ai.request.id snow_case_url
```

**Bulk case creation for safety violations:**
```spl
index=gen_ai_log gen_ai.safety.violated="true" earliest=-7d
| dedup gen_ai.request.id
| aicase
| stats count by snow_case_status
```

### Event Context Menu (Workflow Actions)

Right-click on any event with a `gen_ai.request.id` field to access:

1. **Open Case in ServiceNow** - Creates or opens the associated case
2. **Lookup ServiceNow Case** - Checks if a case already exists
3. **View ServiceNow Case History** - Shows all cases for the app/deployment

### Alert Action (Splunk Cloud Fallback)

For Splunk Cloud environments where custom search commands are restricted:

1. Create a saved search/alert for your GenAI events
2. Add the **Create ServiceNow AI Case** alert action
3. Configure the alert to trigger on desired conditions

Example alert configuration:
```ini
[GenAI Safety Violation - Create Case]
search = index=gen_ai_log gen_ai.safety.violated="true" | head 1
alert.severity = 4
alert.track = 1
action.create_snow_aicase = 1
action.create_snow_aicase.param.request_id = $result.gen_ai.request.id$
```

---

## KV Store Schema

### Collection: `gen_ai_snow_case_map`

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | string | GenAI request ID (unique key) |
| `sys_id` | string | ServiceNow case sys_id |
| `sn_instance` | string | ServiceNow instance name |
| `created_at` | number | Unix epoch when mapping was created |
| `updated_at` | number | Unix epoch when mapping was last updated |
| `created_by` | string | Username who created the case |

### Lookup Definition: `gen_ai_snow_case_map_lookup`

#### Query Examples

**Lookup existing case for a request:**
```spl
| inputlookup gen_ai_snow_case_map_lookup 
| search request_id="abc123-def456"
```

**Find all cases created by user:**
```spl
| inputlookup gen_ai_snow_case_map_lookup 
| search created_by="admin"
| table request_id sys_id created_at
```

**Count cases by instance:**
```spl
| inputlookup gen_ai_snow_case_map_lookup 
| stats count by sn_instance
```

**Join with GenAI events:**
```spl
index=gen_ai_log earliest=-7d
| lookup gen_ai_snow_case_map_lookup request_id AS gen_ai.request.id OUTPUT sys_id, sn_instance
| where isnotnull(sys_id)
| eval case_url = "https://" . sn_instance . ".service-now.com/sn_ai_case_mgmt_ai_case.do?sys_id=" . sys_id
| table _time gen_ai.request.id case_url
```

### Validation SPL

**Check for orphaned mappings (cases without corresponding events):**
```spl
| inputlookup gen_ai_snow_case_map_lookup 
| join type=left request_id [
    search index=gen_ai_log earliest=-30d 
    | stats count by gen_ai.request.id 
    | rename gen_ai.request.id as request_id
  ]
| where isnull(count)
| table request_id sys_id created_at
```

---

## ServiceNow Case Fields

When the `aicase` command creates a case, it sets these fields:

| ServiceNow Field | Value |
|------------------|-------|
| `short_description` | `Splunk Event for <gen_ai.request.id>` |
| `type` | `AI Case` |
| `u_date_of_discovery` | Current date (UTC, format: `YYYY-MM-DD`) |
| `description` | Auto-generated with source information |
| `u_source` | `Splunk TA-gen_ai_cim` |

---

## Required Capabilities and Roles

### Splunk Capabilities

| Capability | Required For |
|------------|--------------|
| `list_storage_passwords` | Reading ServiceNow credentials |
| `admin_all_objects` | (admin only) Managing credentials |
| `write_kvstore` | Creating case mappings |

### Recommended Role Configuration

Create a role `genai_snow_user` with these capabilities:

```ini
# authorize.conf
[role_genai_snow_user]
importRoles = user
srchIndexesAllowed = gen_ai_log
srchIndexesDefault = gen_ai_log
capability.list_storage_passwords = enabled
```

---

## ServiceNow API Permissions

The service account requires these permissions in ServiceNow:

| Endpoint | Method | Required For |
|----------|--------|--------------|
| `/api/now/table/sn_ai_case_mgmt_ai_case` | POST | Creating cases |
| `/api/now/table/sn_ai_case_mgmt_ai_case` | GET | (future) Reading case details |
| `/api/now/table/sys_user` | GET | Connection testing |

### ACL Requirements

```
Table: sn_ai_case_mgmt_ai_case
Operation: create
Required: sn_ai_case_mgmt.ai_case_manager role

Table: sn_ai_case_mgmt_ai_case  
Operation: read
Required: sn_ai_case_mgmt.ai_case_manager role
```

---

## Splunk Cloud Compatibility

### What Works

- ✅ KV Store collections and lookups
- ✅ Workflow actions (Event Context menu)
- ✅ Alert actions
- ✅ Storage passwords (credential storage)
- ✅ Standard SPL with lookups

### Potential Limitations

- ⚠️ Custom search commands may require Splunk Cloud vetting
- ⚠️ External network calls require allow-listing

### Splunk Cloud Deployment Steps

1. **Submit for vetting** - Package the TA and submit to Splunk Cloud for app vetting
2. **Allow-list ServiceNow** - Request network access to `*.service-now.com` endpoints
3. **Use Alert Action fallback** - If custom command is blocked, use the alert action workflow

### Fallback Workflow (No Custom Command)

If the `aicase` command is not available:

1. **Create a saved search** for your GenAI events
2. **Add alert action** `Create ServiceNow AI Case`
3. **Use workflow action** to trigger the saved search with parameters

```spl
# Manual case creation via SPL (no custom command)
| makeresults 
| eval request_id="abc123"
| lookup gen_ai_snow_case_map_lookup request_id OUTPUT sys_id
| eval has_case=if(isnotnull(sys_id), "yes", "no")
| table request_id has_case sys_id
```

---

## Troubleshooting

### Issue: "ServiceNow credentials not configured"

**Cause:** Credentials not stored in passwords.conf

**Solution:**
```bash
$SPLUNK_HOME/bin/splunk cmd python bin/snow_setup.py --interactive --test
```

### Issue: "ServiceNow API error 401"

**Cause:** Invalid username/password

**Solution:**
1. Verify credentials in ServiceNow
2. Check account is not locked
3. Re-run setup script with `--test` flag

### Issue: "ServiceNow API error 403"

**Cause:** Insufficient permissions

**Solution:**
1. Verify service account has `sn_ai_case_mgmt.user` role
2. Check ACLs on `sn_ai_case_mgmt_ai_case` table
3. Verify REST API is enabled for the user

### Issue: "Connection error" or timeout

**Cause:** Network connectivity issues

**Solution:**
1. Verify Splunk server can reach `*.service-now.com`
2. Check firewall rules
3. For Splunk Cloud, ensure domain is allow-listed

### Issue: Workflow action not appearing

**Cause:** Missing `gen_ai.request.id` field

**Solution:**
1. Verify events have the field extracted
2. Check props.conf field extraction rules
3. Run: `index=gen_ai_log | table gen_ai.request.id | head 5`

---

## Security Considerations

1. **Credential Storage** - All credentials are stored encrypted using Splunk's `passwords.conf`
2. **Service Account** - Use a dedicated service account with minimal permissions
3. **Audit Trail** - All case creations are logged in the KV Store with timestamps and user info
4. **SSL/TLS** - All ServiceNow API calls use HTTPS with certificate verification
5. **No PII in URLs** - Case URLs use sys_id, not request content

---

## File Reference

| File | Purpose |
|------|---------|
| `bin/aicase.py` | Custom search command |
| `bin/snow_setup.py` | Credential setup utility |
| `bin/create_snow_case.py` | Alert action script |
| `default/commands.conf` | Command registration |
| `default/collections.conf` | KV Store definition |
| `default/transforms.conf` | Lookup definition |
| `default/workflow_actions.conf` | Event Context menu actions |
| `default/alert_actions.conf` | Alert action definition |
| `default/ta_gen_ai_cim_servicenow.conf` | ServiceNow configuration |
| `default/data/ui/views/servicenow_setup.xml` | Setup dashboard |

---

## Version History

### v1.2.0 (2026-01-19)

**ServiceNow AI Case Management Integration**
- NEW: `aicase` custom search command for case creation/lookup
- NEW: KV Store collection `gen_ai_snow_case_map` for auditable linkage
- NEW: Event Context menu workflow actions
- NEW: Alert action for Splunk Cloud compatibility
- NEW: Secure credential storage via passwords.conf
- NEW: Setup utility and configuration dashboard
- NEW: Comprehensive documentation

---

## Support

For issues with this integration:

1. Check the troubleshooting section above
2. Review Splunk `_internal` logs for errors
3. Test ServiceNow API access independently
4. Contact: ai-governance@example.com
