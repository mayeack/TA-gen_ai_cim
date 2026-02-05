# ServiceNow Integration

## Overview

The TA-gen_ai_cim provides two ServiceNow integrations for AI governance:

| Integration | ServiceNow Table | Purpose |
|-------------|------------------|---------|
| **Open Case in ServiceNow** | `sn_ai_case_mgmt_ai_case` | Escalate individual AI events to ServiceNow AI Case Management for investigation |
| **Sync AI System in ServiceNow** | `alm_ai_system_digital_asset` | Automatically register AI applications in ServiceNow's AI System inventory |

---

# Integration 1: Open Case in ServiceNow

## Overview

One-click escalation of AI events into ServiceNow AI Case Management with auditable linkage. This integration allows you to:

- **Create AI Cases** in ServiceNow directly from Splunk events
- **Track linkages** between `gen_ai.event.id` and ServiceNow `sys_id` via KV Store
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
| 'sn_ai_governance.ai_stewards' | Access to create AI Asseets |

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

---

# Integration 2: Sync AI System in ServiceNow

## Overview

Automatically sync `gen_ai.app.name` values from Splunk events to ServiceNow's `alm_ai_system_digital_asset` table. This integration:

- **Auto-registers AI applications** discovered in GenAI telemetry
- **Links Splunk apps to ServiceNow assets** for unified AI inventory management
- **Prevents duplicates** by checking both KV Store and ServiceNow before creation
- **Runs on a schedule** to continuously discover new AI applications

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Scheduled Search: "GenAI - ServiceNow Asset Sync"                 │
│  (Runs hourly - finds new gen_ai.app.name values)                  │
└────────────────────┬────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  KV Store Check: gen_ai_app_asset_map                              │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Lookup app_name → If sys_id exists → Skip (already mapped)   │ │
│  │                  → If no sys_id → Continue to alert action    │ │
│  └────────────────────────────────────────────────────────────────┘ │
└────────────────────┬────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Alert Action: sync_snow_asset                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  1. Query ServiceNow alm_ai_system_digital_asset               │ │
│  │     - If found → Get sys_id, save with status="found"         │ │
│  │     - If not found → Create record, save with status="created"│ │
│  └────────────────────────────────────────────────────────────────┘ │
└────────────────────┬────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  ServiceNow Table: alm_ai_system_digital_asset                     │
│  Fields: name, short_description, u_source                         │
└─────────────────────────────────────────────────────────────────────┘
```

## How It Works

1. **Hourly scheduled search** finds all unique `gen_ai.app.name` values from the last 24 hours
2. **KV Store lookup** filters out app names that are already mapped
3. **Alert action triggers** for each unmapped app name
4. **sync_snow_asset.py script** queries ServiceNow:
   - If the app name exists in `alm_ai_system_digital_asset` → stores `sys_id` with `sync_status="found"`
   - If not found → creates a new record and stores `sys_id` with `sync_status="created"`

## Setup

### Prerequisites

1. **ServiceNow credentials configured** via the Configuration page (same credentials used for AI Case integration)
2. **ServiceNow permissions** for `alm_ai_system_digital_asset` table:

| Permission | Required For |
|------------|--------------|
| `GET /api/now/table/alm_ai_system_digital_asset` | Query existing assets |
| `POST /api/now/table/alm_ai_system_digital_asset` | Create new assets |

### Enable the Scheduled Search

The scheduled search is **enabled by default**. To modify or disable:

1. Navigate to **Settings** → **Searches, reports, and alerts**
2. Find **"GenAI - ServiceNow Asset Sync"**
3. Adjust the schedule or disable as needed

Default schedule: `0 * * * *` (hourly at minute 0)

## KV Store Schema

### Collection: `gen_ai_app_asset_map`

| Field | Type | Description |
|-------|------|-------------|
| `app_name` | string | GenAI application name (unique key) |
| `sys_id` | string | ServiceNow alm_ai_system_digital_asset sys_id |
| `sync_status` | string | `found` (existing in ServiceNow) or `created` (newly created) |
| `created_at` | number | Unix epoch when mapping was created |
| `updated_at` | number | Unix epoch when mapping was last updated |
| `created_by` | string | Username who created the mapping |

### Lookup Definition: `gen_ai_app_asset_map_lookup`

#### Query Examples

**View all synced applications:**
```spl
| inputlookup gen_ai_app_asset_map_lookup
| table app_name sys_id sync_status created_at
| sort -created_at
```

**Count by sync status:**
```spl
| inputlookup gen_ai_app_asset_map_lookup
| stats count by sync_status
```

**Find applications created vs found:**
```spl
| inputlookup gen_ai_app_asset_map_lookup
| eval created_time=strftime(created_at, "%Y-%m-%d %H:%M:%S")
| table app_name sync_status created_time created_by
```

**Join with GenAI events to see asset linkage:**
```spl
index=gen_ai_log earliest=-7d
| stats count by gen_ai.app.name
| lookup gen_ai_app_asset_map_lookup app_name AS gen_ai.app.name OUTPUT sys_id, sync_status
| eval status=if(isnotnull(sys_id), "Synced (".sync_status.")", "Not synced")
| table gen_ai.app.name count status sys_id
```

**Find unsynced applications:**
```spl
index=gen_ai_log earliest=-7d gen_ai.app.name=*
| stats count by gen_ai.app.name
| lookup gen_ai_app_asset_map_lookup app_name AS gen_ai.app.name OUTPUT sys_id
| where isnull(sys_id)
| table gen_ai.app.name count
```

## Saved Search Details

### GenAI - ServiceNow Asset Sync

```spl
index=gen_ai_log gen_ai.app.name=*
| stats count by gen_ai.app.name
| lookup gen_ai_app_asset_map_lookup app_name AS gen_ai.app.name OUTPUT sys_id
| where isnull(sys_id)
| fields gen_ai.app.name
| rename gen_ai.app.name AS app_name
```

| Setting | Value |
|---------|-------|
| Schedule | `0 * * * *` (hourly) |
| Time Range | Last 24 hours |
| Alert Action | `sync_snow_asset` |

## ServiceNow Record Fields

When a new asset is created, these fields are set:

| ServiceNow Field | Value |
|------------------|-------|
| `name` | The `gen_ai.app.name` value |
| `short_description` | `GenAI Application: <app_name>` |
| `u_source` | `Splunk TA-gen_ai_cim` |

## Manual Sync

To manually trigger a sync for a specific application:

**Option 1: Run the saved search manually**
1. Navigate to **Settings** → **Searches, reports, and alerts**
2. Find **"GenAI - ServiceNow Asset Sync"**
3. Click **Run**

**Option 2: Use SPL with the alert action**
```spl
| makeresults
| eval app_name="my-new-ai-app"
| sendalert sync_snow_asset
```

## Troubleshooting

### Issue: "No ServiceNow account configured"

**Cause:** Credentials not set up in Configuration page

**Solution:**
1. Navigate to GenAI Governance app → Configuration
2. Add a ServiceNow account with URL, username, and password
3. Test the connection

### Issue: "ServiceNow API error 404"

**Cause:** `alm_ai_system_digital_asset` table doesn't exist

**Solution:**
1. Verify the table name in your ServiceNow instance
2. Contact your ServiceNow admin to confirm the AI Asset Management module is installed

### Issue: Assets not being synced

**Cause:** Scheduled search may be disabled or failing

**Solution:**
1. Check the search is enabled: Settings → Searches, reports, and alerts
2. Review search job history for errors
3. Check logs: `$SPLUNK_HOME/var/log/splunk/sync_snow_asset.log`

### Issue: Duplicate entries in KV Store

**Cause:** Race condition or manual insertion

**Solution:**
```spl
| inputlookup gen_ai_app_asset_map_lookup
| stats count by app_name
| where count > 1
```

Remove duplicates manually via the KV Store REST API if needed.

## Logs

The sync script logs to: `$SPLUNK_HOME/var/log/splunk/sync_snow_asset.log`

**View recent log entries:**
```spl
index=_internal source="*sync_snow_asset.log"
| table _time log_level message
| sort -_time
```

## File Reference

| File | Purpose |
|------|---------|
| `bin/sync_snow_asset.py` | Alert action script for syncing assets |
| `default/collections.conf` | KV Store definition (`gen_ai_app_asset_map`) |
| `default/transforms.conf` | Lookup definition (`gen_ai_app_asset_map_lookup`) |
| `default/alert_actions.conf` | Alert action definition (`sync_snow_asset`) |
| `default/savedsearches.conf` | Scheduled search (`GenAI - ServiceNow Asset Sync`) |

---

## Version History

### v1.3.0 (2026-02-02)

**ServiceNow AI System Digital Asset Sync**
- NEW: Automatic sync of `gen_ai.app.name` to ServiceNow `alm_ai_system_digital_asset`
- NEW: KV Store collection `gen_ai_app_asset_map` for app-to-asset mapping
- NEW: `sync_snow_asset` alert action for asset sync
- NEW: Scheduled search for hourly discovery and sync
- NEW: Comprehensive documentation for AI System integration

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
