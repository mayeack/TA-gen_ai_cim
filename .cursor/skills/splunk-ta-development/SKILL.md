---
name: splunk-ta-development
description: Build Splunk Technology Add-ons (TAs) by parsing log samples, creating props.conf and transforms.conf configurations, loading data, and validating field extractions using the Splunk MCP server. Use when creating Splunk add-ons, parsing log files for Splunk, developing sourcetypes, or configuring field extractions.
---

# Splunk TA Development

This skill guides the development of Splunk Technology Add-ons (TAs) following a structured workflow: analyze samples, build configurations, load data, validate extractions, and iterate until complete.

## Project Structure

TAs are created in their own subfolder within the workspace. This allows multiple TAs to be developed in the same workspace directory.

```
<workspace>/
└── <app_name>/                 # TA parent folder (e.g., TA-vendor-product)
    ├── bin/                    # Scripts (optional)
    │   └── README
    ├── default/                # Default configurations (REQUIRED)
    │   ├── app.conf            # App metadata
    │   ├── props.conf          # Field extraction configurations
    │   ├── transforms.conf     # Transform definitions
    │   └── data/ui/nav/default.xml
    ├── metadata/               # Permissions (REQUIRED)
    │   └── default.meta        # Default permissions
    ├── README.txt              # Documentation (recommended)
    ├── static/                 # Static assets (optional)
    │   └── appIcon.png         # 36x36 app icon
    └── samples/                # Sample data (recommended)
        └── *.log, *.txt, etc.
```

**Important:** Do NOT include in packages:
- `/local/` directory (created at runtime for user modifications)
- `metadata/local.meta` (local permission overrides)
- `.git/` or version control files

## Sample Data

**Location:** Flexible. Sample files can be:
- In the TA's `samples/` directory (convention for distribution)
- Anywhere on the filesystem (common during development)
- Multiple files with different formats/scenarios

**Naming:** No restrictions. Use descriptive names:
- `firewall_allow_deny.log`
- `error_with_stacktrace.txt`
- `sample_2024-01-15.json`

**At project start**, ask the user for the sample file path if not obvious. Store as `<sample_path>` for use in commands.

**Convention:** Including samples in the TA's `samples/` directory is recommended for:
- Documentation (shows expected log format)
- Testing after deployment
- Splunkbase submission requirements

## Installation & Deployment

### During Development: Symlink to Splunk

The TA must be in Splunk's apps directory for Splunk to recognize it. **Create a symlink** from the TA subfolder to Splunk's apps folder:

```bash
# Create symlink (run once at project start)
# Note: symlink points to the TA subfolder, not the workspace root
ln -s "$(pwd)/<app_name>" /Applications/Splunk/etc/apps/<app_name>

# Verify symlink
ls -la /Applications/Splunk/etc/apps/<app_name>
```

This allows:
- Multiple TAs to be developed in the same workspace
- Editing files in your workspace (version control, IDE features)
- Splunk sees each TA as an installed app
- Changes are immediately available after Splunk restart

**Note:** The symlink target is the TA subfolder (e.g., `workspace/TA-vendor-product/`), not the workspace root.

### After Development: Packaging for Distribution

When the TA is complete and validated:

**1. Create distributable tarball:**

```bash
# From the workspace directory containing the TA folder
tar -czvf <app_name>.tgz <app_name>/ \
  --exclude='.git' \
  --exclude='local' \
  --exclude='local/*' \
  --exclude='metadata/local.meta' \
  --exclude='*.pyc' \
  --exclude='__pycache__'
```

**2. Validate with AppInspect** (required for Splunkbase/Cloud):

```bash
# Install AppInspect CLI
pip install splunk-appinspect

# Run validation
splunk-appinspect inspect <app_name>.tgz --mode precert

# For Splunk Cloud submission
splunk-appinspect inspect <app_name>.tgz --included-tags cloud
```

Common AppInspect checks:
- No credentials in plain text
- No `/local` directory in package
- Proper file permissions
- Valid `app.conf` with version number
- No deprecated Python 2 code

**3. Distribution options:**
- Install on Splunk instances via **Settings → Install app from file**
- Upload to Splunkbase (requires AppInspect pass)
- Deploy via Splunk Deployment Server

### Production Deployment

For production Splunk instances:

1. **Copy method** - Extract TA to `/opt/splunk/etc/apps/` (or equivalent)
2. **Deployment Server** - Place in `$SPLUNK_HOME/etc/deployment-apps/` and deploy to clients
3. **Splunk Cloud** - Upload via self-service app install or work with Splunk support

## Development Workflow

Copy this checklist and track progress:

```
Task Progress:
- [ ] Phase 0: Create TA folder and symlink to Splunk
- [ ] Phase 1: Analyze sample logs
- [ ] Phase 2: Build props.conf and transforms.conf
- [ ] Phase 3: Load data into Splunk
- [ ] Phase 4: Validate extractions via MCP
- [ ] Phase 5: Iterate until complete
- [ ] Phase 6: Package and validate with AppInspect (optional)
```

**Note:** This skill covers field extraction TAs (props.conf/transforms.conf). For TAs with modular inputs, custom UI, or data collection scripts, consider the [UCC Framework](https://splunk.github.io/addonfactory-ucc-generator/) which follows Splunk's Gold Standard methodology.

### Phase 0: Create TA Folder and Symlink

Before starting, create the TA folder structure and symlink.

**1. Choose an app name** following official Splunk naming conventions:

For third-party developers:
- Format: `<Company/Brand> <Technology> Add-on` (e.g., `Acme Firewall Add-on`)
- Directory name: lowercase with hyphens (e.g., `acme-firewall-addon`)
- Do NOT prefix with "Splunk" unless officially built by Splunk Inc.

For internal/enterprise use:
- Format: `TA-<vendor>-<product>` is acceptable (e.g., `TA-acme-firewall`)
- Must be unique across all installed apps

**2. Check for conflicts:**

```bash
# List existing apps to verify name is unique
ls /Applications/Splunk/etc/apps/ | grep -i "<app_name>"

# Also check if sourcetype exists (from another app)
/Applications/Splunk/bin/splunk btool props list <sourcetype_name> --debug 2>/dev/null | head -5
```

If the app name or sourcetype already exists, choose a different name.

**3. Create the TA folder structure:**

```bash
# Create the TA parent folder and required subdirectories
mkdir -p <app_name>/default <app_name>/metadata <app_name>/bin <app_name>/samples

# Create required files
touch <app_name>/bin/README
```

**4. Create the symlink:**

```bash
# Verify symlink doesn't already exist
ls -la /Applications/Splunk/etc/apps/<app_name> 2>/dev/null

# Create symlink from TA subfolder to Splunk apps
ln -s "$(pwd)/<app_name>" /Applications/Splunk/etc/apps/<app_name>

# Verify it was created correctly
ls -la /Applications/Splunk/etc/apps/<app_name>
```

**5. Update app.conf** with proper metadata (required for AppInspect):

```ini
# <app_name>/default/app.conf
[install]
is_configured = false
build = 1

[ui]
is_visible = false
label = <App Display Name>

[launcher]
author = <your name or company>
description = Technical Add-on for <product> - extracts fields from <log type>
version = 1.0.0

[package]
id = <app_name>
check_for_updates = true
```

**Version format:** Use semantic versioning (`major.minor.patch`). AppInspect requires this format.

### Phase 1: Sample Analysis

1. **Locate sample data** - Ask user for path if not provided: `<sample_path>`
2. **Read** the sample file
3. **Identify format** - If recognized (Apache, syslog, JSON, etc.), leverage domain knowledge but still validate explicitly
4. **Analyze structure**:
   - Log structure (single-line, multi-line, structured)
   - Timestamp format and location
   - Key-value pairs and delimiters
   - Field patterns (IPs, URLs, usernames, error codes)
   - Embedded JSON/XML/CSV
4. **Document all fields** to extract

### Phase 2: Configuration Development

#### props.conf

Create `<app_name>/default/props.conf`:

```ini
[<sourcetype_name>]
# Time extraction
TIME_FORMAT = <strftime_format>
TIME_PREFIX = <regex_before_timestamp>
MAX_TIMESTAMP_LOOKAHEAD = <number>

# Line breaking
SHOULD_LINEMERGE = <true|false>
LINE_BREAKER = <regex>

# Field extractions - inline for simple patterns
EXTRACT-<field_name> = <regex_with_named_groups>

# Field extractions - reference transforms for complex patterns
REPORT-<extraction_name> = <transform_name>
```

#### transforms.conf

Create `<app_name>/default/transforms.conf` for complex extractions:

```ini
[<transform_name>]
REGEX = (?<field_name>pattern)(?<field2>pattern2)

# For delimited data
[<transform_name>]
DELIMS = "<delimiter>"
FIELDS = "field1","field2","field3"
```

For detailed configuration options, see [REFERENCE.md](REFERENCE.md).

### Phase 3: Load and Test

Before loading, prompt for Splunk credentials.

**Check if sourcetype exists:**

```bash
/Applications/Splunk/bin/splunk btool props list <sourcetype_name> --debug
```

**Load sequence:**

```bash
# Create index (project directory name = index name)
/Applications/Splunk/bin/splunk add index <project_dir_name> -auth <user>:<pass>

# Stop, clean, start
/Applications/Splunk/bin/splunk stop
/Applications/Splunk/bin/splunk clean eventdata -index <project_dir_name> -f
/Applications/Splunk/bin/splunk start

# Load sample (use absolute path to sample file)
/Applications/Splunk/bin/splunk add oneshot <sample_path> \
  -index <project_dir_name> \
  -sourcetype <sourcetype_name> \
  -auth <user>:<pass>
```

**Subsequent iterations** (config changes only):

```bash
/Applications/Splunk/bin/splunk stop
/Applications/Splunk/bin/splunk clean eventdata -index <project_dir_name> -f
/Applications/Splunk/bin/splunk start

# Reload sample
/Applications/Splunk/bin/splunk add oneshot <sample_path> \
  -index <project_dir_name> \
  -sourcetype <sourcetype_name> \
  -auth <user>:<pass>
```

### Phase 4: Validation via Splunk MCP

Use the **Splunk MCP server** `run_splunk_query` tool for all validation. Use `earliest_time: "0"` (no latest constraint) since samples may have historical timestamps.

#### 4.1 Validate Line Breaking

**CRITICAL: Verify event count before proceeding.**

1. **Count expected events** in sample file by counting timestamp patterns
2. **Verify indexed count**:
   ```spl
   index=<project_dir_name> sourcetype=<sourcetype_name> | stats count
   ```
3. **Inspect raw events**:
   ```spl
   index=<project_dir_name> sourcetype=<sourcetype_name> | head 10 | table _raw
   ```

Issues:
- Too few events → LINE_BREAKER merging events incorrectly
- Too many events → LINE_BREAKER splitting multi-line events

#### 4.2 Validate Timestamp Extraction

**CRITICAL: Verify timestamps parse from log content, not index time.**

1. **Compare _time to raw**:
   ```spl
   index=<project_dir_name> sourcetype=<sourcetype_name> | head 10 | table _time _raw
   ```

2. **Detect timestamp defaulting**:
   ```spl
   index=<project_dir_name> sourcetype=<sourcetype_name> 
   | eval index_delay=_indextime-_time 
   | stats avg(index_delay) min(index_delay) max(index_delay)
   ```
   If all delays near 0, timestamps are defaulting to index time.

3. **Verify distribution**:
   ```spl
   index=<project_dir_name> sourcetype=<sourcetype_name> 
   | stats min(_time) as earliest max(_time) as latest 
   | eval earliest=strftime(earliest,"%Y-%m-%d %H:%M:%S"), latest=strftime(latest,"%Y-%m-%d %H:%M:%S")
   ```

#### 4.3 Validate Field Extractions

1. **Check extracted fields**:
   ```spl
   index=<project_dir_name> sourcetype=<sourcetype_name> | head 100
   ```

2. **Validate field values**:
   ```spl
   index=<project_dir_name> sourcetype=<sourcetype_name> | stats count by <field_name>
   ```

3. **Find extraction failures**:
   ```spl
   index=<project_dir_name> sourcetype=<sourcetype_name> | where isnull(<expected_field>)
   ```

### Phase 5: Iteration Loop

If validation reveals issues:

| Problem | Likely Cause | Fix |
|---------|--------------|-----|
| Missing fields | Regex not matching | Adjust EXTRACT- or REPORT- regex |
| Wrong values | Regex capturing wrong content | Refine capture groups |
| Missing events | LINE_BREAKER issues | Adjust LINE_BREAKER regex |
| Wrong timestamps | TIME_FORMAT/TIME_PREFIX | Correct strftime format |

Repeat Phase 3-4 until:
- [ ] All fields from sample file extracted
- [ ] Field names follow conventions (lowercase, underscores)
- [ ] Timestamps parsed correctly
- [ ] No events lost to line breaking
- [ ] Field values match raw log content

## Extraction Strategy Priority

1. **Auto key-value** - For `key=value` logs:
   ```ini
   KV_MODE = auto
   ```

2. **Delimited** - For CSV-like data:
   ```ini
   [transform_name]
   DELIMS = ","
   FIELDS = "f1","f2","f3"
   ```

3. **Named capture groups** - For structured patterns:
   ```ini
   EXTRACT-myfield = (?<src_ip>\d+\.\d+\.\d+\.\d+)\s+(?<action>\w+)
   ```

4. **Transform-based** - For complex or reusable patterns

## Debugging

**Test regex with rex:**
```spl
index=<index> | rex "(?<myfield>pattern)" | table myfield _raw
```

**Check config issues:**
```bash
/Applications/Splunk/bin/splunk btool props list <sourcetype> --debug
/Applications/Splunk/bin/splunk btool transforms list --debug
```

**View parsing errors:**
```spl
index=_internal sourcetype=splunkd component=LineBreakingProcessor OR component=DateParserVerbose
```

## Additional Resources

- [REFERENCE.md](REFERENCE.md) - Detailed configuration options and common patterns
- [EXAMPLES.md](EXAMPLES.md) - Example configurations for common log formats
