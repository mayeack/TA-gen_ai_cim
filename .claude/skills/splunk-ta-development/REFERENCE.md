# Splunk TA Configuration Reference

## props.conf Options

### Time Extraction

```ini
[<sourcetype>]
# strftime format for timestamp parsing
TIME_FORMAT = %Y-%m-%d %H:%M:%S

# Regex pattern immediately before the timestamp
TIME_PREFIX = ^

# How many characters to look ahead for timestamp
MAX_TIMESTAMP_LOOKAHEAD = 150

# Set to true if timestamp spans multiple tokens
DATETIME_CONFIG = CURRENT
```

#### Common TIME_FORMAT Patterns

| Log Format | TIME_FORMAT |
|------------|-------------|
| ISO 8601 | `%Y-%m-%dT%H:%M:%S` |
| ISO 8601 with TZ | `%Y-%m-%dT%H:%M:%S%z` |
| ISO 8601 with millis | `%Y-%m-%dT%H:%M:%S.%3N` |
| Apache/CLF | `%d/%b/%Y:%H:%M:%S %z` |
| Syslog (BSD) | `%b %d %H:%M:%S` |
| Syslog (RFC 3339) | `%Y-%m-%dT%H:%M:%S.%6N%:z` |
| Windows Event | `%m/%d/%Y %H:%M:%S %p` |
| Epoch seconds | `%s` |
| Epoch millis | `%s%3N` |

### Line Breaking

```ini
[<sourcetype>]
# Whether to merge lines into events (default: true)
SHOULD_LINEMERGE = false

# Regex that matches event boundaries (consumes delimiter)
LINE_BREAKER = ([\r\n]+)

# Max event length before truncation
TRUNCATE = 10000

# For multi-line events, break before pattern
BREAK_ONLY_BEFORE = ^\d{4}-\d{2}-\d{2}

# For multi-line events, break after pattern
BREAK_ONLY_AFTER = -----END-----
```

#### Multi-line Event Patterns

**Java stack traces** (break before timestamp, merge rest):
```ini
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = ^\d{4}-\d{2}-\d{2}
```

**Continuation lines** (break before non-whitespace):
```ini
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = ^[^\s]
```

### Field Extractions

```ini
[<sourcetype>]
# Inline extraction with named capture groups
EXTRACT-<name> = (?<field1>pattern1)\s+(?<field2>pattern2)

# Reference a transform
REPORT-<name> = <transform_name>

# Field alias
FIELDALIAS-<name> = original_field AS new_field

# Calculated field
EVAL-<name> = if(status>=400, "error", "ok")

# Key-value extraction mode
KV_MODE = auto | none | multi | json | xml

# Sed command for data cleanup
SEDCMD-<name> = s/pattern/replacement/g
```

## transforms.conf Options

### Regex-Based Extraction

```ini
[<transform_name>]
# Named capture groups (preferred)
REGEX = (?<src_ip>\d+\.\d+\.\d+\.\d+):(?<src_port>\d+)

# Numbered groups with FORMAT
REGEX = (\d+\.\d+\.\d+\.\d+):(\d+)
FORMAT = src_ip::$1 src_port::$2
```

### Delimited Extraction

```ini
[<transform_name>]
DELIMS = ","
FIELDS = "timestamp","level","message"

# Multiple delimiters
DELIMS = ",|"

# Quoted fields
DELIMS = ","
FIELDS = "f1","f2","f3"
```

### Key-Value Extraction

```ini
[<transform_name>]
REGEX = (\w+)=("[^"]*"|\S+)
FORMAT = $1::$2
CLEAN_KEYS = true
```

### MV (Multi-Value) Extraction

```ini
[<transform_name>]
REGEX = tag=(?<tags>[^\s,]+)
MV_ADD = true
```

## Common Regex Patterns

| Field Type | Regex Pattern |
|------------|---------------|
| IPv4 | `(?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})` |
| IPv6 | `(?<ipv6>[0-9a-fA-F:]+)` |
| MAC | `(?<mac>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})` |
| Email | `(?<email>[\w.+-]+@[\w.-]+\.\w+)` |
| URL | `(?<url>https?://[^\s]+)` |
| Hostname | `(?<host>[\w.-]+\.\w{2,})` |
| Integer | `(?<num>-?\d+)` |
| Float | `(?<float>-?\d+\.?\d*)` |
| Quoted string | `"(?<value>[^"]*)"` |
| Key=Value | `(?<_KEY_1>\w+)=(?<_VAL_1>[^\s,]+)` |
| UUID | `(?<uuid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})` |
| HTTP status | `(?<status>[1-5]\d{2})` |
| HTTP method | `(?<method>GET\|POST\|PUT\|DELETE\|PATCH\|HEAD\|OPTIONS)` |
| Log level | `(?<level>DEBUG\|INFO\|WARN(?:ING)?\|ERROR\|FATAL\|CRITICAL)` |

## Best Practices

1. **Use named capture groups** - `(?<field>pattern)` over numbered groups
2. **Keep regex efficient** - Avoid excessive backtracking
3. **Use REPORT- for reusable transforms** - Keeps props.conf clean
4. **Use EXTRACT- for simple one-off extractions**
5. **Set appropriate TIME_FORMAT** - Critical for search performance
6. **Use SHOULD_LINEMERGE=false** with explicit LINE_BREAKER for predictable behavior
7. **Normalize field names** with FIELDALIAS for CIM compliance
8. **Use SEDCMD sparingly** - Only for cleanup before indexing

## CIM Field Naming

For Splunk Common Information Model compliance:

| Category | Standard Fields |
|----------|-----------------|
| Authentication | `user`, `src`, `dest`, `action`, `app` |
| Network | `src_ip`, `src_port`, `dest_ip`, `dest_port`, `transport` |
| Web | `http_method`, `uri_path`, `status`, `bytes`, `http_user_agent` |
| Alerts | `severity`, `signature`, `category` |

## Validation Queries

### Count events
```spl
index=<idx> sourcetype=<st> earliest=0 | stats count
```

### Check field extraction rate
```spl
index=<idx> sourcetype=<st> earliest=0 
| stats count(eval(isnotnull(<field>))) as extracted, count as total 
| eval pct=round(extracted/total*100,2)
```

### Find unique field values
```spl
index=<idx> sourcetype=<st> earliest=0 | stats count by <field> | sort -count
```

### Debug regex inline
```spl
index=<idx> sourcetype=<st> earliest=0 
| rex "(?<test_field>pattern)" 
| table _raw test_field
```

## Required Metadata Files

### metadata/default.meta

```ini
# Application-level permissions
[]
access = read : [ * ], write : [ admin ]
export = system

# Props permissions
[props]
access = read : [ * ], write : [ admin ]
export = system

# Transforms permissions
[transforms]
access = read : [ * ], write : [ admin ]
export = system
```

### app.conf Template

```ini
# default/app.conf
[install]
is_configured = false
build = 1

[ui]
is_visible = false
label = <Display Name>

[launcher]
author = <Author/Company>
description = Technical Add-on for <product>
version = 1.0.0

[package]
id = <app_directory_name>
check_for_updates = true
```

**Important:**
- `version` must use semantic versioning (major.minor.patch)
- `id` must match the app directory name exactly
- `is_visible = false` for TAs (they have no UI)
