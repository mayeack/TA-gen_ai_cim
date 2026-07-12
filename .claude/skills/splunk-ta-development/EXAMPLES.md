# Splunk TA Configuration Examples

## Apache Access Log (Combined Format)

**Sample:**
```
192.168.1.100 - john [10/Oct/2023:13:55:36 -0700] "GET /api/users HTTP/1.1" 200 2326 "https://example.com" "Mozilla/5.0"
```

**props.conf:**
```ini
[apache:access]
TIME_FORMAT = %d/%b/%Y:%H:%M:%S %z
TIME_PREFIX = \[
MAX_TIMESTAMP_LOOKAHEAD = 32
SHOULD_LINEMERGE = false

EXTRACT-apache_access = ^(?<clientip>\S+)\s+\S+\s+(?<user>\S+)\s+\[(?<timestamp>[^\]]+)\]\s+"(?<method>\w+)\s+(?<uri_path>\S+)\s+\S+"\s+(?<status>\d+)\s+(?<bytes>\d+)\s+"(?<http_referrer>[^"]+)"\s+"(?<http_user_agent>[^"]+)"
```

## Apache Error Log

**Sample:**
```
[Wed Oct 11 14:32:52.123456 2023] [error] [pid 12345] [client 192.168.1.50:54321] AH01071: Got error 'PHP message: Error in script'
```

**props.conf:**
```ini
[apache:error]
TIME_FORMAT = %a %b %d %H:%M:%S.%f %Y
TIME_PREFIX = \[
MAX_TIMESTAMP_LOOKAHEAD = 40
SHOULD_LINEMERGE = false

EXTRACT-apache_error = \[(?<level>\w+)\]\s+\[pid\s+(?<pid>\d+)\](?:\s+\[client\s+(?<clientip>[^:]+):(?<clientport>\d+)\])?\s+(?<error_code>\w+):\s+(?<message>.+)
```

## Syslog (RFC 3164)

**Sample:**
```
Oct 11 14:32:52 server01 sshd[12345]: Accepted publickey for admin from 192.168.1.100 port 54321 ssh2
```

**props.conf:**
```ini
[syslog]
TIME_FORMAT = %b %d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 15
SHOULD_LINEMERGE = false

EXTRACT-syslog = ^(?<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?<host>\S+)\s+(?<process>\w+)\[(?<pid>\d+)\]:\s+(?<message>.+)
```

## JSON Application Log

**Sample:**
```json
{"timestamp":"2023-10-11T14:32:52.123Z","level":"ERROR","service":"api","trace_id":"abc123","message":"Connection timeout","duration_ms":5000}
```

**props.conf:**
```ini
[json:application]
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%Z
TIME_PREFIX = "timestamp"\s*:\s*"
MAX_TIMESTAMP_LOOKAHEAD = 30
SHOULD_LINEMERGE = false

KV_MODE = json
```

## Java Stack Trace (Multi-line)

**Sample:**
```
2023-10-11 14:32:52.123 ERROR [main] com.example.App - Database connection failed
java.sql.SQLException: Connection refused
    at com.mysql.jdbc.Driver.connect(Driver.java:123)
    at com.example.db.Pool.getConnection(Pool.java:45)
Caused by: java.net.ConnectException: Connection refused
    at java.net.Socket.connect(Socket.java:591)
```

**props.conf:**
```ini
[java:application]
TIME_FORMAT = %Y-%m-%d %H:%M:%S.%3N
MAX_TIMESTAMP_LOOKAHEAD = 30
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = ^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}

EXTRACT-java_log = ^(?<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(?<level>\w+)\s+\[(?<thread>[^\]]+)\]\s+(?<class>\S+)\s+-\s+(?<message>.+?)(?=\n[a-z]|$)
```

## Windows Event Log (XML)

**Sample:**
```xml
<Event><System><TimeCreated SystemTime="2023-10-11T14:32:52.1234567Z"/><EventID>4624</EventID><Level>0</Level></System><EventData><Data Name="TargetUserName">admin</Data><Data Name="IpAddress">192.168.1.100</Data></EventData></Event>
```

**props.conf:**
```ini
[winevent:security]
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%7NZ
TIME_PREFIX = SystemTime="
MAX_TIMESTAMP_LOOKAHEAD = 35
SHOULD_LINEMERGE = false

KV_MODE = xml
REPORT-winevent_fields = winevent_extract
```

**transforms.conf:**
```ini
[winevent_extract]
REGEX = <EventID>(?<event_id>\d+)</EventID>

[winevent_user]
REGEX = Name="TargetUserName">(?<user>[^<]+)

[winevent_ip]
REGEX = Name="IpAddress">(?<src_ip>[^<]+)
```

## CSV Log

**Sample:**
```
2023-10-11T14:32:52,ERROR,api-server,user123,/api/orders,POST,500,Connection timeout
```

**props.conf:**
```ini
[csv:application]
TIME_FORMAT = %Y-%m-%dT%H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 20
SHOULD_LINEMERGE = false

REPORT-csv_fields = csv_extract
```

**transforms.conf:**
```ini
[csv_extract]
DELIMS = ","
FIELDS = "timestamp","level","host","user","uri_path","method","status","message"
```

## Key-Value Log

**Sample:**
```
timestamp=2023-10-11T14:32:52 level=ERROR service=api user=admin action=login status=failed reason="invalid password" duration=1234ms
```

**props.conf:**
```ini
[kv:application]
TIME_FORMAT = %Y-%m-%dT%H:%M:%S
TIME_PREFIX = timestamp=
MAX_TIMESTAMP_LOOKAHEAD = 20
SHOULD_LINEMERGE = false

KV_MODE = auto
```

## Nginx Access Log

**Sample:**
```
192.168.1.100 - - [11/Oct/2023:14:32:52 +0000] "GET /api/health HTTP/2.0" 200 45 "-" "curl/7.68.0" rt=0.001 uct=0.000 uht=0.001 urt=0.001
```

**props.conf:**
```ini
[nginx:access]
TIME_FORMAT = %d/%b/%Y:%H:%M:%S %z
TIME_PREFIX = \[
MAX_TIMESTAMP_LOOKAHEAD = 32
SHOULD_LINEMERGE = false

EXTRACT-nginx_base = ^(?<clientip>\S+)\s+\S+\s+(?<user>\S+)\s+\[[^\]]+\]\s+"(?<method>\w+)\s+(?<uri_path>\S+)\s+\S+"\s+(?<status>\d+)\s+(?<bytes>\d+)
EXTRACT-nginx_timing = rt=(?<response_time>[\d.]+)\s+uct=(?<upstream_connect_time>[\d.]+)\s+uht=(?<upstream_header_time>[\d.]+)\s+urt=(?<upstream_response_time>[\d.]+)
```

## Firewall Log (Key-Value)

**Sample:**
```
Oct 11 14:32:52 fw01 action=allow src=192.168.1.100 srcport=54321 dst=10.0.0.50 dstport=443 proto=tcp bytes_sent=1234 bytes_recv=5678 duration=120
```

**props.conf:**
```ini
[firewall]
TIME_FORMAT = %b %d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 15
SHOULD_LINEMERGE = false

EXTRACT-fw_host = ^\w+\s+\d+\s+[\d:]+\s+(?<host>\S+)
REPORT-fw_kv = fw_kv_extract

# CIM field aliases
FIELDALIAS-src_ip = src AS src_ip
FIELDALIAS-dest_ip = dst AS dest_ip
FIELDALIAS-src_port = srcport AS src_port
FIELDALIAS-dest_port = dstport AS dest_port
FIELDALIAS-transport = proto AS transport
```

**transforms.conf:**
```ini
[fw_kv_extract]
REGEX = (\w+)=(\S+)
FORMAT = $1::$2
```

## Database Audit Log

**Sample:**
```
2023-10-11 14:32:52.123456 UTC [12345] user@database LOG: statement: SELECT * FROM users WHERE id = 123
```

**props.conf:**
```ini
[postgres:audit]
TIME_FORMAT = %Y-%m-%d %H:%M:%S.%6N %Z
MAX_TIMESTAMP_LOOKAHEAD = 35
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = ^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}

EXTRACT-postgres = ^\S+\s+\S+\s+\S+\s+\[(?<pid>\d+)\]\s+(?<db_user>[^@]+)@(?<database>\S+)\s+(?<level>\w+):\s+(?<log_type>\w+):\s+(?<statement>.+)
```
