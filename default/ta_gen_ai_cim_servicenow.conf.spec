#
# ta_gen_ai_cim_servicenow.conf.spec
#
# Specification file for ServiceNow configuration
# Place credentials in passwords.conf using the REST API or setup UI
#

[settings]
# ServiceNow instance name (e.g., "ciscoaidfsir" for ciscoaidfsir.service-now.com)
# Do NOT include .service-now.com suffix
instance = <string>

# Default table for AI Case creation (typically sn_ai_case_mgmt_ai_case)
default_table = <string>

# API timeout in seconds
api_timeout = <integer>

# Enable SSL certificate verification (recommended: true)
ssl_verify = <boolean>
