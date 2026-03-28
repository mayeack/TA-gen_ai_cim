#
# ta_gen_ai_cim_account.conf.spec
# Account configuration for ServiceNow integration
#

[<name>]
url = <string>
* ServiceNow instance URL (e.g., https://instance.service-now.com)

auth_type = <string>
* Authentication type: basic, oauth_auth_code, oauth_client_creds

username = <string>
* ServiceNow username for authentication

client_id = <string>
* OAuth 2.0 Client ID (for OAuth auth types)

client_secret = <string>
* OAuth 2.0 Client Secret (for OAuth auth types)

# AI Asset Discovery Settings - AI System
ai_system_table = <string>
* ServiceNow table name for AI System records
* Default: alm_ai_system_digital_asset

ai_system_match_field = <string>
* Field on the AI System table to match gen_ai.app.name against
* Default: display_name

ai_system_approval_field = <string>
* Field on the AI System table that indicates approval status
* Default: approval

ai_system_approved_values = <string>
* Comma-separated list of values that indicate the AI System is approved
* Matching is case-sensitive
* Default: approved

# AI Asset Discovery Settings - AI Model
ai_model_table = <string>
* ServiceNow table name for AI Model records
* Default: alm_ai_model_digital_asset

ai_model_match_field = <string>
* Field on the AI Model table to match gen_ai.response.model against
* Default: display_name

ai_model_approval_field = <string>
* Field on the AI Model table that indicates approval status
* Default: approval

ai_model_approved_values = <string>
* Comma-separated list of values that indicate the AI Model is approved
* Matching is case-sensitive
* Default: approved
