#
# ta_gen_ai_cim_account.conf.spec
# TA-gen_ai_cim
#
# Accounts for the add-on's integrations, one stanza per account:
#   * ServiceNow (AI Case Management, AI asset inventory). The alert actions
#     and | aicase use the first ServiceNow account by name whose url is a
#     *.service-now.com / *.servicenow.com host, else the first by name with
#     a ServiceNow auth_type that is not named soar or duo
#     (bin/sync_snow_asset.py select_snow_account).
#   * soar - the optional SOAR account | genaiseedes reads.
#   * Cisco Duo Admin API accounts (auth_type = duo_hmac), read by the Duo
#     modular input (ta_gen_ai_cim_duo://<input>, account = <name>).
# The [asset_discovery] stanza holds settings, not an account.
#
# Write accounts through the account REST handler
# (/servicesNS/nobody/TA-gen_ai_cim/ta_gen_ai_cim_account/ta_gen_ai_cim_account,
# bin/ta_gen_ai_cim_account_handler.py) or the Configuration page.
#
# Secrets are NOT settings of this file. Passwords, OAuth client secrets, the
# SOAR token and the Duo secret key live only in storage/passwords, realm
# ta_gen_ai_cim_account__<name>, credential name `password` or
# `client_secret`; nothing returns them once stored.
#
# Compatible with: Splunk Enterprise 9.0+, Splunk Cloud
#

###############################################################################
# ACCOUNT SETTINGS
###############################################################################

[<name>]
url = <string>
* The account's endpoint.
* ServiceNow: the instance URL, for example https://<instance>.service-now.com.
* soar: the SOAR base URL.
* duo_hmac: the Duo Admin API hostname as an https URL,
  https://api-<id>.duosecurity.com or https://api-<id>.duofederal.com.
  The handler accepts the bare hostname the Duo Admin Panel shows, rejects
  http, any other host, a port, a path or credentials, and stores this form.

auth_type = <string>
* One of basic, oauth_auth_code, oauth_client_creds, token, duo_hmac.
* basic: ServiceNow or soar; username here, password in storage/passwords.
* oauth_auth_code, oauth_client_creds: ServiceNow OAuth 2.0; client_id here,
  client_secret (and an optional password) in storage/passwords.
* token: the soar account; its automation token is the stored password.
* duo_hmac: a Cisco Duo Admin API application (v5 HMAC-SHA512 request
  signing). client_id is its integration key; its secret key is the stored
  client_secret. Give the application only "Grant read log" and
  "Grant resource - Read".
* An account cannot switch between duo_hmac and another auth type: delete
  it and create it again.
* Default: basic

username = <string>
* basic and the OAuth types: the user name. Not used by token or duo_hmac.

client_id = <string>
* The OAuth 2.0 client ID, or for duo_hmac the Admin API integration key
  (ikey, for example DIXXXXXXXXXXXXXXXXXX).

verify_ssl = <boolean>
* soar only: whether | genaiseedes verifies the SOAR TLS certificate.
* Default: true

###############################################################################
# ASSET DISCOVERY SETTINGS ([asset_discovery] stanza)
###############################################################################

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
