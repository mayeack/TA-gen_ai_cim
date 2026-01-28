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
