#
# alert_actions.conf.spec - Alert Action Specification
# TA-gen_ai_cim
#
# Defines configurable parameters for custom alert actions.
#
# Compatible with: Splunk Enterprise 9.0+, Splunk Cloud
#

###############################################################################
# CREATE SERVICENOW AI CASE
###############################################################################

[create_snow_aicase]
param.request_id = <string>
* The gen_ai.request.id for the event to create a case for.

param.case_description = <string>
* Optional description for the ServiceNow case.

###############################################################################
# SYNC AI SYSTEM TO SERVICENOW
###############################################################################

[sync_snow_asset]
param._cam = <json>
* CAM configuration for adaptive response actions.

###############################################################################
# PULL FULL SERVICENOW AI INVENTORY
###############################################################################

[pull_snow_inventory]
param._cam = <json>
* CAM configuration for adaptive response actions.

###############################################################################
# AI DEFENSE RESPONSE ACTIONS
#
# Simulated containment actions. Each records an audit event in gen_ai_log
# (sourcetype ai_cim:response:action) with "simulated": true and calls nothing
# externally. Every param below is optional: when unset, the action resolves
# the target from the triggering result.
###############################################################################

[ai_defense_suspend_user]
param._cam = <json>
* CAM configuration for adaptive response actions.

param.enduser_id = <string>
* The identity to record the suspension against.
* When unset, resolved from the triggering result in this order:
  enduser_id, gen_ai.user.id, user, risk_object, actor.

[ai_defense_revoke_session]
param._cam = <json>
* CAM configuration for adaptive response actions.

param.session_id = <string>
* The GenAI session to record the revocation against.
* When unset, resolved from the triggering result in this order:
  session_id, gen_ai.session.id, conversation_id.

[ai_defense_tighten_guardrail]
param._cam = <json>
* CAM configuration for adaptive response actions.

param.app_name = <string>
* The GenAI application whose guardrail profile is recorded as tightened.
* When unset, resolved from the triggering result in this order:
  app_name, gen_ai.app.name, app, service_name.
