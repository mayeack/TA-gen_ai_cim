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
