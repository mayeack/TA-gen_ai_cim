#
# ta_gen_ai_cim_es.conf.spec - Enterprise Security integration settings
# TA-gen_ai_cim
#

[es_integration]
seed_response_plan = <bool>
* Seed the AI Incident Response Plan and the AI Findings queue into Mission
  Control (idempotent, TA-owned records only). No investigation type is
  seeded; assign the plan to one in ES
* Default: true

seed_identity_response_plan = <bool>
* Seed the Compromised Identity Response Plan (AI Trust Lab 5) into Mission
  Control and bind its containment task to the "PseudoCo Identity" SOAR app's
  pseudoco_identity asset when that app and asset already exist on the paired
  SOAR. Never installs that app or creates that asset
* Default: false

bind_soar_actions = <bool>
* Bind the plan's Containment tasks to the simulated "MedAdvice Identity
  Provider" SOAR actions through the ES/SOAR pairing proxy; creates the
  `medadvice_idp` asset when the app is installed on the paired SOAR
* Default: true

install_simulator = <bool>
* Install the simulator app on the paired SOAR when missing. Requires a
  `soar` account in ta_gen_ai_cim_account.conf (url, optional username,
  auth_type = token|basic, verify_ssl) whose token or password is stored as
  the account password (realm ta_gen_ai_cim_account__soar)
* Default: false

enable_triage_agent = <bool>
* Set ai_triage_enabled = 1 and add the primary prompt-injection detection
  and the Lab 5 compromised-identity detection to the ES Triage agent's
  allowlist, keeping every existing entry (no-op without the allow_ai_triage
  entitlement)
* Default: false

route_findings_to_queue = <bool>
* Give the seeded AI Findings queue the routing rule
  (rule_title =~ "^GenAI Prompt Injection" or
  rule_title =~ "^GenAI Compromised Identity") so AI Governance findings land there
  instead of the default Analyst Queue. Grant analyst roles access to the queue
  in ES, or only admins will see those findings.
* Default: false
