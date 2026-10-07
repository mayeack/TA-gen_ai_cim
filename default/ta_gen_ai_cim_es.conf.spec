#
# ta_gen_ai_cim_es.conf.spec - Enterprise Security integration settings
# TA-gen_ai_cim
#

[es_integration]
seed_response_plan = <bool>
* Seed the AI Incident Response Plan, the "ai security incident" investigation
  type and the AI Findings queue into Mission Control (idempotent, TA-owned
  records only)
* Default: true

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
* Set ai_triage_enabled = 1 and allowlist the primary prompt-injection
  detection for the ES Triage agent (no-op without the allow_ai_triage
  entitlement)
* Default: false

route_findings_to_queue = <bool>
* Give the seeded AI Findings queue the routing rule
  (rule_title =~ "^GenAI Prompt Injection") so AI Governance findings land there
  instead of the default Analyst Queue. Grant analyst roles access to the queue
  in ES, or only admins will see those findings.
* Default: false
