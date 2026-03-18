#
# ta_gen_ai_cim_detection.conf.spec - Detection Settings Configuration Specification
# TA-gen_ai_cim
#

[settings]
detect_pii = <bool>
* Enable or disable PII (Personally Identifiable Information) detection
* When enabled, the PII detection alert will analyze GenAI events for sensitive personal data
* such as names, email addresses, phone numbers, SSNs, and credit card numbers
* Default: 1 (enabled)

detect_phi = <bool>
* Enable or disable PHI (Protected Health Information) detection
* When enabled, the PHI detection alert will analyze GenAI events for health-related data
* such as medical records, diagnoses, treatment information, and health insurance details
* Default: 1 (enabled)

detect_prompt_injection = <bool>
* Enable or disable Prompt Injection detection
* When enabled, the prompt injection detection alert will analyze GenAI events for
* malicious input patterns that attempt to manipulate AI model behavior
* Default: 1 (enabled)

detect_anomalies = <bool>
* Enable or disable Anomaly detection
* When enabled, the anomaly detection alert will analyze GenAI events for
* unusual patterns such as abnormal request volumes, atypical response times,
* or unexpected model behaviors
* Default: 1 (enabled)

random_escalation = <bool>
* Enable or disable Random Escalation
* When enabled, events will be randomly escalated to the Review Queue if
* the last alphanumeric characters of the gen_ai.event.id match the rng_seed
* Default: 0 (disabled)

rng_seed = <string>
* Alphanumeric characters to match against the end of gen_ai.event.id
* Events with IDs ending in these characters will be escalated to the Review Queue
* Only used when random_escalation is enabled
* Example: "a1b2" will match event IDs ending in "a1b2"
* Default: empty (no matching)
