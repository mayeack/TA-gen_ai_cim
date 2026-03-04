#
# ta_gen_ai_cim_genai_scoring.conf.spec - GenAI Scoring Pipeline Specification
# TA-gen_ai_cim
#

[settings]
system_prompt = <string>
* Global system prompt prepended to every pipeline-specific prompt
* Establishes the LLM's role and enforces the JSON output schema
* Sent as the first part of the prompt for all enabled scoring pipelines
* Default: (security analyst role with JSON schema enforcement)

[pipeline_1]
enabled = <bool>
* Enable or disable this scoring pipeline
* When enabled, the corresponding saved search will be activated
* Default: 0 (disabled)

pipeline_name = <string>
* Free-form name for this scoring pipeline (e.g., "pii", "toxicity", "compliance")
* Used to construct field names: gen_ai.<pipeline_name>.risk_score, gen_ai.<pipeline_name>.genai_detected, etc.
* Used to construct source: <pipeline_name>_genai_scoring
* Used to construct sourcetype: ai_cim:<pipeline_name>:gen_ai_scoring
* Must contain only lowercase alphanumeric characters and underscores
* Note: "name" is reserved by Splunk REST API, so "pipeline_name" is used instead
* Default: empty

prompt = <string>
* Pipeline-specific scoring prompt that instructs the LLM what to analyze
* Appended after the global system_prompt
* The event data (JSON) is automatically appended after this prompt
* Example: "Analyze this GenAI event for personally identifiable information (PII)."
* Default: empty

[pipeline_2]
enabled = <bool>
pipeline_name = <string>
prompt = <string>

[pipeline_3]
enabled = <bool>
pipeline_name = <string>
prompt = <string>

[pipeline_4]
enabled = <bool>
pipeline_name = <string>
prompt = <string>

[pipeline_5]
enabled = <bool>
pipeline_name = <string>
prompt = <string>

[pipeline_6]
enabled = <bool>
pipeline_name = <string>
prompt = <string>

[pipeline_7]
enabled = <bool>
pipeline_name = <string>
prompt = <string>

[pipeline_8]
enabled = <bool>
pipeline_name = <string>
prompt = <string>

[pipeline_9]
enabled = <bool>
pipeline_name = <string>
prompt = <string>

[pipeline_10]
enabled = <bool>
pipeline_name = <string>
prompt = <string>
