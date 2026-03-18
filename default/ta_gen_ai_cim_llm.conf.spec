#
# ta_gen_ai_cim_llm.conf.spec - GenAI Summary Configuration Specification
# TA-gen_ai_cim
#

[settings]
enabled = <bool>
* Enable or disable GenAI summary generation
* When enabled, AI-generated summaries will be included in ServiceNow cases
* Default: 0 (disabled)

model = <string>
* Anthropic model to use for summary generation
* Options: claude-sonnet-4-20250514, claude-3-5-sonnet-20241022, claude-3-5-haiku-20241022
* Default: claude-sonnet-4-20250514

max_tokens = <integer>
* Maximum number of tokens for generated summaries
* Range: 100-1000
* Default: 300
