# Sample Events

Representative GenAI inference events used to demonstrate and test the
TA-gen_ai_cim search-time field extractions.

| File | Provider | Notes |
|------|----------|-------|
| `anthropic_chat.log` | Anthropic Claude | One safety-violation event, one normal event |
| `openai_chat.log` | OpenAI GPT | Two normal completion events |
| `bedrock_chat.log` | AWS Bedrock | One PII-detected event, one normal event |

Each line is a single JSON event in the raw provider format that the TA
expects to find in the configured GenAI index (default: `gen_ai_log`).

## Loading samples for testing

```bash
SPLUNK_HOME=/opt/splunk    # adjust as needed

$SPLUNK_HOME/bin/splunk add index gen_ai_log -auth admin:<pass>

for f in anthropic_chat.log openai_chat.log bedrock_chat.log; do
    $SPLUNK_HOME/bin/splunk add oneshot \
        "$(pwd)/samples/$f" \
        -index gen_ai_log \
        -sourcetype gen_ai:inference:json \
        -auth admin:<pass>
done
```

## Validating extractions

```spl
index=gen_ai_log earliest=0
| stats count by gen_ai.provider.name gen_ai.request.model gen_ai.safety.violated
```

A successful run should show three providers (anthropic, openai, aws.bedrock)
with their expected request models and at least one safety violation
(from `anthropic_chat.log`).
