# Provider-Specific Normalization Examples

This document shows concrete examples of how raw provider events are normalized into the unified GenAI CIM.

## Table of Contents

1. [Anthropic (Claude)](#anthropic-claude)
2. [OpenAI (GPT)](#openai-gpt)
3. [AWS Bedrock](#aws-bedrock)
4. [Local/Internal Models](#localinternal-models)

---

## Anthropic (Claude)

### Raw Event (from medadvice_v3)

```json
{
  "operation_name": "chat",
  "provider_name": "anthropic",
  "request_model": "claude-sonnet-4-5-20250929",
  "response_model": "claude-sonnet-4-5-20250929",
  "response_id": "msg_018BKj1t1m7kRd23PRYpK8Vb",
  "conversation_id": "b091c6c6-c52f-4be6-bda9-4a95ec18b4e7",
  "deployment_id": "medadvice-v3-prod",
  "request_id": "fa09f5c5-2390-4e74-9b60-8017f7ef9f1e",
  "session_id": "b091c6c6-c52f-4be6-bda9-4a95ec18b4e7",
  "trace_id": "31b0937c-7b8e-4801-80e4-fa93c747a459",
  "input_messages": [
    {"role": "user", "content": "Help I'm not feeling well"},
    {"role": "assistant", "content": "What symptoms are you experiencing?"}
  ],
  "output_messages": [
    {"role": "assistant", "content": "Based on your symptoms..."}
  ],
  "output_type": "text",
  "token_type": "output",
  "response_finish_reasons": ["end_turn"],
  "request_choice_count": 1,
  "usage_input_tokens": 685,
  "usage_output_tokens": 497,
  "usage_total_tokens": 1182,
  "client_operation_duration": 11.159581899642944,
  "safety_violated": true,
  "safety_categories": ["High severity level: EMERGENCY"],
  "guardrail_triggered": true,
  "guardrail_ids": ["escalation_rules"],
  "pii_detected": false,
  "policy_blocked": false,
  "evaluation_score_value": 0.7,
  "evaluation_score_label": "medium",
  "service_name": "medadvice-v3",
  "client_address": "127.0.0.1",
  "timestamp": "2026-01-15T22:59:08.450627"
}
```

### Normalized Output (After TA Processing)

```
gen_ai.operation.name = "chat"
gen_ai.provider.name = "anthropic"
gen_ai.request.model = "claude-sonnet-4-5-20250929"
gen_ai.response.model = "claude-sonnet-4-5-20250929"
gen_ai.response.id = "msg_018BKj1t1m7kRd23PRYpK8Vb"
gen_ai.conversation.id = "b091c6c6-c52f-4be6-bda9-4a95ec18b4e7"
gen_ai.deployment.id = "medadvice-v3-prod"
gen_ai.request.id = "fa09f5c5-2390-4e74-9b60-8017f7ef9f1e"
gen_ai.session.id = "b091c6c6-c52f-4be6-bda9-4a95ec18b4e7"
trace_id = "31b0937c-7b8e-4801-80e4-fa93c747a459"

gen_ai.input.messages = [{"role": "user", "content": "Help I'm not feeling well"}, ...]
gen_ai.output.messages = [{"role": "assistant", "content": "Based on your symptoms..."}]
gen_ai.output.type = "text"

gen_ai.token.type = "output"
gen_ai.request.choice.count = 1
gen_ai.response.finish_reasons = ["end_turn"]

gen_ai.usage.input_tokens = 685
gen_ai.usage.output_tokens = 497
gen_ai.usage.total_tokens = 1182

gen_ai.client.operation.duration = 11.159581899642944

gen_ai.safety.violated = "true"
gen_ai.safety.categories = ["High severity level: EMERGENCY"]
gen_ai.guardrail.triggered = "true"
gen_ai.guardrail.ids = ["escalation_rules"]
gen_ai.pii.detected = "false"
gen_ai.policy.blocked = "false"

gen_ai.evaluation.score.value = 0.7
gen_ai.evaluation.score.label = "medium"

service.name = "medadvice-v3"
gen_ai.app.name = "medadvice-v3"
client.address = "127.0.0.1"
```

### Mapping Logic

| Raw Field | Normalized Field | Transform |
|-----------|------------------|-----------|
| `operation_name` | `gen_ai.operation.name` | FIELDALIAS (direct) |
| `provider_name` | `gen_ai.provider.name` | FIELDALIAS (direct) |
| `request_model` | `gen_ai.request.model` | FIELDALIAS (direct) |
| `safety_violated` | `gen_ai.safety.violated` | EVAL (boolean normalization to "true"/"false") |
| `safety_categories` | `gen_ai.safety.categories` | REPORT (JSON array extraction) |
| `usage_total_tokens` | `gen_ai.usage.total_tokens` | Already present OR EVAL (sum of input+output) |

---

## OpenAI (GPT)

### Raw Event

```json
{
  "operation_name": "text_completion",
  "provider_name": "openai",
  "request_model": "gpt-4-turbo",
  "response_model": "gpt-4-turbo-2024-04-09",
  "response_id": "chatcmpl-9X4kL0p",
  "conversation_id": null,
  "deployment_id": "prod-chatbot-01",
  "request_id": "req_abc123xyz",
  "trace_id": "trace_def456uvw",
  "input_messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Explain quantum computing"}
  ],
  "output_messages": [
    {
      "role": "assistant",
      "content": "Quantum computing leverages quantum mechanics..."
    }
  ],
  "output_type": "text",
  "request_max_tokens": 1000,
  "request_temperature": 0.8,
  "request_top_p": 0.95,
  "request_frequency_penalty": 0.1,
  "request_presence_penalty": 0.0,
  "request_stop_sequences": ["END", "\n\n"],
  "response_finish_reasons": ["stop"],
  "request_choice_count": 1,
  "usage_input_tokens": 125,
  "usage_output_tokens": 350,
  "client_operation_duration": 3.245,
  "safety_violated": false,
  "guardrail_triggered": false,
  "pii_detected": false,
  "policy_blocked": false,
  "service_name": "chatbot-api",
  "client_address": "192.168.1.100",
  "timestamp": "2026-01-15T14:30:00.000000"
}
```

### Normalized Output

```
gen_ai.operation.name = "text_completion"
gen_ai.provider.name = "openai"
gen_ai.request.model = "gpt-4-turbo"
gen_ai.response.model = "gpt-4-turbo-2024-04-09"
gen_ai.response.id = "chatcmpl-9X4kL0p"
gen_ai.conversation.id = null
gen_ai.deployment.id = "prod-chatbot-01"
gen_ai.request.id = "req_abc123xyz"
trace_id = "trace_def456uvw"

gen_ai.input.messages = [{"role": "system", ...}, {"role": "user", ...}]
gen_ai.output.messages = [{"role": "assistant", "content": "Quantum computing..."}]
gen_ai.output.type = "text"

gen_ai.request.max_tokens = 1000
gen_ai.request.temperature = 0.8
gen_ai.request.top_p = 0.95
gen_ai.request.frequency_penalty = 0.1
gen_ai.request.presence_penalty = 0.0
gen_ai.request.stop_sequences = ["END", "\n\n"]
gen_ai.response.finish_reasons = ["stop"]
gen_ai.request.choice.count = 1

gen_ai.usage.input_tokens = 125
gen_ai.usage.output_tokens = 350
gen_ai.usage.total_tokens = 475

gen_ai.client.operation.duration = 3.245

gen_ai.safety.violated = "false"
gen_ai.guardrail.triggered = "false"
gen_ai.pii.detected = "false"
gen_ai.policy.blocked = "false"

service.name = "chatbot-api"
gen_ai.app.name = "chatbot-api"
client.address = "192.168.1.100"
```

---

## AWS Bedrock

### Raw Event

```json
{
  "operation_name": "generate_content",
  "provider_name": "aws.bedrock",
  "request_model": "amazon.titan-text-express-v1",
  "response_model": "amazon.titan-text-express-v1",
  "response_id": "bedrock-resp-789xyz",
  "deployment_id": "us-east-1-prod",
  "request_id": "req_bedrock_001",
  "trace_id": "aws-trace-abc",
  "input_messages": [
    {"role": "user", "content": "Summarize this document..."}
  ],
  "output_messages": [
    {"role": "assistant", "content": "The document discusses..."}
  ],
  "output_type": "text",
  "request_max_tokens": 512,
  "request_temperature": 0.5,
  "usage_input_tokens": 2048,
  "usage_output_tokens": 256,
  "client_operation_duration": 5.678,
  "safety_violated": false,
  "guardrail_triggered": true,
  "guardrail_ids": ["aws-guardrail-toxicity"],
  "pii_detected": true,
  "pii_types": ["EMAIL", "PHONE"],
  "policy_blocked": false,
  "service_name": "document-summarizer",
  "server.address": "bedrock.us-east-1.amazonaws.com",
  "server.port": 443,
  "timestamp": "2026-01-15T10:15:30.000000"
}
```

### Normalized Output

```
gen_ai.operation.name = "generate_content"
gen_ai.provider.name = "aws.bedrock"
gen_ai.request.model = "amazon.titan-text-express-v1"
gen_ai.response.model = "amazon.titan-text-express-v1"
gen_ai.response.id = "bedrock-resp-789xyz"
gen_ai.deployment.id = "us-east-1-prod"
gen_ai.request.id = "req_bedrock_001"
trace_id = "aws-trace-abc"

gen_ai.input.messages = [{"role": "user", "content": "Summarize..."}]
gen_ai.output.messages = [{"role": "assistant", "content": "The document..."}]
gen_ai.output.type = "text"

gen_ai.request.max_tokens = 512
gen_ai.request.temperature = 0.5

gen_ai.usage.input_tokens = 2048
gen_ai.usage.output_tokens = 256
gen_ai.usage.total_tokens = 2304

gen_ai.client.operation.duration = 5.678

gen_ai.safety.violated = "false"
gen_ai.guardrail.triggered = "true"
gen_ai.guardrail.ids = ["aws-guardrail-toxicity"]
gen_ai.pii.detected = "true"
gen_ai.pii.types = ["EMAIL", "PHONE"]
gen_ai.policy.blocked = "false"

service.name = "document-summarizer"
gen_ai.app.name = "document-summarizer"
server.address = "bedrock.us-east-1.amazonaws.com"
server.port = 443
```

---

## Local/Internal Models

### Raw Event (medadvice_v2 format with nested event)

```json
{
  "time": 1768482962,
  "source": "medadvice_v2",
  "sourcetype": "ai:governance:inference",
  "event": {
    "timestamp": "2026-01-15T05:16:02.159153",
    "event_type": "ai_inference",
    "inference_id": "cf587706-4a99-4962-80b5-a1521c5c8d38",
    "trace_id": "eedc36b0-c5a3-4220-82d7-24cb6192e0a5",
    "model_id": "claude-sonnet-4-5-20250929",
    "model_provider": "anthropic",
    "model_version": "20250929",
    "input": "user: Help I'm not feeling well",
    "output": "What symptoms are you experiencing?",
    "input_size_tokens": 0,
    "output_size_tokens": 0,
    "latency_ms": 2541,
    "cost": 0.0,
    "temperature": 0.7,
    "top_p": 1.0,
    "max_tokens": 2000,
    "safety_score": 1.0,
    "guardrails_triggered": ["EMERGENCY SYMPTOMS"],
    "pii_detected": false,
    "app": "medadvice_v2",
    "source": "recommendation_engine",
    "dest": "recommendation_engine",
    "user": null,
    "session_id": "35c36a8e-fb1f-48f2-ab25-966ecf7c5c44",
    "status": "success",
    "error_message": null
  }
}
```

### Normalized Output

```
gen_ai.operation.name = "ai_inference"
gen_ai.provider.name = "anthropic"
gen_ai.request.model = "claude-sonnet-4-5-20250929"
gen_ai.response.id = "cf587706-4a99-4962-80b5-a1521c5c8d38"
gen_ai.request.id = "cf587706-4a99-4962-80b5-a1521c5c8d38"
gen_ai.session.id = "35c36a8e-fb1f-48f2-ab25-966ecf7c5c44"
trace_id = "eedc36b0-c5a3-4220-82d7-24cb6192e0a5"

gen_ai.input.messages = "user: Help I'm not feeling well"
gen_ai.output.messages = "What symptoms are you experiencing?"

gen_ai.request.max_tokens = 2000
gen_ai.request.temperature = 0.7
gen_ai.request.top_p = 1.0

gen_ai.usage.input_tokens = 0
gen_ai.usage.output_tokens = 0
gen_ai.usage.total_tokens = 0

gen_ai.client.operation.duration = 2.541  (converted from latency_ms)

gen_ai.cost.total = 0.0

gen_ai.safety.score = 1.0
gen_ai.safety.violated = "false"  (derived from score)
gen_ai.guardrail.triggered = "true"
gen_ai.guardrail.ids = ["EMERGENCY SYMPTOMS"]
gen_ai.pii.detected = "false"

gen_ai.status = "success"

service.name = "medadvice_v2"
gen_ai.app.name = "medadvice_v2"
error.message = null
```

### Mapping Logic for Nested Events

| Raw Field | Normalized Field | Transform |
|-----------|------------------|-----------|
| `event.model_provider` | `gen_ai.provider.name` | FIELDALIAS |
| `event.model_id` | `gen_ai.request.model` | FIELDALIAS |
| `event.inference_id` | `gen_ai.response.id` | FIELDALIAS |
| `event.latency_ms` | `gen_ai.client.operation.duration` | EVAL (convert ms to seconds) |
| `event.guardrails_triggered` | `gen_ai.guardrail.ids` | REPORT (JSON array) |
| `event.app` | `service.name` | FIELDALIAS |

---

## Discovery SPL for Admins

Use these searches to explore raw field variation before TA deployment:

### Anthropic Events
```spl
index=gen_ai_log provider_name=anthropic 
| head 50 
| table operation_name provider_name request_model response_model safety_violated guardrail_triggered pii_detected
```

### OpenAI Events
```spl
index=gen_ai_log provider_name=openai 
| head 50 
| table operation_name provider_name request_model usage_input_tokens usage_output_tokens client_operation_duration
```

### AWS Bedrock Events
```spl
index=gen_ai_log provider_name="aws.bedrock" 
| head 50 
| table operation_name request_model guardrail_ids pii_types server.address
```

### Local/Nested Events
```spl
index=gen_ai_log 
| head 50 
| table event.model_provider event.model_id event.latency_ms event.guardrails_triggered event.app
```

### Verify Normalization
```spl
index=gen_ai_log
| head 100
| table gen_ai.operation.name gen_ai.provider.name gen_ai.request.model gen_ai.usage.total_tokens gen_ai.safety.violated gen_ai.guardrail.triggered gen_ai.pii.detected
```
