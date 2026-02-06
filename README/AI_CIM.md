# AI CIM Field Reference

This document provides a comprehensive reference for all indices, fields, and their purposes within the TA-gen_ai_cim (GenAI Common Information Model) Technology Add-on.

## Table of Contents

- [Indices](#indices)
- [Field Categories](#field-categories)
  - [Core Operation / Model Identity](#core-operation--model-identity)
  - [Input/Output Payload](#inputoutput-payload)
  - [Request Parameters](#request-parameters)
  - [Usage, Performance, and Cost](#usage-performance-and-cost)
  - [Safety, Guardrails, and Policy](#safety-guardrails-and-policy)
  - [Evaluation / TEVV / Drift](#evaluation--tevv--drift)
  - [Error and Infrastructure](#error-and-infrastructure)
  - [Actor / Application Context](#actor--application-context)
  - [MLTK-Enhanced Fields](#mltk-enhanced-fields)
  - [TF-IDF Anomaly Detection Fields](#tf-idf-anomaly-detection-fields)
  - [Review Workflow Fields](#review-workflow-fields)
- [KV Store Collections](#kv-store-collections)
- [Lookup Tables](#lookup-tables)
  - [CSV-Based Lookups](#csv-based-lookups)
  - [KV Store Lookups](#kv-store-lookups)
- [Sources and Sourcetypes](#sources-and-sourcetypes)
  - [Sourcetypes](#sourcetypes)
  - [Source Patterns](#source-patterns)

---

## Indices

| Index Name | Purpose | Sourcetypes |
|------------|---------|-------------|
| `gen_ai_cim` | Primary index for normalized GenAI events following the CIM schema. All events are normalized to the `gen_ai.*` namespace. | Any JSON-formatted GenAI logs |
| `gen_ai_log` | Main operational index used in alerts, dashboards, and saved searches. Contains raw and enriched GenAI events. | `medadvice3:json`, `ai_cim:tfidf:ml_scoring`, `ai_cim:pii:ml_scoring` |

**Index References:**
- `props.conf`: Index-based normalization stanza `[index::gen_ai_log]`
- `savedsearches.conf`: All alerts and scheduled searches reference `index=gen_ai_log`
- `genai_governance_overview_studio.json`: All dashboard queries reference `index=gen_ai_log`
- `macros.conf`: Cost and anomaly detection macros reference `index=gen_ai_cim` and `index=gen_ai_log`

---

## Field Categories

### Core Operation / Model Identity

Fields that identify the AI operation, provider, model, and request/response metadata.

| Field | Source Field(s) | Purpose | References |
|-------|-----------------|---------|------------|
| `gen_ai.operation.name` | `operation_name` | Name of the AI operation (e.g., "chat", "completion", "embedding") | `props.conf`, `fields.conf` |
| `gen_ai.provider.name` | `provider_name`, `event.model_provider` | AI service provider (e.g., "openai", "anthropic", "aws.bedrock") | `props.conf`, `fields.conf`, `macros.conf` (genai_token_cost_join, genai_cost_by_provider, genai_cost_by_model), `transforms.conf` (genai_token_cost_lookup), `savedsearches.conf` (multiple alerts), `genai_governance_overview_studio.json` |
| `gen_ai.request.model` | `request_model`, `event.model_id` | Model identifier used for the request (e.g., "gpt-4", "claude-3-opus") | `props.conf`, `fields.conf`, `macros.conf` (token cost macros), `transforms.conf` (genai_token_cost_lookup), `savedsearches.conf` (all alerts), `genai_governance_overview_studio.json` (model filter, model usage) |
| `gen_ai.response.model` | `response_model` | Model identifier returned in response (may differ from request) | `props.conf`, `fields.conf` |
| `gen_ai.response.id` | `response_id`, `event.inference_id` | Unique identifier for the AI response | `props.conf`, `fields.conf`, `macros.conf` (gen_ai_request_id) |
| `gen_ai.conversation.id` | `conversation_id` | Identifier linking multiple turns in a conversation | `props.conf`, `fields.conf` |
| `gen_ai.deployment.id` | `deployment_id` | Deployment or environment identifier | `props.conf`, `fields.conf`, `savedsearches.conf` (all alerts aggregate by deployment) |
| `gen_ai.request.id` | `request_id`, `event.inference_id` | Unique identifier for the AI request | `props.conf`, `fields.conf`, `macros.conf` (gen_ai_request_id), `transforms.conf` (gen_ai_snow_case_map_lookup, gen_ai_review_findings_lookup), `savedsearches.conf` (review workflow, escalation), `genai_governance_overview_studio.json` |
| `gen_ai.session.id` | `session_id`, `event.session_id` | User session identifier | `props.conf`, `fields.conf`, `savedsearches.conf` (all alerts track unique_sessions), `genai_governance_overview_studio.json` (unique sessions, session activity) |
| `gen_ai.event.id` | `event_id`, `event.event_id` | Unique event identifier | `props.conf`, `fields.conf` |
| `trace_id` | `trace_id`, `event.trace_id` | Distributed tracing identifier for correlation | `props.conf`, `fields.conf`, `transforms.conf` (gen_ai_review_findings_lookup), `savedsearches.conf` (TFIDF scoring) |

### Input/Output Payload

Fields containing the actual prompts, responses, and message content.

| Field | Source Field(s) | Purpose | References |
|-------|-----------------|---------|------------|
| `gen_ai.input.messages` | `input_messages{}.content`, `input_messages`, `event.input` | Extracted/concatenated text content from input messages (prompts) | `props.conf` (EVAL), `fields.conf`, `macros.conf` (genai_pii_extract_text, genai_tfidf_preprocess_prompt, genai_pii_score_prompt), `savedsearches.conf` (TFIDF training/scoring) |
| `gen_ai.output.messages` | `output_messages{}.content`, `output_messages`, `event.output` | Extracted/concatenated text content from output messages (responses) | `props.conf` (EVAL), `fields.conf`, `macros.conf` (genai_pii_extract_text, genai_tfidf_preprocess_response, genai_pii_score_response, genai_pii_feature_engineering), `savedsearches.conf` (PII ML scoring, TFIDF training), `genai_governance_overview_studio.json` (PII detection queries) |
| `gen_ai.input.messages_raw` | `input_messages` | Raw JSON array of input messages (preserves structure) | `props.conf`, `fields.conf` |
| `gen_ai.output.messages_raw` | `output_messages` | Raw JSON array of output messages (preserves structure) | `props.conf`, `fields.conf` |
| `gen_ai.system_instructions` | `system_instructions` | System prompt/instructions provided to the model | `props.conf`, `fields.conf` |
| `gen_ai.tool.definitions` | - | Tool/function definitions provided to the model | `fields.conf` |
| `gen_ai.output.type` | `output_type` | Type of output (e.g., "text", "json", "function_call") | `props.conf`, `fields.conf` |

### Request Parameters

Configuration parameters sent with AI requests.

| Field | Source Field(s) | Purpose | References |
|-------|-----------------|---------|------------|
| `gen_ai.token.type` | `token_type` | Type of token being counted | `props.conf`, `fields.conf` |
| `gen_ai.request.max_tokens` | `request_max_tokens`, `event.max_tokens` | Maximum tokens allowed in response | `props.conf`, `fields.conf` |
| `gen_ai.request.temperature` | `request_temperature`, `event.temperature` | Sampling temperature (0-2, controls randomness) | `props.conf`, `fields.conf`, `genai_governance_overview_studio.json` (model usage table) |
| `gen_ai.request.top_p` | `request_top_p`, `event.top_p` | Nucleus sampling parameter | `props.conf`, `fields.conf` |
| `gen_ai.request.frequency_penalty` | `request_frequency_penalty` | Penalty for repeated tokens | `props.conf`, `fields.conf` |
| `gen_ai.request.presence_penalty` | `request_presence_penalty` | Penalty for tokens already present | `props.conf`, `fields.conf` |
| `gen_ai.request.stop_sequences` | `request_stop_sequences` | Stop sequences that halt generation (multi-value) | `props.conf`, `fields.conf`, `transforms.conf` (extract_stop_sequences) |
| `gen_ai.response.finish_reasons` | `response_finish_reasons` | Reasons why generation stopped (multi-value) | `props.conf`, `fields.conf`, `transforms.conf` (extract_finish_reasons) |
| `gen_ai.request.choice.count` | `request_choice_count` | Number of response choices requested | `props.conf`, `fields.conf` |
| `gen_ai.request.seed` | `request_seed` | Random seed for reproducibility | `props.conf`, `fields.conf` |

### Usage, Performance, and Cost

Metrics for token usage, latency, and cost tracking.

| Field | Source Field(s) | Purpose | References |
|-------|-----------------|---------|------------|
| `gen_ai.usage.input_tokens` | `usage_input_tokens`, `event.input_size_tokens` | Number of tokens in the input/prompt | `props.conf`, `fields.conf`, `macros.conf` (genai_token_cost_join, genai_token_cost_summary, cost aggregation macros), `genai_governance_overview_studio.json` (cost calculations) |
| `gen_ai.usage.output_tokens` | `usage_output_tokens`, `event.output_size_tokens` | Number of tokens in the output/response | `props.conf`, `fields.conf`, `macros.conf` (genai_token_cost_join, genai_token_cost_summary, cost aggregation macros), `genai_governance_overview_studio.json` (cost calculations) |
| `gen_ai.usage.total_tokens` | Computed: `input_tokens + output_tokens` | Total tokens for the request | `props.conf` (EVAL), `fields.conf`, `macros.conf` (genai_cost_by_model), `savedsearches.conf` (High Token Usage Alert), `genai_governance_overview_studio.json` (total tokens KPI, token usage chart) |
| `gen_ai.client.operation.duration` | `client_operation_duration`, `event.latency_ms/1000` | Client-measured request duration in seconds | `props.conf`, `fields.conf`, `savedsearches.conf` (Latency Outlier Alert, Slow Response Alert), `genai_governance_overview_studio.json` (avg latency, latency distribution, latency over time) |
| `gen_ai.server.request.duration` | - | Server-reported request duration | `fields.conf` |
| `gen_ai.server.time_per_output_token` | - | Time per output token (streaming) | `fields.conf` |
| `gen_ai.server.time_to_first_token` | - | Time to first token (streaming) | `fields.conf` |
| `gen_ai.cost.total` | `cost`, `event.cost` | Total cost for the request | `props.conf`, `fields.conf`, `savedsearches.conf` (Cost Spike Alert), `macros.conf` |
| `gen_ai.cost.input` | Computed via lookup | Cost for input tokens | `macros.conf` (genai_token_cost_join), `genai_governance_overview_studio.json` |
| `gen_ai.cost.output` | Computed via lookup | Cost for output tokens | `macros.conf` (genai_token_cost_join), `genai_governance_overview_studio.json` |
| `gen_ai.cost.calculated_total` | Computed via lookup | Calculated total cost from token pricing | `macros.conf` (genai_token_cost_join, genai_token_cost_summary) |
| `gen_ai.cost.input_per_million` | From lookup | Input token price per million | `macros.conf` (genai_token_cost_join) |
| `gen_ai.cost.output_per_million` | From lookup | Output token price per million | `macros.conf` (genai_token_cost_join) |
| `gen_ai.cost.currency` | From lookup | Currency code (default: USD) | `macros.conf` (genai_token_cost_join, genai_token_cost_summary) |

### Safety, Guardrails, and Policy

Fields for compliance, safety monitoring, and policy enforcement.

| Field | Source Field(s) | Purpose | References |
|-------|-----------------|---------|------------|
| `gen_ai.safety.violated` | `safety_violated`, `event.safety_violated` | Boolean: whether safety policies were violated | `props.conf` (EVAL for normalization), `fields.conf`, `macros.conf` (gen_ai_high_risk_filter, gen_ai_calc_risk_score), `savedsearches.conf` (Safety Violation Alert, Critical Safety Alert, Review Candidates), `genai_governance_overview_studio.json` (safety violations KPI, compliance summary, status distribution) |
| `gen_ai.safety.categories` | `safety_categories` | Categories of safety violations (multi-value) | `props.conf`, `fields.conf`, `transforms.conf` (extract_safety_categories), `savedsearches.conf` (Safety Violation Alert severity classification) |
| `gen_ai.safety.score` | `event.safety_score` | Numeric safety score | `props.conf`, `fields.conf` |
| `gen_ai.guardrail.triggered` | `guardrail_triggered`, `event.guardrails_triggered` | Boolean: whether guardrails were activated | `props.conf` (EVAL for normalization), `fields.conf`, `macros.conf` (gen_ai_high_risk_filter, gen_ai_calc_risk_score), `savedsearches.conf` (Guardrail Trigger Summary, Review Candidates), `genai_governance_overview_studio.json` (guardrails triggered KPI) |
| `gen_ai.guardrail.ids` | `guardrail_ids`, `event.guardrails_triggered` | IDs of triggered guardrails (multi-value) | `props.conf`, `fields.conf`, `transforms.conf` (extract_guardrail_ids, extract_guardrail_ids_alt), `savedsearches.conf` (Guardrail Trigger Summary, Critical Safety Alert) |
| `gen_ai.pii.detected` | `pii_detected`, `event.pii_detected` | Boolean: whether PII was detected | `props.conf` (EVAL for normalization), `fields.conf`, `macros.conf` (gen_ai_high_risk_filter, gen_ai_calc_risk_score, genai_pii_combined_score), `savedsearches.conf` (PII Detection Alert, PII High Volume Alert, Review Candidates), `genai_governance_overview_studio.json` (PII detected KPI, compliance summary) |
| `gen_ai.pii.types` | `pii_types` | Types of PII detected (multi-value: SSN, EMAIL, PHONE, etc.) | `props.conf`, `fields.conf`, `transforms.conf` (extract_pii_types), `macros.conf` (genai_pii_classify_types), `savedsearches.conf` (PII Detection Alert, PII ML alerts), `genai_governance_overview_studio.json` |
| `gen_ai.policy.blocked` | `policy_blocked` | Boolean: whether request was blocked by policy | `props.conf` (EVAL for normalization), `fields.conf`, `macros.conf` (gen_ai_high_risk_filter, gen_ai_calc_risk_score), `savedsearches.conf` (Policy Block Alert, Review Candidates), `genai_governance_overview_studio.json` (policy blocked KPI, status distribution) |

### Evaluation / TEVV / Drift

Fields for model evaluation, testing, and drift monitoring.

| Field | Source Field(s) | Purpose | References |
|-------|-----------------|---------|------------|
| `gen_ai.evaluation.name` | `evaluation_name` | Name of the evaluation metric | `props.conf`, `fields.conf` |
| `gen_ai.evaluation.score.value` | `evaluation_score_value` | Numeric evaluation score | `props.conf`, `fields.conf` |
| `gen_ai.evaluation.score.label` | `evaluation_score_label` | Categorical evaluation label | `props.conf`, `fields.conf` |
| `gen_ai.evaluation.explanation` | `evaluation_explanation` | Explanation of evaluation results | `props.conf`, `fields.conf` |
| `gen_ai.drift.metric.name` | `drift_metric_name` | Name of the drift metric being tracked | `props.conf`, `fields.conf`, `savedsearches.conf` (Model Drift Critical Alert) |
| `gen_ai.drift.metric.value` | `drift_metric_value` | Numeric value of the drift metric | `props.conf`, `fields.conf`, `savedsearches.conf` (Model Drift Critical Alert, Model Drift Trend) |
| `gen_ai.drift.status` | `drift_status` | Drift status (e.g., "normal", "warning", "critical") | `props.conf`, `fields.conf`, `savedsearches.conf` (Model Drift Critical Alert) |

### Error and Infrastructure

Fields for error tracking and infrastructure details.

| Field | Source Field(s) | Purpose | References |
|-------|-----------------|---------|------------|
| `error.type` | `error_type` | Type/category of error | `props.conf`, `fields.conf`, `savedsearches.conf` (Error Rate Alert, Model Failure Alert) |
| `error.message` | `error_message`, `event.error_message` | Error message text | `props.conf`, `fields.conf`, `savedsearches.conf` (Model Failure Alert) |
| `gen_ai.status` | `status`, `event.status` | Request status (e.g., "success", "failure", "error") | `props.conf`, `fields.conf`, `savedsearches.conf` (Error Rate Alert, Model Failure Alert) |
| `server.address` | `server_address` | AI service server address | `props.conf`, `fields.conf` |
| `server.port` | `server_port` | AI service server port | `props.conf`, `fields.conf` |

### Actor / Application Context

Fields identifying users, applications, and services.

| Field | Source Field(s) | Purpose | References |
|-------|-----------------|---------|------------|
| `enduser.id` | `enduser_id` | End user identifier | `props.conf`, `fields.conf` |
| `service.name` | `service_name`, `event.app` | Service/application name | `props.conf`, `fields.conf`, `savedsearches.conf` (TFIDF scoring) |
| `gen_ai.service.name` | `service_name`, `event.app` | Normalized service name in gen_ai namespace | `props.conf` |
| `client.address` | `client_address` | Client IP address | `props.conf`, `fields.conf`, `macros.conf` (genai_tfidf_anomaly_stats, genai_tfidf_anomaly_by_source), `savedsearches.conf` (Prompt Injection by Source IP, TFIDF Anomaly by Source IP, PII ML by Source IP Alert), `genai_governance_overview_studio.json` (top anomaly sources) |
| `gen_ai.user.id` | Computed: `coalesce(enduser_id, user_id, user)` | Derived user identifier with fallbacks | `props.conf` (EVAL), `fields.conf` |
| `gen_ai.app.name` | Computed: `coalesce(service_name, app_name, app)` | Derived application name with fallbacks | `props.conf` (EVAL), `fields.conf`, `macros.conf` (genai_cost_by_app, genai_tfidf_anomaly_stats, genai_pii_stats_by_app), `savedsearches.conf` (most alerts aggregate by app), `genai_governance_overview_studio.json` (service filter, requests by service, cost by service) |

### MLTK-Enhanced Fields

Fields populated by Machine Learning Toolkit models for PII and prompt injection detection.

| Field | Source Field(s) | Purpose | References |
|-------|-----------------|---------|------------|
| `gen_ai.pii.risk_score` | MLTK model output | PII detection probability (0-1) | `fields.conf`, `macros.conf` (genai_pii_apply_model, genai_pii_high_risk_threshold), `savedsearches.conf` (MLTK PII Risk Score Alert, PII ML High Risk Alert, PII ML Rate Threshold Alert, Auto Escalate PII to Review Queue) |
| `gen_ai.pii.ml_detected` | MLTK model output | Boolean: MLTK-based PII detection flag | `fields.conf`, `macros.conf` (genai_pii_apply_model), `savedsearches.conf` (PII ML alerts, Auto Escalate PII to Review Queue), `genai_governance_overview_studio.json` |
| `gen_ai.pii.confidence` | Computed from risk_score | Confidence level (very_high, high, medium, low, very_low) | `macros.conf` (genai_pii_apply_model), `savedsearches.conf` (PII Scoring, Auto Escalate PII), `genai_governance_overview_studio.json` |
| `gen_ai.pii.category` | Computed | PII category (identity, financial, contact, none) | `macros.conf` (genai_pii_classify_types) |
| `gen_ai.pii.severity` | Computed | PII severity (critical, high, medium, low, none) | `macros.conf` (genai_pii_classify_types) |
| `gen_ai.pii.location` | Computed | Where PII was found (prompt, response, both, none) | `macros.conf` (genai_pii_combined_score) |
| `gen_ai.prompt_injection.risk_score` | MLTK model output | Prompt injection probability (0-1) | `fields.conf`, `savedsearches.conf` (Prompt Injection Alert, Prompt Injection by Source IP) |
| `gen_ai.prompt_injection.ml_detected` | MLTK model output | Boolean: MLTK-based prompt injection detection flag | `fields.conf`, `savedsearches.conf` (Prompt Injection Alert) |
| `gen_ai.prompt_injection.technique` | MLTK model output | Detected injection technique (e.g., ignore_instructions, jailbreak) | `fields.conf`, `savedsearches.conf` (Prompt Injection Alert, Prompt Injection by Source IP) |
| `gen_ai.prompt.has_pii` | Computed | Boolean: PII detected in prompt | `macros.conf` (genai_pii_score_prompt, genai_pii_combined_score) |
| `gen_ai.prompt.pii_types` | Computed | PII types found in prompt | `macros.conf` (genai_pii_score_prompt) |
| `gen_ai.response.has_pii` | Computed | Boolean: PII detected in response | `macros.conf` (genai_pii_score_response, genai_pii_combined_score) |
| `gen_ai.response.pii_types` | Computed | PII types found in response | `macros.conf` (genai_pii_score_response) |

### TF-IDF Anomaly Detection Fields

Fields generated by TF-IDF-based anomaly detection for prompts and responses.

| Field | Source Field(s) | Purpose | References |
|-------|-----------------|---------|------------|
| `gen_ai.prompt.anomaly_score` | TF-IDF OneClassSVM output | Anomaly score for prompts (negative = anomaly) | `fields.conf`, `macros.conf` (genai_tfidf_score_prompt, genai_tfidf_anomaly_stats), `savedsearches.conf` (TFIDF Scoring searches, TFIDF Model Performance Report) |
| `gen_ai.prompt.is_anomaly` | Computed: `anomaly_score < 0` | Boolean: whether prompt is anomalous | `fields.conf`, `macros.conf` (genai_tfidf_score_prompt, genai_tfidf_combined_risk, genai_tfidf_anomaly_stats, genai_tfidf_anomaly_by_model), `savedsearches.conf` (TFIDF Anomalous Prompt Alert, TFIDF Anomaly by Source IP Alert, TFIDF Anomaly Rate Threshold Alert, TFIDF Daily Anomaly Summary), `genai_governance_overview_studio.json` (prompt anomalies KPI, prompt trend) |
| `gen_ai.response.anomaly_score` | TF-IDF OneClassSVM output | Anomaly score for responses (negative = anomaly) | `fields.conf`, `macros.conf` (genai_tfidf_score_response, genai_tfidf_anomaly_stats), `savedsearches.conf` (TFIDF Scoring searches, TFIDF Model Performance Report) |
| `gen_ai.response.is_anomaly` | Computed: `anomaly_score < 0` | Boolean: whether response is anomalous | `fields.conf`, `macros.conf` (genai_tfidf_score_response, genai_tfidf_combined_risk, genai_tfidf_anomaly_stats, genai_tfidf_anomaly_by_model), `savedsearches.conf` (TFIDF Anomalous Response Alert, TFIDF Anomaly by Source IP Alert, TFIDF Anomaly Rate Threshold Alert), `genai_governance_overview_studio.json` (response anomalies KPI, response trend) |
| `gen_ai.tfidf.combined_anomaly` | Computed | Combined classification: "both", "prompt_only", "response_only", "normal" | `fields.conf`, `macros.conf` (genai_tfidf_combined_risk, genai_tfidf_anomaly_by_source), `savedsearches.conf` (TFIDF High Risk Combined Anomaly Alert, TFIDF Anomaly by Source IP Alert, TFIDF Daily Anomaly Summary), `genai_governance_overview_studio.json` |
| `gen_ai.tfidf.risk_level` | Computed | Risk level: "HIGH" (both), "MEDIUM" (prompt_only), "LOW" (response_only), "NONE" (normal) | `fields.conf`, `macros.conf` (genai_tfidf_combined_risk), `savedsearches.conf` (TFIDF High Risk Combined Anomaly Alert), `genai_governance_overview_studio.json` (high risk KPI, risk distribution pie chart) |

### Review Workflow Fields

Fields used in the human review workflow for governance findings.

| Field | Source Field(s) | Purpose | References |
|-------|-----------------|---------|------------|
| `gen_ai.review.status` | KV Store lookup | Review status (new, assigned, in_review, completed, rejected) | `props.conf` (LOOKUP), `macros.conf` (gen_ai_add_review_status), `savedsearches.conf` (Review Candidates, Unreviewed High Risk Events, Review Status Summary) |
| `gen_ai.review.assignee` | KV Store lookup | Assigned reviewer | `props.conf` (LOOKUP), `macros.conf` (gen_ai_add_review_status), `savedsearches.conf` (Review Candidates) |
| `gen_ai.review.reviewer` | KV Store lookup | Reviewer who completed the review | `props.conf` (LOOKUP), `savedsearches.conf` (Reviewer Activity) |
| `gen_ai.review.priority` | KV Store lookup | Review priority (critical, high, medium, low) | `props.conf` (LOOKUP), `macros.conf` (gen_ai_add_review_status), `savedsearches.conf` (Auto Escalate PII to Review Queue) |
| `gen_ai.review.pii_confirmed` | KV Store lookup | Boolean: PII confirmed by reviewer | `props.conf` (LOOKUP), `macros.conf` (gen_ai_add_review_status, gen_ai_any_issue_confirmed, gen_ai_count_issue_types), `savedsearches.conf` (Reviewer Activity) |
| `gen_ai.review.pii_types` | KV Store lookup | Confirmed PII types | `props.conf` (LOOKUP) |
| `gen_ai.review.phi_confirmed` | KV Store lookup | Boolean: PHI confirmed by reviewer | `props.conf` (LOOKUP), `macros.conf` (gen_ai_add_review_status, gen_ai_any_issue_confirmed, gen_ai_count_issue_types), `savedsearches.conf` (Reviewer Activity) |
| `gen_ai.review.phi_types` | KV Store lookup | Confirmed PHI types | `props.conf` (LOOKUP) |
| `gen_ai.review.prompt_injection_confirmed` | KV Store lookup | Boolean: Prompt injection confirmed | `props.conf` (LOOKUP), `macros.conf` (gen_ai_add_review_status, gen_ai_any_issue_confirmed, gen_ai_count_issue_types), `savedsearches.conf` (Reviewer Activity) |
| `gen_ai.review.anomaly_confirmed` | KV Store lookup | Boolean: Anomaly confirmed | `props.conf` (LOOKUP), `macros.conf` (gen_ai_any_issue_confirmed, gen_ai_count_issue_types) |
| `gen_ai.review.anomaly_type` | KV Store lookup | Type of confirmed anomaly | `props.conf` (LOOKUP) |
| `gen_ai.review.notes` | KV Store lookup | Reviewer notes | `props.conf` (LOOKUP) |
| `gen_ai.review.updated_at` | KV Store lookup | Last update timestamp | `props.conf` (LOOKUP), `macros.conf` (gen_ai_add_review_status) |

---

## KV Store Collections

### genai_token_cost

Time-versioned pricing for input/output tokens by provider and model.

| Field | Type | Purpose |
|-------|------|---------|
| `provider` | string | Cloud provider or vendor (e.g., "openai", "anthropic") |
| `model` | string | Model identifier (e.g., "gpt-4", "claude-3-opus") |
| `direction` | string | Token direction: "input" or "output" |
| `cost_per_million` | number | Cost in USD per million tokens |
| `effective_start` | number | Unix epoch when price becomes effective |
| `effective_end` | number | Unix epoch when price expires (null for current) |
| `currency` | string | Currency code (default: "USD") |

**References:** `collections.conf`, `transforms.conf` (genai_token_cost_lookup), `macros.conf` (genai_token_cost_join, genai_get_current_pricing, genai_get_pricing_history), `genai_governance_overview_studio.json` (cost calculations)

### gen_ai_snow_case_map

Maps GenAI request IDs to ServiceNow AI Case sys_ids.

| Field | Type | Purpose |
|-------|------|---------|
| `request_id` | string | GenAI request identifier (gen_ai.request.id) |
| `sys_id` | string | ServiceNow AI Case sys_id |
| `sn_instance` | string | ServiceNow instance name |
| `created_at` | number | Unix epoch when mapping was created |
| `updated_at` | number | Unix epoch when mapping was last updated |
| `created_by` | string | Username who created the linkage |

**References:** `collections.conf`, `transforms.conf` (gen_ai_snow_case_map_lookup)

### gen_ai_review_findings

Stores analyst review outcomes for AI governance workflow. Field names use gen_ai.* namespace to match gen_ai_log index fields.

| Field | Type | Purpose |
|-------|------|---------|
| `gen_ai.request.id` | string | Primary identifier (matches gen_ai_log field) |
| `gen_ai.trace.id` | string | Distributed tracing identifier |
| `event_time` | number | Original event timestamp |
| `gen_ai.app.name` | string | Application name (matches gen_ai_log field) |
| `gen_ai.request.model` | string | Model identifier (matches gen_ai_log field) |
| `gen_ai.input.preview` | string | Truncated prompt for review |
| `gen_ai.output.preview` | string | Truncated response for review |
| `gen_ai.review.reviewer` | string | Reviewer username |
| `gen_ai.review.assignee` | string | Assigned analyst |
| `gen_ai.review.status` | string | Review status: new, assigned, in_review, completed, rejected |
| `gen_ai.review.priority` | string | Priority level: critical, high, medium, low |
| `gen_ai.review.pii_confirmed` | bool | PII confirmed by reviewer |
| `gen_ai.review.pii_types` | string | Confirmed PII types |
| `gen_ai.review.phi_confirmed` | bool | PHI confirmed by reviewer |
| `gen_ai.review.phi_types` | string | Confirmed PHI types |
| `gen_ai.review.prompt_injection_confirmed` | bool | Injection confirmed |
| `gen_ai.review.prompt_injection_type` | string | Type of injection |
| `gen_ai.review.anomaly_confirmed` | bool | Anomaly confirmed |
| `gen_ai.review.anomaly_type` | string | Type of anomaly |
| `gen_ai.review.notes` | string | Reviewer notes |
| `gen_ai.review.created_at` | number | Creation timestamp |
| `gen_ai.review.updated_at` | number | Last update timestamp |
| `gen_ai.review.created_by` | string | Creator username |
| `gen_ai.review.updated_by` | string | Last updater username |

**References:** `collections.conf`, `transforms.conf` (gen_ai_review_findings_lookup), `props.conf` (LOOKUP for enrichment), `macros.conf` (gen_ai_add_review_status), `savedsearches.conf` (Auto Escalate PII, Review workflows)

### gen_ai_review_audit

Audit trail for review actions.

| Field | Type | Purpose |
|-------|------|---------|
| `audit_id` | string | Unique audit entry identifier |
| `request_id` | string | Related request ID |
| `action` | string | Action performed |
| `previous_status` | string | Status before change |
| `new_status` | string | Status after change |
| `changed_fields` | string | Fields that were modified |
| `user` | string | User who performed action |
| `timestamp` | number | When action occurred |
| `notes` | string | Action notes |

**References:** `collections.conf`, `transforms.conf` (gen_ai_review_audit_lookup)

---

## Lookup Tables

### CSV-Based Lookups

| Lookup Name | Filename | Purpose |
|-------------|----------|---------|
| `pii_training_examples` | `pii_training_examples.csv` | PII training examples for model training |
| `pii_model_metadata` | `pii_model_metadata.csv` | PII model accuracy, version metadata |
| `pii_training_data_engineered` | `pii_training_data_engineered.csv` | Feature-engineered training data |
| `llm_pii_mixed_responses_200k` | `llm_pii_mixed_responses_200k.csv` | Large-scale PII training dataset (200k examples) |
| `tfidf_training_examples` | `tfidf_training_examples.csv` | TF-IDF anomaly detection training examples |

**References:** `transforms.conf`, `savedsearches.conf` (PII Train Step 1)

### KV Store Lookups

#### gen_ai_review_findings_lookup

Provides access to the `gen_ai_review_findings` KV store collection for querying and enriching review workflow data. Field names use gen_ai.* namespace to match gen_ai_log index fields.

| Property | Value |
|----------|-------|
| **Lookup Name** | `gen_ai_review_findings_lookup` |
| **Collection** | `gen_ai_review_findings` |
| **Type** | KV Store (external) |
| **Case Sensitive** | No |

**Available Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `_key` | string | Auto-generated unique key |
| `gen_ai.request.id` | string | Primary identifier (matches gen_ai_log) |
| `gen_ai.trace.id` | string | Distributed tracing identifier |
| `event_time` | number | Original event timestamp (epoch) |
| `gen_ai.app.name` | string | Application name (matches gen_ai_log) |
| `gen_ai.request.model` | string | AI model identifier (matches gen_ai_log) |
| `gen_ai.input.preview` | string | Truncated prompt text (first 200 chars) |
| `gen_ai.output.preview` | string | Truncated response text (first 200 chars) |
| `gen_ai.review.reviewer` | string | Username of assigned reviewer |
| `gen_ai.review.assignee` | string | Username of current assignee |
| `gen_ai.review.status` | string | Review status: new, assigned, in_review, completed, rejected |
| `gen_ai.review.priority` | string | Priority level: critical, high, medium, low |
| `gen_ai.review.pii_confirmed` | bool | PII confirmed by reviewer |
| `gen_ai.review.pii_types` | string | Comma-separated PII types (SSN, EMAIL, PHONE, etc.) |
| `gen_ai.review.phi_confirmed` | bool | PHI confirmed by reviewer |
| `gen_ai.review.phi_types` | string | Comma-separated PHI types |
| `gen_ai.review.prompt_injection_confirmed` | bool | Prompt injection attack confirmed |
| `gen_ai.review.prompt_injection_type` | string | Type of injection technique |
| `gen_ai.review.anomaly_confirmed` | bool | Anomaly confirmed by reviewer |
| `gen_ai.review.anomaly_type` | string | Type of anomaly |
| `gen_ai.review.notes` | string | Reviewer notes and comments |
| `gen_ai.review.created_at` | number | Record creation timestamp (epoch) |
| `gen_ai.review.updated_at` | number | Last update timestamp (epoch) |
| `gen_ai.review.created_by` | string | Username who created the record |
| `gen_ai.review.updated_by` | string | Username who last updated the record |

**SPL Usage Examples:**

```spl
# Read all review findings
| inputlookup gen_ai_review_findings_lookup

# Filter by status
| inputlookup gen_ai_review_findings_lookup 
| search "gen_ai.review.status"="new" OR "gen_ai.review.status"="assigned"

# Count findings by status and priority
| inputlookup gen_ai_review_findings_lookup 
| stats count by gen_ai.review.status, gen_ai.review.priority

# Get unreviewed high-priority findings
| inputlookup gen_ai_review_findings_lookup 
| search "gen_ai.review.status" IN ("new", "assigned") "gen_ai.review.priority" IN ("critical", "high")
| sort -gen_ai.review.created_at

# Find all confirmed PII issues
| inputlookup gen_ai_review_findings_lookup 
| search "gen_ai.review.pii_confirmed"="true" OR "gen_ai.review.pii_confirmed"=1
| table gen_ai.request.id, gen_ai.app.name, gen_ai.review.pii_types, gen_ai.review.reviewer, gen_ai.review.notes

# Enrich search results with review status
index=gen_ai_log 
| lookup gen_ai_review_findings_lookup gen_ai.request.id OUTPUT gen_ai.review.status, gen_ai.review.priority, gen_ai.review.pii_confirmed
| where isnotnull('gen_ai.review.status')

# Join events with review findings
index=gen_ai_log gen_ai.pii.ml_detected="true"
| join type=left gen_ai.request.id 
    [| inputlookup gen_ai_review_findings_lookup 
     | table gen_ai.request.id, gen_ai.review.status, gen_ai.review.priority, gen_ai.review.reviewer]
```

**Automatic Enrichment:**

Events in `gen_ai_log` are automatically enriched with review fields via the lookup defined in `props.conf`:

```
LOOKUP-gen_ai_review_enrichment = gen_ai_review_findings_lookup gen_ai.request.id OUTPUTNEW gen_ai.review.status, gen_ai.review.assignee, ...
```

This adds `gen_ai.review.*` fields to matching events without requiring explicit lookup commands.

**References:** `transforms.conf`, `collections.conf`, `props.conf` (LOOKUP), `savedsearches.conf` (Auto Escalate PII, Review workflows), `review_save.js`, `review_landing.js`

---

## Quick Reference: Fields by Use Case

### Cost Analysis
- `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `gen_ai.usage.total_tokens`
- `gen_ai.cost.total`, `gen_ai.cost.input`, `gen_ai.cost.output`, `gen_ai.cost.calculated_total`
- `gen_ai.provider.name`, `gen_ai.request.model`

### Safety & Compliance
- `gen_ai.safety.violated`, `gen_ai.safety.categories`, `gen_ai.safety.score`
- `gen_ai.guardrail.triggered`, `gen_ai.guardrail.ids`
- `gen_ai.policy.blocked`

### PII Detection
- `gen_ai.pii.detected`, `gen_ai.pii.types`
- `gen_ai.pii.risk_score`, `gen_ai.pii.ml_detected`, `gen_ai.pii.confidence`
- `gen_ai.prompt.has_pii`, `gen_ai.response.has_pii`

### Anomaly Detection
- `gen_ai.prompt.anomaly_score`, `gen_ai.prompt.is_anomaly`
- `gen_ai.response.anomaly_score`, `gen_ai.response.is_anomaly`
- `gen_ai.tfidf.combined_anomaly`, `gen_ai.tfidf.risk_level`

### Performance Monitoring
- `gen_ai.client.operation.duration`
- `gen_ai.request.model`, `gen_ai.provider.name`
- `gen_ai.app.name`, `gen_ai.session.id`

### Review Workflow
- `gen_ai.request.id`, `trace_id`
- `gen_ai.review.status`, `gen_ai.review.priority`, `gen_ai.review.assignee`
- `gen_ai.review.pii_confirmed`, `gen_ai.review.phi_confirmed`, `gen_ai.review.anomaly_confirmed`

---

## Sources and Sourcetypes

This section documents all sources and sourcetypes defined or used by this TA.

### Sourcetypes

#### Input Sourcetypes

These sourcetypes are used for ingesting GenAI events into Splunk:

| Sourcetype | Description | Index | Configuration |
|------------|-------------|-------|---------------|
| `medadvice3:json` | Medadvice v3 format - Primary JSON format for GenAI events with flat field structure (e.g., `request_model`, `usage_input_tokens`, `safety_violated`) | `gen_ai_log` | `props.conf` - Full field normalization to `gen_ai.*` namespace with boolean normalization, multi-value extraction, and review enrichment |
| `medadvice:json` | Medadvice v2 format - Legacy JSON format with nested `event.*` structure (e.g., `event.model_id`, `event.input_size_tokens`) | `ai_log2` | `props.conf` - Field aliasing from nested structure to `gen_ai.*` namespace |

#### Generated Sourcetypes

These sourcetypes are created by scheduled saved searches for ML scoring and anomaly detection:

| Sourcetype | Description | Index | Generated By |
|------------|-------------|-------|--------------|
| `ai_cim:tfidf:ml_scoring` | TF-IDF anomaly detection scoring results for prompts and responses | `gen_ai_log` | `savedsearches.conf` - TFIDF Prompt Scoring, TFIDF Response Scoring, TFIDF Combined Scoring searches |
| `ai_cim:pii:ml_scoring` | PII ML detection scoring results from MLTK models | `gen_ai_log` | `savedsearches.conf` - PII ML Scoring search |

### Source Patterns

#### Input Source Patterns

These source patterns are defined in `props.conf` to apply normalization regardless of sourcetype:

| Source Pattern | Description | Configuration |
|----------------|-------------|---------------|
| `source::*/gen_ai_log/*` | Files in gen_ai_log directories - applies JSON parsing and review enrichment lookup | `props.conf` - `KV_MODE=json`, review findings lookup |
| `source::*/ai_log2/*` | Files in ai_log2 directories - applies JSON parsing and review enrichment lookup | `props.conf` - `KV_MODE=json`, review findings lookup |

#### Index-Based Stanzas

| Stanza | Description | Configuration |
|--------|-------------|---------------|
| `index::gen_ai_log` | Primary index stanza - applies full CIM normalization to all events in the gen_ai_log index regardless of sourcetype | `props.conf` - Complete field aliasing, EVAL transforms, boolean normalization, multi-value extractions |

#### Generated Sources

These sources are created by scheduled saved searches:

| Source | Description | Sourcetype |
|--------|-------------|------------|
| `tfidf_prompt_scoring` | TF-IDF anomaly scoring for prompts | `ai_cim:tfidf:ml_scoring` |
| `tfidf_response_scoring` | TF-IDF anomaly scoring for responses | `ai_cim:tfidf:ml_scoring` |
| `tfidf_combined_scoring` | Combined TF-IDF anomaly scoring | `ai_cim:tfidf:ml_scoring` |
| `pii_ml_scoring` | PII ML detection scoring | `ai_cim:pii:ml_scoring` |

### Sourcetype Configuration Details

#### medadvice3:json

The primary input sourcetype for GenAI events. Key configuration includes:

- **JSON Parsing**: `KV_MODE=json` enables automatic JSON field extraction
- **Field Normalization**: 40+ field aliases map raw fields to the `gen_ai.*` namespace
- **Boolean Normalization**: Safety/guardrail/PII/policy boolean fields normalized to consistent `"true"`/`"false"` strings
- **Multi-value Extraction**: JSON arrays for safety categories, guardrail IDs, PII types, finish reasons, and stop sequences
- **Review Enrichment**: Automatic lookup enrichment via `gen_ai_review_findings_lookup`
- **Computed Fields**: `gen_ai.usage.total_tokens`, `gen_ai.user.id`, `gen_ai.app.name`

#### medadvice:json

Legacy sourcetype with nested event structure. Key differences from v3:

- **Nested Fields**: Fields like `event.model_id`, `event.input`, `event.output`
- **Latency Conversion**: Converts `event.latency_ms` to seconds for `gen_ai.client.operation.duration`
- **Simplified Extraction**: Uses `extract_guardrail_ids_alt` for nested guardrail array

#### ai_cim:tfidf:ml_scoring

Generated sourcetype for TF-IDF anomaly detection. Contains:

- `gen_ai.prompt.anomaly_score` - Raw anomaly score (negative = anomaly)
- `gen_ai.prompt.is_anomaly` - Boolean anomaly flag
- `gen_ai.response.anomaly_score` - Response anomaly score
- `gen_ai.response.is_anomaly` - Response anomaly flag
- `gen_ai.tfidf.combined_anomaly` - Combined classification
- `gen_ai.tfidf.risk_level` - Risk level (HIGH/MEDIUM/LOW/NONE)

#### ai_cim:pii:ml_scoring

Generated sourcetype for PII ML detection. Contains:

- `gen_ai.pii.risk_score` - PII probability (0-1)
- `gen_ai.pii.ml_detected` - Boolean ML detection flag
- `gen_ai.pii.confidence` - Confidence level
- `gen_ai.pii.category` - PII category
- `gen_ai.pii.severity` - PII severity level
