# Govern AI at Machine Speed
### Splunk + ServiceNow AI Control Tower — Ideation to Deployment to Monitoring

---

## The Executive Summary

Enterprises are deploying AI faster than they can govern it. **Splunk** and **ServiceNow AI Control Tower (AICT)** close that gap with a tightly integrated, end-to-end solution that gives leaders one source of truth for AI risk, cost, and performance — and the automation to act on it in seconds, not weeks.

| Lifecycle Stage | ServiceNow AI Control Tower | Splunk |
|---|---|---|
| **Ideate & Govern** | AI use-case intake, risk classification, policy, model & system inventory | Reference signals from production telemetry |
| **Deploy** | Approval workflows, ownership, change control | Continuous validation of model behavior in production |
| **Monitor (Machine Speed)** | Receives AI Cases for human-in-the-loop review | Real-time detection across every prompt, response, and token |
| **Respond & Improve** | Case management, audit trail, remediation | Auto-escalation, ML-driven evidence, closed-loop feedback |

The result: a unified control plane where **policy, inventory, and risk live in ServiceNow** while **observability, detection, and forensic evidence live in Splunk** — connected by an auditable, two-way integration.

---

## Why It Matters to the Business

- **Move from policy-on-paper to policy-in-runtime.** Models registered in AICT are continuously matched against live Splunk telemetry — drift, misuse, and PII leakage are detected the moment they happen, not at the next audit.
- **Eliminate shadow AI through CMDB reconciliation.** Splunk auto-discovers every AI application and model in production traffic and reconciles them against ServiceNow's AI System and AI Model digital assets (`alm_ai_system_digital_asset`, `alm_ai_model_digital_asset`). Anything observed in telemetry but missing from the CMDB is flagged as **Uninventoried Unapproved** — turning unsanctioned LLM usage from an invisible risk into a tracked, ownable AI Case in AICT, with a reverse "Inventoried Not Detected" view to retire stale registrations.
- **One-click escalation, full audit trail.** Any GenAI event in Splunk (safety violation, prompt injection, cost anomaly) escalates to an **AI Case in ServiceNow** with a single click. Every case is linked back to the originating `gen_ai.request.id` via a tamper-evident KV Store mapping — no orphaned alerts, no lost evidence.
- **Eliminate duplicate work.** Built-in deduplication checks ServiceNow before creating new cases — the same incident never opens twice, regardless of how many alerts fire.
- **Continuous GenAI monitoring on 100% of traffic.** Every prompt, response, and token across Anthropic, OpenAI, Bedrock, Vertex, Azure, and internal models is normalized into a single OpenTelemetry-aligned schema and scored in-stream for PII/PHI, prompt injection, jailbreaks, drift, and behavioral anomalies — no sampling, no blind spots, no waiting for the next review cycle.
- **Splunk Cloud ready.** Custom search command **and** alert-action fallback patterns ensure the integration works in restricted Cloud environments.
- **Compliance acceleration.** Auditable lineage from AI Case → Splunk event → model → owner satisfies EU AI Act, NIST AI RMF, and internal AI governance requirements out of the box.

> **Bottom line:** Risk officers see governance enforced. Engineers see fewer false alarms. CFOs see waste eliminated.

---

## Tokenomics: See Every Dollar, Before You Spend It

GenAI cost is the new shadow IT. Splunk delivers **token-level financial observability** that AICT can use to drive policy decisions:

- **Time-versioned pricing KV store** — track input/output token rates per provider/model as vendors change pricing; historical reports stay accurate forever.
- **Cost breakdowns at any dimension** — by **provider** (OpenAI, Anthropic, Bedrock, Vertex, Azure), **model**, **deployment**, **business application**, **user**, **team**, or **cost center**.
- **Anomaly detection on spend** — automatic alerting when hourly spend exceeds 2× the rolling 24-hour baseline, surfaced as ServiceNow AI Cases for owner accountability.
- **Cost-per-outcome metrics** — `$ per request`, `$ per 1M tokens`, latency-vs-cost correlation — so finance and engineering speak the same language.
- **Showback / chargeback ready** — KV-store joins enrich every event with the right rate card, enabling per-tenant invoicing without a separate FinOps stack.

> Customers typically uncover **15–30% of GenAI spend** is misaligned with intended use within the first week.

---

## Monitoring AI at Machine Speed in Splunk

Humans cannot review millions of LLM interactions. Splunk does — continuously.

- **Unified schema across providers.** 60+ normalized fields in the `gen_ai.*` namespace, aligned to OpenTelemetry GenAI semantic conventions. One query works across Anthropic, OpenAI, Bedrock, Vertex, Azure, and internal models.
- **ML-powered detection, in-stream.** PII/PHI classification, prompt-injection scoring, and TF-IDF anomaly detection on every prompt and response — not sampled, not delayed.
- **Pre-built governance content.** 15+ alerts (safety violations, PII exposure, jailbreaks, model drift, cost spikes, latency P99), governance dashboards, and risk-scored case packages ready on day one.
- **Closed-loop with ServiceNow.** High-severity detections auto-create AI Cases enriched with evidence, severity, model owner, and a deep link back to the raw event — turning a Splunk alert into a fully scoped ServiceNow workflow in under a second.

---

## The Executive Outcome

| Metric | Before | With Splunk + ServiceNow AICT |
|---|---|---|
| Time to detect AI policy violation | Days–weeks (audit cycle) | **Seconds** (streaming detection) |
| Time to open governed remediation | Manual ticketing | **One click** (auto-AI Case with evidence) |
| AI cost visibility | Monthly invoice surprise | **Real-time** by user, model, app |
| Audit readiness | Reactive evidence gathering | **Continuous, tamper-evident lineage** |
| Coverage of GenAI traffic | Sampled / spot-checked | **100% of prompts and responses** |

**One control plane. One audit trail. AI governed at the speed it operates.**

---

*Splunk Technology Add-on: `TA-gen_ai_cim` · ServiceNow Module: `sn_ai_case_mgmt` · Aligned to OpenTelemetry GenAI semantic conventions, NIST AI RMF, and EU AI Act traceability requirements.*
