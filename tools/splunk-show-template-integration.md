# Splunk Show Template Integration — Cisco AI Defense → ES Agentic SOC Demo

How the `TA-gen_ai_cim` v1.5.0 tarball and the post-deploy script combine to configure a Splunk Show instance for the eight-step demo, what each artifact is responsible for, and what to do if the Show Template cannot run scripts.

---

## 1. The eight-step flow and what carries each step

| # | Step | Carried by | Status |
|---|---|---|---|
| 1 | **Detect** — AI Defense blocks, verdict reaches Splunk | DemoBot live integration → HEC | Works today |
| 2 | **Operationalize** — signal becomes an ES detection | TA ships 3 registered detections | Detection ships; the *Detection Builder agent* is a separate ES entitlement |
| 3 | **Alert** — Finding on risk threshold | Correlation rule + ES risk rule | Works; see §5 for which raises the Finding |
| 4 | **Triage** — agent dispositions the Finding | Post-deploy enables it | Needs ES 8.6 + Premier + Cloud + paired SOAR |
| 5 | **Investigate** — AI IR Plan auto-applies | Response plan asset + investigation type | **No SOAR required** |
| 6 | **Respond** — containment executed | Simulated response actions | Real SOAR optional; see §4 |
| 7 | **Resolve** — close with audit trail | ES investigation + action audit records | Works |
| 8 | **Improve** — detection tuning | Post-Incident phase tasks | Manual; the *Detection Builder agent* is a separate entitlement |

Steps 4 and 6's *agents* depend on stack entitlements, not on these artifacts. Everything the artifacts control is covered.

---

## 2. Artifact responsibilities

The split is not stylistic — it follows from two hard constraints.

**Splunk Cloud apps cannot create indexes**, so `indexes.conf` cannot ship. **Conf layering is per-app**, so the TA cannot override a saved search owned by `SA-ThreatIntelligence` or settings owned by `missioncontrol` — a same-named stanza in the TA creates a *new* object in the TA's namespace instead.

### 2.1 The tarball — `TA-gen_ai_cim-1.5.0.tgz`

| Ships | Detail |
|---|---|
| Normalization | `gen_ai:json` search-time field extraction into the `gen_ai.*` CIM |
| Detections | 3 `AI Governance - *` rules, registered ES correlation searches. `Prompt Injection Attack Correlation` ships **enabled** (v1.6.2+, the documented exception); the other two ship `disabled = 1` per repo convention |
| Response actions | `ai_defense_suspend_user`, `ai_defense_revoke_session`, `ai_defense_tighten_guardrail` |
| Response plan asset | `default/data/response_plans/ai_incident_response_plan.json` |
| Identities | `medadvice_identities.csv` / `medadvice_assets.csv`, registered as ES asset/identity sources |
| Ingest contract | Documented in `README.md` — HEC `/services/collector/event` |

### 2.2 The post-deploy script — `tools/show_postdeploy.py`

Excluded from the tarball (`package.sh` drops `tools/`). Run it after the TA is installed.

Since the TA seeds Mission Control on its own (the shipped search *GenAI - ES - Seed Response Plan and SOAR Binding* runs `| genaiseedes` hourly and on startup, using the ES/SOAR pairing proxy for the SOAR half), steps 4–7 and 10–12 below are the **same code** (`bin/genai_es_seed.py`) run from outside with explicit credentials. Running the script still matters for a demo stack: it applies everything immediately, it can install the simulator app on SOAR (in-product that needs a `soar` account in `ta_gen_ai_cim_account.conf`), and steps 1–3, 8, 9 and 13 exist nowhere else.

| Step | Why it cannot be in the tarball |
|---|---|
| 1. Create `gen_ai_log` | Cloud apps cannot ship `indexes.conf` |
| 2. Create HEC token | Provisioning, not app content |
| 3. Enable the 3 detections | The primary correlation rule ships enabled (v1.6.2+); the other two ship disabled by design. The step is idempotent |
| 4. Seed the response plan | `missioncontrol` KV namespace |
| 5. Investigation type → plan | `missioncontrol` KV namespace |
| 6. Create the AI findings queue | `missioncontrol` KV namespace |
| 7. `ai_triage_enabled = 1` | `missioncontrol` conf namespace |
| 8. Demo timing | Partly TA-owned, partly `SA-ThreatIntelligence`-owned — and TA-owned demo tuning must not ship to real customers |
| 9. Verify | — |
| 10. Install the simulated **MedAdvice Identity Provider** SOAR app (source ships in `default/data/soar_apps/`) | Lives on the paired SOAR, not in Splunk; the ES pairing proxy has no install route, so this needs SOAR credentials (`--soar-url` + `$SOAR_PASSWORD`/`$SOAR_AUTH_TOKEN`) |
| 11. Create its `medadvice_idp` asset | Same |
| 12. List the competing identity assets (read-only) | The demo-mock Okta/Azure/LDAP assets fail for MedAdvice users; deselect them in ES → *Security AI Assistant settings* → Guided Response connectors. The script never edits foreign assets (`POST /rest/asset/<id>` re-saves the whole record and ignores `disabled`) |
| 13. Smoke test (`--soar-smoke-test`) | Runs test connectivity / get user / disable user for `t.nguyen` on a scratch container and closes it |

Steps 10–13 run **first** so that step 4 can turn the plan's `suggestions.soar_binding[]` entries into real task actions with that tenant's app/asset ids. Without SOAR credentials step 4 drops the binding and preserves whatever actions/playbooks the live record already carries per task.

```bash
export SPLUNK_ADMIN_PASSWORD='...'
export SPLUNK_ACS_TOKEN='...'
export SOAR_PASSWORD='...'
python3 tools/show_postdeploy.py --stack https://esp-shw-xxxx.splunkcloud.com \
    --soar-url https://sor-xxxx.soar.splunkcloud.com --dry-run
```

Drop `--dry-run` to apply. It is idempotent — re-running updates in place. `--soar-only` runs steps 10–13 alone.

> **Verification status.** Steps 3, 4 and 8 use endpoints confirmed against a live ES 8.6 stack; steps 5, 6 and 7 were corrected against the `missioncontrol` Python data models and REST handlers (not `collections.conf`). Steps 1 and 2 are built from Splunk's documented ACS API and were **not** executed end-to-end. Steps 10–13 were executed end-to-end on a SOAR Cloud 8.6.0 tenant paired with ES 8.6 (2026-09-03), and the task-action record step 4 writes was validated against the `missioncontrol` `Action` model. Run `--dry-run` first and read the per-step report.

### 2.3 DemoBot

Streams live over HEC. The spray toggle is specified in `demobot-spray-attack-spec.md` — **specification only, no implementation.**

---

## 3. Deployment order

1. Provision the Show instance — ES 8.6, **Premier**, SOAR paired *(steps 4 and 6 need this; 1–3, 5, 7 do not)*.
2. Install `TA-gen_ai_cim-1.5.0.tgz`.
3. Run `show_postdeploy.py`; it prints the HEC endpoint and token.
4. Point DemoBot at that token.
5. Fire one spray to warm the demo, confirm a Finding appears, then reset.

---

## 4. Response actions — simulated by default

The three AI Defense response actions **call nothing externally**. Each records a structured audit event in `gen_ai_log` under sourcetype `ai_cim:response:action` carrying `"simulated": true`, and reports success.

They exist so a stack with no paired SOAR still produces a real adaptive-response entry and a complete audit trail — indistinguishable on screen from a SOAR action, runnable both from a Finding and from a Containment task.

**Be straight about this with an audience if asked.** The `simulated` flag is in every record precisely so the distinction survives into the data.

With SOAR paired, the Containment tasks additionally carry real SOAR actions from the **MedAdvice Identity Provider** app in `tools/soar/` — `disable user` and `clear user sessions` — which is what the ES 8.6 Guided Response agent recommends and runs when asked to disable `t.nguyen`. That app is a simulator too (no directory, no network, `"simulated": true` in every result); it exists because the demo tenant's mock Okta/Azure/LDAP assets fail for the MedAdvice personas. The ES-side steps (plan action, finding next steps, agent settings) are in `es-guided-response-runbook.md`.

Audit trail:

```
index=gen_ai_log sourcetype=ai_cim:response:action
| table _time, action_label, target_type, target, status, simulated, executed_by, execution_id
| sort - _time
```

---

## 5. Demo timing

Verified against ES 8.6 / Splunk Cloud 10.2.

### 5.1 The chain

| Stage | Latency | Owner |
|---|---|---|
| DemoBot turn → HEC → indexed | seconds | DemoBot |
| Correlation rule fires | 0–60s after tuning (`cron */1`) | TA — tuned by post-deploy |
| Finding raised | immediate — rule sets `action.notable = 1` | TA |
| Triage distributor picks it up | 0–30s (`interval = 30`, already default) | `missioncontrol` |
| Triage agent reasons | tens of seconds | LLM |

**Realistic end to end: 60–90 seconds.** Not 30 — Splunk's cron granularity is one minute, so no scheduled detection can fire faster.

### 5.2 Bypass the RBA hop for the live loop

`Risk - 24 Hour Risk Threshold Exceeded - Rule` searches `-2h@h` → `-10m@m`. That `-10m@m` bound makes recent events invisible for ten minutes — an unavoidable floor if the Finding depends on it.

The correlation rule already sets `action.notable = 1` and raises the Finding itself, so **drive the live demo off the correlation rule.** Post-deploy also sets the risk rule's `latest` to `now` and its cron to `*/1` (skip with `--keep-risk-timing`), which pulls the RBA narrative into the fast loop too.

Risk math for the narrative: threshold is `100`, each blocked injection carries `risk_score: 60` — **two events cross it**; the default 15-event spray gives 900.

### 5.3 The suppression trap

The correlation rule ships:

```
alert.suppress = 1
alert.suppress.fields = actor
alert.suppress.period = 86400s
```

**One finding per actor per 24 hours.** Rehearse twice as `t.nguyen` and the second run silently produces nothing — no error, no finding. Post-deploy step 8 disables it. If you configure a stack by hand, do not skip this.

---

## 6. Manual fallback

If the Show Template cannot run arbitrary post-deploy scripts, these are the equivalent manual steps. Order matters.

1. **Create index `gen_ai_log`** — Settings → Indexes, or ACS.
2. **Create a HEC token** — default index `gen_ai_log`, default sourcetype `gen_ai:json`. Record the token.
3. **Enable the detections** — ES → Security content → Content management, search `AI Governance`. `Prompt Injection Attack Correlation` is already enabled (v1.6.2+); enable the other two.
4. **Tune the primary detection** — on `AI Governance - Prompt Injection Attack Correlation - Rule`: cron `*/1 * * * *`, earliest `-15m`, latest `now`, and **turn throttling/suppression OFF**.
5. **Tune the risk rule** *(optional)* — `Risk - 24 Hour Risk Threshold Exceeded - Rule` in `SA-ThreatIntelligence`: latest `now`, cron `*/1 * * * *`.
6. **Create the response plan** — ES → Security content → Response plans → Create. Transcribe the four phases and fifteen tasks from `default/data/response_plans/ai_incident_response_plan.json`, including the seven embedded searches (`suggestions.searches`) and, with SOAR paired, the two Containment task actions (`suggestions.soar_binding` → MedAdvice Identity Provider `disable user` / `clear user sessions`). *(Tedious — the script exists for this reason.)*
7. **Create the investigation type** and associate the response plan, so it auto-applies.
8. **Create a queue** for AI findings.
9. **Enable the Triage agent** — ES → Configure → All configurations → Security AI Assistant settings; turn on AI triage and enable it for `AI Governance - Prompt Injection Attack Correlation - Rule`.
10. **Point DemoBot** at the HEC token.

Steps 1–4 and 10 are the minimum for a working demo of steps 1–3. Steps 6–7 add step 5. Step 9 adds step 4.

---

## 7. Demo runbook

1. **Set the scene** — ES Analyst Queue, empty. Show the detection in Content management: ATLAS `AML.T0051`, OWASP-LLM `LLM01`.
2. **Fire the spray** — flip the DemoBot toggle.
3. **Show the raw verdicts** — `index=gen_ai_log enduser_id="t.nguyen"`; point out `guardrail_ids: ["cisco_ai_defense"]` and `policy_blocked: true`.
4. **Wait ~60–90 seconds** — the raw-events search fills this naturally.
5. **Finding appears** in the queue, attributed to `t.nguyen` — the identity lookup ships `t.nguyen` and `x.collins`, so entity attribution resolves.
6. **Triage agent disposition** — rationale and recommended next steps, grounded in the AI IR Plan.
7. **Escalate to an Investigation** — the AI IR Plan auto-applies via the investigation type.
8. **Work Identification** — especially *Review prompts that were NOT blocked*: the ~15% that got through are why this escalates rather than closing.
9. **Run Containment actions** — Suspend User, Revoke Session, Tighten Guardrail. Show **View results**.
10. **Close it out** — show the audit trail from §4.

---

## 8. Known gaps

| Gap | Impact | Mitigation |
|---|---|---|
| ACS and `missioncontrol` KV writes not executed end-to-end | Steps 1, 2, 5, 6 unproven | `--dry-run`, read the per-step report, §6 fallback |
| The plan's SOAR actions are bound per tenant | `app_id`/`asset` are SOAR ids, so the seed carries `soar_binding` and needs SOAR credentials at post-deploy time to become real actions | Run with `--soar-url`; or attach the action once in the ES plan editor — re-runs without SOAR credentials preserve it |
| Response actions are simulated | Not real containment — both the `ai_defense_*` adaptive responses and the MedAdvice IdP SOAR app | By design; `"simulated": true` in every record |
| Triage and Guided Response agents need Premier + Cloud + SOAR | Steps 4 and 6 blocked on entitlement | Provision accordingly; the rest of the flow is unaffected |
| 60–90s, not 30s | Live pacing | Cron floor is 1 minute; fill with the raw-events search |
