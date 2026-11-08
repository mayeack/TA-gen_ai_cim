# Lab 5 runbook — Cisco Identity Intelligence on a room stack (TA-gen_ai_cim 1.8.0)

AI Trust Lab 5 ("Verify: Cisco Identity Intelligence") on one Splunk Show room
stack: Cisco Identity Intelligence (CII) reports the room's victim persona as
taken over, PseudoCo Assistant 4.23.0+ refuses the victim's signed-in turns,
Splunk ES joins the CII failed checks with Cisco AI Defense blocks, and SOAR
disables the victim in Duo. Everything Lab 5 adds to the TA ships **off**; this
runbook turns it on for one stack and off again.

Run it from a checkout of the TA (`tools/` is not in the package). One run per
room stack. Never on a customer stack.

## Before the takeover (T-4 at the latest)

1. **Cisco Security Cloud app** 3.7.3+ (3.x) or 4.1.3+ (4.x) on the stack.
2. **CII input** in that app: *Cisco Identity Intelligence → Configure
   Application*, connection method **Webhook**, index
   `cisco_identity_intelligence` (step L1 below creates it; run `--lab5` first
   if it does not exist yet). In Identity Intelligence, assign the webhook to
   **MFA Flood**, **Impossible Travel** and **Duo Sign In Threat Detected**,
   and run its connectivity test: a `WebhookTest` event must arrive (the TA
   drops it from the detection on purpose). Those three are the only checks
   the TA counts (`genai_cii_takeover_checks`, by check ID: `mfa-flood`,
   `impossible-travel`, `duo-sign-in-threat-detected`). A bypass-code or
   weak-MFA failure, which every persona gets after a handout code, never
   raises the finding.
3. This must exist **before the T-2 takeover**: CII webhooks announce only
   newly failing users.

## `--lab5` (per room stack)

```bash
export SPLUNK_ADMIN_PASSWORD='...' SPLUNK_ACS_TOKEN='...' SOAR_PASSWORD='...'
export DUO_IDENTITY_OPS_API_HOST='api-XXXXXXXX.duosecurity.com'
export DUO_IDENTITY_OPS_IKEY='...' DUO_IDENTITY_OPS_SKEY='...'
python3 tools/show_postdeploy.py --stack https://<stack>.splunkcloud.com \
    --soar-url https://<tenant>.soar.splunkcloud.com \
    --lab5 --lab5-victim <victim persona> --lab5-room <workshop>-<room> \
    --out <room>-stack.json --dry-run
```

Drop `--dry-run` once the report reads right. The Duo keys are the **PseudoCo
Identity Ops** Admin API application (*Grant resource* read + write). They are
read from the environment only, never from argv, and only their last four
characters are printed.

| Step | What it does |
|---|---|
| L1 | index `cisco_identity_intelligence` (ACS) |
| L2 | HEC token `cisco-identity-intelligence` for a labelled backfill (planned, see T-1); written to `--out`, never printed |
| L3 | Cisco Security Cloud app version floor |
| L4 | enables the Lab 5 rule, the persona identity input and `seed_identity_response_plan` in the TA's `local/` on the stack |
| L5 | the CII index in `admin`/`ess_admin`/`ess_analyst` default indexes and searchable by `splunker` |
| L6 | installs/upgrades both SOAR apps: MedAdvice Identity Provider 1.1.0 (refuses Lab 5 identities) and PseudoCo Identity |
| L7 | creates or re-saves the `pseudoco_identity` asset: Duo host and keys, `victim_username`, room |
| L8 | smoke test: `get user <victim>` on a scratch container (read-only; never disables) |
| L9 | seeds the Compromised Identity Response Plan, binds its containment task to PseudoCo Identity, verifies |

`--out` writes a 0600 JSON file with the stack's HEC URL and tokens for the
PseudoCo Assistant Lab 5 setup tool.

## T-1: is the victim's evidence in the stack?

```spl
`genai_cii_failed_checks` | search identity_user="<victim>"
| table _time, cii_check, cii_trust_level, cii_provenance
```

At least one row for MFA Flood, Impossible Travel or Duo Sign In Threat
Detected; the query shows takeover checks only, like the rule. If CII never
sent it:

1. In CII *Check Results*, use the victim's **Send notification** for each
   failing check (CII re-sends the real event).
2. A **labelled backfill** from the CII API is planned, not built:
   `lab5-setup` has no command for it yet (it is spike S1's last option).
   Until it exists, a room whose webhook never arrived and whose
   *Send notification* does not help has no Lab 5 finding. When it lands, it
   writes into the same index, with `source=lab5-setup` and
   `"backfill": true` in the event body. The CII API gives no failure time,
   so each event carries the time it was written. The rule already accepts
   that shape, and the finding says `cii_provenance = backfill (lab5-setup)`.
3. Never synthetic events in a room stack. `"synthetic": true` is for test
   stacks only, and the finding labels it `synthetic test event`.

## Lab day

- The spray aimed at the victim raises **two findings**: the Lab 4
  prompt-injection correlation and the Lab 5 rule
  *GenAI Compromised Identity: `<victim>`*. Work the Lab 5 one. ES's 24-hour
  risk threshold (*Risk - 24 Hour Risk Threshold Exceeded - Rule*) may add a
  third, depending on the stack's RBA rule and the Risk data model's lag. On
  the ES 8.5.1 dry run (2026-11-06) it raised nothing, although the victim
  had 180 risk in 24 hours, so do not promise it.
- Containment prompt for the ES agent (Guided Response 8.6, AI SOC analyst 8.7,
  Triage and Response 8.8): *"Using PseudoCo Identity, disable user `<victim>`.
  Reason: `<investigation id>` compromised identity"*. If it picks the MedAdvice
  simulator, that app now fails with "managed by PseudoCo Identity".
- Verify: *PseudoCo Identity → get user* reads `disabled`, and the victim's
  PseudoCo Assistant sessions show the revocation banner
  (`identity_session_revoked`). *Unblock me* restores an attendee's app session
  but leaves Duo disabled; the finding's evidence is unchanged.
- Dashboard: *AI Governance → Dashboards → Compromised Identity*.

## Teardown

```bash
python3 tools/show_postdeploy.py --stack https://<stack>.splunkcloud.com \
    --soar-url https://<tenant>.soar.splunkcloud.com --lab5-teardown
```

It disables the rule, the persona input and the seed switch, and deletes the
`pseudoco_identity` asset with its Duo secret. Then, by hand: delete the
Security Cloud CII input (that unregisters the webhook) and confirm the target
is gone in Identity Intelligence **before** the stack is destroyed; revoke the
stack's CII API client; rotate the Identity Ops keys after the workshop.

## What the TA reads from PseudoCo Assistant 4.23.0

The identity fields are flat top-level keys. A nested `identity_risk` object
(the pre-release draft shape) is still read, as a fallback only.

| Event field | TA field | Notes |
|---|---|---|
| `guardrail_ids=["cisco_identity_intelligence"]`, `policy_blocked` | `gen_ai.guardrail.ids`, eventtype `gen_ai_identity_block` | excluded from the Lab 4 correlation |
| `identity_verified`, `identity_source` | `gen_ai.identity.verified`, `.source` | signed-in turns only |
| `identity_check` (`ok` / `unavailable`) | `gen_ai.identity.check` | `unavailable`: Duo or CII could not be asked, and the gate failed open |
| `identity_override=true` | `gen_ai.identity.override` | the attendee pressed *Unblock me* |
| `identity_risk` (`allow` / `block`) | `gen_ai.identity.risk.verdict` | the real verdict, also under an override |
| `identity_risk_reasons[]` | `gen_ai.identity.risk.reasons` | the gate's reason codes (`trust_untrusted`, `mfa_flood`, ...) |
| `identity_duo_status`, `identity_trust_level` | `gen_ai.identity.risk.duo_status`, `.trust_level` | present when the gate learned them |
| `identity_failing_checks[]` | `gen_ai.identity.risk.failing_checks` | the CII checks the user is failing |
| audit `identity_signin_success` / `_failure` | CIM Authentication: `action`, `user`, `src`, `dest` (HEC host), `authentication_service=duo` | eventtype `gen_ai_identity_authentication`, tag `authentication` |
| audit `identity_session_revoked`, `identity_unblocked`, `identity_reblocked` | `gen_ai.audit.action` | eventtype `gen_ai_identity_session` |
