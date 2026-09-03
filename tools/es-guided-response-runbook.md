# ES runbook — make the Guided Response agent inactivate `t.nguyen` (staging)

Stack-side steps for the Splunk Enterprise Security 8.6 half of the Agentic
Trust workshop's "inactivate the account" moment. The SOAR half (the simulated
**MedAdvice Identity Provider** app and its `medadvice_idp` asset) is applied by
`tools/show_postdeploy.py --soar-only`;
this document covers what has to be done in the ES UI, in order, with the exact
text to paste. Nothing here touches a real directory: every action the agent
runs returns `"simulated": true`.

Stack: `stg-shw-051e9803c1c971.stg.splunkcloud.com` (ES 8.6, paired with SOAR
`sor-shw-16b02b7abdc021.soar.stg.splunkcloud.com`).

## E1. Prerequisites (5 min)

1. **Configure → All configurations → Security AI Assistant settings.**
   AI Assistant **on**. *Model choice*: the **non-SecA1** (Frontier) option —
   the Guided Response agent is not available under SecA1. In the Guided
   Response connector list, confirm **MedAdvice Identity Provider** is selected
   (new connectors are added automatically on install) and **deselect Okta,
   Azure AD Graph and AD LDAP**: their assets on this tenant run in demo mock
   mode and answer *"No data found for app/action/parameter"* for every
   MedAdvice user, so the agent must not be able to pick them. (They stay
   installed on SOAR — SOAR has no REST-safe way to switch an asset off.)
2. **Configure → All configurations → Triage agent → Detections.**
   `AI Governance - Prompt Injection Attack Correlation - Rule` is on (it is —
   the Analysis panel already renders on today's findings).

## E2. Response plan — attach the SOAR action (10 min)

**Security content → Response plans → My organization's response plans → AI
Incident Response Plan → Containment.**

1. Expand task 1 (*Suspend the offending identity*). Rename it to:

   ```
   Inactivate the offending identity's account
   ```

   Replace its description with:

   ```
   Stop further attempts from this actor.

   **Containment standard:** 3 or more blocked prompt-injection attempts within 24 hours from one actor, with no authorized-testing record for that actor, means the account is inactivated pending review. The finding's `injection_attempts` and `policy_blocks` counts are the evidence; the note on this task is the review record.

   Run the attached SOAR action **MedAdvice Identity Provider -> disable user** with the username from the finding's `user` field (the actor). The result is recorded on this task and on the investigation's Automation tab, and `enable user` on the same app reverses it during Recovery.

   NOTE: the MedAdvice Identity Provider is a workshop simulator - every result carries "simulated": true and no directory is touched. On a stack without a paired SOAR, run the adaptive response action Suspend User (AI Defense) instead; it is equally simulated and records its audit entry in gen_ai_log under sourcetype ai_cim:response:action.
   ```

   Tick **Require a note upon task completion**.
2. Still in that task: **Actions → + Action** → App **MedAdvice Identity
   Provider** → Action **disable user** → `username`: try the token `$user$`
   first; if the picker rejects it or the dry run in E7 shows it unsubstituted,
   use `t.nguyen` → `reason`: `GenAI prompt injection containment - AI Incident
   Response Plan` → **Submit**.
3. Task 2 (*Revoke active sessions and API credentials*): **+ Action** → App
   **MedAdvice Identity Provider** → Action **clear user sessions** → same
   `username` → **Submit**. Replace its description with:

   ```
   Invalidate anything the actor could reuse, including tokens issued before the account was inactivated.

   Run the attached SOAR action **MedAdvice Identity Provider -> clear user sessions** for the same username. Repeat per session if the Identification phase found more than one application session.

   Without a paired SOAR, run the adaptive response action Revoke Session / API Key instead. The same "simulated": true caveat applies as for account inactivation.
   ```
4. Toggle **Status → Published**, then **Save changes**.
5. **⋮ → Export** the plan and hand the JSON back: it pins the exact
   `parameters` shape the seed writes (`tools/show_postdeploy.py` step 4) and
   confirms whether `$user$` is stored.

> The repo seed (`default/data/response_plans/ai_incident_response_plan.json`)
> now carries the same two actions as `soar_binding`, so a rebuilt stack gets
> them from `show_postdeploy.py` without this step. Re-running the script
> without SOAR credentials keeps whatever you attached here.

## E3. Investigation type (2 min)

**Configure → Findings and investigations → Investigation types →
`ai security incident`.** *AI Incident Response Plan* is listed first. If the
type is missing (the post-deploy script never ran on this stack), create it
with exactly that lowercase name and assign the plan.

## E4. Finding text — steer the agents (5 min)

**Configure → Content → Content management → GenAI - Prompt Injection Attack
Correlation → Edit → Adaptive response actions → Create a finding.**

- **Description**: keep the narrative and append:

  ```
  Containment standard: 3+ blocked injection attempts in 24h with no authorized-testing record -> inactivate the account pending review.
  ```

- **Next steps** (plain text; use *Insert Adaptive Response Action* for the
  fallback link in step 3):

  ```
  1. Review the raw prompts and sessions for the actor (Contributing events drill-down).
  2. Validate intent with the user's manager: authorized red-team or testing record?
  3. If repeat attempts and no authorization: inactivate the account via SOAR - MedAdvice Identity Provider -> disable user (username = the finding's user). Without SOAR, run Suspend User (AI Defense).
  4. Revoke the actor's active DemoBot sessions (MedAdvice Identity Provider -> clear user sessions, or Revoke Session / API Key).
  5. Record the disposition and rationale on the investigation.
  ```

- **Recommended actions**: add *Suspend User (AI Defense)*, *Revoke Session /
  API Key*, *Tighten Guardrail Policy*, plus any SOAR-backed action the list
  offers on this stack (note what is offered). **Save.** This writes the
  stack's `local/savedsearches.conf` and survives TA upgrades.

## E5. Throttling (1 min)

Same detection → **Throttling**: suppression must be **off** (the post-deploy
script sets `alert.suppress = 0`). A `t.nguyen` finding already exists today;
with suppression on, the next spray produces nothing.

## E6. Permissions (1 min)

The attendee role needs `edit_tokens_own`, `edit_tokens_all` and
`edit_correlationsearches` for the sparkle chat. No SOAR change is needed: the
pairing account `es_soar_integration_user` is a SOAR Administrator and asset
approvals are off.

## E7. Dry run (10 min)

1. DemoBot → toggle the **Prompt-Injection Spray** (Lab 4.1.2). Within ~90 s a
   fresh **GenAI Prompt Injection Attack: t.nguyen (critical)** finding appears
   with the E4 text; the Triage Analysis panel renders.
2. Finding → **Start investigation** → **Response** tab shows *AI Incident
   Response Plan*; the Containment task shows the `disable user` action.
3. Sparkle chat with the investigation selected:
   *How should I respond to the prompt injection attempt from t.nguyen?* →
   the recommendation names account inactivation via MedAdvice Identity
   Provider. Then *Disable user t.nguyen* → the agent proposes **MedAdvice
   Identity Provider → disable user (username=t.nguyen)**, asks for double
   confirmation, runs, and reports success with `simulated: true`.
4. **Automation** tab lists the run with its JSON; **Response** tab task →
   *Completed*; add the required note; set Disposition/Status.
5. Repeat step 3 as a second user: identical result, no reset needed.
6. Negative checks: Model choice → SecA1 → agent unavailable (switch back);
   SOAR asset `medadvice_idp` disabled → agent cannot run it (re-enable).

## Rollback

- ES: remove the two actions from the tasks in the plan editor; revert the
  detection's *Create a finding* text. Existing findings and investigations are
  unaffected.
- SOAR: delete the `medadvice_idp` asset and the *MedAdvice Identity Provider*
  app; re-select the other connectors in the ES Guided Response list.
