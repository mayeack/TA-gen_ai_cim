# ES runbook — the Guided Response agent inactivates `t.nguyen` (per-tenant prerequisites)

What still has to happen outside the TA for the Agentic Trust workshop's
"inactivate the account" moment, now that the package configures itself. The
TA ships the finding's next steps and recommended actions as conf, and the
shipped search **GenAI - ES - Seed Response Plan and SOAR Binding** runs
`| genaiseedes` hourly and on startup to seed Mission Control and bind the
response plan's Containment tasks to the simulated **MedAdvice Identity
Provider** SOAR app. Nothing here touches a real directory: every action the
agent runs returns `"simulated": true`.

Stack: `stg-shw-051e9803c1c971.stg.splunkcloud.com` (ES 8.6, paired with SOAR
`sor-shw-16b02b7abdc021.soar.stg.splunkcloud.com`).

## What is automatic (no action needed)

| Done by | What |
|---|---|
| Conf on the detections | Finding **Next steps** (containment standard + the SOAR action to run) and **Recommended actions** on all three AI Governance rules |
| `\| genaiseedes` (hourly, on startup) | Response plan *AI Incident Response Plan* with the two Containment task actions bound, investigation type `ai security incident` → plan, queue *AI Findings*, `medadvice_idp` asset on SOAR (when the app is there) |
| `tools/show_postdeploy.py --soar-only` (already run on this SOAR, 2026-09-03) | The simulator app itself (id 198) and its asset (id 34); smoke test passed |

`| genaiseedes dry_run=true` in the search bar shows the per-step report without
writing.

## E1. Agent settings (per tenant, once)

1. **Configure → All configurations → Security AI Assistant settings.**
   AI Assistant **on**. *Model choice*: the **non-SecA1** (Frontier) option —
   the Guided Response agent is not available under SecA1. In the Guided
   Response connector list, confirm **MedAdvice Identity Provider** is selected
   (new connectors are added automatically on install) and **deselect Okta,
   Azure AD Graph and AD LDAP**: their assets on this tenant run in demo mock
   mode and answer *"No data found for app/action/parameter"* for every
   MedAdvice user, so the agent must not be able to pick them. (They stay
   installed on SOAR — SOAR has no REST-safe way to switch an asset off, and
   the TA never edits foreign assets.)
2. **Configure → All configurations → Triage agent → Detections.**
   `AI Governance - Prompt Injection Attack Correlation - Rule` is on. On a new
   tenant, either flip it here or set `enable_triage_agent = true` in
   `local/ta_gen_ai_cim_es.conf` and let the next `| genaiseedes` run do it
   (needs the `allow_ai_triage` entitlement: ES 8.6 Premier, Platform 10.1+,
   AWS Cloud, paired SOAR).

## E2. Simulator app on a new SOAR tenant (once per tenant)

Pick one:

- `python3 tools/show_postdeploy.py --soar-only --soar-url https://<tenant>.soar.splunkcloud.com --soar-smoke-test`
  with `$SOAR_PASSWORD` or `$SOAR_AUTH_TOKEN` exported (dry-run first).
- Create a `soar` account in the TA (`local/ta_gen_ai_cim_account.conf`:
  `url`, `auth_type = token`; the automation token stored as the account
  password through the account REST handler) and set
  `install_simulator = true` in `local/ta_gen_ai_cim_es.conf`; the next
  `| genaiseedes` run installs the app and creates the asset.
- SOAR UI: *Apps → Install App* → upload `tools/soar/dist/medadvice_idp.tgz`
  (from `tools/soar/build.sh`) → *Configure New Asset* named `medadvice_idp`.
  The next `| genaiseedes` run binds the plan tasks.

## E3. Verify the seeding (2 min)

- Search bar: `| genaiseedes dry_run=true` → every row `OK` or an expected
  `SKIP` (`triage agent` when off, `SOAR simulator app` on a tenant without
  the app).
- **Security content → Response plans → My organization's response plans →
  AI Incident Response Plan → Containment**: task 1 *Inactivate the offending
  identity's account* shows the `disable user` action, task 2 shows
  `clear user sessions`. *⋮ → Export* the plan once and hand the JSON back: it
  confirms whether ES keeps `$user$` in action parameters. If it does not, the
  agent and the analyst supply the username at run time — the simulator
  rejects an unsubstituted token rather than "disabling" it.
- **Configure → Findings and investigations → Investigation types →
  `ai security incident`**: *AI Incident Response Plan* listed first.
- Open the correlation detection → *Adaptive response actions → Create a
  finding*: **Next steps** and **Recommended actions** are populated from conf.

## E4. Demo timing (workshop stacks only)

The correlation rule ships `alert.suppress.period = 86400s` per actor: a
`t.nguyen` finding already exists today, so with suppression on the next spray
produces nothing. `tools/show_postdeploy.py` step 8 turns it off (`alert.suppress
= 0`, cron `*/1`, `-15m` window); by hand: detection → *Throttling*.

## E5. Permissions (1 min)

The attendee role needs `edit_tokens_own`, `edit_tokens_all` and
`edit_correlationsearches` for the sparkle chat. No SOAR change is needed: the
pairing account `es_soar_integration_user` is a SOAR Administrator and asset
approvals are off.

## E6. Dry run (10 min)

1. DemoBot → toggle the **Prompt-Injection Spray** (Lab 4.1.2). Within ~90 s a
   fresh **GenAI Prompt Injection Attack: t.nguyen (critical)** finding appears
   with the shipped next steps; the Triage Analysis panel renders.
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
   deselect the MedAdvice connector → agent cannot run it (re-select).

## Rollback

- ES: set `seed_response_plan = false` (or disable the seed search) in
  `local/`, then delete the plan, the investigation type association and the
  queue in the UI if wanted; existing findings and investigations are
  unaffected. The finding next steps revert with the TA version.
- SOAR: delete the `medadvice_idp` asset and the *MedAdvice Identity Provider*
  app; re-select the other connectors in the ES Guided Response list.
