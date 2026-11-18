# Lab 5 runbook — Cisco Identity Intelligence on a room stack (TA-gen_ai_cim 1.8.0)

AI Trust Lab 5 ("Verify: Cisco Identity Intelligence") on one Splunk Show room
stack: Cisco Identity Intelligence (CII) reports the room's victim persona as
taken over, PseudoCo Assistant 4.23.0+ refuses the victim's signed-in turns,
Splunk ES joins the CII failed checks with Cisco AI Defense blocks, and SOAR
disables the victim in Duo. Everything Lab 5 adds to the TA ships **off**; this
runbook turns it on for one stack and off again.

Run it from a checkout of the TA (`tools/` is not in the package). One run per
room stack. Never on a customer stack.

The Cisco Duo feed (TA-gen_ai_cim 1.9.0) is set up and removed by two more
commands of the same script, `--duo` and `--duo-teardown`, described after
`--lab5` below. They are separate runs, with their own keys.

## Before the takeover (T-4 at the latest)

1. **Cisco Security Cloud app** 3.7.3+ (3.x) or 4.1.3+ (4.x) on the stack.
2. **CII input** in that app: *Cisco Identity Intelligence → Configure
   Application*, connection method **Webhook**, index
   `cisco_identity_intelligence` (step L1 below creates it; run `--lab5` first
   if it does not exist yet). In Identity Intelligence, assign the webhook to
   **MFA Flood** and **Impossible Travel**,
   and run its connectivity test: a `WebhookTest` event must arrive (the TA
   drops it from the detection on purpose). Those two are the only checks
   the TA counts (`genai_cii_takeover_check_ids`, by check ID: `mfa-flood`,
   `impossible-travel`), the same two PseudoCo Assistant's Identity Risk Gate
   refuses. A bypass-code or weak-MFA failure, which every persona gets after
   a handout code, never raises the finding. The webhook is optional since
   2026-11-16: the rule also reads the failing checks PseudoCo Assistant
   records on every signed-in turn (`genai_cii_gate_failed_check_rows`).
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

## `--duo` (per stack that polls Duo)

The Cisco Duo feed of TA-gen_ai_cim 1.9.0: Duo's own authentication log in
index `duo`, the Duo rule and the joined rule. One run per stack that is to
hold the feed, once the TA is installed and the stack has restarted (splunkd
registers the input scheme when it starts). Which stacks get the feed is
decided elsewhere; the script only has to be told how often *this* stack polls.

```bash
export SPLUNK_ADMIN_PASSWORD='...' SPLUNK_ACS_TOKEN='...'
export DUO_LOG_FEED_API_HOST='api-XXXXXXXX.duosecurity.com'
export DUO_LOG_FEED_IKEY='...'
python3 tools/show_postdeploy.py --stack https://<stack>.splunkcloud.com \
    --duo --duo-poll-slot <K>/<N> --dry-run
```

Drop `--dry-run` once the report reads right. A dry run makes every read,
searches included, and prints each write instead of sending it.

**The keys.** They are the **read-only** Admin API application (*Grant read
log* and *Grant resource - Read*), never the Identity Ops keys that `--lab5`
uses. The **secret key** is not on the command line and not in a file. Leave
`DUO_LOG_FEED_SKEY` unset and the script asks for it at a hidden prompt, at the
moment it creates the account; or export it (or name another variable with
`--duo-skey-env NAME`) for an unattended run. No part of it is printed, the
hostname and the integration key are printed masked, and a dry run never asks
for it. The script verifies the stack's certificate on port 8089 before it
sends anything and stops if it cannot. If a private CA signed that
certificate, pass `--duo-ca-file PATH` with the CA's certificate (PEM): it is
trusted for the stack only, beside the default roots, whichever Python runs
the script. The `SSL_CERT_FILE` variable is not a way in (Apple's Python
ignores it, Splunk's launcher overwrites it, and where it is read it replaces
the roots ACS needs). `--duo-no-tls-verify` switches verification off as a last
resort, and the run then says that the key and the admin password go to a
server that was not authenticated. Create one read-only application per delivery and
delete it in Duo afterwards: the key is stored on every stack that runs
`--duo`, and it opens the whole tenant for reading to anyone who administers
that stack.

**What the stack will hold.** The authentication input has no user filter, so
the stack indexes every sign-in of the whole Duo tenant, all users, with their
source addresses, and `splunker` may search them. Every run prints this before
its first step. Two more pieces are left out unless they are asked for,
because on a stack that polls only the lab tenant they add the tenant owner's
own record to what the room can read:

- `--duo-with-users` creates the users input: the tenant's user list (names,
  email addresses, status), daily. Without it *Identity Activity* reads
  `no snapshot in range` for Duo status and the snapshot panel of *Duo
  Identity Feed* stays empty; the rules do not use it.
- `--duo-with-lookup-gen` (needs `--duo-with-users`) enables the search
  *GenAI - Identity - Duo Identity Lookup Gen*. On a lab-tenant stack it
  writes one row, the tenant owner's own Duo user, into a lookup every role
  can read.

A later run without these two flags leaves what an earlier run added as it is;
only the teardown removes it. `--duo-attendee-role ''` withholds the role's
access. The script never adds the Duo identity source (README, "Turning it
on", step 6).

**How often to poll.** Duo asks for no more than one log request a minute, and
every stack polls the same Duo tenant. `--duo-poll-slot K/N` says "this is
stack K, counting from 0, of the N stacks that poll": it polls every N minutes,
K minutes past, so no two stacks share a minute (N is 2, 3, 4, 5, 6, 10, 12,
15, 20 or 30; stack 3 of 20 gets the schedule `3,23,43 * * * *`). A single
stack can use `--duo-auth-interval 300` instead (seconds, 120 or more, or a
five-field cron schedule). One of the two is required: there is no default. To
change it later, run `--duo` again with the new value; nothing else is touched.
With a cron schedule, a poll slot included, the first poll (the backfill) runs
at the stack's next scheduled minute, not the moment the input is created;
with an interval in seconds it runs at once.

| Step | What it does |
|---|---|
| D0 | TA-gen_ai_cim 1.9.0+ is installed, its `ta_gen_ai_cim_duo` input scheme is registered and the stack serves the endpoint the inputs are created through; the run stops here, before any write, otherwise. Only a 404 reads as "not there": any other answer is reported as a read the stack refused or failed |
| D1 | index `duo` (ACS, searchable 90 days), then **waits** until ACS reports it; an existing index must keep the backfill plus 14 days |
| D2 | the Duo account `duo`, through the TA's account handler: hostname and integration key in the conf, the secret key in `storage/passwords` only |
| D3 | `splunker` may search index `duo`: `srchIndexesAllowed` only, never a default index (`--duo-attendee-role` names other roles, `''` none) |
| D4 | a note, read-only: whether `cim_Authentication_indexes` lets ES's own Authentication data model see index `duo`. It never holds the inputs back: the TA's two rules read the Duo events themselves |
| D5 | enables *AI Governance - Duo Authentication Fraud or Denial Burst - Rule* and *AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule*, and checks that each judges by index time on a slot exactly one cron period wide |
| D6 | creates the input `duo_authentication`, whose first poll reads the last 720 hours (`--duo-lookback-hours`); with `--duo-with-users`, `duo_users` first |
| D7 | read-only: the inputs are enabled, events by sourcetype, and a note on how many of them ES's Authentication data model returns |
| D8 | read-only: every burst and chain the two rules should have raised from what is indexed has its risk event (`N of N raised`), or which were never raised |

The order matters on a stack that is created after the scenarios were staged.
The first poll of `duo_authentication` brings the whole history in at once, and
a rule judges each event once, in the run after it is indexed, however old the
event is. So the rules are enabled **before** the input exists, and the input
is created only when:

- the index is there (events sent to a missing index are lost, and the input
  does not read them again);
- the index keeps the backfill long enough, and both rules are on with the
  schedule they ship with (`--duo-force` overrides these two). A rule's time
  range is the slot of index time one run judges, not how far back it reads
  events, so D5 never compares it with the backfill; it fails when the range
  is no longer exactly one cron period wide, for example when a catch-up range
  was left in;
- the index and the input's checkpoint agree. A checkpoint left behind on an
  empty index would skip the history, and events with no checkpoint would be
  indexed a second time; both are refused, with the way out printed. Where the
  search sees no event in the index, ACS has to agree that it is empty;
- no index delete is still under way. A `--duo-teardown --duo-purge-data`
  whose delete ACS has accepted but not carried out leaves a marker beside the
  checkpoints, and `--duo` creates no input while it is there (`--duo-force`
  does not override this): run that teardown again until it reports the index
  gone.

Every one of these checks refuses on an answer it cannot read: a read that
fails never lets an input be created.

**The first run against a stack is a dry run.** Nothing in this tool has run
against a real Splunk Cloud stack, ACS or Duo yet. A dry run makes every read
and no write, so it shows a refused endpoint with nothing changed. Note what
the first one reports for the three things only a real stack can answer: D0
(does the stack serve `data/inputs/ta_gen_ai_cim_duo` over REST), the
certificate on port 8089 (verified against the default roots, or which CA file
it needed), and D1 (ACS answers `404-index-not-found` for a missing index;
any other 404 is reported as an error and nothing is created).

A second run changes nothing and asks for no key. Run it again once the first
poll is in: D8 then dispatches each rule's own search in one pass over
everything indexed more than 20 minutes ago (15 for the joined rule), ad hoc,
so no alert action runs, and compares the findings it yields with the rule's
risk events by `burst_id` and `chain_id`. `never raised` means history was
indexed while the rule was off, or in a slot whose run failed: judge that index
time once more (README, "Judging history that is already indexed").

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

## T-1: is the staged Duo evidence in the stack?

Run `--duo` once more: its last step (D8) says whether every burst and chain
that is indexed was raised. The searches below show the same by hand, over the
last 30 days.

The authentication input reads up to 1000 events a run, oldest first, so a
tenant with more than that in the lookback needs one interval per 1000. How
far it has got:

```spl
| tstats count min(_time) as oldest_event max(_time) as newest_event max(_indextime) as last_indexed
    where `genai_duo_auth_events`
| eval oldest_event=strftime(oldest_event, "%F %T"), newest_event=strftime(newest_event, "%F %T"),
    last_indexed=strftime(last_indexed, "%F %T")
```

The victim's Duo sign-ins in ten-minute buckets, and how each bucket arrived:

```spl
`genai_duo_auth_events` event_type=authentication
| eval identity_user=`genai_identity_join_key(user)`, duo_class=`genai_identity_duo_class`
| search identity_user="<victim>"
| bin _time span=10m
| stats count(eval(duo_class=="denied" OR duo_class=="fraud")) as denied,
    count(eval(duo_class=="success")) as success, values(app) as app,
    min(_indextime) as first_indexed by _time
| eval arrived=if(first_indexed-_time>3600, "backfill", "live"),
    first_indexed=strftime(first_indexed, "%F %T")
| sort _time
```

Every staged burst must be listed; on a stack created after the staging they
all read `backfill`, with one `first_indexed`. Then the Duo rule's findings. A
finding's own time is when the rule raised it; the time of the sign-ins it is
about is `orig_time`, and `burst_time` and `burst_id` name the burst:

```spl
index=notable search_name="AI Governance - Duo Authentication Fraud or Denial Burst - Rule" user="<victim>"
| eval event_time=strftime(orig_time, "%F %T"), raised=strftime(_time, "%F %T")
| table event_time, raised, signature, failures, max_failures_10m, burst_time, burst_id
| sort event_time
```

One row per staged burst, `raised` at the backfill and `event_time` at the
staging. The joined finding (the burst, then the sign-in to PseudoCo Assistant,
then a blocked turn) has one row per staged sign-in:

```spl
index=notable search_name="AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule" user="<victim>"
| eval event_time=strftime(orig_time, "%F %T"), raised=strftime(_time, "%F %T")
| table event_time, raised, burst_time, signin_time, blocked_time, blocked_turns, signin_duo, chain_id
| sort event_time
```

No row there is expected while the stack holds no identity events of PseudoCo
Assistant for the victim: the Duo input backfills its history into a new
stack, the assistant's HEC feed does not. `tools/staged_resend.py` copies those
events into a stack that was created later (see "T-1: copy the staged
assistant events into the stack" below). Whether they are in the stack:

```spl
`genai_identity_activity_events`
| eval identity_key=`genai_identity_join_key(user)`
| search identity_key="<victim>"
| eval step=case('gen_ai.audit.action'=="identity_signin_success", "application sign-in",
    `genai_identity_verified_turn` AND 'gen_ai.policy.blocked'=="true", "verified turn, blocked",
    `genai_identity_verified_turn`, "verified turn, allowed")
| where isnotnull(step)
| stats count, min(_time) as first, max(_time) as last, max(_indextime) as last_indexed by step
| eval first=strftime(first, "%F %T"), last=strftime(last, "%F %T"), last_indexed=strftime(last_indexed, "%F %T")
```

The joined finding needs all three: a staged burst above, an
`application sign-in` less than 30 minutes after it, and a
`verified turn, blocked` within 60 minutes of that sign-in. No rows here means
the joined rule raises nothing on this stack and *Identity Activity* reads 0
for the victim's sign-ins and turns, whatever the Duo feed shows.

## T-1: copy the staged assistant events into the stack

PseudoCo Assistant sends each event once, to the HEC destinations it has at
that moment, so a stack created after the staging holds none of the victim's
application sign-ins or AI turns. `tools/staged_resend.py` copies them from the
Splunk that does hold them. `tools/staged-resend-runbook.md` is the full
procedure; in short:

1. **Once, after the staging:** `export` reads the staged events from the
   facilitator's Splunk into a bundle file, and `review --approve` records that
   you looked at what it holds. The bundle carries whole events, prompt text
   and client address included: keep it out of any repository.
2. **Per stack, after `--out` and `--duo` have run there:** `send` copies the
   bundle over HEC with each event's original time, host, source and text, and
   marks every copy with the indexed fields `resend`, `resend_bundle` and
   `resend_orig_indextime`. It refuses while the joined rule is off or the Duo
   half is not in the stack yet, sends one event first and continues only if
   that one arrived unchanged, and never sends an event the stack already
   holds.
3. **Then:** `verify` checks every copy and waits for the joined finding.

```bash
python3 tools/staged_resend.py send --bundle <bundle.json> --stack https://<stack>.splunkcloud.com --hec-file stack.json
python3 tools/staged_resend.py verify --bundle <bundle.json> --stack https://<stack>.splunkcloud.com
```

A copy cannot be taken back: the tool cannot delete from an index.

## T-1: is the spray that named the victim in the stack?

*Identity Activity* (TA-gen_ai_cim 1.9.0) counts a prompt-injection spray that
only names the victim as `claimed_not_verified`, beside the victim's verified
turns and never added to them. For the room to see that count above 0, on its
own stack:

1. **The staged scenario includes a spray that names the victim.** Sign-ins
   and signed-in turns alone leave the count at 0.
2. **PseudoCo Assistant's events for the staging are in this stack.** The
   assistant forwards an event once, to the HEC destinations it has at that
   moment. A stack created after the staging has none of them, so
   `claimed_not_verified`, `ai_turns` and `app_signins` all read 0 there for
   the staged days, whatever the Duo feed backfills, unless those events are
   sent to it as well. `tools/staged_resend.py` does that, once per event and
   with its original time, which matters here: the view counts events and
   does not drop a second copy.
3. **The victim has a Duo sign-in or an application identity event in the
   view's time range** (default: the last 14 days), and the spray falls in it
   too. A name that is only claimed gets no row.

```spl
`genai_identity_claimed_events`
| where `genai_identity_claimed_turn`
| eval identity_key=`genai_identity_join_key(user)`
| search identity_key="<victim>"
| stats count as claimed_not_verified, count(eval('gen_ai.policy.blocked'=="true")) as claimed_blocked,
    min(_time) as first, max(_time) as last
| eval first=strftime(first, "%F %T"), last=strftime(last, "%F %T")
```

Run it over the time range the room will use. `claimed_not_verified` 0 means
the stack holds no such turn in that range: no spray named the victim,
PseudoCo Assistant's events never reached this stack, or the spray is outside
the range. The *Activity timeline* then has no *AI turn claimed, not
verified* series either.

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

The Duo feed has its own teardown:

```bash
python3 tools/show_postdeploy.py --stack https://<stack>.splunkcloud.com \
    --duo-teardown --duo-purge-data --dry-run
```

It disables both rules and the lookup search (DT1), deletes the inputs (DT2),
deletes the account and makes sure its secret key is gone from
`storage/passwords` (DT3), takes index `duo` out of `splunker`'s searchable
indexes (DT4) and deletes the generated `ta_gen_ai_cim_duo_identities.csv`
(DT5; kept, with a failure, while an ES identity source still reads it or
while that could not be checked). It needs no Duo key.

DT4 changes only the roles the command line names. If the setup was run with
`--duo-attendee-role <role>`, pass the same option to the teardown: a role
that still lists index `duo` and was not named is reported as a failure and
left as it is, because the run cannot know who added the entry.

What happens to the data (DT6) is a choice the command line has to make:

- `--duo-purge-data` deletes index `duo` and the inputs' checkpoints. The
  index goes only if it holds nothing but `ta_gen_ai_cim:duo:*` events and no
  other input of the scheme writes to it (a hand-made input is not this
  tool's to delete; it is named, and the index stays). ACS deletes an index in
  the background and may restart the stack afterwards. The checkpoints are
  cleared only once ACS confirms the index is gone: until then the run ends
  with a failure, the checkpoints stay with a marker beside them, and `--duo`
  creates no input. Run the teardown again until DT6 reports the index gone.
- `--duo-keep-data` keeps both, so a later `--duo` resumes where the feed
  stopped.

Never one without the other: an index without its checkpoints is indexed twice
by the next `--duo`, and checkpoints without their index skip the history.
Afterwards (DT7), if anyone else could administer the stack, rotate the
read-only application's secret key in the Duo Admin Panel, and delete the
application in Duo when the delivery is over.

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
