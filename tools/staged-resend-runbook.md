# Staged events re-send runbook: copying a staged scenario into a stack created later

`tools/staged_resend.py` copies the PseudoCo Assistant events of one staged
scenario from the facilitator's Splunk into a Splunk stack that did not exist
when the scenario was staged. The Cisco Duo input backfills its own history
into a new stack; the assistant's HEC feed does not. Without this copy a late
stack has the Duo half of a takeover chain and none of the application half,
so the joined rule never raises its finding and *Identity Activity* shows no
application sign-ins or AI turns for the persona.

The copy is verbatim: each event keeps its text, time, host, source,
sourcetype, index and `log_type`, and gets three label fields that say it is a
copy (see [The label](#the-label)).

Run it from a checkout of the TA (`tools/` is not in the package). Dev-only
tooling, for room and test stacks. Never on a customer stack.

**Read this first.** A sent event cannot be taken back: the tool cannot delete
from an index (see [What cannot be undone](#what-cannot-be-undone)). Nothing in
it has run against a real Splunk Cloud stack, ACS or a real HEC; the first room
stack is the first real proof unless the scratch end-to-end has been run on a
dev Splunk first.

Contents: [the four commands](#what-it-does-in-four-commands),
[the order](#the-order-on-a-new-stack),
[secrets](#secrets-where-each-one-comes-from),
[`export`](#export-read-the-scenario-into-a-bundle-once),
[`review`](#review-read-what-will-be-sent-then-approve-it),
[`send`](#send-copy-the-bundle-into-one-stack),
[the label](#the-label),
[`verify`](#verify-prove-the-copy-and-the-finding),
[checking by hand](#checking-by-hand),
[what cannot be undone](#what-cannot-be-undone),
[deadlines](#deadlines),
[before the first room stack](#before-the-first-room-stack),
[one stack, start to finish](#one-stack-start-to-finish),
[what has not been proven](#what-has-not-been-proven).

| Word | Meaning here |
|---|---|
| facilitator's Splunk | the Splunk that received the scenario live, when it was staged. The source of the copy |
| stack | a Splunk Cloud (Splunk Show) stack created later. The target |
| persona | a lab identity such as `nina.osei`, from `lookups/pseudoco_identity_personas.csv` |
| host label | the `host` value the assistant's events carry (`l5-dev` for the dev copy), not a machine name |
| bundle | the file `export` writes: the events, their hashes and the expected results |
| ledger | the file `send` keeps beside the bundle: what was handed to which stack |
| canary | the one event `send` sends first and reads back before the rest |
| chain | Duo denial burst, then application sign-in, then blocked AI turn, for one identity |
| joined rule | *AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule*, which raises one finding per chain |

## What it does, in four commands

| Command | Reads | Writes | Where it runs |
|---|---|---|---|
| `export` | the facilitator's Splunk (port 8089), once | a bundle file, mode 0600 | the facilitator's Mac |
| `review` | the bundle | an approval stamp in the bundle | the facilitator's Mac |
| `send` | the bundle, the stack's port 8089 | events to the stack's HEC, a ledger beside the bundle | per stack |
| `verify` | the bundle, the ledger, the stack's port 8089 | nothing | per stack |

`export` is done once per scenario. `send` and `verify` read only the bundle,
so the facilitator's Splunk can be off at room time, and every stack gets the
same reviewed bytes.

Exit codes of every command: `0` all checks passed (or nothing to do), `1` a
check failed, `2` wrong usage or a refused input (nothing was sent), `3`
delivery unknown (something was sent and the tool cannot prove the stack took
it; see [Delivery unknown](#delivery-unknown-exit-3)).

## The order on a new stack

1. `show_postdeploy.py --stack <url> --out <stack>.json`: the index
   `gen_ai_log`, the HEC token, the base detections. `--out` is where `send`
   gets the HEC URL and token from.
2. `show_postdeploy.py --stack <url> --duo ...`: the Duo feed. It enables both
   Duo rules **before** it creates the input (`tools/lab5-identity-runbook.md`,
   `--duo`). Wait for the first poll, then run `--duo` once more and read its
   last step (D8).
3. `staged_resend.py send`: the copy.
4. `staged_resend.py verify`: the proof, and the finding.

`export` and `review` come before all of this, once, on the facilitator's Mac.

**Why this order.** The joined rule, *AI Governance - Duo Denial Burst to
Blocked AI Turn Correlation - Rule*, judges an event once, in the scheduled run
after the event is indexed, however old the event is. A chain (Duo denial
burst, application sign-in, blocked AI turn) is raised in the run that indexes
its last missing step. So the rule must be on and running before the last
piece arrives. Measured on the shipped rule text:

| What arrives, and when | Findings |
|---|---|
| Duo events and the copy in one 5-minute slot | 1 |
| Duo events first, the copy now | 1 |
| the copy first, Duo events now | 1 |
| sign-in record in an earlier slot, blocked turn now | 1 |
| blocked turn in an earlier slot, sign-in record now | 1 |
| the copy twice in one slot | 1, `blocked_turns` 1 |
| everything was indexed before the rule first ran | **0** |
| the copy only, no Duo events | **0** |
| the stack already had the events live, a copy arrives | 0 |
| only Duo's success record, or only an allowed turn, is new | 0 |

The rows with 0 in bold are the ones the order prevents. That is why `send`
refuses when the joined rule is off or has not run (step R5) and when the Duo
half of the sign-ins is not in the stack yet (step R6).

Other rules and the copy:

- The Duo rule, *AI Governance - Duo Authentication Fraud or Denial Burst -
  Rule*, reads Duo's events only. No order of sending reaches it.
- The prompt-injection rules judge by event time and need an event from the
  last 5 minutes. `send` refuses a bundle whose newest event is under 15
  minutes old, so a copy never raises them: a stack that gets the copy gets
  the chain finding, not the facilitator's prompt-injection findings.
- **The Lab 5 rule can fire.** *AI Governance - Compromised Identity AI Attack
  Correlation - Rule* reads AI Defense blocks of the last 24 hours by event
  time. If the copied blocked turns are under 24 hours old and Cisco Identity
  Intelligence evidence for the same persona arrives in that time, the Lab 5
  rule raises its own finding. That is correct behaviour, not a fault of the
  copy; expect it on a stack that has Lab 5 enabled.
- Scoring does not score a copy (it reads by event time), so the scoring
  dashboards stay empty for the copied turns.

## Secrets: where each one comes from

No option of `staged_resend.py` takes a secret, and no secret or part of one
is printed, written to the bundle or written to the ledger. Output, the ledger
and `--dry-run` show ids, hashes, times and counts only: never an event body,
an address or a Duo transaction id.

| Secret | Used by | Comes from |
|---|---|---|
| password or token of the facilitator's Splunk | `export` | `STAGED_RESEND_SOURCE_PASSWORD`, or `STAGED_RESEND_SOURCE_TOKEN` |
| admin password or token of the stack (port 8089) | `send`, `verify` | `SPLUNK_ADMIN_PASSWORD`, or `SPLUNK_ADMIN_TOKEN` |
| the stack's HEC token | `send` | the 0600 file named by `--hec-file`, or `STAGED_RESEND_HEC_TOKEN` together with `--hec-url` |

The two Splunk credentials have different names on purpose, so the
facilitator's password can never be sent to a stack, or a stack's to the
facilitator's Splunk.

Nothing ties `SPLUNK_ADMIN_PASSWORD` (or `SPLUNK_ADMIN_TOKEN`) to one stack:
`send` and `verify` send whatever it holds, as Basic or Bearer auth, to the
stack named by `--stack`. It must hold the password of **that** stack. Read it
at the start of each stack and unset it at the end, before the next stack, so
one stack's admin password is never sent to another.

**User names** are not secrets and are options. A password needs one:
`--source-username` on `export` and `--username` on `send` and `verify`, both
`admin` unless given (the same default as `show_postdeploy.py --username`). A
token needs no user name. If the stack's admin account is not called `admin`
and `--username` is left out, step R3 stops with HTTP 401 before anything is
sent.

**The HEC file** is the one `show_postdeploy.py --out` writes: mode 0600, with
`hec_url`, `hec_token`, `index` and `sourcetype`. `send` refuses it unless it
is 0600, holds `hec_url` and `hec_token`, names the bundle's index, and its
HEC host belongs to the stack given by `--stack` (step R2). A file written by
a `--lab5` run holds the Cisco Identity Intelligence backfill token; `send`
refuses it and says that this is what it was given.

**Known gap in `--out`.** On a real Splunk Cloud stack the current
`show_postdeploy.py` may write no file: its HEC step reads the token from a
place where ACS does not put it. It then prints `No HEC token returned`. Until
that step is fixed (a later change, not part of this tool), take the token of
the HEC input `demobot-ai-defense` from the stack and use the second form:

```bash
read -rs STAGED_RESEND_HEC_TOKEN && export STAGED_RESEND_HEC_TOKEN
python3 tools/staged_resend.py send --bundle ... --stack ... \
    --hec-url https://http-inputs-<stack>.splunkcloud.com/services/collector/event
```

`read -rs` keeps the token out of the shell history and off the screen. Always
run `show_postdeploy.py` with `--out`: without it, a token it does find is
printed in full.

**Certificates.** Every connection is verified by default, and the override is
named in the output whenever one is used:

| Connection | Verified against | Override |
|---|---|---|
| the facilitator's Splunk (`export`) | the system trust store, or `--ca-file` | `--no-verify-source`; a loopback address (`127.0.0.1`, `localhost`) is not verified |
| the stack's port 8089 (`send`, `verify`) | the system trust store, or `--ca-file` | `--no-verify-splunkd` |
| the stack's HEC (`send`) | the system trust store, or `--ca-file` | none: the HEC token goes unverified only to a loopback address |

`--ca-file` names a CA bundle that is trusted in addition to the system trust
store. On `send` it applies to the stack's port 8089 and to its HEC alike, on
`verify` to port 8089. `show_postdeploy.py` does not verify port 8089 outside
its `--duo` mode, so a stack that it configured without complaint can still be
refused here: then pass the stack's CA with `--ca-file`, or name the risk with
`--no-verify-splunkd`.

Plain `http://` is refused for every address that is not loopback. A redirect
(any 3xx) from a Splunk server is a failed call and is never followed: a
followed redirect would carry the password to another server.

## `export`: read the scenario into a bundle (once)

```
staged_resend.py export --source URL --host H --persona P --from ISO --to ISO --bundle PATH
    [--source-username admin] [--index gen_ai_log] [--event-source demobot:hec]
    [--exact-window] [--allow-partial-session] [--allow-unlisted-persona]
    [--check-logs DIR] [--list-only] [--no-verify-source | --ca-file P]
```

Nothing is guessed: the operator names the host label, the persona and the
window. The index `gen_ai_log` and the source `demobot:hec` are defaults, and
the run prints them.

| Option | Meaning |
|---|---|
| `--source` | the facilitator's splunkd, its **management** port (8089 unless changed), not Splunk Web |
| `--host` | the `host` label the staged events carry; repeatable |
| `--persona` | the persona's short name (`nina.osei`); repeatable |
| `--from`, `--to` | ISO-8601 with a UTC offset or `Z`, whole seconds; `--to` is exclusive; at most 7 days apart |
| `--bundle` | where to write the bundle; the path must not exist. Not needed with `--list-only` |
| `--index` | the index the events are in, and will be sent to: `gen_ai_log`. Another index is for the scratch rehearsal only |
| `--event-source` | the `source` the assistant's HEC forwarder sets: `demobot:hec` |
| `--check-logs DIR` | also compare every event with the assistant's own JSONL log in `DIR` |
| `--list-only` | print the selection and the census and stop; no bundle is written |

Not sure of the window? Run it with `--list-only` first and read the census:
it counts what lies before, in and after the window, on the selected host and
on others, for the selected persona and for other identities, and it names
nobody else.

**Worked example**, the scenario staged on 16 Nov 2026 by persona `nina.osei`
on the dev copy whose events carry `host=l5-dev`:

```bash
read -rs STAGED_RESEND_SOURCE_PASSWORD && export STAGED_RESEND_SOURCE_PASSWORD
mkdir -p -m 700 ~/staged-bundles
python3 tools/staged_resend.py export --source https://127.0.0.1:8089 \
    --host l5-dev --persona nina.osei \
    --from 2026-11-16T21:05:00-08:00 --to 2026-11-16T21:37:00-08:00 \
    --check-logs <assistant checkout>/logs \
    --bundle ~/staged-bundles/nina-takeover.bundle.json
```

What a good run reports for this set:

- the census of everything near the window: 4 eligible `demobot:audit` events
  and 5 eligible `gen_ai:json` events of the selected persona on the selected
  host, plus 5 `genai_scoring` events with no `log_type` and no user, which
  are counted and never copied;
- 9 events selected, 9 distinct ids, times `1794891919.556` to
  `1794893804.201`, about 22 KB of event text;
- every event's SHA-256 as Splunk computed it equal to the one computed
  locally, and with `--check-logs`, `9 of 9` equal to the assistant's log;
- the bundle id, of the form `rs-20261117-3f9a1c2b7d4e`: the UTC date of the
  first event and the first 12 characters of the content digest. Exporting
  the same selection again gives the same id.

**What is eligible.** An event is copied only if all of this holds: it carries
the indexed field `log_type` (`governance`, `audit`, `escalation` or `error`);
its source is the assistant's; its text starts with exactly one of the keys
`audit_id`, `escalation_id`, `event_id`; its sourcetype is not a scoring one;
it carries no re-send label and is not itself a copy; it is older than 15
minutes; and its `_time` equals the `timestamp` in its body by the forwarder's
own rule. Error records carry an `event_id` and are copied like the rest.

The persona is matched in Python on the parsed body (`enduser_id`, else
`user`, lowercased, the part before `@`), never by an SPL extraction, because
the field can sit deep in a long event. The match is exact, so a spray actor
whose name is a persona name followed by a sentence is never selected. A
persona must be a lowercase dotted name such as `first.last`, must not start
with `l5-` (participant accounts are never copied) and must be in
`lookups/pseudoco_identity_personas.csv`, which lists seven personas.

**The bundle** is one JSON file created at mode 0600. It holds the events'
whole text, which means **prompt and answer text and the client address of
whoever staged the scenario**, plus the selection, the census, a SHA-256 per
event, the expected results (`expect`) and counts of what is sensitive
(`privacy`). It holds no credential. Keep it in a folder only you can read,
outside any git work tree and any synced folder, and delete it when the last
stack is done.

**What `export` refuses.** A refusal exits 2 and writes no bundle.

| Refusal | Why | Override |
|---|---|---|
| the bundle path already exists, is a symbolic link, lies inside a git work tree, or its folder does not exist | event text must never land in a file someone else can read, in a tracked file or in the package; checked before any text is read | none: name a new path elsewhere |
| `--from` or `--to` has no offset, has a fraction of a second, `--to` is in the future, or the two are over 7 days apart | a naive time is ambiguous; the two searches that read the window cut a fraction differently; a scenario is staged first and exported afterwards | none |
| the persona is not in `lookups/pseudoco_identity_personas.csv` | a typo would export nothing, or someone else | `--allow-unlisted-persona` (the name rules above still apply) |
| no event of the persona lies in the window | nothing to export | none: check `--host`, `--persona` and the window with `--list-only` |
| an event of the persona in the window is not eligible (see *What is eligible* above) | the scenario would be copied with a hole in it | none |
| Splunk's census and the tool's own count of eligible events disagree | an event would be left out or added without anyone seeing it | none |
| an event of the same persona lies within 300 s outside the window | the window cuts the scenario | `--exact-window` |
| an event that is not selected shares a session with one that is | the copy would hold part of a session | `--allow-partial-session` |
| the window holds events from before 31 July 2026 | the forwarder of that time indexed body keys as fields, which a copy cannot carry, and many ids of 27 to 30 July 2026 are indexed two or three times on the facilitator's Splunk (a HEC copy beside a file-monitor copy); the message says which of the two it found | none: such a window cannot be exported |
| an id is held more than once on the facilitator's Splunk | the source itself has a duplicate | none |
| an event is larger than 900,000 bytes | it cannot be sent in one request | none |
| an event is under 15 minutes old | it could still raise an event-time rule on the stack | none: wait |
| Splunk's SHA-256 of an event differs from the one computed locally | the text changed on the way out of Splunk | none |
| with `--check-logs`: an event's hash differs from the assistant's log, or the id is not in the log | the indexed event is not what the assistant wrote | none |

A search that answers with an error stops the run. Splunk sometimes attaches
a warning about its own start-up time to a correct answer; the presence
search is then run again, up to twice more, and the run stops only if the
warning is still there, with its text printed.

## `review`: read what will be sent, then approve it

```
staged_resend.py review --bundle PATH [--approve DIGEST12]
```

```bash
python3 tools/staged_resend.py review --bundle ~/staged-bundles/nina-takeover.bundle.json
```

It prints one line per event (time in UTC, sourcetype, what kind of record
it is, its size, the first 12 characters of its SHA-256, its id), then the
privacy counts (how many events carry message text, how many carry a client
address, how many distinct addresses those are and how many of them are
public), the number of application sign-ins and how many of them name a Duo
transaction, the selection, the census and the expected results, and last
the digest with `approved as it is` or `NOT approved`. It never prints a
body, an address or a Duo transaction id. Read it for three things:

1. Is this the scenario, whole, and nothing else? For the 16 Nov set: two
   application sign-ins, two session starts and five AI turns of which two
   are blocked, all `nina.osei`, all `l5-dev`.
2. Do you accept that the bodies, with the prompts and the stager's client
   address, become readable by everyone who can search `gen_ai_log` on every
   stack you send to? The Duo events of the same sign-ins carry the same
   address into the stack anyway.
3. The expected results: the row `send` and `verify` compare each stack with
   (`events 9`, `identity_events 7`, `ai_turns 5`, `ai_blocked 2`,
   `app_signins 2` for this set) and the chain id
   `nina.osei:takeover:1794893749`.

Then approve it with the 12 characters the review printed:

```bash
python3 tools/staged_resend.py review --bundle ~/staged-bundles/nina-takeover.bundle.json \
    --approve 3f9a1c2b7d4e
```

`send` refuses a bundle that is not approved, and one whose content no longer
matches the approved digest. An approval covers the bytes, not a stack: one
approval serves every stack.

## `send`: copy the bundle into one stack

```
staged_resend.py send --bundle PATH --stack URL (--hec-file PATH | --hec-url URL) [--dry-run]
    [--username admin] [--allow-rule-off] [--without-duo] [--no-canary]
    [--resend-unconfirmed] [--retention-days N] [--settle 180] [--wait-finding N]
    [--ca-file P] [--no-verify-splunkd]
```

One run per stack, after `show_postdeploy.py --out` and `--duo` on that stack
and after the first Duo poll is in. The machine that runs it must reach the
stack's port 8089 as well as its HEC: every check before and after sending is
a search on the stack.

**Worked example.** Always a dry run first. The password read here is the
admin password of `<stack>`, the stack named by `--stack`:

```bash
read -rs SPLUNK_ADMIN_PASSWORD && export SPLUNK_ADMIN_PASSWORD   # <stack>'s own admin password
python3 tools/staged_resend.py send --bundle ~/staged-bundles/nina-takeover.bundle.json \
    --stack https://<stack>.splunkcloud.com --hec-file <stack>.json --dry-run
```

When that stack is done, `unset SPLUNK_ADMIN_PASSWORD SPLUNK_ADMIN_TOKEN`
before the next one.

A dry run makes every read (steps R1 to R8 below) and prints, per id, what a
real run would do: `send`, `skip` or stop. It posts nothing to HEC and prints
no event text. When it reads right, run the same command without `--dry-run`,
and add `--wait-finding 900` to have it wait for the finding as well.

What a real run does, in order:

1. Steps R1 to R8. Any failure stops the run before anything is sent.
2. **The canary.** One event goes first, alone: the earliest audit record that
   is not a sign-in (for the 16 Nov set the session start at
   `1794891951.147`), else the earliest event. The rest is sent only after the
   stack returns the canary exactly once, with the same SHA-256, time, host,
   source, sourcetype, index and `log_type`, and labelled with this bundle. If
   the stack changed the event in any way, one event is wrong on that stack
   and the rest was never sent. A stack can change one sourcetype and keep
   another, so a second request then carries one event of each other
   sourcetype and `log_type` in the bundle, and it too must come back
   identical before any other event is sent. A kind of which a copy of this
   bundle is on the stack already needs no canary.
3. The rest, at most 50 events and 512 KiB in one request (the 16 Nov set is
   one request).
4. It polls every 10 s, up to `--settle` seconds (180), until every id is on
   the stack once and identical.
5. With `--wait-finding N`: it waits up to N seconds for the joined rule's
   finding (see [`verify`](#verify-prove-the-copy-and-the-finding)).

A second run on the same stack sends nothing: every id is found and skipped.

### The checks before sending, and every refusal

All of them only read. A failed step stops the run before anything is sent
(exit 1 or 2, never 0); the output names the step and, where there is one,
the option that overrides it.

| Step | What must hold | Override |
|---|---|---|
| R1 bundle | the file is 0600, is not a symbolic link and is not inside a git work tree; its digest and every event's SHA-256 still match; it is approved, for this digest | none |
| R2 HEC | the `--hec-file` is 0600 and holds `hec_url` and `hec_token`; its index is the bundle's; the URL is https and ends `/services/collector/event`; its host belongs to the stack named by `--stack`. A `--lab5` file is refused and named as such | none |
| R3 stack | splunkd on port 8089 answers and accepts the credential; the server is **not** the Splunk the bundle was exported from; TA-gen_ai_cim is 1.9.0 or later | none |
| R4 index and age | the index exists and this account can search it; it is the index the stack's own macro `genai_identity_ai_events` reads (where the stack does not serve the macro: `gen_ai_log` only, marked NOT CHECKED); it keeps the oldest event at least 7 more days; the newest event is over 15 minutes old and the oldest under 180 days | none, but see `--retention-days` below |
| R5 rule | the joined rule exists and is enabled, judges by index time on a slot exactly one cron period wide, with `realtime_schedule = 0`; its text parses on this stack; one of its last ticks (2 periods + 5 minutes, so 15 minutes) ran successfully | `--allow-rule-off` |
| R6 Duo half | the Duo authentication of every sign-in in the bundle (the record's `details.duo_txid`) is in the stack's Duo events exactly once; the persona's Duo failures there are at least the bundle's | `--without-duo` |
| R7 presence and ledger | no id is on the stack in a different form or more than once; no id of an earlier run is still unconfirmed | `--resend-unconfirmed`, for unconfirmed ids only |
| R8 HEC health | `GET /services/collector/health` on the HEC host answers healthy | none |

Notes on single steps:

- **R3, wrong account name.** HTTP 401 here usually means the admin account
  is not called `admin`: pass `--username`.
- **R4, the index.** The tool asks the search tier whether the index is there
  (`| eventcount summarize=false index="gen_ai_log"` must return a row). An
  index this account cannot search looks empty to every later check, and
  "empty" would mean "send": that is why this step has no override. `--index`
  at export exists for a scratch index on a dev Splunk; on a stack whose
  macro reads `gen_ai_log`, a bundle for any other index is refused, because
  *Identity Activity* and the rule would never read the copy.
- **R4, a macro the stack does not serve.** Where the stack does not serve
  the definition of `genai_identity_ai_events` (`configs/conf-macros`
  unreadable, likely on a Cloud search head), the step cannot prove which
  index the macro reads. It then says `NOT CHECKED: which index ... reads`,
  accepts a `gen_ai_log` bundle on the shipped definition, and refuses a
  bundle for any other index. `verify` reads the copies through the macro,
  so V3 and V5 show whether the stack really reads them.
- **R4, retention.** It is read from the stack's `data/indexes`. Where a
  stack does not serve that endpoint (403 or 404), the step says so and
  stops; give the index's searchable days yourself with `--retention-days N`
  (90 for an index `show_postdeploy.py` created). The output then says the
  retention was stated by the operator, not read.
- **R5, what counts as a run.** Runs are judged per tick. A tick the
  scheduler first deferred (`continued`) and then ran is a successful tick,
  reported as lag. A rule whose runs fail writes no status line at all; the
  tool reads the scheduler's error lines too and prints the rule's error
  message. A stack whose TA build has no joined rule fails here with "no
  such rule": the rule arrived with the Duo work of TA 1.9.0, and a 1.9.0
  build from before it does not have it.
- **R5, wait for a tick.** Straight after `--duo` enabled the rule, it has no
  run yet. Wait for the next 5-minute tick plus about two minutes and run
  `send` again; do not reach for the override.
- **R6, Duo not in yet.** With a cron poll schedule the first Duo poll runs at
  the stack's next scheduled minute. Run `show_postdeploy.py --duo` again and
  read D7 and D8, then `send` again.

**What each override costs.** Every override is named in the output of the
run that used it.

| Option | It lets through | The price |
|---|---|---|
| `--allow-rule-off` | a stack whose joined rule is off, absent or has not run | the copy is indexed with no run to judge it, so the schedule never raises the chain ("everything indexed earlier: 0"). Use it only when the events are wanted for the dashboards alone, or when you will judge that index time by hand afterwards (README, *Judging history that is already indexed*) |
| `--without-duo` | a stack that does not hold the Duo half | no chain can form until Duo's events arrive; if they never do (another tenant, a lookback that is too short), the copy stays without its finding. The finding's `signin_duo` reads `none indexed` when only the sign-in's own Duo record is missing |
| `--no-canary` | sending everything in the first request | a stack that rewrites events gets all of them wrong, not one |
| `--resend-unconfirmed` | ids an earlier run handed to HEC, at least 3600 s ago, that the stack still does not show | if the stack did take them and is only slow, each becomes a duplicate for good |
| `--retention-days N` | an index whose retention the stack will not report | the 7-day margin rests on your number |
| `--no-verify-splunkd` | port 8089 with a certificate that does not verify | the admin credential goes to a server that was not authenticated |
| `--exact-window`, `--allow-partial-session`, `--allow-unlisted-persona`, `--no-verify-source` | see [`export`](#export-read-the-scenario-into-a-bundle-once) | a scenario cut in two, or a persona nobody listed |

### Sent once: how the tool decides per id

The key is the id that opens each event's text (`audit_id`, `escalation_id`
or `event_id`). Before anything is sent, and again after, one search (over
all time, 40 ids at a time) asks the stack what it holds for each id:

| The stack holds | Decision |
|---|---|
| nothing | send |
| one copy, identical (SHA-256, time to the millisecond, host, source, sourcetype, index, `log_type`), without a label | skip: the stack got it live |
| the same, with a label (this bundle's or another bundle's) | skip: it was re-sent before |
| one copy that differs in any of those | **conflict**: stop, nothing is sent |
| more than one copy | **duplicate**: stop, nothing is sent |

"Identical" includes the sourcetype. A stack that received the same events
live through a HEC destination that writes one sourcetype for everything
holds events that differ: that is a conflict, and the copy is not for that
stack.

Only events of the assistant's own shape count as copies. Records that merely
quote an id do not: the scoring results, and the audit record an AI Defense
response action (*Suspend user*, *Revoke session*, *Tighten guardrail*) writes
into `gen_ai_log` with the turn's `event_id` in it.

A search that answers with an error is a failed check, never "the stack
holds nothing". A warning Splunk attaches to a correct answer (it warns about
its own slow start under load) makes the tool ask again, up to twice more; a
decision is only ever taken from an answer without a warning.

A conflict or a duplicate has no override, because the tool cannot repair
either. A stack that reaches one of them keeps what it has; see
[What cannot be undone](#what-cannot-be-undone).

### What the tool does with HEC's answer

A request is sent again only when the answer **proves** the stack took
nothing. Everything else is treated as possibly delivered.

| Class | The answer | What the tool does |
|---|---|---|
| accepted | HTTP 200 with HEC code 0, 24 or 25 | never sends those events again |
| not sent | no connection (connect, DNS or certificate failure before the request left); exactly HTTP 503 with code 9 or 23; exactly HTTP 429 with code 26 or 27 | sends again after 5, 15 and 45 s, then gives up |
| refused | HTTP 401 or 403; HTTP 400 with code 5, 10, 11, 14, 16, 21 or 22; HTTP 400 with code 6, 7, 12, 13 or 15 at the first event | stops; nothing of that request was indexed |
| too large | HTTP 413 | halves the batch and sends the halves |
| unknown | a timeout or a reset after the request left; a 503 or a 429 **without** one of the codes above (a proxy's answer, not HEC's); any other 5xx; a 3xx, 404 or 408; a 400 past the first event; a 200 without code 0, 24 or 25 | **never sends it again**; polls the stack for `--settle` seconds; if the events do not appear, exit 3 |

HEC's indexer acknowledgement is not used (Splunk Cloud offers it to Firehose
clients only). That is why the tool asks the stack by search what it holds,
and why it needs port 8089.

### The ledger

`send` keeps `<bundle>.ledger.jsonl` beside the bundle: mode 0600, one line
appended per step, keyed by the stack's server GUID, by a hash of its HEC
endpoint and index and by a hash of the `--stack` address, so one bundle and
one ledger serve every stack. Every
line also goes to the journal, `journal.jsonl` in the state directory
(`$STAGED_RESEND_STATE_DIR`, else `~/.staged-resend`, created 0700): what
every bundle sent from this machine handed over. `send` reads both and
prints the GUID it keys on. Before each request it writes the ids it is about
to send and forces the line to disk; only then does it post. If the run dies
at any point after that, the next run knows those ids may be on the stack.

From that line on an id is **unconfirmed** until the stack shows it, or until
HEC's answer proves it took nothing (not sent, refused, too large). This is
counted per request: a refusal of a later request (after
`--resend-unconfirmed`, say) says nothing of an earlier one whose answer was
unknown, so the id stays unconfirmed. The stack shows it only as the copy of
the bundle that handed it over: a live copy, or another bundle's, leaves it
unconfirmed, and the run ends with exit 3. Every
later `send` to the same stack waits for unconfirmed ids and does not send
them, whatever the earlier run's last line says and also when that line is
missing.

Rules that follow from it:

- Keep the ledger with the bundle. Never delete it, never edit it, and never
  copy a bundle to a second machine to send from there as well: the second
  machine has no ledger, and a stack that is slow to index would get the
  events twice.
- One `send` per machine at a time. The journal is locked for the whole run,
  so a second `send`, of this bundle or any other, cannot send beside the
  first.
- A re-export of the same selection, or an overlapping one (another persona,
  a wider window), sent from the same machine and user, holds what the first
  bundle handed over: the journal knows those ids. Never send it from
  another user or machine, and never point `$STAGED_RESEND_STATE_DIR`
  elsewhere between sends.
- Send a bundle with the same `--stack` URL every time. Another member of
  a search head cluster behind that address answers with another GUID; the
  hash of the `--stack` address (and, for `send`, of the HEC endpoint) still ties
  the lines to the stack, for `send` and `verify` alike.
- The ledger holds ids, hashes, times, counts and HEC's code and status.
  It holds no token, no body and no address.
- `send` refuses a ledger that is a symbolic link, that others can read or
  that belongs to another user, before it reads or writes a line.

### Delivery unknown (exit 3)

Exit 3 means: a request left this machine, the answer does not prove what
happened, and the stack did not show the events within `--settle` seconds.
Usually the stack took them and is slow to make them searchable.

1. Do **not** change anything and do not use an override yet.
2. Wait a few minutes and run `verify`. If it finds every id once, the
   delivery is confirmed: a later `send` finds the ids on the stack and
   skips them.
3. If ids are still missing, run `send` again. While no copy of this bundle
   shows on the stack, it sends nothing new: the unconfirmed ids print as
   `HOLD` and the never-attempted ones as `WAIT`, unless `--no-canary` is
   given. It waits `--settle` seconds for the unconfirmed ids, sends none of
   them, and ends with exit 3 while any is missing.
4. Only when an unconfirmed id is still missing **an hour** after it was
   sent does `--resend-unconfirmed` let it through. Look once more by hand
   first (the search under [Checking by hand](#checking-by-hand)): a
   duplicate cannot be removed.

## The label

A copy is the original event with three extra **indexed fields**, set through
HEC's `fields`. The event text is not touched.

| Field | Value | Meaning |
|---|---|---|
| `resend` | `true` | this event is a re-sent copy |
| `resend_bundle` | the bundle id, such as `rs-20261117-3f9a1c2b7d4e` | exactly which reviewed bytes the stack holds |
| `resend_orig_indextime` | epoch seconds | when the facilitator's Splunk indexed the original |

Host, source, sourcetype, index and `log_type` are the original's, on purpose:
the TA's props read `host` (it becomes `dest` of the sign-in records), and its
macros read `source` and a field called `backfill` for other things. Nothing
in the TA's `default/`, `bin/` or `lookups/` reads the three label names.

What that means in practice:

- Search the label as `resend::true`, with two colons. The TA ships no
  `fields.conf` entry for it, so `resend=true` is not promised to work on
  every Splunk version. `tstats` and `stats ... by resend_bundle` work.
- The label is on the events only. *Identity Activity*, the other dashboards
  and the finding do not say that the application half is a copy. Whoever
  presents the stack has to know.
- A copy's index time on the stack is the moment it was sent. The index time
  of the original is kept in `resend_orig_indextime`.

## `verify`: prove the copy and the finding

```
staged_resend.py verify --bundle PATH --stack URL [--username admin] [--wait SECONDS]
    [--ca-file P] [--no-verify-splunkd]
```

`--wait` defaults to 0: `verify` looks once. Right after a `send`, pass
`--wait 900`. (The spec's synopsis gave 900 as if it were the default; the
built default is 0, so that a later `verify` never blocks.)

```bash
python3 tools/staged_resend.py verify --bundle ~/staged-bundles/nina-takeover.bundle.json \
    --stack https://<stack>.splunkcloud.com --wait 900
```

It only reads: the bundle, the ledger and the stack. It needs no HEC token.
Run it after `send`, and again whenever someone asks whether a stack is
ready.

| Step | What must hold | Wait |
|---|---|---|
| V1 | every id of the bundle is on the stack exactly once, identical, labelled with this bundle or delivered live | polls every 10 s, up to 180 s, for ids the ledger says were sent; any other missing id fails at once |
| V2 | the events that carry this bundle's label are the ones the ledger says were sent | none |
| V3 | read through the TA's own macros, the stack gives the bundle's expected row | none |
| V4 | the Duo authentication of every sign-in is on the stack once | none |
| V5 | the stack's own rule text, run ad hoc over all index time (no alert action runs), returns the bundle's chain ids | none |
| V6 | each chain has one row in index `notable` and one in index `risk` | until the finding is due (`tick + 420 s`, below) or `--wait` runs out, whichever comes first; none when V1 failed |

For the 16 Nov set a good run reads: 9 of 9 ids once and identical; the row
`nina.osei`, `events 9`, `copies 9`, `identity_events 7`, `ai_turns 5`,
`ai_blocked 2`, `app_signins 2`; two Duo authentications found once each; one
chain, `nina.osei:takeover:1794893749`, with `blocked_turns 1` and
`duo_failures_10m 6`; one finding and one risk event for it. The set has two
sign-ins and one chain: the first sign-in had no denial burst in the 30
minutes before it.

*Identity Activity* then shows `nina.osei` with 2 application sign-ins, 5 AI
turns and 2 blocked turns.

**How long the finding takes.** The joined rule runs every 5 minutes and each
run judges what was indexed between 7 and 2 minutes before its tick. A copy
indexed at second `t` is judged at the first tick after `t + 120`:
`tick = (floor((t + 120) / 300) + 1) * 300`. The scheduler starts the run a
minute or more after the tick and may skew it by up to 5 minutes, so the tool
allows `tick + 420 s`. In wall-clock terms the finding is there between about
3 and 14 minutes after the send; `--wait 900` covers the worst case, and the
wait ends early once the finding is there or overdue.

### When a check after sending fails

| What the output says | What it means | What to do |
|---|---|---|
| V1: ids missing | the stack has not made them searchable yet, or did not take them | wait, run `verify` again; then [Delivery unknown](#delivery-unknown-exit-3) |
| V1: the canary differs | this stack's HEC changed the event text or the digits of its time | stop. One event is wrong on this stack and stays; nothing else was sent. Do not use `--no-canary`; report it |
| V1: an id is on the stack more than once | a duplicate | it stays; see [What cannot be undone](#what-cannot-be-undone) |
| V3: the row differs | the events are there, but the stack's TA reads them differently from the facilitator's | compare the TA versions and look for a local override of the TA's macros or props on the stack |
| V4 or V5: no Duo authentication, no chain | the Duo half is missing or from another tenant | `show_postdeploy.py --duo` again, read D7 and D8 |
| V6: `NOT RAISED YET` (exit 1) | the finding is not due yet: the tick that judges the copy, plus 420 s, has not passed | nothing is wrong; run `verify --wait N` as printed, or `verify` again after the printed due time |
| V6: no finding although V5 shows the chain | the scheduled run that should have judged the copy did not raise it | read the lines the tool prints next, below |

When the finding is late, the tool prints the scheduler's own record of the
run that judged the copy (scheduled time, start, lag, status, result count,
suppressed, alert actions) and any error line the scheduler wrote for the
rule:

- **deferred**: the scheduler is behind. The rule never skips a period; wait
  and run `verify` again.
- **an error line**: the run failed, and a failed run loses its slot: the
  schedule will not look at that index time again. Fix what the message
  names, then judge that index time once more by hand (README, *Judging
  history that is already indexed*).
- **success with 0 results**: the copy was not the last missing step in that
  slot. Check V4: the Duo half was probably indexed while the rule was off.
- **suppressed**: the chain was already raised in the last 24 hours; look for
  the earlier finding.

## Checking by hand

Searches for the stack's own search bar. **Set the time range to All time**
(or to one that covers the scenario): a copy keeps the time of the original
event, so "Last 15 minutes" shows nothing a minute after the send.

Which copies does this stack hold?

```spl
| tstats count as events, min(_indextime) as first_indexed, max(_indextime) as last_indexed
    where index=gen_ai_log resend="true" by resend_bundle, sourcetype, log_type, host
```

For the 16 Nov set: `demobot:audit`, `audit`, `l5-dev`, 4 and `gen_ai:json`,
`governance`, `l5-dev`, 5, both under one bundle id.

The copied events themselves:

```spl
index=gen_ai_log resend::true
| table _time, host, sourcetype, log_type, resend_bundle, resend_orig_indextime
```

How many copies of one id (the id is in the tool's output and in the ledger):

```spl
index=gen_ai_log sourcetype!="ai_cim:response:*" "<id>"
| eval rs_id=coalesce(spath(_raw, "audit_id"), spath(_raw, "escalation_id"), spath(_raw, "event_id"))
| search rs_id="<id>"
| eval sha256=sha256(_raw), label=coalesce(mvjoin(resend_bundle, ","), "none")
| stats count as copies, values(sha256) as sha256, values(label) as label,
    values(host) as host, values(sourcetype) as sourcetype, min(_indextime) as first_indexed by rs_id
```

`copies` must be 1. Records that only quote the id stay out of the count, as
in the tool's own search: the `sourcetype!=` term drops the response actions'
audit records, and a scoring result has no id of its own, so it drops out at
`search rs_id=`.

The finding and its risk event, one row each:

```spl
(index=notable OR index=risk)
    search_name="AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule"
    chain_id="nina.osei:takeover:1794893749"
| eval event_time=coalesce(orig_time, _time)
| stats count as rows, min(_indextime) as first_raised, values(event_time) as event_time by index, chain_id
```

The two rows are dated differently: the risk event at the first blocked turn
(16 Nov for this set), the finding at the moment it was raised, with the
event time in `orig_time`. A search over "Last 24 hours" finds the finding
and misses the risk event.

Is the rule running, tick by tick, and did a run fail?

```spl
index=_internal sourcetype=scheduler
    savedsearch_name="AI Governance - Duo Denial Burst to Blocked AI Turn Correlation - Rule"
| stats count(eval(status=="success")) as ok, count(eval(status=="continued")) as deferred,
    count(eval(status=="skipped")) as skipped by scheduled_time
| sort - scheduled_time | head 6
```

```spl
index=_internal source=*scheduler.log* log_level=ERROR "Duo Denial Burst to Blocked AI Turn Correlation"
```

A healthy rule shows `ok 1` on its latest ticks, 300 s apart, and no error
line. For these two the range is the last hour, not All time.

## What cannot be undone

- **A sent event stays.** The tool cannot delete from an index, and neither
  can HEC. A copy, a duplicate or a canary the stack changed stays until the
  index's retention ends or the stack is deleted.
- **A duplicate doubles the counts.** *Identity Activity* counts events, so
  an id that is on the stack twice shows one sign-in or one turn too many for
  the life of the stack. The joined rule itself is not fooled: a chain is
  raised once however often its events are indexed.
- **Hiding is not deleting.** An admin with the `can_delete` role can hide
  copies with `index=gen_ai_log resend_bundle::<bundle id> | delete`. That
  hides every copy of that bundle, not one of two, and frees no storage. The
  tool never does it.
- **A raised finding and its risk stay** in `notable` and `risk`, and in the
  persona's risk score.
- **An approval** can be given again for a new export, but a stack that got
  the old bytes keeps them.

What the copy sets off on the stack, besides the finding:

- The finding's own row (risk score 80) and the findings of the Duo backfill
  all count in Enterprise Security's "last 24 hours" of risk at the moment
  they are raised, whatever the age of the events. Together they can trip
  ES's 24-hour risk threshold rule for the persona.
- The two sign-in records enter the Authentication data model with
  `dest=l5-dev`: the host label of the facilitator's dev copy travels to
  every stack. Before staging a scenario that is meant to be copied, give the
  assistant a neutral host label (`HEC_HOST`).
- The Lab 5 rule can fire, see [the order](#the-order-on-a-new-stack).

## Deadlines

Limits that hold for every bundle:

| Limit | Value | Enforced by |
|---|---|---|
| youngest event at `export` and at `send` | over 15 minutes old | `export`, R4 |
| oldest event at `send` | under 180 days old (the rule's context reaches 181 days) | R4 |
| the index must keep the oldest event | 7 more days at `send` | R4 |
| the rule's last successful run | within 15 minutes | R5 |
| an unconfirmed id before `--resend-unconfirmed` may send it | 3600 s | R7 |
| the finding after a send | 3 to 14 minutes | `--wait-finding`, `verify --wait` |

Dates for the set staged on 16 Nov 2026 (first event 21:05 PST):

| By | What ends | What to do |
|---|---|---|
| now | the assistant's own log of the set is a rotating file in one checkout, and it is what `--check-logs` compares with | run `export` with `--check-logs` while that log and the facilitator's Splunk both hold the set |
| 17 Nov, 21:36 PST | the copied blocked turns are under 24 hours old until then, so the Lab 5 rule can read them | nothing; expect its finding where CII evidence arrives before then |
| 30 Nov | the last day *Identity Activity*'s default range (14 days) shows the set | after that, widen the dashboard's time range |
| about 16 Dec | Duo's first poll reads back 30 days by default (`--duo-lookback-hours 720`); a stack first polled later does not get the denial burst | run `--duo` on the stack before then, or R6 refuses and no chain can form |
| about 7 Feb 2027 | an index created by `show_postdeploy.py` keeps 90 days; R4 wants 7 days of margin | last day to send into such a stack |
| about 14 Feb 2027 | the copy ages out of a 90-day index | nothing can be done on the stack |
| 15 May 2027 | the oldest event is 180 days old | the bundle is refused from then on; stage a new scenario |

## Before the first room stack

Nothing here has run against Splunk Cloud. Two things reduce what the first
room stack has to prove.

**The offline tests**, from the TA checkout:

```bash
python3 -B -m unittest discover -s tools/tests -p 'test_staged_resend.py'
/opt/splunk104/bin/splunk cmd python3.13 -B -m unittest discover -s tools/tests -p 'test_staged_resend.py'
python3 -B tools/tests/fixtures/staged_resend_gen.py --check
```

Read the result line, not the exit code: it must say `Ran N tests`, with N
at least 200, and then `OK`. Under the system `python3` nothing may be
skipped. Under Splunk's `python3.13` exactly one test is: Python-Markdown is
not part of that Python, so the comparison of this page with its `.html`
does not run there. Under Python 3.9 a suite that
found no test at all also exits 0 (`Ran 0 tests`). The suite needs the joined
rule's stanza in `default/savedsearches.conf` of the checkout and fails, not
skips, without it.

**The scratch end-to-end**, `tools/tests/staged_resend_scratch_e2e.py`, is
opt-in and is the only rehearsal on a real splunkd and a real HEC; without it
the first room stack is the test. It sends the lines of the test fixture
(invented persona data, ids that exist in no index) into an index named
`rs_scratch_*` on a dev Splunk on the same machine, canary first, and reads
the copies back through searches that name the scratch index. It refuses
anything else: a host that is not loopback, a Splunk Cloud instance, an index
the TA's macros read, an index that holds someone else's events. It creates
no index and deletes nothing: create `rs_scratch_copy` on the dev Splunk
first and remove it afterwards.

```bash
export STAGED_RESEND_SCRATCH_E2E=1
export SPLUNK_TEST_URL=https://127.0.0.1:8089 SCRATCH_HEC_URL=https://127.0.0.1:8088
read -rs SPLUNK_TEST_PASSWORD && export SPLUNK_TEST_PASSWORD
read -rs SCRATCH_HEC_TOKEN && export SCRATCH_HEC_TOKEN
python3 tools/tests/staged_resend_scratch_e2e.py plan      # contacts nothing
python3 tools/tests/staged_resend_scratch_e2e.py send
python3 tools/tests/staged_resend_scratch_e2e.py verify
```

The HEC token there must be one that may write to `rs_scratch_*`. The
script's own docstring is the reference for it.

## One stack, start to finish

Once, on the facilitator's Mac:

1. `export` with `--check-logs`, into a private folder.
2. `review`, read it, `review --approve <digest12>`.

Per stack, in this order:

1. `read -rs SPLUNK_ADMIN_PASSWORD && export SPLUNK_ADMIN_PASSWORD`: the admin
   password of this stack, the one named by `--stack` below. Never carry the
   last stack's over.
2. `python3 tools/show_postdeploy.py --stack <url> --out <stack>.json`
   If it printed `No HEC token returned`, there is no `<stack>.json`: use the
   `--hec-url` form from *Known gap in `--out`* in steps 4 and 5 instead of
   `--hec-file`.
3. `python3 tools/show_postdeploy.py --stack <url> --duo --duo-poll-slot <K>/<N>`,
   wait for the first poll, run it again and read D7 and D8.
4. `python3 tools/staged_resend.py send --bundle <bundle> --stack <url> --hec-file <stack>.json --dry-run`
   (or, after `No HEC token returned`, `read -rs STAGED_RESEND_HEC_TOKEN && export STAGED_RESEND_HEC_TOKEN`
   and `--hec-url https://http-inputs-<stack>.splunkcloud.com/services/collector/event`
   in place of `--hec-file <stack>.json`)
5. The same without `--dry-run`, with `--wait-finding 900`.
6. `python3 tools/staged_resend.py verify --bundle <bundle> --stack <url> --wait 900`
7. Open *Identity Activity* on the stack, time range covering the scenario.
8. `unset SPLUNK_ADMIN_PASSWORD SPLUNK_ADMIN_TOKEN STAGED_RESEND_HEC_TOKEN`, before the next stack.

Afterwards: unset the environment variables, keep the bundle and its ledger
together until the last stack is done, then delete both and the `--out`
files.

## What has not been proven

- Anything on Splunk Cloud, ACS or a real HEC. No event was ever sent to a
  stack by this tool.
- That Splunk Cloud's HEC keeps an event's text and the digits of its time
  as Splunk 10.4.3 does. The canary is the test: it fails loudly on the
  first event if not.
- That an accepted event is searchable within minutes on a stack.
- That the stack's admin account (`sc_admin`) may read `_internal`, the saved
  searches and `data/indexes` on port 8089, and that a room stack's port 8089
  is reachable from the facilitator's machine at all. Without port 8089 the
  tool cannot run, and it must not be run blind.
- A scheduled run of the joined rule that raises a finding with a
  `chain_id`: on the dev Splunk the rule has never run on a schedule, so step
  V6 is proven in shape only, on the Duo rule's findings.
