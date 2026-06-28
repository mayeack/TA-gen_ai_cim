---
name: splunk-workshop-design
description: Design and build customer-ready Splunk workshops as a sibling kit (outline, click-by-click participant guide, deterministic backfill generator, planted incidents) without modifying the target Splunk app. Use when the user asks to build a Splunk workshop, demo script, customer hands-on, click-by-click guide, evaluation script, lab, POC walkthrough, or backfill data generator for an existing Splunk app or TA.
---

# Splunk Workshop Design

Build hands-on Splunk workshops that demonstrate the business value of an existing app or TA. Every workshop ships as a **sibling kit** (`<APP>_workshop/`) so the target app is never edited. The kit is two markdown deliverables plus a deterministic backfill generator that plants the incidents the workshop walks through.

## Core principles (do not violate)

1. **Never modify the target app.** The workshop lives in `<APP>_workshop/`, beside the app, not inside it. No new conf files, lookups, or saved searches in the app being demo'd.
2. **Two deliverables + one runnable kit.** Every workshop produces `WORKSHOP_OUTLINE.md` (the narrative), `WORKSHOP_GUIDE.md` (click-by-click participant guide), and `bin/` (the generator).
3. **Deterministic, reproducible data.** The generator is seeded. Same seed → same incidents at the same offsets. Workshops must be re-runnable and previewable.
4. **Respect the target's schema.** The generator emits raw fields that the target's existing `FIELDALIAS` / `EVAL` rules already normalize. It never assumes new TA configuration.
5. **Add Data → Upload is the default ingest.** Works on every Splunk install with zero participant config. Forwarder / HEC paths are optional alternates, never primary.
6. **Click-by-click, not concept-by-concept.** The guide is exhaustive enough that an LLM reading it can drive every step.
7. **Smoke test before claiming done.** Verify event shape, scenario placement, and (when an MCP is available) that the data ingests and `gen_ai.*`/normalized fields populate.

## Quick start

When the user asks to build a workshop:

1. **Discover** the target app: read its `README.md`, `default/data/ui/nav/default.xml`, `props.conf` (find `KV_MODE`, `FIELDALIAS`, `EVAL` rules), and walk the existing dashboards. Identify 3-6 dashboards / saved searches / workflow actions worth demonstrating.
2. **Design** a 5-7 act narrative covering frame → seed → operate → govern → score/configure → review → escalate. Write `WORKSHOP_OUTLINE.md` first and review with the user before writing the participant guide.
3. **Build** the workshop kit at `<APP>_workshop/` (sibling, not child). Follow the directory layout below.
4. **Smoke test** the generator with `--no-incidents` and a default run. Verify scenario counts, time-window placement, and field shape match the schema rules in [TEMPLATES.md](TEMPLATES.md).

## Workshop kit layout

```
<APP>_workshop/                    # SIBLING of the target app, not child
├── WORKSHOP_OUTLINE.md            # narrative for presenter prep + customer handout
├── WORKSHOP_GUIDE.md              # click-by-click participant guide
├── README.md                      # optional: ties the kit together
└── bin/
    ├── gen_<domain>_events.py     # main generator (argparse, deterministic)
    ├── scenarios.py               # planted-incident factories
    └── run_<domain>_backfill.sh   # bash wrapper, picks python3 sensibly
```

The kit is its own folder. It is not packaged as a Splunk app. It does not need `default/`, `metadata/`, or `app.conf`.

## The act framework

Every workshop is a 5-7 act narrative with explicit timing. Match acts to the **business hooks** the customer's audit team / executive cares about, not to dashboard tabs.

| Phase | Act | Length | Role |
|---|---|---:|---|
| Frame | Act 0 — Frame the demo | 1m | Set the lens. No clicks. |
| Seed | Act 1 — Seed the demo | 8-12m | Run the backfill, ingest via **Add Data → Upload**, verify normalization. |
| Operate | Act 2 — Operational visibility | 15-20m | Fleet-wide view: cost, latency, usage, asset discovery. |
| Govern | Act 3 — Risk surfaces | 15-25m | Walk the targeted detection dashboards. Each planted incident lights up here. |
| Configure | Act 4 — Configure detectors | 10-15m | Show the *runtime* configurability (UI-driven detectors, scoring pipelines, thresholds). Optional but high-value. |
| Review | Act 5 — Review pipeline | 10-15m | In-platform review queue → event review → audit trail. |
| Escalate | Act 6 — Escalate (conditional) | 10-15m | Hand off to ServiceNow / SOAR / ITSM. Mark conditional if the target system isn't always present. |
| Wrap | Wrap | 2-3m | Reset narrative, three takeaways, Q&A. |

Skip acts the target app doesn't support. Mark conditionally-runnable acts (e.g. ServiceNow) explicitly so the workshop time-budgets cleanly with or without them.

## The two markdown deliverables

### WORKSHOP_OUTLINE.md

Audience: presenter and the customer's exec sponsor reading before the session.

Required sections (template in [TEMPLATES.md](TEMPLATES.md)):
- Quick reference table (length, audience, prereqs, app link, kit path)
- Narrative diagram (mermaid flowchart of the acts)
- Per-act block: business message (italicized one-liner), goal, beats, time budget
- Outcomes (what the customer leaves with)
- Constraints (e.g. "no edits to target app", "ServiceNow optional")

### WORKSHOP_GUIDE.md

Audience: presenter mid-flight, or an LLM driving Splunk Web.

Required structure for **every act-stage**:
1. **Goal** — one sentence, what the participant proves at this step.
2. **Click path** — numbered, exact menu labels in **bold**, exact dashboard names, exact filter values.
3. **Exact SPL** — code block, copy-pasteable, with `index=` and `earliest=` always set.
4. **What you see** — bullet list of expected panel values / row counts / colors.
5. **Things to point at** — the 1-3 product capabilities the participant should be told to notice.
6. **Say out loud** — verbatim presenter-narration block, italicized blockquote.
7. **Common gotchas** — 3-5 failure modes with fixes.

Pre-flight checklist (before Act 0): env health (`| rest /services/server/info`), target-app enabled (`| rest /services/apps/local/<app>`), index exists (`| rest /services/data/indexes/<idx>`), dependent apps (e.g. `splunk_ai_toolkit`), optional integrations (e.g. ServiceNow).

## The generator pattern

Every workshop's generator must be:
- **Deterministic.** Default `--seed N`. Same seed → same events at the same offsets.
- **Time-windowed.** `--backfill-minutes N` (default 60), optional `--end ISO8601` for replay.
- **Sized.** `--rate N` events/min (typical default 50, ~3000/hr).
- **Smoke-test-able.** `--no-incidents` produces baseline only (zero governance flags) for shape verification.
- **Cosmetic re-skin only.** `COMPANY_NAME` env var renames tenant strings. The narrative does not depend on the value.
- **Output JSONL to `--out`.** One event per line. Sorted by timestamp. This is the file the participant uploads via **Add Data → Upload**.

### Field-shape rule (critical)

The generator emits two kinds of fields based on what the target TA's `props.conf` does:

1. **Underscore-form raw fields** for everything the TA's `FIELDALIAS` or `EVAL` rules already normalize. Example: emit `"safety_violated": true` because the TA aliases `safety_violated AS gen_ai.safety.violated`.
2. **Dotted-form fields directly** for ML / scoring / computed fields the TA does **not** alias. Example: emit `"gen_ai.pii.risk_score": 0.87` directly. Splunk's `KV_MODE = json` extracts dotted JSON keys as fields verbatim.

Before writing the generator, **read the target sourcetype's `[stanza]` in `props.conf`** and list every `FIELDALIAS-*` and `EVAL-*` rule. Anything aliased → emit raw underscore. Anything not aliased that a dashboard panel reads → emit dotted directly.

### Planted incidents

Each scenario is a function in `scenarios.py` that takes a `base_factory(t) -> dict` baseline-event closure and returns a list of overlaid events. Compose **3-5 scenarios** that map 1:1 to the saved searches / dashboard panels the workshop demonstrates. Typical sizes (60-min window):

| Scenario type | Count | Placement |
|---|---:|---|
| Detection-class A (e.g. PII leak) | 50-80 | Scattered |
| Detection-class B (e.g. attack burst) | 25-40 | Single sub-window from one source |
| High-severity outliers (e.g. EMERGENCY) | 3-8 | Scattered |
| Operational outlier (e.g. cost spike) | 20-30 | Last 10-20 minutes only |

Cap any sub-window placement so it never extends before `start` for short backfills. Test with `--backfill-minutes 5` to catch this.

### Why `Add Data → Upload`

- Works on every Splunk install regardless of forwarder / HEC config.
- Zero participant config — the generator drops a JSONL file, the participant clicks Upload.
- The wizard auto-detects the sourcetype if its name is in props.conf.
- The same event landing path is used by the participant's existing live data, so dashboards merge cleanly.

Mention forwarder / HEC alternates briefly in the guide as fallbacks, but never as the primary path.

## Workflow

### Phase 1: Discover the target

Read in this order:
1. `<APP>/README.md` — what's the elevator pitch? what does the customer get?
2. `<APP>/default/data/ui/nav/default.xml` — exact dashboard / view labels for click paths.
3. `<APP>/default/data/ui/views/*.xml` — what panels exist? what SPL drives them?
4. `<APP>/default/props.conf` — list the `[stanza]` lines, then for each sourcetype list `KV_MODE`, every `FIELDALIAS`, every `EVAL`. This is the schema contract for the generator.
5. `<APP>/default/savedsearches.conf` — saved searches the workshop can fire (especially scheduled alerts).
6. `<APP>/default/transforms.conf`, `<APP>/default/macros.conf` — KV-store joins, cost lookups, helper macros.
7. Sample raw events under `<APP>/samples/`, or any provider-example doc — this is your event shape ground truth.

Confirm with the user: customer name (for `COMPANY_NAME`), workshop length, audience seniority, whether optional acts (e.g. ServiceNow) apply.

### Phase 2: Design the narrative

Write `WORKSHOP_OUTLINE.md` only. Show the user the act table and per-act business messages before writing any code or the participant guide. Iterate until the act list reflects the **customer's risk vocabulary**, not the dashboard tab names.

### Phase 3: Build the kit

Order:
1. `bin/scenarios.py` — define the 3-5 incident factories. Use stdlib only (no extra deps).
2. `bin/gen_<domain>_events.py` — argparse, baseline factory honoring the target's schema rule, scenario orchestration, JSONL writer with sorted timestamps.
3. `bin/run_<domain>_backfill.sh` — bash wrapper, `set -euo pipefail`, picks `python3` from PATH, falls back to `$SPLUNK_HOME/bin/python3`.
4. `WORKSHOP_GUIDE.md` — written **after** the generator works. Every SPL block in the guide must reference real fields the generator actually emits.

Skeletons for all four files are in [TEMPLATES.md](TEMPLATES.md).

### Phase 4: Smoke test

Mandatory before declaring the kit complete. Run all of:

```bash
# 1. Baseline shape — no governance flags should fire
bin/run_<domain>_backfill.sh --out /tmp/smoke_baseline.jsonl \
  --backfill-minutes 5 --rate 5 --no-incidents

# 2. Default workshop run — verify scenario counts and placement
bin/run_<domain>_backfill.sh --out /tmp/smoke_default.jsonl

# 3. Short window — verify no scenario extends before --backfill window start
bin/run_<domain>_backfill.sh --out /tmp/smoke_short.jsonl --backfill-minutes 5 --rate 5

# 4. Cosmetic re-skin
COMPANY_NAME='AcmeCo' bin/run_<domain>_backfill.sh --out /tmp/smoke_skin.jsonl --backfill-minutes 5
```

Then load JSONL into Python and assert: total event count matches expectation, each scenario count is right, all events carry the required raw-field set, the cost/operational outlier is confined to its sub-window, and at least one event from each scenario has the dotted ML fields populated.

If the user has a Splunk MCP server connected (e.g. `user-splunk-mcp-server`), additionally:
- Run a real ingest via the MCP and verify a sample event normalizes (`| eval gen_ai...` returns populated values).
- Spot-check that one of the saved searches the workshop demonstrates fires when run over the backfill window.

## Constraints — non-negotiables

- **No edits to the target app.** Not `local/`, not `default/`, not `lookups/`. The workshop kit folder is sibling, not child.
- **No hardcoded credentials.** ServiceNow / external-system credentials are referenced only by name; participant configures them via the target app's existing UI.
- **No new Splunk-side config.** The participant should not need to create indexes, monitor inputs, HEC tokens, or saved searches *for the workshop*. (Exception: the guide can instruct the participant to **enable** an existing scheduled saved search.)
- **No model training.** Bake ML scores into the events. The workshop is about demonstrating governance, not training models.
- **Conditional acts are explicit.** If Act 6 (or any act) requires an integration that isn't always present, mark it conditional in both the outline and the guide, and time-budget the workshop with and without it.
- **Sourcetype name is real.** The generator's emitted events must match a sourcetype `[stanza]` already defined in the target app's `props.conf`. Never invent a new sourcetype.

## Reference implementation

The TA-gen_ai_cim AI Governance workshop at `/opt/splunk/etc/apps/TA-gen_ai_cim_workshop/` is the canonical reference. When applying this skill, study:
- [`WORKSHOP_OUTLINE.md`](/opt/splunk/etc/apps/TA-gen_ai_cim_workshop/WORKSHOP_OUTLINE.md) — six-act narrative with conditional Act 6.
- [`WORKSHOP_GUIDE.md`](/opt/splunk/etc/apps/TA-gen_ai_cim_workshop/WORKSHOP_GUIDE.md) — full click-by-click guide, including Add Data → Upload flow.
- [`bin/gen_genai_events.py`](/opt/splunk/etc/apps/TA-gen_ai_cim_workshop/bin/gen_genai_events.py) — main generator.
- [`bin/scenarios.py`](/opt/splunk/etc/apps/TA-gen_ai_cim_workshop/bin/scenarios.py) — four planted incidents.
- [`bin/run_workshop_backfill.sh`](/opt/splunk/etc/apps/TA-gen_ai_cim_workshop/bin/run_workshop_backfill.sh) — bash wrapper.

That kit's field-shape strategy is the model for any new workshop: read `[medadvice3:json]` in `default/props.conf`, list every alias, emit raw underscore for aliased fields, dotted directly for the ML score fields without aliases.

## Templates

Skeleton content for the outline, guide, and three generator files is in [TEMPLATES.md](TEMPLATES.md). Copy and adapt; do not write from scratch.

## Related skills

- `splunk-ta-development` — for *modifying* a TA. This skill is the opposite: never modify, only demonstrate.
- `splunk-dashboard-studio` — if the workshop involves designing a new dashboard inside the target app, that's out of scope here; use the dashboard-studio skill.
- `splunk-ml-detection` — if the workshop is about *building* an ML detector, use that skill. This skill assumes detectors already exist and only demonstrates them.
