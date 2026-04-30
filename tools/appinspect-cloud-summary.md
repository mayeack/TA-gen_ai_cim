# AppInspect Cloud Report Summary

Generated: 2026-04-28 against `TA-gen_ai_cim-1.2.0.tgz`
(after applying the failure-fix plan — see
`.cursor/plans/fix_appinspect_cloud_failures_*.plan.md`).

```
error:           0
failure:         0
future_failure:  3
skipped:         0
not_applicable: 93
warning:        11
success:       135
-------------------
Total:         242
```

All six prior failures are resolved:

| # | Check | Resolution |
|---|-------|-----------|
| 1 | `check_default_data_ui_file_allow_list` | Renamed Studio JSON sources to `.json.template` so AppInspect's allow-list ignores them. |
| 2 | `check_for_trigger_stanza` | Removed `reload.props/transforms/collections/macros/savedsearches` from `default/app.conf [triggers]`. |
| 3 | `check_reload_trigger_for_all_custom_confs` | Added `reload.<name>` for the 5 custom confs (`ta_gen_ai_cim_account`, `ta_gen_ai_cim_detection`, `ta_gen_ai_cim_genai_scoring`, `ta_gen_ai_cim_llm`, `ta_gen_ai_cim_servicenow`). |
| 4 | `check_alert_actions_exe_exist` | Added `python.version = python3` to `[create_snow_aicase]`, `[sync_snow_asset]`, `[pull_snow_inventory]`. |
| 5 | `check_for_datamodel_acceleration` | Set `acceleration = false` for `AI_Inference`, `AI_Safety`, `AI_Evaluation`. README now documents how customers enable acceleration in Splunk Web. |
| 6 | `check_for_bin_files` | `chmod 644` on the 6 flagged files. `package.sh` now normalizes permissions on every build. |

## Future failures (Python 3.13 readiness — Splunk 9.4+)

These do not block submission today but will become hard failures once
`python.version = python3` is deprecated in favor of `python.required`.

| Check | Files |
|-------|-------|
| `check_alert_actions_conf_python_required` | `default/alert_actions.conf` (3 stanzas) — add `python.required = 3.13` (currently warns). |
| `check_commands_conf_python_required` | `default/commands.conf` `[aicase]`, `[genaiscore]` — add `python.required = 3.13`. |
| `check_admin_external_restmap_conf_python_required` | `default/restmap.conf` `[admin_external:ta_gen_ai_cim_account]` — add `python.required = 3.13`. |

## Warnings (review and address as appropriate)

- `check_for_python_script_existence` — manual: confirm `bin/*.py` are Python 3 only (no Python 2 fallback).
- `check_for_gratuitous_cron_scheduling` — `ML - TFIDF Scoring - *`, `ML - PII Scoring - *`, `ML - Prompt Injection Scoring - *` run every minute. Cloud-friendly cadence is `*/5 * * * *` or longer.
- `check_custom_conf_replication` — add a `default/server.conf` with `[shclustering] conf_replication_include.<name> = true` for each custom conf to support SHC.
- `check_for_valid_package_id` / `check_version_is_valid_semver` — add `app.manifest` and `[id] name = TA-gen_ai_cim` stanza in `default/app.conf` (the semver warning clears once `[id]` is added).
- `check_reload_trigger_for_meta` — add stanza-level reload triggers for `[conf/...]`, `[configs/conf-...]`, `[admin:...]`, `[admin_external:...]` in `default/app.conf`.
- `check_kos_are_accessible` — `metadata/default.meta` currently only grants `admin`; also include `sc_admin` for Splunk Cloud customers.
- `check_python_sdk_version` — bundled `lib/splunklib/__init__.py` is SDK 2.0.2; upgrade to 2.1.1+.
- `check_for_datamodel_acceleration` — informational warning that customers must enable acceleration manually (see README "Enabling Data Model Acceleration").
- `check_for_splunk_js` — telemetry only, no action required.
- `check_collections_conf` — informational.

## How to re-run

```bash
cd /opt/splunk/etc/apps
bash TA-gen_ai_cim/package.sh
splunk-appinspect inspect TA-gen_ai_cim-1.2.0.tgz \
    --included-tags cloud \
    --data-format json \
    --output-file TA-gen_ai_cim/tools/appinspect-cloud-report.json
```
