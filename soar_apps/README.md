# SOAR apps shipped with TA-gen_ai_cim

This folder is deliberately separate from the rest of the add-on. Splunk SOAR is
a different product with its own connector format and Python runtime, so its
apps install on the SOAR instance, not on the Splunk search head. Keeping them
here means the folder, or the tarball beside it, can be lifted straight out of a
checkout and uploaded to SOAR on its own.

| File | What it is |
|---|---|
| `medadvice_idp/` | Source of the **MedAdvice Identity Provider** app |
| `medadvice_idp.tgz` | The same app, packaged and ready to upload. Rebuild with `bash tools/soar/build.sh` |

## MedAdvice Identity Provider

A simulated identity provider for the MedAdvice / DemoBot workshop personas.
Actions: `test connectivity`, `get user`, `list user sessions`, `disable user`,
`enable user`, `clear user sessions`.

**It is a simulator.** The connector opens no network connection, touches no
directory, keeps no state, and every result carries `"simulated": true`. That
flag is the only thing separating a lab containment record from a real one, so
never strip it and never let the app imply real enforcement. Because it is
stateless, every attendee running `disable user` on the same account gets the
same success, with nothing to reset in between.

It exists because Splunk Enterprise Security 8.6 response plans and the
**Guided Response agent** can only run actions that are installed on the paired
SOAR. Without an identity app there, asking the agent to disable a user makes it
reach for whatever identity connectors do exist, and on a demo tenant those are
usually mock assets that fail.

## Upload it to SOAR

In the SOAR UI: **Apps**, then **Install App**, then drop in
`medadvice_idp.tgz`. Create an asset named `medadvice_idp` and leave `mode` at
`simulate`.

The rest is automatic. The add-on's hourly seeding search notices the app, ensures
the asset, and binds the AI Incident Response Plan's Containment tasks to
`disable user` and `clear user sessions`. Newly installed connectors are added to
the Guided Response agent's pre-selected list by ES itself.

Two alternatives to the manual upload:

- `python3 tools/show_postdeploy.py --soar-only --soar-url https://<tenant>.soar.splunkcloud.com --soar-smoke-test`
  with a SOAR password or token exported.
- Configure a `soar` account in `ta_gen_ai_cim_account.conf` and set
  `install_simulator = true` in `ta_gen_ai_cim_es.conf`. The add-on then
  installs it over the SOAR REST API on the next seeding run. This route needs a
  SOAR credential because Mission Control's pairing proxy, which the add-on uses
  for everything else, has no app-install route.

## Build and test

```bash
python3 tools/soar/gen_personas.py          # only after editing lookups/medadvice_identities.csv
PYTHONPATH=tools/soar/tests/phantom_shim:soar_apps/medadvice_idp \
  /opt/splunk104/bin/splunk cmd python3.13 -m unittest discover -s tools/soar/tests -v
bash tools/soar/build.sh
```

See `tools/soar/README.md` for the action table, the parameter contract and
rollback.
