# SOAR apps shipped with TA-gen_ai_cim

This folder is deliberately separate from the rest of the add-on. Splunk SOAR is
a different product with its own connector format and Python runtime, so its
apps install on the SOAR instance, not on the Splunk search head. Keeping them
here means the folder can be lifted straight out of the add-on and uploaded to
SOAR on its own.

| File | What it is |
|---|---|
| `medadvice_idp/` | Source of the **MedAdvice Identity Provider** app. Ships in the TA package |
| `medadvice_idp.tgz` | The same app, packaged and ready to upload. **Git checkout only:** `package.sh` leaves it out of the TA package so the add-on holds no nested tarball. Rebuild with `bash tools/soar/build.sh` |
| `pseudoco_identity/` | Source of the **PseudoCo Identity** app (AI Trust Lab 5). **Git checkout only:** `package.sh` leaves it out of the TA package |
| `pseudoco_identity.tgz` | The same app, packaged. Installed by `tools/show_postdeploy.py --lab5`, never by the TA itself |

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

## PseudoCo Identity (AI Trust Lab 5)

The containment step of Lab 5 ("Verify: Cisco Identity Intelligence"). Unlike
the simulator it is **real**: `disable user` sets the room's victim persona to
`disabled` in Duo through the Duo Admin API, and every result carries
`"simulated": false`. Guard rails, all checked before any call that writes:

- it disables exactly one account, the asset's `victim_username`, which must be
  a Lab 5 victim persona (never a trusted persona or an `l5-*` participant
  account);
- `get user` reads Lab 5 personas only;
- unresolved ES tokens (`$user$`, `%24user%24`) are refused;
- `api_host` must be a Duo API hostname; TLS is verified; the secret key only
  signs requests (Duo v5, HMAC-SHA512) and is never logged;
- no undo: the lab's persona tooling re-enables the victim after the debrief.

Install it with `tools/show_postdeploy.py --lab5` (it also creates the
`pseudoco_identity` asset from the `DUO_IDENTITY_OPS_*` environment variables)
and remove the asset with `--lab5-teardown`. See
`tools/lab5-identity-runbook.md`.

## Upload it to SOAR

SOAR installs an app from a `.tgz` whose top-level directory is the app
directory, `medadvice_idp/`. Get one of two ways:

- **From the TA package** (`TA-gen_ai_cim-<version>.tgz`, the file you install
  on Splunk). It ships the app's source but not the prebuilt tarball, so build
  the tarball from that source:

  ```bash
  tar -xzf TA-gen_ai_cim-<version>.tgz TA-gen_ai_cim/soar_apps/medadvice_idp
  COPYFILE_DISABLE=1 tar --no-xattrs --exclude='__pycache__' --exclude='*.pyc' \
      -czf medadvice_idp.tgz -C TA-gen_ai_cim/soar_apps medadvice_idp
  ```

  Archive from the parent directory (`-C`) as shown, not from inside
  `medadvice_idp/`, or the tarball has no top-level app directory. On Splunk
  Enterprise you can skip the extract and point `-C` at
  `$SPLUNK_HOME/etc/apps/TA-gen_ai_cim/soar_apps`. `COPYFILE_DISABLE=1` and
  `--no-xattrs` stop macOS tar adding `._*` members and extended-attribute
  headers that GNU tar on SOAR cannot read; drop `--no-xattrs` if your `tar`
  does not recognise it. Building from the package keeps the SOAR app at the
  same version as the add-on whose response plan binds to it.
- **From a git checkout:** use the prebuilt `medadvice_idp.tgz` beside this
  file.

Then, in the SOAR UI: **Apps**, then **Install App**, then drop in
`medadvice_idp.tgz`. Create an asset named `medadvice_idp` and leave `mode` at
`simulate`.

The rest is automatic. The add-on's hourly seeding search notices the app, ensures
the asset, and binds the AI Incident Response Plan's Containment tasks to
`disable user` and `clear user sessions`. Newly installed connectors are added to
the Guided Response agent's pre-selected list by ES itself.

Two alternatives to the manual upload:

- Configure a `soar` account in `ta_gen_ai_cim_account.conf` and set
  `install_simulator = true` in `ta_gen_ai_cim_es.conf`. The add-on then
  installs it over the SOAR REST API on the next seeding run, packaging
  `medadvice_idp/` in memory, so this works from the TA package with no
  tarball. This route needs a SOAR credential because Mission Control's pairing
  proxy, which the add-on uses for everything else, has no app-install route.
- From a git checkout only (`tools/` is not in the TA package):
  `python3 tools/show_postdeploy.py --soar-only --soar-url https://<tenant>.soar.splunkcloud.com --soar-smoke-test`
  with a SOAR password or token exported.

## Build and test

These need a git checkout; `tools/` is not in the TA package.

```bash
python3 tools/soar/gen_personas.py          # only after editing lookups/medadvice_identities.csv
PYTHONPATH=tools/soar/tests/phantom_shim:soar_apps/medadvice_idp \
  /opt/splunk104/bin/splunk cmd python3.13 -m unittest discover -s tools/soar/tests -v
bash tools/soar/build.sh
```

See `tools/soar/README.md` for the action table, the parameter contract and
rollback.
