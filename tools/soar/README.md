# MedAdvice Identity Provider — simulated SOAR app for the GenAI workshop

`tools/soar/` holds a small **Splunk SOAR app that pretends to be MedAdvice's
identity provider**. It exists for one reason: Splunk Enterprise Security 8.6
response plans and the **Guided Response agent** can only recommend and run
actions that are installed on the paired SOAR, and the demo-mock Okta / Azure AD
/ AD LDAP assets on the ES8 demo tenant return *"No data found for
app/action/parameter"* for every MedAdvice persona. With this app installed, the
agent can answer *"Disable user t.nguyen"* with a real, repeatable action.

**Everything here is simulated.** The connector never opens a network
connection, never touches a directory, keeps no state, and every result carries
`"simulated": true`. That flag is the only thing separating a lab containment
record from a real one — never strip it, and never let the app imply real
enforcement. The `tools/` tree is dev-only and is not part of the TA tarball.

## Layout

| Path | Purpose |
|---|---|
| `medadvice_idp/medadvice_idp.json` | App manifest (classic connector format): six actions, `contains` chosen so the finding's `user` artifact matches |
| `medadvice_idp/medadvice_idp_connector.py` | `BaseConnector` implementation, standard library only, Python 3.9 and 3.13 |
| `medadvice_idp/medadvice_idp_consts.py` | **Generated** persona table from `lookups/medadvice_identities.csv` plus messages |
| `gen_personas.py` | Regenerates the consts module (`--check` fails when it is stale) |
| `build.sh` | Packages `dist/medadvice_idp.tgz` (gitignored) |
| `tests/` | Offline unit tests with a 60-line stand-in for the `phantom` package |

## Actions

| Action | Type | Parameters | Result |
|---|---|---|---|
| test connectivity | test | — | always succeeds |
| get user | investigate | `username` | persona record (`status: active`, synthetic department, user id, last login) |
| list user sessions | investigate | `username` | 1–2 synthetic DemoBot sessions |
| **disable user** | **contain** | `username`, `reason` | `status: disabled`, message *Account t.nguyen disabled (simulated)* |
| enable user | correct | `username`, `reason` | `status: active` |
| clear user sessions | contain | `username`, `reason` | `sessions_revoked: N` |

`username` accepts a username, a user id or an email (`contains`: `user name`,
`user id`, `email`). Unknown usernames get a synthesised record marked
`known: false` rather than an error. A username that still contains `$` or
`%24` — an ES token such as `$user$` that was never substituted — is rejected
with an explicit message so nobody "disables" a token.

## Build, test, install

```bash
python3 tools/soar/gen_personas.py                 # only after editing the identities CSV
PYTHONPATH=tools/soar/tests/phantom_shim:tools/soar/medadvice_idp \
  /opt/splunk104/bin/splunk cmd python3.13 -m unittest discover -s tools/soar/tests -v
bash tools/soar/build.sh                            # -> tools/soar/dist/medadvice_idp.tgz
```

Install and configure it on the paired SOAR with the post-deploy script (steps
10–13), which is idempotent and also binds the response-plan Containment tasks
to the app's actions when run together with the Splunk steps:

```bash
export SOAR_PASSWORD='...'        # or SOAR_AUTH_TOKEN
python3 tools/show_postdeploy.py --soar-only \
  --soar-url https://<tenant>.soar.splunkcloud.com --soar-username soar_local_admin \
  --soar-smoke-test --dry-run
```

Drop `--dry-run` to apply. Or install by hand: SOAR → *Apps → Install App* →
upload the tarball → *Configure New Asset* named `medadvice_idp`. The Guided
Response agent adds new connectors to its pre-selected list automatically.

Step 12 of the script only *lists* the other identity-management assets on the
tenant (on the ES8 demo tenant: `okta`, `azure_ad`, `ldap`, all in demo mock
mode). Keep the Guided Response agent off them by deselecting those connectors
in ES under *Configure → All configurations → Security AI Assistant settings*
— not by editing the assets: `POST /rest/asset/<id>` re-saves the whole asset
(absent fields fall back to defaults such as `concurrency_limit` and the
`mock_app` flag, masked secrets are re-stored) and ignores `disabled`.

## Rollback

Delete the `medadvice_idp` asset and the app in the SOAR UI (or
`DELETE /rest/asset/<id>` and `DELETE /rest/app/<id>`), and re-select the other
connectors in the ES Guided Response list. Existing findings and investigations
are unaffected.
