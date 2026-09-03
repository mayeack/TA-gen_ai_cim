# MedAdvice Identity Provider — simulated SOAR app for the GenAI workshop

The TA ships a small **Splunk SOAR app that pretends to be MedAdvice's identity
provider** (source in `default/data/soar_apps/medadvice_idp/`; this directory
holds its build script, persona generator and offline tests). It exists for one
reason: Splunk Enterprise Security 8.6 response plans and the **Guided Response
agent** can only recommend and run actions that are installed on the paired
SOAR, and the demo-mock Okta / Azure AD / AD LDAP assets on the ES8 demo tenant
return *"No data found for app/action/parameter"* for every MedAdvice persona.
With this app installed, the agent can answer *"Disable user t.nguyen"* with a
real, repeatable action.

**Everything here is simulated.** The connector never opens a network
connection, never touches a directory, keeps no state, and every result carries
`"simulated": true`. That flag is the only thing separating a lab containment
record from a real one — never strip it, and never let the app imply real
enforcement. Nothing in the TA installs it on a SOAR unless an operator asks
(`install_simulator = true` plus a `soar` account, or `tools/show_postdeploy.py`).

## Layout

| Path | Purpose |
|---|---|
| `default/data/soar_apps/medadvice_idp/medadvice_idp.json` | App manifest (classic connector format): six actions, `contains` chosen so the finding's `user` artifact matches |
| `default/data/soar_apps/medadvice_idp/medadvice_idp_connector.py` | `BaseConnector` implementation, standard library only, Python 3.9 and 3.13 |
| `default/data/soar_apps/medadvice_idp/medadvice_idp_consts.py` | **Generated** persona table from `lookups/medadvice_identities.csv` plus messages |
| `bin/genai_es_seed.py` | Packages the source in memory (`build_soar_app_tgz`), installs it, creates the asset, binds the response plan — shared by `| genaiseedes` and `show_postdeploy.py` |
| `tools/soar/gen_personas.py` | Regenerates the consts module (`--check` fails when it is stale) |
| `tools/soar/build.sh` | Packages `tools/soar/dist/medadvice_idp.tgz` (gitignored) for a manual upload |
| `tools/soar/tests/` | Offline unit tests: the connector (60-line stand-in for the `phantom` package) and the seeding core (fake splunkd/SOAR transports) |

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

## Build and test

```bash
python3 tools/soar/gen_personas.py                 # only after editing the identities CSV
PYTHONPATH=tools/soar/tests/phantom_shim:default/data/soar_apps/medadvice_idp \
  /opt/splunk104/bin/splunk cmd python3.13 -m unittest discover -s tools/soar/tests -v
bash tools/soar/build.sh                            # -> tools/soar/dist/medadvice_idp.tgz
```

## Install (once per SOAR tenant)

The ES/SOAR pairing proxy that `| genaiseedes` uses has no app-install route,
so the app reaches a tenant one of three ways; the asset and the response-plan
binding follow automatically on the next `| genaiseedes` run in every case.

1. `tools/show_postdeploy.py --soar-only --soar-url https://<tenant>.soar.splunkcloud.com --soar-smoke-test`
   with `$SOAR_PASSWORD` or `$SOAR_AUTH_TOKEN` exported (dry-run first).
2. A `soar` account in the TA (`ta_gen_ai_cim_account.conf`: `url`,
   `auth_type = token` or `basic`, the token/password stored as the account
   password) plus `install_simulator = true` in `ta_gen_ai_cim_es.conf`.
3. SOAR UI: *Apps → Install App* → upload the tarball → *Configure New Asset*
   named `medadvice_idp`.

The Guided Response agent adds new connectors to its pre-selected list
automatically. `| genaiseedes` (and the script's step 12) only *lists* the other
identity-management assets on the tenant (on the ES8 demo tenant: `okta`,
`azure_ad`, `ldap`, all in demo mock mode). Keep the agent off them by
deselecting those connectors in ES under *Configure → All configurations →
Security AI Assistant settings* — not by editing the assets: `POST
/rest/asset/<id>` re-saves the whole asset (absent fields fall back to defaults
such as `concurrency_limit` and the `mock_app` flag, masked secrets are
re-stored) and ignores `disabled`.

## Rollback

Delete the `medadvice_idp` asset and the app in the SOAR UI (or
`DELETE /rest/asset/<id>` and `DELETE /rest/app/<id>`), and re-select the other
connectors in the ES Guided Response list. Existing findings and investigations
are unaffected; the next `| genaiseedes` run reports the binding as skipped and
preserves whatever the plan tasks still carry.
