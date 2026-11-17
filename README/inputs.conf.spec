#
# inputs.conf.spec - Modular input schemes
# TA-gen_ai_cim
#
# Declares the ta_gen_ai_cim_duo modular input (entry point
# bin/ta_gen_ai_cim_duo.py, logic in bin/ta_gen_ai_cim_duo_input.py):
# Cisco Duo authentication logs, activity logs or a users snapshot from the
# Duo Admin API, one endpoint per instance. Splunk reads modular-input
# schemes only from README/inputs.conf.spec, so this file ships in the
# package. No instance ships in default/; add one in local/.
#
# Compatible with: Splunk Enterprise 9.0+, Splunk Cloud
#

###############################################################################
# CISCO DUO (ta_gen_ai_cim_duo)
###############################################################################

[ta_gen_ai_cim_duo://<name>]

account = <string>
* Required. The ta_gen_ai_cim_account stanza that holds the Duo Admin API
  credentials: auth_type = duo_hmac, url = https://api-<x>.duosecurity.com
  (or .duofederal.com; https only), client_id = the integration key. The
  secret key lives in storage/passwords (realm
  ta_gen_ai_cim_account__<account>, name client_secret) and is read with the
  input's own session key. The Admin API application needs only "Grant read
  log" and "Grant resource - Read".
* Letters, digits, underscore, dot and hyphen only.

endpoint = authentication|activity|users
* Required. The one Duo endpoint this instance reads:
  * authentication: GET /admin/v2/logs/authentication, sourcetype
    ta_gen_ai_cim:duo:authentication, _time from the record's timestamp.
  * activity: GET /admin/v2/logs/activity (Duo public preview; opt in),
    sourcetype ta_gen_ai_cim:duo:activity, _time from the record's ts.
  * users: GET /admin/v1/users, sourcetype ta_gen_ai_cim:duo:user, one event
    per user with an allowlist of fields plus snapshot_id, snapshot_total
    and snapshot_seq; _time is the snapshot time. Use interval = 86400.

lag_seconds = <integer>
* How far behind now a log window ends. Duo delays its logs by about two
  minutes, so the value must be at least 120; at most 86400.
* Ignored for endpoint = users.
* Default: 180

initial_lookback_hours = <integer>
* Where the first log window starts, in hours before now, when no
  checkpoint exists yet. Between 1 and 4320 (Duo keeps 180 days of logs; a
  start older than that, less an hour of margin, begins at that floor).
* Ignored for endpoint = users.
* Default: 24

# Behaviour notes (not settings):
# * Interval: at least 120 seconds (validated on UI/REST edits; a run that
#   starts less than 115 s after the last checkpoint write is skipped, so a
#   lower interval set directly in local/ cannot poll faster). Each run makes
#   one Duo log call (up to 1000 records, sort=ts:asc), as Duo asks for no
#   more than one log request a minute; at interval = 300 that is about
#   288,000 records a day. The users endpoint pages through every user in one
#   run, retrying a page that answers 429 or a transient error up to 6 times
#   (1 s doubling to 32 s plus jitter, at least Retry-After, at most 120 s of
#   waiting per snapshot) before it gives up and writes nothing.
# * Checkpoint: KV collection ta_gen_ai_cim_duo_checkpoint, _key = the input
#   stanza name, fields mintime_ms, maxtime_ms, next_offset, backoff_until and
#   updated, saved after each page. Duo returns a next_offset on its last page
#   with records too, so a saved next_offset is a cursor: the next run resumes
#   after it with mintime = its timestamp and maxtime = now - lag_seconds. A
#   page with no records or no next_offset (or a next_offset equal to the one
#   sent, logged at WARN) completes the window; the next one starts at
#   maxtime + 1 ms. A run is skipped while the window would be empty
#   (mintime >= now - lag_seconds).
# * Retention: an unfinished window is never abandoned; once Duo's retention
#   floor passes its cursor it resumes at the floor (WARN), so only records
#   Duo no longer holds are missed.
# * Duplicates: a run killed after writing a page but before saving its
#   checkpoint resends that page (at most one page); deduplicate on txid.
# * Loss: a page is checkpointed once its events reach splunkd, so events still
#   in splunkd's pipeline when splunkd crashes are not re-read (at most once).
# * Rate limits: HTTP 429 / Duo code 42901 backs off 120 s, doubling per
#   consecutive 429 up to an hour (backoff_until in the checkpoint).
# * Search head cluster: only the captain polls (best effort, untested); a
#   failed captain lookup skips the run with a WARN.
# * index: set it per instance (the docs and macros assume duo); never
#   gen_ai_log.
