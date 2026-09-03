#!/usr/bin/env python3
"""
check_search_owner.py - R-CONF-005.

An object shipped in default/ is owned by `nobody`, which holds no roles, and
the scheduler runs a saved search in its owner's context. So any enabled saved
search that invokes a custom command whose [commands/<name>] read ACL excludes
`nobody` must carry an owner stanza in metadata/default.meta:

    [savedsearches/<URL-encoded name>]
    owner = admin

Without it the search fails config load with "Session is not logged in" and,
having nobody to report to, does so silently.

Run from the app root. Exits non-zero on any FAIL.
"""
import io, re, sys, urllib.parse
conf = io.open('default/savedsearches.conf', encoding='utf-8').read()
meta = io.open('metadata/default.meta', encoding='utf-8').read()
restricted = {m for m, acl in re.findall(r'\[commands/([^\]]+)\]\s*\naccess = read : \[([^\]]*)\]', meta)
              if '*' not in acl}
owners = {urllib.parse.unquote(m) for m in re.findall(r'\[savedsearches/([^\]]+)\]', meta)}
fails = 0
for st in re.finditer(r'^\[([^\]]+)\]\n(.*?)(?=\n\[|\Z)', conf, re.S | re.M):
    name, body = st.group(1), st.group(2)
    if not re.search(r'^disabled = 0$', body, re.M):
        continue
    # only the search= value, joining conf line-continuations; comments excluded
    m = re.search(r'^search = ((?:.*\\\n)*.*)$', body, re.M)
    spl = m.group(1).replace('\\\n', ' ') if m else ''
    used = sorted(c for c in restricted if re.search(r'\|\s*' + re.escape(c) + r'\b', spl))
    status = 'OK  ' if (not used or name in owners) else 'FAIL'
    if status == 'FAIL':
        fails += 1
    print('  %s %-58s cmd=%-14s owner=%s' % (status, name[:58], ','.join(used) or '-', name in owners))
print('  failures:', fails)
sys.exit(1 if fails else 0)
