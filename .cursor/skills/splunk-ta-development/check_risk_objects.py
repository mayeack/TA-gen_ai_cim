#!/usr/bin/env python3
"""
check_risk_objects.py - R-CONF-006.

When a result row carries a risk_object field, the ES risk action
(SA-ThreatIntelligence/bin/risk_extractor.py) uses it - and a result-level
risk_object_type - in place of EVERY entry in action.risk.param._risk. A rule
that declares two risk objects (user + src) and also evals risk_object therefore
writes the first object twice and never the second. Any rule with risk_object
_field entries in _risk must leave risk_object out of its results.

The finding still needs an entity: Mission Control's Entity column and
risk-score badge read risk_object on the finding. So a rule that raises a
finding (action.notable = 1) with risk configured must name its entity in
action.notable.param._entities, which notable.py applies to the finding only.
Without it the Entity column renders "--".

Run from the app root. Matches only the search= value, joining conf
line-continuations, so a comment that mentions risk_object is not a hit.
Exits non-zero on any FAIL.
"""
import io, json, re, sys
conf = io.open('default/savedsearches.conf', encoding='utf-8').read()
fails = 0
for st in re.finditer(r'^\[([^\]]+)\]\n(.*?)(?=\n\[|\Z)', conf, re.S | re.M):
    name, body = st.group(1), st.group(2)
    risk = re.search(r'^action\.risk\.param\._risk = (.*)$', body, re.M)
    if not re.search(r'^action\.risk = 1$', body, re.M) or not risk:
        continue
    fields = [e.get('risk_object_field') for e in json.loads(risk.group(1)) if e.get('risk_object_field')]
    m = re.search(r'^search = ((?:.*\\\n)*.*)$', body, re.M)
    spl = m.group(1).replace('\\\n', ' ') if m else ''
    emits = bool(re.search(r'(?i)(\beval\b[^|]*\brisk_object(_type)?\s*=|\bas\s+risk_object(_type)?\b)', spl))
    finding = bool(re.search(r'^action\.notable = 1$', body, re.M))
    ent = re.search(r'^action\.notable\.param\._entities = (.*)$', body, re.M)
    entities = [e.get('risk_object_field') for e in json.loads(ent.group(1))] if ent else []
    status = 'FAIL' if (fields and emits) or (fields and finding and not entities) else 'OK  '
    fails += status == 'FAIL'
    print('  %s %-62s risk_objects=%s emits_risk_object=%s entities=%s'
          % (status, name[:62], ','.join(fields), emits, ','.join(entities) or '-'))
print('  failures:', fails)
sys.exit(1 if fails else 0)
