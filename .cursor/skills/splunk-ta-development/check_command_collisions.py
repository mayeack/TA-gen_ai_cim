#!/usr/bin/env python3
"""
check_command_collisions.py - R-PY-001.

A custom search command subclasses splunklib's SearchCommand, which owns a set
of names: read-only properties (logger, service, metadata, ...) and the
instance attributes its __init__ assigns (_service, _metadata, ...). A command
that assigns one of those properties fails with "property ... has no setter",
and a command method named like one of those attributes is replaced by the
attribute's value on every instance ("'NoneType' object is not callable"). Both
happen only at dispatch, after btool and py_compile have passed.

Run from the app root under Splunk's Python, so lib/splunklib resolves:

    /opt/splunk104/bin/splunk cmd python3.13 .claude/skills/splunk-ta-development/check_command_collisions.py

Exits non-zero on any FAIL.
"""
import ast, glob, sys
sys.path.insert(0, 'lib')
from splunklib.searchcommands import (EventingCommand, GeneratingCommand,  # noqa: E402
                                      ReportingCommand, StreamingCommand)
BASES = {c.__name__: c for c in (EventingCommand, GeneratingCommand, ReportingCommand, StreamingCommand)}
fails = 0
for path in sorted(glob.glob('bin/*.py')):
    tree = ast.parse(open(path, encoding='utf-8').read())
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        bases = [b.id if isinstance(b, ast.Name) else getattr(b, 'attr', '') for b in cls.bases]
        base = next((BASES[b] for b in bases if b in BASES), None)
        if base is None:
            continue
        owned = set(vars(base()))
        readonly = {n for n in dir(base) if isinstance(getattr(base, n, None), property)
                    and getattr(base, n).fset is None}
        methods = {n.name for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        assigned = {t.attr for n in ast.walk(cls) if isinstance(n, ast.Assign) for t in n.targets
                    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == 'self'}
        shadowed, readonly_set = sorted(methods & owned), sorted(assigned & readonly)
        status = 'FAIL' if (shadowed or readonly_set) else 'OK  '
        fails += status == 'FAIL'
        print('  %s %-22s %-20s shadowed=%s assigns_readonly=%s'
              % (status, path[4:], cls.name, shadowed or '-', readonly_set or '-'))
print('  failures:', fails)
sys.exit(1 if fails else 0)
