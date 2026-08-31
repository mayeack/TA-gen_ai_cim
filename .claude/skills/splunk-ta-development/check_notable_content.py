#!/usr/bin/env python3
"""
check_notable_content.py - Mechanical enforcement of R-SEC-001.

Flags any savedsearches.conf stanza that interpolates a $token$ into an
outbound parameter (ES notable, email, ServiceNow case) when that token's
field is derived from raw model input/output.

Usage: python3 check_notable_content.py [path/to/savedsearches.conf]
Exit:  0 clean, 1 violations found.
"""
import re
import sys
import pathlib

# Field expressions that carry raw model content, or free text written about it.
RAW = re.compile(
    r"gen_ai\.(input|output)\.messages"
    r"|input_messages\{\}|output_messages\{\}"
    r"|\bprompt_text\b|\bresponse_text\b"
    r"|_prompt\b|_response\b"
    r"|\.explanation\b|pi_explanation",
    re.I,
)

# Parameters whose value leaves the source index.
OUTBOUND = re.compile(
    r"^(action\.notable\.param\.(?:rule_description|rule_title)"
    r"|action\.email\.(?:subject|message)"
    r"|action\.create_snow_case\.param\.\S+)\s*=\s*(.*)$",
    re.M,
)



def producing_exprs(search, token):
    """Yield each expression that assigns `token`, as a whole term.

    Walks backwards from the `as <token>` / `eval <token> =` site to the start
    of the term, treating a comma or pipe at parenthesis depth 0 as the
    boundary. A fixed-width window is not enough: the real-world offender
    `values(eval(if(is_injection=1,_prompt,null()))) as injection_prompts`
    contains commas inside its own parentheses.
    """
    out = []
    sites = [m.start() for m in
             re.finditer(r"\b(?:as|AS)\s+" + re.escape(token) + r"\b", search)]
    sites += [m.start() for m in
              re.finditer(r"\beval\s+" + re.escape(token) + r"\s*=", search)]
    for site in sites:
        depth = 0
        i = site - 1
        while i >= 0:
            c = search[i]
            if c == ")":
                depth += 1
            elif c == "(":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and c in ",|":
                break
            i -= 1
        term = search[i + 1:site].strip().rstrip("\\").strip()
        # For `eval x = <expr>`, the payload is to the RIGHT of the site.
        if re.match(r"^eval\s", search[site:site + 5]):
            tail = search[site:]
            depth = 0
            for j, c in enumerate(tail):
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                elif depth == 0 and c in ",|" and j > 0:
                    break
            else:
                j = len(tail)
            term = tail[:j].strip().rstrip("\\").strip()
        if term:
            out.append(term)
    return out


def main() -> int:
    path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1
                        else "default/savedsearches.conf")
    if not path.is_file():
        print(f"not found: {path}", file=sys.stderr)
        return 2

    text = path.read_text()
    hits = []

    for stanza in re.split(r"\n(?=\[)", text):
        name = stanza.split("\n", 1)[0].strip()
        if not name.startswith("["):
            continue
        # The search body: the `search =` key plus its backslash continuations.
        search = "".join(
            re.findall(r"^search\s*=\s*(.*(?:\n(?!\w+\s*=|\[).*)*)", stanza, re.M)
        )
        for m in OUTBOUND.finditer(stanza):
            key, value = m.group(1), m.group(2)
            for token in sorted(set(re.findall(r"\$(\w[\w.]*)\$", value))):
                for expr in producing_exprs(search, token):
                    if RAW.search(expr):
                        hits.append((name, key, token, expr[:160]))

    if hits:
        print("  FAIL  R-SEC-001  raw model content reaches an outbound parameter:")
        for name, key, token, expr in hits:
            print(f"        {name}")
            print(f"          {key} <- ${token}$")
            print(f"          derived from: {expr}")
        return 1

    print("  PASS  R-SEC-001  no outbound parameter carries raw model content")
    return 0


if __name__ == "__main__":
    sys.exit(main())
