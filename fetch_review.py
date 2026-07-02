dari import subprocess, json, sys

data = json.loads(subprocess.check_output(
    ["gh", "api", "repos/carlitotate12160-tech/agent-alpha/pulls/69/comments", "--paginate"]
))

for c in data:
    path = c.get("path", "?")
    line = c.get("line", "?")
    body = c.get("body", "")
    # Extract first meaningful lines
    lines = body.split("\n")
    summary = []
    for l in lines:
        if l.strip().startswith("<!--") or l.strip().startswith("<a") or l.strip().startswith("<picture") or l.strip().startswith("<img") or l.strip().startswith("<source") or l.strip().startswith("</"):
            continue
        if l.strip().startswith("---") or l.strip().startswith("*Was this helpful"):
            break
        summary.append(l)
    print(f"---\nFILE: {path}:{line}")
    print("\n".join(summary[:10]))
    print()
