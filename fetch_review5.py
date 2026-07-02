import subprocess, json

data = json.loads(subprocess.check_output(
    ["gh", "api", "repos/carlitotate12160-tech/agent-alpha/pulls/69/comments", "--paginate"]
))

for i, c in enumerate(data[:2], 1):
    path = c.get("path", "?")
    line = c.get("line", "?")
    body = c.get("body", "")
    lines = body.split("\n")
    summary = []
    for l in lines:
        s = l.strip()
        if s.startswith("<!--") or s.startswith("<a") or s.startswith("<picture") or s.startswith("<img") or s.startswith("<source") or s.startswith("</"):
            continue
        if s.startswith("---") or s.startswith("*Was this helpful"):
            break
        summary.append(l)
    text = "\n".join(summary[:12])
    print(f"=== ISSUE {i} ===")
    print(f"FILE: {path}:{line}")
    print(text)
    print()
