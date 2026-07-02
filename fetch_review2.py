import subprocess, json

data = json.loads(subprocess.check_output(
    ["gh", "api", "repos/carlitotate12160-tech/agent-alpha/pulls/69/comments", "--paginate"]
))

for i, c in enumerate(data, 1):
    path = c.get("path", "?")
    line = c.get("line", "?")
    body = c.get("body", "")
    lines = body.split("\n")
    summary = []
    for l in lines:
        if l.strip().startswith("<!--") or l.strip().startswith("<a") or l.strip().startswith("<picture") or l.strip().startswith("<img") or l.strip().startswith("<source") or l.strip().startswith("</"):
            continue
        if l.strip().startswith("---") or l.strip().startswith("*Was this helpful"):
            break
        summary.append(l)
    text = "\n".join(summary[:12])
    print(f"=== ISSUE {i}/{len(data)} ===")
    print(f"FILE: {path}:{line}")
    print(text)
    print()
