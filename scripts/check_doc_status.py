#!/usr/bin/env python3
"""Check that ADR, bug, and GAP status fields are consistent.

Rules:
- Every tracked section must have a Status field.
- OPEN / IN_PROGRESS entries must NOT have a Closed by / Fixed in / Implemented in / Verified in reference.
- DONE / FIXED / CLOSED / ADDRESSED / TERADDRESS entries MUST have at least one reference.
- LOCKED is allowed for ADR decisions and moved-to-ADR GAP stubs; reference optional.
- WONTFIX is allowed; reference optional.

Run locally: python scripts/check_doc_status.py
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

ROOT: Final[Path] = Path(__file__).resolve().parents[1]

# (file, heading regex, label)
TRACKED_FILES: Final[list[tuple[Path, re.Pattern[str], str]]] = [
    (ROOT / "docs" / "BUGS.md", re.compile(r"^## Bug \d+:", re.MULTILINE), "Bug"),
    (ROOT / "docs" / "ADR.md", re.compile(r"^### \d+\.\d+", re.MULTILINE), "ADR"),
    (ROOT / "docs" / "BUGS_AND_GAPS.md", re.compile(r"^## GAP-\d+:", re.MULTILINE), "GAP"),
]

# Status keywords that imply the item is finished and should be referenced.
FINAL_STATUSES: Final[set[str]] = {"DONE", "FIXED", "CLOSED", "ADDRESSED", "TERADDRESS"}

# Status keywords that imply the item is not yet finished and must NOT be referenced.
OPEN_STATUSES: Final[set[str]] = {"OPEN", "IN_PROGRESS"}

# Status keywords that are allowed but have no strict reference requirement.
ALLOWED_STATUSES: Final[set[str]] = {"LOCKED", "WONTFIX", "PROPOSED", "DRAFT", "PARTIALLY"} | FINAL_STATUSES | OPEN_STATUSES

REF_PATTERNS: Final[list[re.Pattern[str]]] = [
    re.compile(r"closed by", re.IGNORECASE),
    re.compile(r"fixed in", re.IGNORECASE),
    re.compile(r"implemented in", re.IGNORECASE),
    re.compile(r"verified in", re.IGNORECASE),
    re.compile(r"resolved by", re.IGNORECASE),
    re.compile(r"pr\s*#", re.IGNORECASE),
    re.compile(r"commit\s+[0-9a-f]{7,40}", re.IGNORECASE),
]


@dataclass(frozen=True)
class Section:
    file: Path
    kind: str
    title: str
    body: str


def iter_sections(path: Path, pattern: re.Pattern[str], kind: str) -> list[Section]:
    text = path.read_text(encoding="utf-8")
    matches = list(pattern.finditer(text))
    sections: list[Section] = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        title = text[start : text.find("\n", start)].strip()
        body = text[start:end]
        sections.append(Section(path, kind, title, body))
    return sections


def extract_status(body: str, title: str, kind: str) -> str | None:
    # Match lines like "- **Status**: OPEN" or "**Status:** LOCKED (2026-07-14)"
    m = re.search(r"\*\*Status\*\*:\s*([A-Za-z_]+)", body)
    if m:
        return m.group(1).strip().upper()
    # Fallback: plain "Status: OPEN" line
    m = re.search(r"^Status:\s*([A-Za-z_]+)", body, re.MULTILINE)
    if m:
        return m.group(1).strip().upper()
    # For ADR, infer status from heading keywords if no explicit field is present.
    if kind == "ADR":
        upper = title.upper()
        if "LOCKED" in upper:
            return "LOCKED"
        if "PROPOSED" in upper:
            return "PROPOSED"
        if "DRAFT" in upper:
            return "DRAFT"
    return None


def has_reference(body: str) -> bool:
    return any(p.search(body) for p in REF_PATTERNS)


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []
    summary: dict[str, dict[str, int]] = {}

    for path, pattern, kind in TRACKED_FILES:
        if not path.exists():
            # Some tracked files may be .gitignored locally (e.g. client-named docs).
            # Treat as a warning so CI does not fail when they are absent.
            warnings.append(f"{path}: file not found — skipped")
            continue

        sections = iter_sections(path, pattern, kind)
        summary[kind] = {}
        for section in sections:
            status = extract_status(section.body, section.title, section.kind)
            if status is None:
                if section.kind == "ADR":
                    # ADR sections created before this convention may lack a Status.
                    # Treat as a warning so the convention can be adopted gradually.
                    warnings.append(
                        f"{path}:{section.title}: no explicit Status field "
                        "(add **Status**: LOCKED/PROPOSED/DRAFT)"
                    )
                    continue
                errors.append(f"{path}:{section.title}: missing Status field")
                continue

            summary[kind][status] = summary[kind].get(status, 0) + 1

            if status not in ALLOWED_STATUSES:
                errors.append(f"{path}:{section.title}: unknown status '{status}'")
                continue

            ref = has_reference(section.body)
            if status in OPEN_STATUSES and ref:
                errors.append(
                    f"{path}:{section.title}: status {status} but contains a close/fix reference"
                )
            if status in FINAL_STATUSES and not ref:
                errors.append(
                    f"{path}:{section.title}: status {status} but missing a close/fix reference "
                    "(add 'Closed by:', 'Fixed in:', 'Implemented in:', 'Verified in:', PR#, or commit)"
                )

    print("Documentation status summary")
    print("=" * 40)
    for kind, counts in summary.items():
        print(f"\n{kind}:")
        for status, count in sorted(counts.items()):
            print(f"  {status:15s} {count}")

    if warnings:
        print("\nWarnings:")
        for warn in warnings:
            print(f"  - {warn}")

    if errors:
        print("\nErrors:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("\nAll documentation status checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
