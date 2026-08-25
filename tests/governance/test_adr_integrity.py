from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_ADR = _ROOT / "docs" / "ADR.md"
_SUMMARY = _ROOT / "docs" / "ADR_SUMMARY.md"
_SUPPLEMENTAL_IDS = {
    "12.24": _ROOT / "docs" / "adr_bounded_autonomy_stall_semantics.md",
    "ADR-GOV-001": _ROOT / "docs" / "adr_wiring_gate.md",
}
_DECISION_STATUSES = frozenset(
    {"PROPOSED", "ACCEPTED", "SUPERSEDED", "REJECTED", "DEFERRED", "PARKED"}
)


def _duplicates(values: list[str]) -> set[str]:
    return {value for value, count in Counter(values).items() if count > 1}


def _main_ids(text: str) -> list[str]:
    return re.findall(r"^### (?:§)?(12\.\d+)\b", text, re.MULTILINE)


def _summary_ids(text: str) -> list[str]:
    return re.findall(r"^- \*\*(12\.\d+)\b", text, re.MULTILINE)


def test_adr_numeric_ids_are_unique() -> None:
    ids = _main_ids(_ADR.read_text(encoding="utf-8"))
    assert not _duplicates(ids), f"duplicate ADR numeric IDs: {sorted(_duplicates(ids))}"


def test_summary_ids_are_unique_and_resolve() -> None:
    adr_ids = set(_main_ids(_ADR.read_text(encoding="utf-8")))
    summary_ids = _summary_ids(_SUMMARY.read_text(encoding="utf-8"))
    assert not _duplicates(summary_ids), (
        f"duplicate ADR summary IDs: {sorted(_duplicates(summary_ids))}"
    )
    unresolved = set(summary_ids) - adr_ids - set(_SUPPLEMENTAL_IDS)
    assert not unresolved, f"summary references unknown ADR IDs: {sorted(unresolved)}"
    assert all(path.is_file() for path in _SUPPLEMENTAL_IDS.values())


def test_canonical_domain_authority_is_unique_and_resolves() -> None:
    text = _ADR.read_text(encoding="utf-8")
    start = text.index("**Canonical domain authority matrix:**")
    end = text.index("## 0. Design Principles", start)
    matrix = text[start:end]
    rows = re.findall(r"^\| ([a-z][a-z0-9_]*) \| (.+) \|$", matrix, re.MULTILINE)
    domains = [domain for domain, _ in rows]
    assert domains
    assert not _duplicates(domains), (
        f"duplicate canonical authority domains: {sorted(_duplicates(domains))}"
    )

    adr_ids = set(_main_ids(text))
    unresolved: set[str] = set()
    for _, authority in rows:
        for ref in re.findall(r"§(12\.\d+)|\b(ADR-[A-Z]+-\d+)\b", authority):
            identifier = ref[0] or ref[1]
            if identifier not in adr_ids and identifier not in _SUPPLEMENTAL_IDS:
                unresolved.add(identifier)
    assert not unresolved, f"authority matrix references unknown ADR IDs: {sorted(unresolved)}"


def test_explicit_decision_statuses_use_canonical_vocabulary() -> None:
    text = _ADR.read_text(encoding="utf-8")
    statuses = re.findall(r"\*\*Decision status:\*\*\s*([A-Z]+)", text)
    assert statuses
    invalid = set(statuses) - _DECISION_STATUSES
    assert not invalid, f"invalid architecture decision statuses: {sorted(invalid)}"
    assert "**Status:** PROPOSED / LOCKED" not in text


def test_security_and_state_authority_regressions_are_absent() -> None:
    adr = _ADR.read_text(encoding="utf-8")
    wiring = (_ROOT / "docs" / "adr_wiring_gate.md").read_text(encoding="utf-8")
    assert "AttackGraph as single source of truth" not in adr
    assert "`sha256(canonical_profile_json)` + principal" not in adr
    assert "# ADR §12.35 — Wiring Gate" not in wiring
    assert wiring.startswith("# ADR-GOV-001")
