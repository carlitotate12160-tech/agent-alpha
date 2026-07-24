"""Offline scorer unit tests for the A1 validation-vs-scanner comparison.

CI-guarded (no network) — validates the SCORER logic, not the live chain.

Test contract:
  T1: parse_nuclei_jsonl handles synthetic .jsonl (2 findings) + empty file -> [].
  T2: scanner-missed TRUE: chain_proven=True + nuclei info/low -> scanner_missed True.
  T3: honest-both-ways: 50 nuclei findings + proven chain -> report shows BOTH.
  T4: CDN-blocked outcome: web_access_level="" -> "blocked by CDN -> evasion gap".
  T5: no-overclaim: scanner_missed_exploitability False when chain_proven=False.
"""

from __future__ import annotations

import json
import pathlib

from agent_alpha.live_fire.odoo_chain_runner import OdooChainResult
from agent_alpha.live_fire.validation_vs_scanner import (
    NucleiFinding,
    compare,
    format_report,
    parse_nuclei_jsonl,
)

# ── Helpers ───────────────────────────────────────────────────────────


def _proven_chain_result() -> OdooChainResult:
    """A chain result where chain_proven is True."""
    return OdooChainResult(
        leak_creds_added=1,
        web_access_level="admin",
        edge_from_harvested_cred=True,
        db_enumerated=True,
        leak_suspected=False,
    )


def _failed_chain_result() -> OdooChainResult:
    """A chain result where chain_proven is False (no leak found)."""
    return OdooChainResult(
        leak_creds_added=0,
        web_access_level="",
        edge_from_harvested_cred=False,
        db_enumerated=False,
        leak_suspected=False,
    )


def _cdn_blocked_chain_result() -> OdooChainResult:
    """A chain result simulating CDN/WAF block — empty access, no creds."""
    return OdooChainResult(
        leak_creds_added=0,
        web_access_level="",
        edge_from_harvested_cred=False,
        db_enumerated=False,
        leak_suspected=False,
    )


def _make_nuclei_line(
    template_id: str = "http-missing-security-headers",
    severity: str = "info",
    matched_at: str = "https://odoo.lab:443",
) -> str:
    """Build a single Nuclei JSONL line."""
    return json.dumps({
        "template-id": template_id,
        "info": {"severity": severity},
        "matched-at": matched_at,
    })


# ── T1: parse_nuclei_jsonl ────────────────────────────────────────────


class TestParseNucleiJsonl:
    """T1: parse_nuclei_jsonl handles synthetic .jsonl + empty file."""

    def test_parse_two_findings(self, tmp_path: pathlib.Path) -> None:
        """Two valid JSONL lines -> two NucleiFinding objects."""
        p = tmp_path / "nuclei.jsonl"
        lines = [
            _make_nuclei_line("http-missing-security-headers", "info", "https://odoo.lab:443"),
            _make_nuclei_line("wp-config-exposure", "low", "https://odoo.lab/wp-config.php.bak"),
        ]
        p.write_text("\n".join(lines), encoding="utf-8")

        findings = parse_nuclei_jsonl(p)
        assert len(findings) == 2
        assert findings[0].template_id == "http-missing-security-headers"
        assert findings[0].severity == "info"
        assert findings[1].template_id == "wp-config-exposure"
        assert findings[1].severity == "low"

    def test_empty_file(self, tmp_path: pathlib.Path) -> None:
        """Empty file -> empty list (tolerant)."""
        p = tmp_path / "empty.jsonl"
        p.write_text("", encoding="utf-8")
        assert parse_nuclei_jsonl(p) == []

    def test_missing_file(self, tmp_path: pathlib.Path) -> None:
        """Non-existent file -> empty list (tolerant)."""
        assert parse_nuclei_jsonl(tmp_path / "nope.jsonl") == []

    def test_malformed_lines_skipped(self, tmp_path: pathlib.Path) -> None:
        """Malformed JSON lines are silently skipped."""
        p = tmp_path / "bad.jsonl"
        p.write_text(
            "not json\n" + _make_nuclei_line("valid-template", "medium") + "\n{broken",
            encoding="utf-8",
        )
        findings = parse_nuclei_jsonl(p)
        assert len(findings) == 1
        assert findings[0].template_id == "valid-template"


# ── T2: scanner-missed TRUE ──────────────────────────────────────────


class TestScannerMissedTrue:
    """T2: chain_proven=True + nuclei info/low -> scanner_missed True."""

    def test_scanner_missed_exploitability(self) -> None:
        chain = _proven_chain_result()
        nuclei = [
            NucleiFinding("http-missing-security-headers", "info", "https://odoo.lab"),
            NucleiFinding("wp-config-exposure", "low", "https://odoo.lab/wp-config.php.bak"),
        ]
        verdict = compare(chain, nuclei)

        assert verdict.scanner_missed_exploitability is True
        assert verdict.nuclei_proved_exploitable is False
        assert verdict.alpha_chain_proven is True
        assert verdict.alpha_access_level == "admin"
        assert verdict.nuclei_flagged_leak is True
        assert verdict.nuclei_leak_severity == "low"

    def test_nuclei_proved_exploitable_always_false(self) -> None:
        """nuclei_proved_exploitable is structurally False, regardless of findings."""
        chain = _proven_chain_result()
        # Even with a "critical" nuclei finding, it cannot PROVE exploitability.
        nuclei = [NucleiFinding("rce-template", "critical", "https://odoo.lab")]
        verdict = compare(chain, nuclei)
        assert verdict.nuclei_proved_exploitable is False


# ── T3: honest-both-ways ─────────────────────────────────────────────


class TestHonestBothWays:
    """T3: 50 nuclei findings + proven chain -> report shows BOTH numbers."""

    def test_report_shows_both_nuclei_total_and_chain(self) -> None:
        chain = _proven_chain_result()
        nuclei = [
            NucleiFinding(f"template-{i}", "info", f"https://odoo.lab/path-{i}")
            for i in range(50)
        ]
        verdict = compare(chain, nuclei)

        assert verdict.nuclei_total == 50
        assert verdict.alpha_chain_proven is True

        report = format_report(verdict)
        # Report text must carry BOTH numbers — honest both ways.
        assert "50" in report  # Nuclei's total finding count
        assert "admin" in report  # Alpha's proven access level
        assert "SCANNER-MISSED-EXPLOITABILITY PROVEN: True" in report
        # Must note Nuclei's breadth advantage.
        assert "BROADER" in report or "broader" in report.lower()
        assert "NARROW" in report or "narrow" in report.lower()


# ── T4: CDN-blocked outcome ──────────────────────────────────────────


class TestCdnBlocked:
    """T4: CDN-blocked -> "blocked by CDN -> evasion gap", scanner_missed=False."""

    def test_cdn_blocked_verdict(self) -> None:
        chain = _cdn_blocked_chain_result()
        nuclei = [NucleiFinding("waf-detect", "info", "https://odoo.lab")]
        verdict = compare(chain, nuclei, cdn_blocked=True)

        assert verdict.cdn_blocked is True
        assert verdict.scanner_missed_exploitability is False  # honest: proved nothing
        assert verdict.alpha_chain_proven is False

        report = format_report(verdict)
        assert "blocked by CDN" in report
        assert "evasion gap" in report
        assert "SCANNER-MISSED-EXPLOITABILITY PROVEN: False" in report


# ── T5: no-overclaim ─────────────────────────────────────────────────


class TestNoOverclaim:
    """T5: scanner_missed_exploitability False when chain_proven=False."""

    def test_failed_chain_no_overclaim(self) -> None:
        chain = _failed_chain_result()
        nuclei = [NucleiFinding("some-template", "info", "https://odoo.lab")]
        verdict = compare(chain, nuclei)

        assert verdict.scanner_missed_exploitability is False
        assert verdict.alpha_chain_proven is False

    def test_partial_chain_no_overclaim(self) -> None:
        """Even with creds but no access level, scanner_missed is False."""
        chain = OdooChainResult(
            leak_creds_added=1,
            web_access_level="",
            edge_from_harvested_cred=True,
            db_enumerated=True,
            leak_suspected=False,
        )
        assert chain.chain_proven is False

        verdict = compare(chain, [])
        assert verdict.scanner_missed_exploitability is False

    def test_leak_suspected_no_overclaim(self) -> None:
        """leak_suspected=True -> chain_proven=False -> no overclaim."""
        chain = OdooChainResult(
            leak_creds_added=1,
            web_access_level="admin",
            edge_from_harvested_cred=True,
            db_enumerated=True,
            leak_suspected=True,  # suspected = not proven
        )
        assert chain.chain_proven is False

        verdict = compare(chain, [])
        assert verdict.scanner_missed_exploitability is False
