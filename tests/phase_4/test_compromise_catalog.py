"""Contract: compromise_catalog detects an ALREADY-COMPROMISED site (injected SEO/
gambling spam) from already-fetched HTML — the "looks fine outside, owned inside" case
(§12.40). Deterministic + high-precision (anti-#3): only strong signals mint a finding.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_4/test_compromise_catalog.py -v
"""

from __future__ import annotations

import inspect

from agent_alpha.recon import compromise_catalog as mod
from agent_alpha.recon.compromise_catalog import SEO_INJECTION_SPEC, detect_seo_injection


def test_legit_prose_mentioning_gambling_is_not_flagged() -> None:
    """Precision: a single 'casino' in a legitimate article must NOT trigger (no FP)."""
    html = "<html><body><p>This article discusses casino addiction risks.</p>"
    html += "<a href='/about'>About us</a></body></html>"
    assert detect_seo_injection(html) is None


def test_injected_gambling_link_farm_is_flagged() -> None:
    """An injected spam link farm (many gambling anchors) is a proven compromise indicator."""
    html = (
        "<html><body>"
        + "".join(
            f"<a href='https://slot{i}.xyz/gacor'>Situs Judi Slot Gacor Maxwin {i}</a>"
            for i in range(8)
        )
        + "</body></html>"
    )
    result = detect_seo_injection(html)
    assert result is not None
    assert result.spam_anchor_count >= 5
    assert "judi" in result.matched_terms or "slot" in result.matched_terms


def test_cloaked_hidden_block_is_flagged_even_at_low_count() -> None:
    """A hidden container (display:none) carrying spam terms is cloaked injection —
    strong signal even with few links."""
    html = (
        "<html><body><div style='display:none'>"
        "<a href='/x'>judi online togel</a><a href='/y'>sbobet</a>"
        "</div></body></html>"
    )
    result = detect_seo_injection(html)
    assert result is not None
    assert result.hidden_block is True


def test_clean_and_empty_pages_return_none() -> None:
    assert detect_seo_injection("<html><body><h1>Welcome</h1></body></html>") is None
    assert detect_seo_injection("") is None


def test_spec_is_report_accurate() -> None:
    assert SEO_INJECTION_SPEC.vuln_id_suffix == "seo_injection_compromise"
    assert SEO_INJECTION_SPEC.cwe == "CWE-506"
    assert SEO_INJECTION_SPEC.cvss >= 9.0


def test_no_wordlist_file_or_llm() -> None:
    """Deterministic, self-contained lexicon — no external file, no LLM import/call."""
    src = inspect.getsource(mod)
    assert "open(" not in src, "must not read an external wordlist file"
    assert "import openai" not in src and "LLMOrchestrator" not in src
    assert "provider.generate" not in src and ".complete(" not in src


def test_cloaked_external_link_farm_without_keywords_is_flagged() -> None:
    """Bernofarm (Strix #1/#2): 3 HIDDEN external links to random compromised domains,
    cloaked via position:absolute;left:-9999px, carrying NO gambling keyword. The
    keyword-based path would miss it; the structural hidden-link-farm signal must catch it."""
    html = (
        "<html><body><h1>Bernofarm</h1>"
        '<div style="position:absolute; left:-9999px;">'
        '<a href="https://synergyformusic.com/x">music</a>'
        '<a href="https://pd-vosac.hr/y">vosac</a>'
        '<a href="https://scherpfondstad.org/z">stad</a>'
        "</div><p>Welcome.</p></body></html>"
    )
    result = detect_seo_injection(html)
    assert result is not None
    assert result.hidden_link_farm is True


def test_visible_social_footer_is_not_flagged() -> None:
    """Precision: a VISIBLE footer with external social links is normal — no FP."""
    html = (
        "<html><body><footer>"
        '<a href="https://facebook.com/us">FB</a>'
        '<a href="https://twitter.com/us">TW</a>'
        '<a href="https://instagram.com/us">IG</a>'
        "</footer></body></html>"
    )
    assert detect_seo_injection(html) is None
