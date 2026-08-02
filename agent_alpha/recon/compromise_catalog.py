# agent_alpha/recon/compromise_catalog.py — SSOT. Data-tier (refreshed as data, never code).
"""Compromise indicators over already-fetched HTML (§12.40 content-analysis).

Detects that a site is ALREADY COMPROMISED — e.g. injected SEO/gambling spam (a
parasite-hosting / cloaked-injection pattern rife on hacked WordPress in SE Asia).
This is what a CVE scanner misses and what an external attacker (and Strix on
bernofarm) surfaces: "from outside it looks fine, inside it is owned."

Deterministic + high-precision (anti-#3): a finding is minted ONLY when the injection
signal is strong (many gambling anchors OR hidden-link blocks), never on a single stray
keyword in legitimate prose. Zero LLM. The site owner usually cannot see this (served to
crawlers / injected into templates) — detecting it from outside is the differentiator.

NOTE (doctrine §12.45): a POSITIVE is a proven compromise indicator. A NEGATIVE is NOT a
clean bill of health — it means "no injected-spam signal in the fetched HTML", nothing more.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Gambling / SEO-spam lexicon (Indonesian + generic). Data-tier — expand as observed.
_SPAM_TERMS: frozenset[str] = frozenset(
    {
        "judi", "slot", "togel", "casino", "poker", "gacor", "bandar", "sbobet",
        "maxwin", "rtp", "pragmatic", "toto", "bola", "taruhan", "jackpot", "pokerv",
        "domino", "qq", "situs judi", "slot online", "judi online", "slot gacor",
    }
)

# Anchor-context spam matches at/above this count = injected spam link farm, not prose.
_MIN_SPAM_ANCHORS: int = 5

_ANCHOR_RE = re.compile(r"<a\b[^>]*>(.*?)</a>", re.IGNORECASE | re.DOTALL)
_HREF_RE = re.compile(r'<a\b[^>]*\bhref=["\']([^"\']+)["\']', re.IGNORECASE)
# Hidden containers commonly used to cloak injected link farms from human visitors.
_HIDDEN_RE = re.compile(
    r'style=["\'][^"\']*(display\s*:\s*none|font-size\s*:\s*0|position\s*:\s*absolute[^"\']*left\s*:\s*-)',
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CompromiseFindingSpec:
    """Report-ready facts for a compromise indicator (SSOT)."""

    vuln_id_suffix: str
    cvss: float
    cwe: str
    label: str


SEO_INJECTION_SPEC = CompromiseFindingSpec(
    vuln_id_suffix="seo_injection_compromise",
    cvss=9.1,  # a live compromise / parasite hosting is a critical integrity + reputational breach
    cwe="CWE-506",  # Embedded Malicious Code
    label="Indicator of compromise: injected SEO/gambling spam content",
)


@dataclass(frozen=True)
class SeoInjectionResult:
    matched_terms: tuple[str, ...]
    spam_anchor_count: int
    hidden_block: bool


def _spam_hits(text: str) -> list[str]:
    low = text.lower()
    return [t for t in _SPAM_TERMS if t in low]


def detect_seo_injection(html: str) -> SeoInjectionResult | None:
    """Return a SeoInjectionResult iff the HTML shows a STRONG injected-spam signal,
    else None. Signal = many gambling anchors, OR a hidden container carrying spam terms.

    High-precision by design: a single 'casino' in an article never triggers; an injected
    link farm (many spam anchors) or a cloaked hidden block does.
    """
    if not html:
        return None

    # Count anchors whose TEXT or HREF carries a spam term (link-farm signature).
    spam_anchor_count = 0
    matched: set[str] = set()
    for m in _ANCHOR_RE.finditer(html):
        hits = _spam_hits(m.group(1))
        if hits:
            spam_anchor_count += 1
            matched.update(hits)
    for m in _HREF_RE.finditer(html):
        hits = _spam_hits(m.group(1))
        if hits:
            spam_anchor_count += 1
            matched.update(hits)

    # Hidden container carrying spam terms = cloaked injection (strong signal even at low count).
    hidden_block = False
    for m in _HIDDEN_RE.finditer(html):
        window = html[m.start(): m.start() + 2000]  # bounded look-ahead into the hidden block
        if _spam_hits(window):
            hidden_block = True
            matched.update(_spam_hits(window))
            break

    if spam_anchor_count >= _MIN_SPAM_ANCHORS or hidden_block:
        return SeoInjectionResult(
            matched_terms=tuple(sorted(matched)),
            spam_anchor_count=spam_anchor_count,
            hidden_block=hidden_block,
        )
    return None
