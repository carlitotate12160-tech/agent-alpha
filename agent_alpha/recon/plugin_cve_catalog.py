# agent_alpha/recon/plugin_cve_catalog.py — compatibility API over the §12.67 JSONL corpus.
from dataclasses import dataclass

from agent_alpha.recon.cve_correlation import correlate, load_corpus


@dataclass(frozen=True)
class CveHit:
    cve_id: str
    cvss: float
    cwe: str
    summary: str


def lookup(slug: str, version: str | None) -> CveHit | None:
    """Return the highest-ranked known-CVE hit for a product and affected version."""
    if version is None:
        return None
    hypotheses = correlate(slug, version, corpus=load_corpus())
    if not hypotheses:
        return None
    hypothesis = hypotheses[0]
    return CveHit(
        cve_id=hypothesis.cve_id,
        cvss=hypothesis.cvss,
        cwe=hypothesis.cwe,
        summary=hypothesis.summary,
    )
