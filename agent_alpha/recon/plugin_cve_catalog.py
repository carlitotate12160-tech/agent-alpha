# agent_alpha/recon/plugin_cve_catalog.py — SSOT. Data-tier (refreshed as data, never code).
from dataclasses import dataclass


@dataclass(frozen=True)
class CveHit:
    cve_id: str
    cvss: float
    cwe: str
    summary: str


# slug -> [(max_affected_version, CveHit)]. Start narrow; expand as data.
_CATALOG: dict[str, list[tuple[str, CveHit]]] = {
    "wp-file-manager": [
        (
            "6.8",
            CveHit(
                "CVE-2020-25213", 9.8, "CWE-434", "WP File Manager unrestricted file upload -> RCE"
            ),
        ),
    ],
}


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a dotted version string into a tuple of ints for comparison."""
    parts: list[int] = []
    for chunk in v.split("."):
        # Strip non-digit suffixes (e.g. "6.0-beta" -> 6, 0)
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _version_le(version: str, max_affected: str) -> bool:
    """Return True iff version <= max_affected (numeric comparison)."""
    v_parts = _parse_version(version)
    m_parts = _parse_version(max_affected)
    # Pad shorter tuple with zeros
    length = max(len(v_parts), len(m_parts))
    v_padded = v_parts + (0,) * (length - len(v_parts))
    m_padded = m_parts + (0,) * (length - len(m_parts))
    return v_padded <= m_padded


def lookup(slug: str, version: str | None) -> CveHit | None:
    """Return a CveHit iff slug is catalogued AND version is known AND <= max_affected.
    version=None -> None (cannot confirm 'affected' -> not a finding, anti-#3)."""
    if version is None:
        return None
    for max_affected, hit in _CATALOG.get(slug, []):
        if _version_le(version, max_affected):
            return hit
    return None
