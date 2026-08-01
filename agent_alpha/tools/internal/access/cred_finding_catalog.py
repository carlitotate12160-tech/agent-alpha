# agent_alpha/tools/internal/access/cred_finding_catalog.py
"""cred_finding_catalog — SSOT for credential-ACCESS finding classes.

When Beta gains access with a NEWLY obtained credential, the vuln node it mints must
name the finding ACCURATELY — a client report is only payable if it is correct. A
default credential (``admin/admin``, publicly known) and a *predictable* credential
derived from an enumerated username (GAP-015) are DIFFERENT findings with different
CWE/CVSS. This module is the single place mapping each class →
(vuln id-suffix, CVSS, CWE, human label, exploit_available), so no tool or persistence
site hardcodes those values (anti-#4/#7). Beta.step reads the class the tool declares on
its finding; a finding with no class resolves to DEFAULT_CREDENTIALS, keeping the
historical default_creds output byte-identical (backward compatible).
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum


class CredFindingClass(StrEnum):
    """The kind of credential-access finding Beta proved. One class per concept (#6)."""

    DEFAULT_CREDENTIALS = "default_credentials"  # admin/admin — publicly known default
    PREDICTABLE_CREDENTIAL = "predictable_credential"  # derived from enumerated identity (GAP-015)


@dataclasses.dataclass(frozen=True)
class CredFindingSpec:
    """Canonical, report-ready facts for one credential-access finding class."""

    vuln_id_suffix: str
    cvss: float
    cwe: str
    label: str
    exploit_available: bool


CRED_FINDING_CATALOG: dict[CredFindingClass, CredFindingSpec] = {
    CredFindingClass.DEFAULT_CREDENTIALS: CredFindingSpec(
        vuln_id_suffix="default_credentials",
        cvss=9.8,
        cwe="CWE-1392",  # Use of Default Credentials
        label="Default credentials accepted",
        exploit_available=True,
    ),
    CredFindingClass.PREDICTABLE_CREDENTIAL: CredFindingSpec(
        vuln_id_suffix="predictable_credential",
        cvss=8.8,
        cwe="CWE-521",  # Weak Password Requirements — guessable from a public identity
        label="Predictable credential derived from an enumerated username",
        exploit_available=True,
    ),
}

# Backward-compatible default: a finding that declares no class is a default-credential
# win (the historical default_creds behaviour) — existing output stays byte-identical.
DEFAULT_CRED_FINDING_CLASS = CredFindingClass.DEFAULT_CREDENTIALS


def resolve_cred_finding_spec(finding_class: str | None) -> CredFindingSpec:
    """Map a finding's declared class (or None → default) to its canonical spec.

    Fail-safe: an unknown/malformed value falls back to the default rather than raising —
    a buggy tool must never crash Beta's persistence path (anti-Lyndon #3-adjacent: a
    persistence error must not be silently swallowed elsewhere, but a bad label degrades
    gracefully to the conservative default class).
    """
    if finding_class is None:
        return CRED_FINDING_CATALOG[DEFAULT_CRED_FINDING_CLASS]
    try:
        cls = CredFindingClass(finding_class)
    except ValueError:
        return CRED_FINDING_CATALOG[DEFAULT_CRED_FINDING_CLASS]
    return CRED_FINDING_CATALOG[cls]
