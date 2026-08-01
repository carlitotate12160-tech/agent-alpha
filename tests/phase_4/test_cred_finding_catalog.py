"""Contract: cred_finding_catalog is the SSOT mapping a credential-access finding
class → accurate report facts (vuln id-suffix, CVSS, CWE). A payable report must NOT
mislabel a predictable-credential win as a default credential.

RED before the catalog exists: the import fails.

Lyndon checks:
  #4/#7 — one place defines each class's CVSS/CWE/id; no hardcoding at the tool or
          persistence site.
  #3-adjacent — resolve() is fail-safe: a bad class degrades to the conservative
          default, never crashes the persistence path.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_4/test_cred_finding_catalog.py -v
"""

from __future__ import annotations

from agent_alpha.tools.internal.access.cred_finding_catalog import (
    CRED_FINDING_CATALOG,
    DEFAULT_CRED_FINDING_CLASS,
    CredFindingClass,
    resolve_cred_finding_spec,
)


def test_default_credentials_spec_is_accurate() -> None:
    spec = CRED_FINDING_CATALOG[CredFindingClass.DEFAULT_CREDENTIALS]
    assert spec.vuln_id_suffix == "default_credentials"
    assert spec.cvss == 9.8
    assert spec.cwe == "CWE-1392"
    assert spec.exploit_available is True


def test_predictable_credential_spec_is_distinct_and_accurate() -> None:
    """GAP-015 win must be its OWN finding — different id, CVSS, and CWE (CWE-521,
    weak/guessable), never conflated with a default credential."""
    spec = CRED_FINDING_CATALOG[CredFindingClass.PREDICTABLE_CREDENTIAL]
    assert spec.vuln_id_suffix == "predictable_credential"
    assert spec.cwe == "CWE-521"
    default = CRED_FINDING_CATALOG[CredFindingClass.DEFAULT_CREDENTIALS]
    assert spec.vuln_id_suffix != default.vuln_id_suffix
    assert spec.cwe != default.cwe


def test_resolve_none_is_default_backward_compat() -> None:
    """A finding with no declared class stays exactly the historical default_creds
    finding (byte-identical output)."""
    assert resolve_cred_finding_spec(None) is CRED_FINDING_CATALOG[DEFAULT_CRED_FINDING_CLASS]


def test_resolve_known_class_by_string() -> None:
    spec = resolve_cred_finding_spec("predictable_credential")
    assert spec.vuln_id_suffix == "predictable_credential"
    assert spec.cvss == 8.8


def test_resolve_unknown_class_fails_safe_to_default() -> None:
    """A malformed/unknown class degrades to the conservative default — a buggy tool
    must never crash Beta's persistence path."""
    assert (
        resolve_cred_finding_spec("garbage_class")
        is (CRED_FINDING_CATALOG[DEFAULT_CRED_FINDING_CLASS])
    )
