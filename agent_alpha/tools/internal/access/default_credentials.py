# agent_alpha/tools/internal/access/default_credentials.py
"""Known-default credential catalog loader — the SINGLE source (anti-Lyndon #7).

Externalizes the default-credential dictionary out of tool bodies into
``default_credentials.yaml`` (data, not logic — mirrors coverage.load_catalog).
Before this, ``default_creds._DEFAULT_CREDENTIALS`` (a per-platform dict) and
``odoo_access._assemble_candidates`` (an inline admin/admin list) were TWO diverged
sources for one concept ("the default creds to try"). This module is now the one
place both read from.

Pure + deterministic: the only I/O is loading the static YAML. Public defaults only
— never recon-harvested secrets, never a spray wordlist (bounded per platform).
"""

from __future__ import annotations

import pathlib
from collections.abc import Mapping

import yaml

_CATALOG_PATH = pathlib.Path(__file__).with_name("default_credentials.yaml")

# Type alias: platform -> ordered list of (username, password) default pairs.
CredentialCatalog = dict[str, list[tuple[str, str]]]


def load_default_credentials(path: pathlib.Path | None = None) -> CredentialCatalog:
    """Load the default-credential catalog from YAML.

    YAML sequences become tuples (hashable — required for the order-stable dedup in
    ``credentials_for``). Returns a fresh mutable dict each call (so a caller may cache
    it at module import and monkeypatch it in tests without mutating other callers)."""
    data = yaml.safe_load((path or _CATALOG_PATH).read_text())
    catalog: CredentialCatalog = {}
    for platform, pairs in (data.get("default_credentials") or {}).items():
        catalog[str(platform)] = [(str(u), str(p)) for u, p in pairs]
    return catalog


def credentials_for(
    tech_stack: Mapping[str, str], *, catalog: CredentialCatalog | None = None
) -> list[tuple[str, str]]:
    """Assemble the default-credential list for a target: ``generic`` + every platform
    whose key appears as a substring in ``tech_stack`` values. Deduplicated, order-stable.

    ``catalog`` lets a caller pass a specific (e.g. import-cached, monkeypatchable) dict;
    when omitted the YAML is loaded fresh. Single implementation of the merge (anti-#6):
    ``default_creds._build_credential_list`` delegates here."""
    cat = catalog if catalog is not None else load_default_credentials()
    creds: list[tuple[str, str]] = list(cat.get("generic", []))
    tech_blob = " ".join(tech_stack.values()).lower()
    for platform, platform_creds in cat.items():
        if platform != "generic" and platform in tech_blob:
            creds.extend(platform_creds)
    return list(dict.fromkeys(creds))


def platform_defaults(
    platform: str, *, catalog: CredentialCatalog | None = None
) -> list[tuple[str, str]]:
    """Return ONLY the named platform's default pairs (no generic merge). Used by
    odoo_access, which tries its own platform defaults, not the generic set."""
    cat = catalog if catalog is not None else load_default_credentials()
    return list(cat.get(platform, []))
