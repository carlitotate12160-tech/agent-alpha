"""Slice X: default-credential catalog externalized to YAML (single source, anti-#7).

Cardinal contract: default_creds AND odoo_access read known-default creds from ONE
source (default_credentials.yaml), never inline literals in the tool bodies. The
externalization is BEHAVIOUR-PRESERVING — the exact pairs each tool tried are unchanged.
"""

from __future__ import annotations

from pathlib import Path

import agent_alpha.tools.internal.access.default_creds as dc_mod
import agent_alpha.tools.internal.access.odoo_access as odoo_mod
from agent_alpha.tools.internal.access.default_credentials import (
    credentials_for,
    load_default_credentials,
    platform_defaults,
)
from agent_alpha.tools.internal.access.odoo_access import OdooAccessTool


def test_yaml_is_single_source_with_all_platforms() -> None:
    cat = load_default_credentials()
    assert {"generic", "wp", "tomcat", "jenkins", "phpmyadmin", "grafana", "joomla", "odoo"} <= set(
        cat
    )
    # odoo now HAS an entry (was orphaned inline in the tool — the #7 divergence)
    assert cat["odoo"] == [("admin", "admin"), ("admin", "password")]
    # pairs are hashable tuples (order-stable dedup relies on it)
    assert all(isinstance(p, tuple) and len(p) == 2 for creds in cat.values() for p in creds)


def test_credentials_for_merges_generic_and_platform() -> None:
    creds = credentials_for({"cms": "wp"})
    assert ("admin", "admin") in creds  # wp + generic overlap
    assert ("root", "toor") in creds  # generic-only
    assert len(creds) == len(dict.fromkeys(creds)), "must be deduped, order-stable"


def test_odoo_defaults_sourced_from_yaml_single_source() -> None:
    """CARDINAL: odoo's default candidates derive from the SAME yaml catalog, and the
    exact pairs (behaviour) are preserved — admin/admin then admin/password."""
    tool = OdooAccessTool(http_client=object())
    defaults = [(u, p) for (u, p, src, _node) in tool._assemble_candidates() if src == "default"]
    assert defaults == platform_defaults("odoo")
    assert defaults == [("admin", "admin"), ("admin", "password")]


def test_no_inline_credential_literals_remain_in_tool_bodies() -> None:
    """GUARD against #7 regression: the cred PAIRS live in the yaml, not the tool source.
    RED until the orphaned literals are removed from both tool bodies."""
    odoo_src = Path(odoo_mod.__file__).read_text(encoding="utf-8")
    dc_src = Path(dc_mod.__file__).read_text(encoding="utf-8")
    # the orphaned odoo default candidate literals
    assert '("admin", "admin", "default"' not in odoo_src
    # a distinctive generic pair that must have moved out of default_creds into the yaml
    assert '("root", "toor")' not in dc_src
    assert '("admin", "admin123")' not in dc_src
