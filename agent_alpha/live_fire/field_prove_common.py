"""Shared field-prove verdict helpers — ONE definition for all self-owned lab
harnesses (git_exposure, backup_file, and future stack probes).

Anti-Lyndon #6 (duplicate canonical logic): the "is a minted CREDENTIAL actually
vaulted?" check is stack-agnostic — it inspects the graph and the vault, never a
stack-specific format. Hoisted here (mirrors the slice-1 extract_secrets hoist to
security/leak_extraction.py) so every field-prove runner shares the SAME honesty
gate instead of forking it and drifting the anti-#3 invariant.
"""

from __future__ import annotations

from typing import Any

from agent_alpha.graph.nodes import NodeType


def credential_vaulted(graph_store: Any, secrets_manager: Any) -> bool:
    """True iff a CREDENTIAL node carries a vault pointer (secret_ref) that
    actually resolves in the secrets manager.

    An inline/unresolvable pointer is NOT proof of a vaulted secret (anti-#3):
    a "credential" that cannot be retrieved from the vault is not payable.
    """
    for node in graph_store.nodes_by_type(NodeType.CREDENTIAL):
        ref = getattr(node.properties, "secret_ref", "")
        if not ref.startswith("secret_"):
            continue
        try:
            secrets_manager.retrieve(ref)
            return True
        except Exception:
            continue
    return False
