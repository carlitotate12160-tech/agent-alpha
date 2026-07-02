# agent_alpha/security/credential_assembly.py
"""Shared credential-assembly seam — ONE pipeline for all stack-specific leak
extractors (Laravel Whoops, WordPress wp-config, future stacks).

Anti-Lyndon #6 (duplicate-type): without this, each stack would fork the
pairing + standalone + vault logic, and the anti-#3 / vault invariants would
drift apart.  Each stack provides its own ``leaked`` dict and per-stack key
maps; this module does the generic assembly.

Behaviour-preserving extraction from ``Alpha._extract_leaked_credentials``
(scout.py).  The Laravel tests (test_credential_pairing, test_alpha_vaulting,
test_cred_reuse_chain) are the regression guard.
"""

from __future__ import annotations

from typing import Any

from agent_alpha.graph.nodes import (
    AttackEdge,
    AttackNode,
    CredentialProperties,
    NodeType,
    RelationshipType,
)


def assemble_leaked_credentials(
    leaked: dict[str, str],
    *,
    host: str,
    vuln_node_id: str,
    login_pairs: dict[str, tuple[str, str]],
    username_keys: frozenset[str],
    secret_keys: frozenset[str],
    service_map: dict[str, str],
    secrets_manager: Any | None,
    engagement_id: str,
    now_utc: str,
    leak_source: str = "laravel_debug",
) -> tuple[list[AttackNode], list[AttackEdge]]:
    """Assemble CREDENTIAL nodes from a stack-agnostic ``{KEY: value}`` leak dict.

    Emits ONE paired login node per service in *login_pairs* whose (ukey, skey)
    are BOTH present (username=ukey value, secret_ref=vault(skey value)).
    Username keys are NEVER standalone (anti-#3 false credential).

    ADDITIVE: the secret key (e.g. DB_PASSWORD) is ALSO emitted as a standalone
    fragment so the web cred_reuse chain (which depends on it with
    ``username=""``) continues to work.  The paired login node is emitted FIRST
    so cred_reuse tries it before the fragment.

    Only keys in *secret_keys* become standalone nodes — metadata like DB_NAME
    or DB_HOST is dropped (they are not credentials).

    Returns ``(nodes, edges)`` — the caller persists them.
    """
    nodes: list[AttackNode] = []
    edges: list[AttackEdge] = []

    # ── Paired login credentials (emitted first) ───────────────────────
    for service, (ukey, skey) in login_pairs.items():
        if ukey not in leaked or skey not in leaked:
            continue
        uvalue = leaked[ukey]
        svalue = leaked[skey]

        if secrets_manager is not None:
            record = secrets_manager.store(
                label=f"{service}:login",
                value=svalue,
                engagement_id=engagement_id,
            )
            secret_ref = record.secret_id
        else:
            secret_ref = f"engagements/{engagement_id}/proofs/{leak_source}_{host}#login"

        cred_node = AttackNode(
            id=f"cred:{host}:{service}:login",
            type=NodeType.CREDENTIAL,
            properties=CredentialProperties(
                username=uvalue,
                secret_ref=secret_ref,
                service=service,
                access_level="unverified",
            ),
            confidence=0.85,
            agent="alpha",
            timestamp_utc=now_utc,
        )
        nodes.append(cred_node)
        edges.append(
            AttackEdge(
                source_id=vuln_node_id,
                target_id=cred_node.id,
                relationship=RelationshipType.LEADS_TO,
                confidence=0.85,
            )
        )

    # ── Standalone credential nodes for secret keys only ───────────────
    for key, raw_value in leaked.items():
        # Skip username keys — they are NOT secrets (anti-#3).
        if key in username_keys:
            continue
        # Skip keys that are not in the secret set — metadata like DB_NAME /
        # DB_HOST are not credentials and must not become nodes.
        if key not in secret_keys:
            continue

        # Determine the service label from the key prefix (SSOT).
        service = "unknown"
        for prefix, svc in service_map.items():
            if key.startswith(prefix):
                service = svc
                break

        if secrets_manager is not None:
            record = secrets_manager.store(
                label=f"{service}:{key}",
                value=raw_value,
                engagement_id=engagement_id,
            )
            secret_ref = record.secret_id
        else:
            secret_ref = f"engagements/{engagement_id}/proofs/{leak_source}_{host}#{key}"

        cred_node = AttackNode(
            id=f"cred:{host}:{key.lower()}",
            type=NodeType.CREDENTIAL,
            properties=CredentialProperties(
                username="",
                secret_ref=secret_ref,
                service=service,
                access_level="unverified",
            ),
            confidence=0.85,
            agent="alpha",
            timestamp_utc=now_utc,
        )
        nodes.append(cred_node)
        edges.append(
            AttackEdge(
                source_id=vuln_node_id,
                target_id=cred_node.id,
                relationship=RelationshipType.LEADS_TO,
                confidence=0.85,
            )
        )

    return nodes, edges
