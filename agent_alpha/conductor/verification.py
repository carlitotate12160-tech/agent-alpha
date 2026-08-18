# agent_alpha/conductor/verification.py
"""Autonomous cross-verification seam (slice-1c).

Single source (#7) of the attestor roster that runs on the Conductor path. Runs the
independent attestors over ACCESS_LEVEL nodes so a payable report can claim 'proven'
(CROSS_VERIFIED) autonomously — not only via the a1 field-prove runner.

Pure graph+event orchestration: CredReuseAttestor checks proof-binding (no live re-auth,
no network, no auth tier). Emits provenance-checked NodeVerified events; the graph
projection promotes SELF_VERIFIED → CROSS_VERIFIED only when provenance is present.
"""

from __future__ import annotations

from typing import Any

from agent_alpha.attestation.attestor import CredReuseAttestor, run_verification_pass


def verify_access_nodes(
    graph_store: Any, event_store: Any, engagement_id: str, secrets_manager: Any = None
) -> None:
    """Run the autonomous attestor roster over the engagement's ACCESS_LEVEL nodes.

    Idempotent-safe: INCONCLUSIVE nodes are left untouched; CONFIRMED nodes are promoted
    via an event-sourced NodeVerified with attestor provenance.

    ``secrets_manager`` (GAP-118): threaded to CredReuseAttestor so Rule 3 requires the backing
    credential's ``secret_ref`` to RESOLVE in the vault (not merely be non-empty) — closes the
    false-provenance where a bare-UUID proof pointer cross-verified a non-harvested access.
    """
    run_verification_pass(
        graph_store, event_store, [CredReuseAttestor(secrets_manager)], engagement_id
    )
