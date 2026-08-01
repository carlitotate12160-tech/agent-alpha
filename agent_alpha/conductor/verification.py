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


def verify_access_nodes(graph_store: Any, event_store: Any, engagement_id: str) -> None:
    """Run the autonomous attestor roster over the engagement's ACCESS_LEVEL nodes.

    Idempotent-safe: INCONCLUSIVE nodes are left untouched; CONFIRMED nodes are promoted
    via an event-sourced NodeVerified with attestor provenance.
    """
    run_verification_pass(graph_store, event_store, [CredReuseAttestor()], engagement_id)
