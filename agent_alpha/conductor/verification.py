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
    graph_store: Any, event_store: Any, engagement_id: str, secrets_manager: Any
) -> None:
    """Run the autonomous attestor roster over the engagement's ACCESS_LEVEL nodes.

    Fail-closed: production callers must always pass the engagement-scoped vault. The legacy
    non-empty fallback remains only for explicit direct-attestor unit tests; silently defaulting to
    no vault on the runtime verification seam re-opens the false-provenance bug.
    """
    if secrets_manager is None:
        raise ValueError("secrets_manager is required for production verification")

    run_verification_pass(
        graph_store,
        event_store,
        [CredReuseAttestor(secrets_manager=secrets_manager, engagement_id=engagement_id)],
        engagement_id,
    )
