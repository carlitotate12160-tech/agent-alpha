"""Conductor-side applicator factory — the ONLY place where authorization state
and scope are read to decide WHICH credential applicators cred_reuse may use, and
against WHICH in-scope target each one is bound.

Why this exists (the three flaws it converges):

  FLAW 1 (auth-gate softening): the tier filter — required_auth vs the engagement's
          current authorization state — lives ONLY here. cred_reuse receives the
          OUTPUT list and merely iterates; it holds no `auth` handle and never reads
          authorization state. If a future cred_reuse edit needs an `auth`/`scope`
          handle to do its job, the design has broken — STOP and redesign here.

  FLAW 2 (out-of-scope DB host trap): the MySQL/MariaDB target is resolved from an
          IN-SCOPE ASSET host:port discovered during authorized recon, validated by
          the gate (is_db_endpoint_in_scope). It is NEVER the leaked DB_HOST from the
          .env (which is typically localhost / an out-of-SOW internal IP).

  FLAW 3 (ServiceProperties has no host): host comes from AssetProperties.host; the
          DB port is bound to an asset only when it appears in that asset's
          open_ports. Host ⊕ port are joined here, not assumed co-located.

Lane: Claude (Conductor lane). Zero offensive body. The MySqlApplicator.apply body
that actually connects to 3306 is GLM/Kimi's; this module only selects and binds.

Single source of truth (#7): the required_auth -> state ladder is defined once here,
mirroring AuthorizationStateMachine.can_agent_proceed's tier ladder.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import STATE_RANK
from agent_alpha.graph.nodes import AssetProperties, NodeType, ServiceProperties

# required_auth label -> minimum engagement state that satisfies it.
_REQUIRED_AUTH_TO_STATE: dict[str, int] = {
    "ACTIVE_APPROVED": a2a_pb2.ACTIVE_APPROVED,
    "OFFENSIVE_APPROVED": a2a_pb2.OFFENSIVE_APPROVED,
}

# Services whose applicators bind to a host:port DB endpoint (vs an HTTP web login).
_DB_SERVICES: frozenset[str] = frozenset({"mysql", "mariadb"})


@runtime_checkable
class _Applicator(Protocol):
    """Structural view of CredentialApplicator the factory relies on (service + tier).
    The full protocol (applies_to/apply) lives in tools/internal/access/applicator.py;
    the factory only needs the selection metadata."""

    service: str
    required_auth: str


@dataclasses.dataclass(frozen=True)
class BoundApplicator:
    """An applicator paired with the in-scope target the Conductor resolved for it.

    cred_reuse calls ``applicator.apply(target=target, ...)`` passing this ``target``
    through VERBATIM. cred_reuse never chooses a target and never scope-checks one —
    the scope check already happened here, with the gate. This is the structural
    guarantee behind FLAW 1: the tool cannot bypass scope because it never sees a
    target that was not pre-validated.
    """

    applicator: Any  # CredentialApplicator (full protocol)
    target: str  # in-scope "host:port" (DB) or the web login URL (HTTP)

    def applies_to(self, credential_service: str, target: str) -> Any:
        return self.applicator.applies_to(credential_service, self.target)

    def apply(self, username: str, secret: str, target: str, budget: Any) -> Any:
        return self.applicator.apply(
            username=username,
            secret=secret,
            target=self.target,
            budget=budget,
        )


class AuthScopeView(Protocol):
    """Read-only slice of AuthorizationStateMachine the factory consumes. The factory
    receives the real gate instance (Conductor owns it); this Protocol documents the
    exact, minimal surface used — no transition methods, read-only."""

    def get_state(self, engagement_id: str) -> int: ...

    def is_db_endpoint_in_scope(self, engagement_id: str, host: str, port: int) -> bool: ...

    def assert_offensive_web_target(self, engagement_id: str, target: str) -> bool: ...


def build_applicators_for_engagement(
    *,
    engagement_id: str,
    auth: AuthScopeView,
    graph_store: Any,
    web_target: str | None = None,
    candidates: Sequence[_Applicator],
) -> list[BoundApplicator]:
    """Select and bind the applicators cred_reuse is permitted to use this engagement.

    Args:
        engagement_id: the engagement whose authorization state + scope gate apply.
        auth: the AuthorizationStateMachine (read-only here — FLAW 1 lives here only).
        graph_store: AttackGraph store; queried for ASSET + SERVICE nodes (FLAW 2/3).
        web_target: the engagement's web login target — already in scope and verified
            when the engagement entered RECON_ONLY (HTTP applicators bind to it).
        candidates: CredentialApplicator instances (http, mysql, ...). The registry of
            what *could* run; the factory decides what *may* run.

    Returns:
        BoundApplicator list. cred_reuse iterates it and calls apply(target=...) with
        the bound target. Empty list = nothing authorized/in-scope (a valid outcome,
        not an error).
    """
    current_state = auth.get_state(engagement_id)
    bound: list[BoundApplicator] = []
    for applicator in candidates:
        if not _tier_satisfied(applicator.required_auth, current_state):
            continue  # FLAW 1: tier gate — required_auth must be met by the state.
        for target in _resolve_in_scope_targets(
            applicator=applicator,
            engagement_id=engagement_id,
            auth=auth,
            graph_store=graph_store,
            web_target=web_target,
        ):
            bound.append(BoundApplicator(applicator=applicator, target=target))
    return bound


def _tier_satisfied(required_auth: str, current_state: int) -> bool:
    """True when ``current_state`` ranks at or above ``required_auth``'s min state.

    Fail-closed: an unknown required_auth label is DENIED (never silently allowed)."""
    required_state = _REQUIRED_AUTH_TO_STATE.get(required_auth)
    if required_state is None:
        return False
    return STATE_RANK.get(current_state, 0) >= STATE_RANK[required_state]


def _resolve_in_scope_targets(
    *,
    applicator: _Applicator,
    engagement_id: str,
    auth: AuthScopeView,
    graph_store: Any,
    web_target: str | None = None,
) -> list[str]:
    """Resolve the in-scope target(s) this applicator may run against.

    HTTP applicators bind to the engagement web target (already in scope). DB
    applicators bind ONLY to ASSET host:port endpoints that (a) the asset actually
    exposes (port in its open_ports — FLAW 3 join) and (b) the gate confirms are in
    the signed SOW scope (is_db_endpoint_in_scope — FLAW 2).
    """
    if applicator.service not in _DB_SERVICES:
        # HTTP applicators bind to the web target ONLY when it passes the
        # offensive web target gate (domain, not bare IP — shared-hosting safety).
        if web_target is None:
            return []
        if not auth.assert_offensive_web_target(engagement_id, web_target):
            return []  # bare IP or out-of-scope domain — do NOT bind
        return [web_target]

    asset_nodes = graph_store.nodes_by_type(NodeType.ASSET)
    service_nodes = graph_store.nodes_by_type(NodeType.SERVICE)

    # DB ports must come from an IDENTIFIED DB service node (anti-#3: proven service,
    # not a guessed well-known port). ServiceProperties has no host — that is why the
    # port is joined to an asset below via the asset's open_ports, never assumed.
    db_ports = sorted(
        {
            node.properties.port
            for node in service_nodes
            if isinstance(node.properties, ServiceProperties)
            and node.properties.name in _DB_SERVICES
            and node.properties.port > 0
        }
    )
    if not db_ports:
        return []

    targets: list[str] = []
    for asset in asset_nodes:
        props = asset.properties
        if not isinstance(props, AssetProperties):
            continue
        host = props.host
        for port in db_ports:
            if port not in props.open_ports:
                continue  # FLAW 3: this DB port belongs to THIS asset, not assumed.
            if not auth.is_db_endpoint_in_scope(engagement_id, host, port):
                continue  # FLAW 2 + gate: endpoint must be in the signed SOW scope.
            targets.append(f"{host}:{port}")
    return targets
