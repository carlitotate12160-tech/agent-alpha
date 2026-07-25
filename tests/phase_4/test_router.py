"""RED tests for the graph-driven kill-chain router (slice 1a).

Proves ``route_next`` decides the next agent as a pure function of AttackGraph
state — NOT a static pipeline (Lyndon #11). The CARDINAL test is the niagamas
closure: after Beta proves a payable cred-reuse chain but Gamma is not
authorized, routing goes to OMEGA for a report NOW (was: emit GAMMA → park →
no report).

VERIFY: Oracle ARM64 only —
  .venv312/bin/python3 -m pytest tests/phase_4/test_router.py -v
"""

from __future__ import annotations

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.router import (
    _AUTH_SURFACE_LABELS,
    has_access_from_harvested_cred,
    has_harvested_credential,
    has_web_auth_surface,
    route_next,
)
from agent_alpha.graph.networkx_store import NetworkXGraphStore

# ── Graph builders ────────────────────────────────────────────────────────────


def _empty_graph() -> NetworkXGraphStore:
    return NetworkXGraphStore()


def _graph_with_vaulted_cred(*, tech_stack: list[str] | None = None) -> NetworkXGraphStore:
    """Graph with a vaulted CREDENTIAL and optionally an auth-surface ASSET."""
    g = NetworkXGraphStore()
    g.apply_event(
        "NodeDiscovered",
        {
            "id": "cred:leaked-1",
            "type": "credential",
            "properties": {
                "username": "admin",
                "secret_ref": "secret_wp_db_1",
                "service": "mysql",
                "access_level": "admin",
            },
            "confidence": 0.95,
        },
    )
    if tech_stack is not None:
        g.apply_event(
            "NodeDiscovered",
            {
                "id": "asset:target.test",
                "type": "asset",
                "properties": {"host": "target.test", "tech_stack": tech_stack},
                "confidence": 0.9,
            },
        )
    return g


def _graph_with_access_proven() -> NetworkXGraphStore:
    """Graph with vaulted CREDENTIAL → ENABLES → ACCESS_LEVEL (Beta proved access)."""
    g = _graph_with_vaulted_cred(tech_stack=["wp"])
    g.apply_event(
        "NodeDiscovered",
        {
            "id": "access:admin-wp",
            "type": "access_level",
            "properties": {"level": "admin", "user_context": "wp-admin"},
            "confidence": 0.9,
        },
    )
    g.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "cred:leaked-1",
            "target_id": "access:admin-wp",
            "relationship": "enables",
            "confidence": 0.9,
        },
    )
    return g


def _graph_without_access_edge() -> NetworkXGraphStore:
    """Graph with vaulted CREDENTIAL and ACCESS_LEVEL but NO ENABLES edge — Beta
    found the cred but did NOT prove access."""
    g = _graph_with_vaulted_cred(tech_stack=["wp"])
    g.apply_event(
        "NodeDiscovered",
        {
            "id": "access:admin-wp",
            "type": "access_level",
            "properties": {"level": "admin", "user_context": "wp-admin"},
            "confidence": 0.9,
        },
    )
    # No ENABLES edge — the credential is harvested but access is NOT proven.
    return g


# ── Predicate unit tests ──────────────────────────────────────────────────────


def test_has_harvested_credential_true() -> None:
    g = _graph_with_vaulted_cred()
    assert has_harvested_credential(g) is True


def test_has_harvested_credential_false_no_cred() -> None:
    assert has_harvested_credential(_empty_graph()) is False


def test_has_harvested_credential_false_not_vaulted() -> None:
    """A CREDENTIAL whose secret_ref does NOT start with 'secret_' is not vaulted."""
    g = NetworkXGraphStore()
    g.apply_event(
        "NodeDiscovered",
        {
            "id": "cred:not-vaulted",
            "type": "credential",
            "properties": {
                "username": "test",
                "secret_ref": "vault://eng/something",
                "service": "http",
                "access_level": "user",
            },
            "confidence": 0.8,
        },
    )
    assert has_harvested_credential(g) is False


def test_has_web_auth_surface_true() -> None:
    g = _graph_with_vaulted_cred(tech_stack=["wp"])
    assert has_web_auth_surface(g) is True


def test_has_web_auth_surface_false_no_asset() -> None:
    assert has_web_auth_surface(_empty_graph()) is False


def test_has_web_auth_surface_false_openapi_only() -> None:
    """An ASSET with only 'openapi' in tech_stack is NOT an auth surface —
    this test enforces the absence of a vacuous SERVICE http/https fallback.
    If that fallback is (re)introduced, this test goes RED."""
    g = _graph_with_vaulted_cred(tech_stack=["openapi"])
    assert has_web_auth_surface(g) is False


def test_has_web_auth_surface_false_graphql_only() -> None:
    """'graphql' is a recon surface, not a login surface."""
    g = _graph_with_vaulted_cred(tech_stack=["graphql"])
    assert has_web_auth_surface(g) is False


def test_has_web_auth_surface_true_each_label() -> None:
    """Every label in _AUTH_SURFACE_LABELS individually triggers the predicate."""
    for label in _AUTH_SURFACE_LABELS:
        g = _graph_with_vaulted_cred(tech_stack=[label])
        assert has_web_auth_surface(g) is True, f"label={label!r} should be an auth surface"


def test_has_access_from_harvested_cred_true() -> None:
    assert has_access_from_harvested_cred(_graph_with_access_proven()) is True


def test_has_access_from_harvested_cred_false_no_edge() -> None:
    assert has_access_from_harvested_cred(_graph_without_access_edge()) is False


def test_has_access_from_harvested_cred_false_empty() -> None:
    assert has_access_from_harvested_cred(_empty_graph()) is False


# ── route_next decision tests ────────────────────────────────────────────────


class TestRouteNextAlpha:
    """Alpha (RECON) → routing decision."""

    def test_alpha_cred_plus_auth_surface_routes_beta(self) -> None:
        g = _graph_with_vaulted_cred(tech_stack=["wp"])
        result = route_next(
            g, from_agent=a2a_pb2.ALPHA, status=a2a_pb2.COMPLETE, gamma_authorized=False
        )
        assert result == a2a_pb2.BETA

    def test_alpha_cred_but_no_auth_surface_routes_omega(self) -> None:
        """Credential found but no login surface → recon-only report."""
        g = _graph_with_vaulted_cred()  # no tech_stack / no ASSET
        result = route_next(
            g, from_agent=a2a_pb2.ALPHA, status=a2a_pb2.COMPLETE, gamma_authorized=False
        )
        assert result == a2a_pb2.OMEGA

    def test_alpha_openapi_asset_no_cred_routes_omega(self) -> None:
        """Vacuous-fallback guard: ASSET with openapi (non-auth surface) and
        no credential → OMEGA (recon-only report). Must NOT route to BETA."""
        g = _graph_with_vaulted_cred(tech_stack=["openapi"])
        # has cred but no auth surface → OMEGA
        result = route_next(
            g, from_agent=a2a_pb2.ALPHA, status=a2a_pb2.COMPLETE, gamma_authorized=False
        )
        assert result == a2a_pb2.OMEGA

    def test_alpha_no_cred_routes_omega(self) -> None:
        result = route_next(
            _empty_graph(),
            from_agent=a2a_pb2.ALPHA,
            status=a2a_pb2.COMPLETE,
            gamma_authorized=False,
        )
        assert result == a2a_pb2.OMEGA

    def test_alpha_failed_routes_omega(self) -> None:
        """Bug #22: FAILED status → OMEGA regardless of graph state."""
        g = _graph_with_vaulted_cred(tech_stack=["wp"])
        result = route_next(
            g, from_agent=a2a_pb2.ALPHA, status=a2a_pb2.FAILED, gamma_authorized=False
        )
        assert result == a2a_pb2.OMEGA


class TestRouteNextBeta:
    """Beta (STRIKE) → routing decision."""

    def test_cardinal_beta_access_proven_gamma_not_authorized_routes_omega(self) -> None:
        """CARDINAL — the niagamas closure: Beta proved a payable cred-reuse chain
        but Gamma is not authorized → OMEGA for a report NOW (was: emit GAMMA →
        advance parks → no report → client never sees the payable finding)."""
        g = _graph_with_access_proven()
        result = route_next(
            g, from_agent=a2a_pb2.BETA, status=a2a_pb2.COMPLETE, gamma_authorized=False
        )
        assert result == a2a_pb2.OMEGA

    def test_beta_access_proven_gamma_authorized_routes_gamma(self) -> None:
        g = _graph_with_access_proven()
        result = route_next(
            g, from_agent=a2a_pb2.BETA, status=a2a_pb2.COMPLETE, gamma_authorized=True
        )
        assert result == a2a_pb2.GAMMA

    def test_beta_no_access_routes_omega(self) -> None:
        g = _graph_without_access_edge()
        result = route_next(
            g, from_agent=a2a_pb2.BETA, status=a2a_pb2.COMPLETE, gamma_authorized=True
        )
        assert result == a2a_pb2.OMEGA

    def test_beta_blocked_routes_omega(self) -> None:
        """Bug #22: BLOCKED → OMEGA for a partial report."""
        g = _graph_with_access_proven()
        result = route_next(
            g, from_agent=a2a_pb2.BETA, status=a2a_pb2.BLOCKED, gamma_authorized=True
        )
        assert result == a2a_pb2.OMEGA


class TestRouteNextOther:
    """GAMMA/DELTA/EPSILON/unknown → OMEGA."""

    def test_gamma_routes_omega(self) -> None:
        assert (
            route_next(
                _empty_graph(),
                from_agent=a2a_pb2.GAMMA,
                status=a2a_pb2.COMPLETE,
                gamma_authorized=True,
            )
            == a2a_pb2.OMEGA
        )

    def test_delta_routes_omega(self) -> None:
        assert (
            route_next(
                _empty_graph(),
                from_agent=a2a_pb2.DELTA,
                status=a2a_pb2.COMPLETE,
                gamma_authorized=False,
            )
            == a2a_pb2.OMEGA
        )


class TestDifferential:
    """DIFFERENTIAL — proves next = f(graph), not a static pipeline (Lyndon #11).

    Two graphs identical except for the ENABLES edge. With edge → GAMMA (when
    authorized) or OMEGA (when not). Without edge → always OMEGA.
    """

    def test_differential_access_edge_determines_routing(self) -> None:
        with_access = _graph_with_access_proven()
        without_access = _graph_without_access_edge()

        # Same from_agent, same status, same gamma_authorized — different graph → different result.
        result_with = route_next(
            with_access, from_agent=a2a_pb2.BETA, status=a2a_pb2.COMPLETE, gamma_authorized=True
        )
        result_without = route_next(
            without_access, from_agent=a2a_pb2.BETA, status=a2a_pb2.COMPLETE, gamma_authorized=True
        )

        assert result_with == a2a_pb2.GAMMA
        assert result_without == a2a_pb2.OMEGA
        assert result_with != result_without, (
            "same-input, different-graph must yield different routing"
        )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
