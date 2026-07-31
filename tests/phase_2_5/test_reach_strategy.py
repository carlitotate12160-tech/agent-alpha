"""Tests for reach_strategy (A1 Slice B).

Differential test contract — the mitigation *class* drives the strategy
(anti-#11).  OriginDiscovery seam verified via a stand-in that injects a
fixed candidate list (no hardcoded IPs, no network I/O).
"""

from __future__ import annotations

from agent_alpha.recon.reach_strategy import ReachStrategy, choose_reach
from agent_alpha.recon.transport_resilience import MitigationClass

# ── choose_reach differential tests ──────────────────────────────────────────


class TestChooseReach:
    """Decision table: mitigation class × context → strategy."""

    def test_none_mitigation_returns_direct(self) -> None:
        result = choose_reach(None, browser_solve_viable=False, authorized_origin=None)
        assert result is ReachStrategy.DIRECT

    def test_challenge_with_viable_solve_returns_evasion(self) -> None:
        result = choose_reach(
            MitigationClass.CHALLENGE,
            browser_solve_viable=True,
            authorized_origin=None,
        )
        assert result is ReachStrategy.EVASION

    def test_challenge_no_viable_solve_with_origin_returns_origin_direct(self) -> None:
        result = choose_reach(
            MitigationClass.CHALLENGE,
            browser_solve_viable=False,
            authorized_origin="203.0.113.42",
        )
        assert result is ReachStrategy.ORIGIN_DIRECT

    def test_challenge_no_viable_solve_no_origin_returns_direct(self) -> None:
        """Honest result — no silent cheat when solve is not viable."""
        result = choose_reach(
            MitigationClass.CHALLENGE,
            browser_solve_viable=False,
            authorized_origin=None,
        )
        assert result is ReachStrategy.DIRECT

    def test_rule_deny_with_origin_returns_origin_direct(self) -> None:
        result = choose_reach(
            MitigationClass.RULE_DENY,
            browser_solve_viable=False,
            authorized_origin="203.0.113.42",
        )
        assert result is ReachStrategy.ORIGIN_DIRECT

    def test_rule_deny_no_origin_returns_direct(self) -> None:
        result = choose_reach(
            MitigationClass.RULE_DENY,
            browser_solve_viable=False,
            authorized_origin=None,
        )
        assert result is ReachStrategy.DIRECT

    def test_rule_deny_with_viable_solve_still_origin_direct_if_origin_set(
        self,
    ) -> None:
        """RULE_DENY is not CHALLENGE — browser solve doesn't help."""
        result = choose_reach(
            MitigationClass.RULE_DENY,
            browser_solve_viable=True,
            authorized_origin="203.0.113.42",
        )
        assert result is ReachStrategy.ORIGIN_DIRECT

    # ── FINGERPRINT + TLS_IMPERSONATE ────────────────────────────────────

    def test_fingerprint_with_impersonate_viable_returns_tls_impersonate(self) -> None:
        """FINGERPRINT + tls_impersonate_viable → TLS_IMPERSONATE."""
        result = choose_reach(
            MitigationClass.FINGERPRINT,
            browser_solve_viable=False,
            authorized_origin=None,
            tls_impersonate_viable=True,
        )
        assert result is ReachStrategy.TLS_IMPERSONATE

    def test_fingerprint_without_impersonate_viable_returns_direct(self) -> None:
        """FINGERPRINT + tls_impersonate_viable=False → DIRECT (honest block)."""
        result = choose_reach(
            MitigationClass.FINGERPRINT,
            browser_solve_viable=False,
            authorized_origin=None,
            tls_impersonate_viable=False,
        )
        assert result is ReachStrategy.DIRECT

    def test_fingerprint_with_authorized_origin_prefers_origin_direct(self) -> None:
        """FINGERPRINT + authorized_origin → ORIGIN_DIRECT (origin wins over impersonation)."""
        result = choose_reach(
            MitigationClass.FINGERPRINT,
            browser_solve_viable=False,
            authorized_origin="203.0.113.42",
            tls_impersonate_viable=True,
        )
        assert result is ReachStrategy.ORIGIN_DIRECT

    # ── is_cloudflare_ip() ─────────────────────────────────────────────────────

    def test_is_cloudflare_ip_known_cf_range(self) -> None:
        from agent_alpha.recon.reach_strategy import is_cloudflare_ip

        # 172.66.166.211 is in 172.64.0.0/13 (bernofarm real CF IP)
        assert is_cloudflare_ip("172.66.166.211") is True
        # 104.20.17.247 is in 104.16.0.0/13
        assert is_cloudflare_ip("104.20.17.247") is True

    def test_is_cloudflare_ip_non_cf_returns_false(self) -> None:
        from agent_alpha.recon.reach_strategy import is_cloudflare_ip

        # TEST-NET-3 (RFC 5737) — documentation range, never CF
        assert is_cloudflare_ip("203.0.113.42") is False
        # Private range — not CF
        assert is_cloudflare_ip("10.0.0.1") is False


# ── ReachStrategy is a proper StrEnum ─────────────────────────────────────────


class TestReachStrategyEnum:
    def test_values(self) -> None:
        assert set(ReachStrategy) == {
            ReachStrategy.DIRECT,
            ReachStrategy.EVASION,
            ReachStrategy.ORIGIN_DIRECT,
            ReachStrategy.TLS_IMPERSONATE,
        }

    def test_str_round_trip(self) -> None:
        for member in ReachStrategy:
            assert ReachStrategy(str(member)) is member


# ── OriginDiscovery seam (Protocol stand-in) ─────────────────────────────────


class _StubOriginDiscovery:
    """Lab stand-in — injects a fixed candidate list."""

    def __init__(self, candidates: list[str]) -> None:
        self._candidates = candidates

    def candidates(self, fronted_host: str) -> list[str]:
        return self._candidates


class TestOriginDiscoverySeam:
    """OriginDiscovery is a Protocol; any conforming class satisfies it."""

    def test_stub_returns_injected_candidates(self) -> None:
        stub = _StubOriginDiscovery(["198.51.100.1", "198.51.100.2"])
        result = stub.candidates("example.com")
        assert result == ["198.51.100.1", "198.51.100.2"]

    def test_stub_satisfies_protocol(self) -> None:
        stub = _StubOriginDiscovery(["10.0.0.1"])
        # Structural subtyping — isinstance checks require runtime_checkable,
        # so we just verify the attribute exists and is callable.
        assert callable(getattr(stub, "candidates", None))

    def test_empty_candidates(self) -> None:
        stub = _StubOriginDiscovery([])
        assert stub.candidates("no-origins.example.com") == []
