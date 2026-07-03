# agent_alpha/live_fire/beta_runner.py
"""Beta (STRIKE) live-fire runner — drives Beta end-to-end against a self-owned
login lab and scores the outcome. Phase 3 gate (analog to live_fire/runner for
Alpha→Omega).

Two layers:
  * ``run_beta_live_fire(...)`` — hermetic, injected-dependency (tested with fakes).
  * ``main()`` — builds REAL HttpClient + a NO-LLM orchestrator (the login playbook
    keeps Beta rule-tier, so no DeepSeek key is needed) from config + env.

Reuses canonical types only — EngagementConfig/load_engagement_config come from
the Alpha runner (anti-Lyndon #6, one config contract).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
from dataclasses import dataclass
from typing import Any

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.beta.strike import Beta
from agent_alpha.agents.http_client import HttpClient
from agent_alpha.conductor.applicator_factory import build_applicators_for_engagement
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.live_fire.runner import EngagementConfig, load_engagement_config
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.internal.access.applicator import HttpFormApplicator
from agent_alpha.tools.playbook import PlaybookEngine

# Belt-and-suspenders leak heuristic for a REAL run (the unit test
# test_session_token_redaction is the hard guarantee; this just flags surprises).
_LEAK_RE = re.compile(r"(session|sid|token|sess)=[a-z0-9._-]{12,}", re.IGNORECASE)


@dataclass(frozen=True)
class BetaResult:
    """Scored outcome of one Beta live-fire target."""

    url: str
    status: int
    gained_access: bool
    expected_access: bool
    proof_count: int
    leak_suspected: bool

    @property
    def correct(self) -> bool:
        return self.gained_access == self.expected_access and not self.leak_suspected


class _NoLLMProvider:
    """Reasoning provider that must NEVER be called: the login playbook should match
    and keep Beta rule-tier. An LLM escalation here is a bug (and the key is revoked)."""

    model = "none"

    def complete(self, *args: object, **kwargs: object) -> Any:
        raise RuntimeError(
            "Beta live-fire escalated to the LLM — the login playbook failed to match. "
            "Rule-tier is required (no DeepSeek key)."
        )


def _scan_leak(event_store: Any, engagement_id: str) -> bool:
    """True if a session-token-looking value appears in any persisted event.

    Only the regex pattern is used — the old 'set-cookie' string check was a
    false positive because header_names=['set-cookie', ...] is now the only
    header representation (values are redacted). The regex catches actual
    session=value patterns with long values (>12 chars).
    """
    blob = json.dumps([e.payload for e in event_store.get_events(engagement_id)], default=str)
    return _LEAK_RE.search(blob) is not None


def run_beta_live_fire(
    config: EngagementConfig,
    *,
    auth: Any,
    http_client: Any,
    orchestrator: Any,
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any = None,
) -> list[BetaResult]:
    """Authorize each target to ACTIVE_APPROVED and run Beta.run_strike; score it."""
    results: list[BetaResult] = []
    for target in config.targets:
        rec = auth.create_engagement(client_id=config.client_id, target=target.host)
        auth.enable_recon(
            rec.engagement_id,
            Scope(ip_ranges=config.scope_ip_ranges, domains=config.scope_domains, exclusions=[]),
        )
        auth.enable_active(rec.engagement_id)

        candidates = [HttpFormApplicator(http_client=http_client)]
        applicators = build_applicators_for_engagement(
            engagement_id=rec.engagement_id,
            auth=auth,
            graph_store=graph_store,
            web_target=target.host,
            candidates=candidates,
        )

        beta = Beta(
            authorization=auth,
            graph_store=graph_store,
            event_store=event_store,
            orchestrator=orchestrator,
            http_client=http_client,
            secrets_manager=secrets_manager,
            cred_applicators=applicators,
        )
        msg = beta.run_strike(rec.engagement_id, target.url)
        payload = a2a_pb2.HandoffPayload()
        payload.ParseFromString(msg.payload)

        results.append(
            BetaResult(
                url=target.url,
                status=payload.status,
                gained_access=payload.status == a2a_pb2.COMPLETE,
                expected_access=target.ground_truth_vulnerable,
                proof_count=len(payload.proof_artifacts),
                leak_suspected=_scan_leak(event_store, rec.engagement_id),
            )
        )
    return results


def main(argv: list[str] | None = None) -> int:
    """CLI: read config, run Beta against each target, print scorecard."""
    parser = argparse.ArgumentParser(description="Agent-Alpha Beta (STRIKE) live-fire")
    parser.add_argument("config", help="Path to engagement YAML config")
    args = parser.parse_args(argv)

    config = load_engagement_config(args.config)

    # ── Lab-only guard: refuse client/prod domains ─────────────────────────────
    from agent_alpha.live_fire.lab_guard import assert_lab_only_target

    for target in config.targets:
        assert_lab_only_target(target.host)

    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    http_client = HttpClient(engagement_id=config.client_id)

    playbook_dir = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"
    orchestrator = LLMOrchestrator(PlaybookEngine.from_directory(playbook_dir), _NoLLMProvider())
    graph_store = NetworkXGraphStore()
    secrets_manager = SecretsManager()

    results = run_beta_live_fire(
        config,
        auth=auth,
        http_client=http_client,
        orchestrator=orchestrator,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
    )

    passed = all(r.correct for r in results)

    print("=" * 64)
    print("BETA (STRIKE) LIVE-FIRE SCORECARD")
    print("=" * 64)
    for r in results:
        verdict = "OK " if r.correct else "XX "
        gained = "ACCESS" if r.gained_access else "no-access"
        exp = "expect-access" if r.expected_access else "expect-none"
        leak = "  LEAK!" if r.leak_suspected else ""
        print(f"  {verdict} {r.url} -> {gained} ({exp}, proof={r.proof_count}){leak}")
    print("-" * 64)
    print(f"  Verdict: {'PASS' if passed else 'FAIL'}")
    print("=" * 64)

    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
