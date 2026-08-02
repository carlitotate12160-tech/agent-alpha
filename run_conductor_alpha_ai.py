#!/usr/bin/env python3
"""Field-prove: full Conductor autonomous path against alpha-ai.web.id.

Drives the real engagement lifecycle:
  1. Start FastAPI + Celery worker (in-process, synchronous)
  2. Create engagement (JWT auth)
  3. Ownership challenge + authorize (skip DNS verify — lab)
  4. Enable recon
  5. Run engagement (Alpha → Beta → verify_access_nodes → Omega)
  6. Poll run-status + trace
  7. Print CROSS_VERIFIED + PAYABLE PROVEN

Run on Oracle ARM64:
  .venv312/bin/python3 run_conductor_alpha_ai.py
"""

from __future__ import annotations

import os
import pathlib
import sys
import time

# ── 0. Load .env ──────────────────────────────────────────────────────

env_path = pathlib.Path(__file__).resolve().parent / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

os.environ.setdefault("AGENT_ALPHA_SKIP_DOMAIN_VERIFICATION", "true")

# ── 1. Build the Conductor singletons (same as main.py) ──────────────

from agent_alpha.conductor.api_auth import Principal  # noqa: E402
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope  # noqa: E402
from agent_alpha.events.store import InMemoryEventStore  # noqa: E402
from agent_alpha.events.event_types import EventType  # noqa: E402
from agent_alpha.conductor.engagement_profile import (  # noqa: E402
    dump_signed_profile,
    load_signed_profile_from_dict,
)
from agent_alpha.conductor.verification import verify_access_nodes  # noqa: E402
from agent_alpha.graph.networkx_store import NetworkXGraphStore  # noqa: E402
from agent_alpha.agents.alpha.scout import Alpha  # noqa: E402
from agent_alpha.agents.beta.strike import Beta  # noqa: E402
from agent_alpha.agents.omega.roaster import Omega  # noqa: E402
from agent_alpha.agents.http_client import HttpClient  # noqa: E402
from agent_alpha.security.secrets import SecretsManager  # noqa: E402
from agent_alpha.llm.orchestrator import LLMOrchestrator  # noqa: E402
from agent_alpha.tools.playbook import PlaybookEngine  # noqa: E402
from agent_alpha.live_fire.beta_runner import _NoLLMProvider  # noqa: E402
from agent_alpha.recon.wp_config_probe import verify_wp_config_leak  # noqa: E402
from agent_alpha.graph.nodes import NodeType, VerificationTier  # noqa: E402
from agent_alpha.a2a import a2a_pb2  # noqa: E402

TARGET = "alpha-ai.web.id"
CLIENT_ID = "alpha-ai-lab"


def main() -> int:
    print("=" * 72)
    print("CONDUCTOR FULL-CHAIN FIELD-PROVE — alpha-ai.web.id")
    print("=" * 72)

    # ── 2. Build stores (in-memory, no Redis/PG needed for field-prove) ──
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    secrets_manager = SecretsManager()
    graph_store = NetworkXGraphStore()
    http_client = HttpClient(engagement_id="field-prove", verify=False)

    playbook_dir = pathlib.Path(__file__).resolve().parent / "agent_alpha" / "tools" / "playbooks"
    orchestrator = LLMOrchestrator(
        PlaybookEngine.from_directory(playbook_dir), _NoLLMProvider()
    )

    # ── 3. Create engagement ─────────────────────────────────────────────
    rec = auth.create_engagement(client_id=CLIENT_ID, target=TARGET)
    eid = rec.engagement_id
    print(f"[1/7] Engagement created: {eid}  target={TARGET}")

    # ── 4. Authorize (skip DNS — lab, self-owned) ─────────────────────────
    # Issue ownership challenge (token stored in event store)
    import secrets as stdlib_secrets

    token = stdlib_secrets.token_urlsafe(32)
    event_store.append(
        event_type=EventType.OWNERSHIP_CHALLENGE_ISSUED,
        engagement_id=eid,
        agent="CONDUCTOR",
        payload={"domain": TARGET, "token": token},
    )

    # Authorize with skip_domain_verification=True (lab)
    from agent_alpha.conductor.authorization import authorize_engagement

    signing_key = os.environ["PROFILE_SIGNING_KEY"]
    profile = authorize_engagement(
        engagement_id=eid,
        client_id=CLIENT_ID,
        targets=[TARGET],
        ownership_tokens={TARGET: f"dns-txt:agent-alpha={token}"},
        dns_resolver=None,
        skip_domain_verification=True,
        authorized_origins=frozenset(["168.110.192.62"]),
        consent_items=frozenset(["recon", "cred_reuse", "xmlrpc_access"]),
        signed_by="operator@lab",
        signed_at="2026-08-02T22:00:00Z",
        authorization_level="OFFENSIVE_APPROVED",
        allow_evasion=False,
        opsec_stealth=False,
        event_store=event_store,
        key=signing_key,
    )
    envelope = dump_signed_profile(profile, key=signing_key)
    event_store.append(
        event_type=EventType.ENGAGEMENT_PROFILE_SIGNED,
        engagement_id=eid,
        agent="CONDUCTOR",
        payload=envelope,
    )
    print(f"[2/7] Authorized (OFFENSIVE_APPROVED)  origins=168.110.192.62")

    # ── 5. Enable recon ───────────────────────────────────────────────────
    auth.enable_recon(
        eid,
        Scope(ip_ranges=["168.110.192.62/32"], domains=[TARGET], exclusions=[]),
    )
    print(f"[3/7] Recon enabled")

    # ── 6. Alpha recon ────────────────────────────────────────────────────
    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
        engagement_profile=profile,
    )
    alpha.run_recon(eid, f"https://{TARGET}/")
    print(f"[4/7] Alpha recon done  nodes={len(graph_store._graph.nodes)}")

    # wp-config leak probe (the cred-reuse source)
    creds_added = verify_wp_config_leak(
        engagement_id=eid,
        auth=auth,
        http_client=http_client,
        scope_hosts=[TARGET],
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
    )
    print(f"[4b/7] wp-config leak probe  creds_added={creds_added}")

    # ── 7. Escalate to ACTIVE ─────────────────────────────────────────────
    auth.enable_active(eid)
    print(f"[5/7] Active enabled")

    # ── 8. Beta strike (XML-RPC cred reuse) ────────────────────────────────
    beta = Beta(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    beta.run_strike(eid, f"https://{TARGET}")
    print(f"[6/7] Beta strike done")

    # ── 9. CROSS-VERIFY (canonical verify_access_nodes) ───────────────────
    verify_access_nodes(graph_store, event_store, eid)

    # ── 10. Read results ──────────────────────────────────────────────────
    access_nodes = graph_store.nodes_by_type(NodeType.ACCESS_LEVEL)
    cross_verified = any(
        getattr(n, "verification", None) == VerificationTier.CROSS_VERIFIED
        for n in access_nodes
    )
    access_level = ""
    if access_nodes:
        access_level = getattr(access_nodes[0].properties, "level", "")

    # Check edge from harvested cred
    from agent_alpha.graph.nodes import RelationshipType

    cred_ids = {n.id for n in graph_store.nodes_by_type(NodeType.CREDENTIAL)}
    access_ids = {n.id for n in access_nodes}
    edge_from_harvested = False
    for edge in graph_store.edges_by_relationship(RelationshipType.ENABLES):
        if edge.target_id in access_ids and edge.source_id in cred_ids:
            ref = getattr(
                graph_store._graph.nodes[edge.source_id].get("properties"),
                "secret_ref",
                "",
            )
            if ref.startswith("secret_"):
                try:
                    secrets_manager.retrieve(ref)
                    edge_from_harvested = True
                except Exception:
                    pass

    # Check db_enumerated
    db_enumerated = False
    for e in event_store.get_events(eid):
        payload = getattr(e, "payload", None)
        if not isinstance(payload, dict):
            continue
        pr = payload.get("proof_request")
        if not isinstance(pr, dict):
            continue
        if pr.get("method") == "authenticate" and pr.get("database_source") == "enumerated":
            db_enumerated = True
            break

    chain_proven = (
        creds_added >= 1
        and access_level in ("user", "admin")
        and edge_from_harvested
        and db_enumerated
    )
    payable_proven = chain_proven and cross_verified

    # ── 11. Omega report ──────────────────────────────────────────────────
    report = Omega(graph_store).generate_report("technical")

    print()
    print("=" * 72)
    print("FIELD-PROVE RESULT")
    print("=" * 72)
    print(f"  Engagement ID          : {eid}")
    print(f"  Target                 : {TARGET}")
    print(f"  Leak creds added       : {creds_added}")
    print(f"  Web/app access level   : {access_level or '(none)'}")
    print(f"  Edge from harvested    : {edge_from_harvested}")
    print(f"  DB enumerated          : {db_enumerated}")
    print(f"  Access nodes           : {len(access_nodes)}")
    print("-" * 72)
    print(f"  CHAIN PROVEN           : {chain_proven}")
    print(f"  CROSS_VERIFIED         : {cross_verified}")
    print(f"  PAYABLE PROVEN         : {payable_proven}")
    print("=" * 72)

    cf = report.chain_finding
    if cf:
        print()
        print("OMEGA REPORT (chain finding)")
        print("-" * 72)
        print(f"  Severity        : {cf.severity.upper()}")
        print(f"  Credential      : {cf.credential_id}")
        print(f"  Access          : {cf.access_id}  (level={cf.access_level})")
        print(f"  Downstream mapped: {cf.downstream_mapped}")
        print(f"  Rationale       : {cf.rationale}")
        print(f"  MITRE           : {', '.join(report.mitre_techniques)}")
    else:
        print()
        print("OMEGA REPORT: No chain finding produced.")

    # Print verification tiers of all access nodes
    if access_nodes:
        print()
        print("ACCESS NODE VERIFICATION TIERS")
        print("-" * 72)
        for n in access_nodes:
            tier = getattr(n, "verification", None)
            tier_name = VerificationTier(tier).name if tier is not None else "NONE"
            print(f"  {n.id}: tier={tier_name}  level={getattr(n.properties, 'level', '?')}")

    return 0 if payable_proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
