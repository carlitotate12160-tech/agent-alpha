"""Tests for agent_alpha/live_fire/coverage_diagnostic.py.

These are hermetic and run without network access.  Mode B live touch is tested
only through the CLI refusal path; the real field prove for Mode B is the
recon_integrated_field_prove suite.
"""

from __future__ import annotations

import json
import os
import platform
import tempfile
from pathlib import Path
from typing import Any

from agent_alpha.a2a import a2a_pb2
from agent_alpha.coverage.coverage_ledger import load_catalog
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.live_fire.coverage_diagnostic import (
    DiagnosticConfig,
    _test_env_name,
    main,
    run_diagnostic,
)


def _store_with_events(events: list[tuple[str, dict[str, Any]]]) -> InMemoryEventStore:
    """Create an InMemory store and append a list of (event_type, payload) tuples."""
    store = InMemoryEventStore()
    engagement_id = "eng_test"
    for _idx, (etype, payload) in enumerate(events):
        store.append(etype, engagement_id, "TEST", payload)
    return store


def _auth_surface_events(excluded: set[str] | None = None) -> list[tuple[str, dict[str, Any]]]:
    """Return a synthetic event list that breaks at S5 with all applicable cells capability_absent."""
    host = "jwt-target.example.com"
    return [
        (
            EventType.ENGAGEMENT_CREATED,
            {"client_id": "c1", "target": host, "state": a2a_pb2.CREATED},
        ),
        (
            EventType.PASSIVE_INTEL_GATHERED,
            {"in_scope_subdomains": [host], "sources_used": ["certspotter"]},
        ),
        (
            EventType.NODE_DISCOVERED,
            {
                "id": f"asset:{host}",
                "type": "asset",
                "properties": {
                    "host": host,
                    "tech_stack": ["login-form", "mech_jwt"],
                },
            },
        ),
    ]


def test_s5_all_applicable_capability_absent() -> None:
    """Cardinal RED test: surfaces + stacks, but every applicable cell is capability_absent."""
    store = _store_with_events(_auth_surface_events())
    catalog = load_catalog()
    config = DiagnosticConfig(
        engagement_ids=("eng_test",),
        excluded_techniques=frozenset(
            {"default_creds_login", "git_exposure_leak", "js_secret_leak"}
        ),
    )
    results = run_diagnostic(store, config, catalog=catalog, test_env="test")
    assert len(results) == 1
    verdict = results[0]
    assert verdict["earliest_failed_transition"] == "S5_APPLICABLE_CAPABILITY"
    assert verdict["new_gap_required"] is False
    s5 = next(s for s in verdict["funnel"] if s["stage"] == "S5_APPLICABLE_CAPABILITY")
    assert s5["passed"] is False


def test_empty_event_stream_no_crash_and_s1_or_s2() -> None:
    """Empty event list must not crash and must fail at S1 or S2, never false-pass."""
    store = InMemoryEventStore()
    catalog = load_catalog()
    config = DiagnosticConfig(engagement_ids=("eng_empty",))
    results = run_diagnostic(store, config, catalog=catalog, test_env="test")
    assert len(results) == 1
    verdict = results[0]
    assert verdict["earliest_failed_transition"] in (
        "S1_AUTHORIZED_ROOT_SEED",
        "S2_PASSIVE_SURFACE",
    )
    assert all(
        s["passed"] is False
        for s in verdict["funnel"]
        if s["stage"] == verdict["earliest_failed_transition"]
    )
    assert verdict["new_gap_required"] is False


def test_all_discovered_hosts_blocked_s3_reach() -> None:
    """If every discovered host is blocked, the earliest failure is S3_REACH."""
    host = "waf-target.example.com"
    events = [
        (
            EventType.ENGAGEMENT_CREATED,
            {"client_id": "c1", "target": host, "state": a2a_pb2.CREATED},
        ),
        (
            EventType.PASSIVE_INTEL_GATHERED,
            {"in_scope_subdomains": [host], "sources_used": ["certspotter"]},
        ),
        (
            EventType.NODE_DISCOVERED,
            {
                "id": f"asset:{host}",
                "type": "asset",
                "properties": {"host": host, "tech_stack": ["login-form"]},
            },
        ),
        (
            EventType.WAF_BLOCKED,
            {"host": host, "path": "/", "status_code": 403},
        ),
    ]
    store = _store_with_events(events)
    catalog = load_catalog()
    config = DiagnosticConfig(engagement_ids=("eng_test",))
    results = run_diagnostic(store, config, catalog=catalog, test_env="test")
    assert len(results) == 1
    verdict = results[0]
    assert verdict["earliest_failed_transition"] == "S3_REACH"
    assert "blocked" in verdict["earliest_failed_detail"].lower()
    assert "surface not exhausted" in verdict["earliest_failed_detail"].lower()
    s3 = next(s for s in verdict["funnel"] if s["stage"] == "S3_REACH")
    assert s3["passed"] is False
    assert "capability_absent" not in verdict["earliest_failed_detail"].lower()
    assert "target safe" not in verdict["earliest_failed_detail"].lower()


def test_determinism() -> None:
    """Same event list must produce byte-identical JSON when serialized with sorted keys."""
    store = _store_with_events(_auth_surface_events())
    catalog = load_catalog()
    config = DiagnosticConfig(
        engagement_ids=("eng_test",),
        excluded_techniques=frozenset(
            {"default_creds_login", "git_exposure_leak", "js_secret_leak"}
        ),
    )
    results1 = run_diagnostic(store, config, catalog=catalog, test_env="test")
    # Re-initialize store with identical events; event sequence numbers reset to 0
    store2 = _store_with_events(_auth_surface_events())
    results2 = run_diagnostic(store2, config, catalog=catalog, test_env="test")
    json1 = json.dumps(results1, sort_keys=True)
    json2 = json.dumps(results2, sort_keys=True)
    assert json1 == json2


def test_mode_b_refuses_without_flag() -> None:
    """Empty in-memory store plus a live target without --allow-live-touch exits non-zero and emits no JSON."""
    env_backup = {k: v for k, v in os.environ.items() if k.startswith("AGENT_ALPHA_")}
    for k in list(os.environ.keys()):
        if k.startswith("AGENT_ALPHA_"):
            del os.environ[k]

    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "coverage_diagnostic.yaml"
        config_path.write_text(
            """
engagement_ids:
  - "eng_empty"
targets:
  - client_id: "test_lab"
    scope:
      domains:
        - "vuln.git.lab"
    recon_url: "https://vuln.git.lab/"
    ownership_tokens:
      "vuln.git.lab": "localhost:git_lab/"
    consent_items:
      - "authorized_recon"
    signed_by: "test"
    signed_at: "2026-01-01T00:00:00Z"
""",
            encoding="utf-8",
        )
        # Override arch so the CLI does not refuse for non-ARM hosts during tests.
        rc = main([str(config_path), "--test-env", "test"])
    assert rc != 0

    for k, v in env_backup.items():
        os.environ[k] = v


def test_test_env_on_arm64() -> None:
    """The native test_env is oracle-arm64 on ARM and a warning prefix elsewhere."""
    machine = platform.machine().lower()
    env = _test_env_name()
    if machine in ("aarch64", "arm64"):
        assert env == "oracle-arm64"
    else:
        assert not env.startswith("oracle-arm64")
