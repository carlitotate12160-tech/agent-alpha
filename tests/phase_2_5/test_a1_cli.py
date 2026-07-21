"""CLI wiring for A1 origin-direct field-prove (Slice C entrypoint)."""

from __future__ import annotations

import agent_alpha.live_fire.a1_validation_runner as runner
from agent_alpha.live_fire.a1_validation_runner import A1Result


def _ok_result() -> A1Result:
    return A1Result(
        valid_run=True,
        challenge_encountered=True,
        challenge_solved=False,          # origin-direct bypasses; never "solved" (anti-#3)
        chain_proven=True,
        edge_from_harvested_cred=True,
        nuclei_findings=0,
        scanner_missed_exploitability=True,
        technique_used="origin_direct",
        origin_authorized=True,
    )


def _capture(store: dict) -> object:
    def _fake(**kwargs: object) -> A1Result:
        store.update(kwargs)
        return _ok_result()
    return _fake


def test_cli_wires_origin_direct(monkeypatch) -> None:
    """--origin builds StaticOriginDiscovery + a signed profile with that origin
    authorized, and injects both (browser_solve_viable=False) into the runner."""
    captured: dict = {}
    monkeypatch.setattr(runner, "run_a1_validation", _capture(captured))

    rc = runner.main(
        ["--engagement-id", "e1", "--target", "lab.example", "--origin", "203.0.113.9"]
    )

    assert rc == 0
    assert captured["origin_discovery"].candidates("lab.example") == ["203.0.113.9"]
    assert "203.0.113.9" in captured["engagement_profile"].authorized_origins
    assert captured["engagement_profile"].engagement_id == "e1"
    assert captured["browser_solve_viable"] is False


def test_cli_without_origin_stays_browser_solve(monkeypatch) -> None:
    """No --origin → origin_discovery/profile stay None (no origin-direct path)."""
    captured: dict = {}
    monkeypatch.setattr(runner, "run_a1_validation", _capture(captured))

    runner.main(["--engagement-id", "e1", "--target", "lab.example"])

    assert captured["origin_discovery"] is None
    assert captured["engagement_profile"] is None
