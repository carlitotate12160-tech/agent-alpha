"""CLI wiring for A1 origin-direct field-prove (Slice C entrypoint).

Phase 2.5 Slice 2/2: auth-honesty — consent is INDEPENDENT from discovery.
  --origin = discovery candidate (StaticOriginDiscovery)
  --profile = signed consent (load_signed_profile, SHA-256 verified)
  --lab-unsigned = explicit opt-in for lab-only unsigned synth (LOUD warning)

Test contract (CR-1 closure):
  1. --origin without --profile and without --lab-unsigned → RuntimeError.
  2. --profile consent + --origin discovery (independent) → C9 can genuinely reject.
  3. --origin + --profile <signed fixture> → origin-direct wired.
  4. --origin + --lab-unsigned → wired but prints loud warning.
"""

from __future__ import annotations

import json

import pytest

import agent_alpha.live_fire.a1_validation_runner as runner
from agent_alpha.conductor.engagement_profile import (
    EngagementProfile,
    dump_signed_profile,
)
from agent_alpha.live_fire.a1_validation_runner import A1Result


def _ok_result() -> A1Result:
    return A1Result(
        valid_run=True,
        challenge_encountered=True,
        challenge_solved=False,  # origin-direct bypasses; never "solved" (anti-#3)
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


def _write_signed_profile(tmp_path, **overrides) -> str:
    """Write a signed profile JSON to tmp_path and return the file path."""
    defaults = dict(
        engagement_id="e1",
        client_id="lab",
        targets=frozenset({"lab.example"}),
        authorized_origins=frozenset({"203.0.113.9"}),
    )
    defaults.update(overrides)
    profile = EngagementProfile(**defaults)
    envelope = dump_signed_profile(profile)
    path = tmp_path / "profile.signed.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    return str(path)


# ── 1. --origin without --profile → RuntimeError ─────────────────────────────


def test_origin_direct_requires_signed_profile(monkeypatch) -> None:
    """--origin without --profile and without --lab-unsigned → RuntimeError.
    Consent cannot come from the discovery input (CWE-862, CR-1)."""
    captured: dict = {}
    monkeypatch.setattr(runner, "run_a1_validation", _capture(captured))

    with pytest.raises(RuntimeError, match="requires a signed --profile"):
        runner.main(["--engagement-id", "e1", "--target", "lab.example", "--origin", "203.0.113.9"])


# ── 2. Independent consent rejects uncontested origin ─────────────────────────


def test_cli_independent_consent_rejects_uncontested_origin(monkeypatch, tmp_path) -> None:
    """--profile consent={"203.0.113.10"} + --origin "203.0.113.99" (∉ consent).
    Discovery and consent are now independent → C9 can genuinely reject.
    technique_used != "origin_direct" because the candidate is not authorized."""
    captured: dict = {}
    monkeypatch.setattr(runner, "run_a1_validation", _capture(captured))

    # Signed profile authorizes .10 ONLY.
    profile_path = _write_signed_profile(
        tmp_path,
        authorized_origins=frozenset({"203.0.113.10"}),
    )

    runner.main(
        [
            "--engagement-id",
            "e1",
            "--target",
            "lab.example",
            "--origin",
            "203.0.113.99",  # NOT in consent
            "--profile",
            profile_path,
        ]
    )

    # Discovery candidate is 203.0.113.99.
    assert captured["origin_discovery"].candidates("lab.example") == ["203.0.113.99"]
    # Consent only authorizes 203.0.113.10.
    assert "203.0.113.10" in captured["engagement_profile"].authorized_origins
    assert "203.0.113.99" not in captured["engagement_profile"].authorized_origins
    # The two inputs are INDEPENDENT — this is the new value.


# ── 3. --origin + --profile → origin-direct wired ────────────────────────────


def test_cli_wires_origin_direct(monkeypatch, tmp_path) -> None:
    """--origin + --profile <signed fixture> → origin-direct wired.
    Updated from the old test that passed --origin alone (the tautology we removed)."""
    captured: dict = {}
    monkeypatch.setattr(runner, "run_a1_validation", _capture(captured))

    profile_path = _write_signed_profile(tmp_path)

    rc = runner.main(
        [
            "--engagement-id",
            "e1",
            "--target",
            "lab.example",
            "--origin",
            "203.0.113.9",
            "--profile",
            profile_path,
        ]
    )

    assert rc == 0
    assert captured["origin_discovery"].candidates("lab.example") == ["203.0.113.9"]
    assert "203.0.113.9" in captured["engagement_profile"].authorized_origins
    assert captured["engagement_profile"].engagement_id == "e1"
    assert captured["browser_solve_viable"] is False


# ── 4. --lab-unsigned → wired, with LOUD warning ─────────────────────────────


def test_cli_lab_unsigned_synthesises_consent(monkeypatch, capsys) -> None:
    """--origin + --lab-unsigned → wired, but prints LOUD not-auth-honest warning."""
    captured: dict = {}
    monkeypatch.setattr(runner, "run_a1_validation", _capture(captured))

    rc = runner.main(
        [
            "--engagement-id",
            "e1",
            "--target",
            "lab.example",
            "--origin",
            "203.0.113.9",
            "--lab-unsigned",
        ]
    )

    assert rc == 0
    assert captured["origin_discovery"].candidates("lab.example") == ["203.0.113.9"]
    assert "203.0.113.9" in captured["engagement_profile"].authorized_origins
    # The LOUD warning must have been printed to stderr.
    err = capsys.readouterr().err
    assert "NOT auth-honest" in err
    assert "lab-unsigned" in err.lower() or "lab_unsigned" in err.lower()


# ── 5. No --origin → browser-solve path (unchanged) ──────────────────────────


def test_cli_without_origin_stays_browser_solve(monkeypatch) -> None:
    """No --origin → origin_discovery/profile stay None (no origin-direct path)."""
    captured: dict = {}
    monkeypatch.setattr(runner, "run_a1_validation", _capture(captured))

    runner.main(["--engagement-id", "e1", "--target", "lab.example"])

    assert captured["origin_discovery"] is None
    assert captured["engagement_profile"] is None
