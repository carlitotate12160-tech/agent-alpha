# CodeIgniter config-leak field-prove — HERMETIC verdict logic (Phase 4 slice-1c-1).
#
# The REAL-HTTP proof (Alpha.run_recon against the self-owned lab) lives in the
# runner: agent_alpha/live_fire/codeigniter_field_prove.py, guarded by lab_guard
# and run on Oracle ARM64. This test file makes NO network calls — it locks the
# chain_proven verdict contract (anti-#3: every clause required) and the config
# loader guard, exactly like tests/phase_4/test_backup_file_field_prove.py.
#
# WHY the split (CodeRabbit PR #470): `tests/**` must not make real network
# calls. Real-HTTP field-prove is a live_fire runner; tests/ verifies its logic.
#
# Run the real proof on Oracle ARM64 after seeding the lab:
#   cd codeigniter_lab && sudo ./seed.sh
#   python -m agent_alpha.live_fire.codeigniter_field_prove <engagement.yaml>

from __future__ import annotations

import pathlib

import pytest

from agent_alpha.live_fire.codeigniter_field_prove import (
    CodeIgniterResult,
    load_codeigniter_config,
)


def _result(**over: object) -> CodeIgniterResult:
    base: dict[str, object] = {
        "creds_added": 1,
        "credential_vaulted": True,
        "leak_detected": True,
    }
    base.update(over)
    return CodeIgniterResult(**base)  # type: ignore[arg-type]


# ── chain_proven clause matrix (every clause REQUIRED — anti-#3) ───────────────
def test_all_clauses_true_is_proven() -> None:
    assert _result().chain_proven is True


def test_no_credential_is_not_proven() -> None:
    assert _result(creds_added=0).chain_proven is False


def test_unvaulted_credential_is_not_proven() -> None:
    assert _result(credential_vaulted=False).chain_proven is False


def test_no_real_leak_is_not_proven() -> None:
    assert _result(leak_detected=False).chain_proven is False


# ── config loader guards the payable contract (self-owned lab only) ───────────
def test_config_loader_rejects_missing_key(tmp_path: object) -> None:
    p = pathlib.Path(str(tmp_path)) / "bad.yaml"
    p.write_text("client_id: x\n")
    with pytest.raises(ValueError):
        load_codeigniter_config(p)


def test_config_loader_rejects_missing_scope_key(tmp_path: object) -> None:
    p = pathlib.Path(str(tmp_path)) / "bad_scope.yaml"
    p.write_text(
        "client_id: x\nrecon_url: https://vuln.codeigniter.lab:8444/\nscope:\n  domains: [vuln.codeigniter.lab]\n"
    )
    with pytest.raises(ValueError):
        load_codeigniter_config(p)


def test_config_loader_happy_path(tmp_path: object) -> None:
    p = pathlib.Path(str(tmp_path)) / "ok.yaml"
    p.write_text(
        "client_id: codeigniter-lab\n"
        "recon_url: https://vuln.codeigniter.lab:8444/\n"
        "scope:\n"
        "  ip_ranges: []\n"
        "  domains: [vuln.codeigniter.lab]\n"
        "  exclusions: []\n"
    )
    cfg = load_codeigniter_config(p)
    assert cfg.scope_domains == ["vuln.codeigniter.lab"]
    assert cfg.recon_url.endswith("8444/")
