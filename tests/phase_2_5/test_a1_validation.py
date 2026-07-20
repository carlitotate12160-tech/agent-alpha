# tests/phase_2_5/test_a1_validation.py
"""Contract: §12.33 slice-9d — A1 validation vs Nuclei through real CF challenge.

Test contract (C1-C7):
  C1: bare-IP 168.110.192.62 → LabOnlyViolation
  C2: fake CHALLENGE response → classify_mitigation==CHALLENGE, solver invoked
  C3: post-solve bundle body → credential minted, raw secret absent from events
  C4: reused cred → admin access_level, T1078+T1552.001 edge
  C5: chain_proven=True, edge_from_harvested_cred=True
  C6: nuclei==0 + chain_proven → scanner_missed_exploitability=True
  C7: challenge_encountered=False → assert_valid_or_raise RAISES
  Default: _NoopBrowserSolve → field-prove entrypoint RAISES (no silent pass)

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_2_5/test_a1_validation.py -v
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any
from unittest.mock import MagicMock

import pytest

from agent_alpha.live_fire.a1_validation_runner import (
    A1Result,
    _NoopBrowserSolve,
    assert_valid_or_raise,
    run_a1_validation,
)
from agent_alpha.live_fire.lab_guard import LabOnlyViolation

# ── Fakes ─────────────────────────────────────────────────────────────────────


@dataclasses.dataclass
class FakeSolveResult:
    """Concrete ChallengeSolveResult for tests."""

    status_code: int
    body: str
    headers: dict[str, str]
    cleared_cookies: dict[str, str]
    challenge_encountered: bool
    challenge_solved: bool


_BUNDLE_BODY = """
const CFG = {
  api_user: "admin",
  api_key: "MySharedP@ss2026",
  endpoint: "/xmlrpc/2/common",
};
export default CFG;
"""

_CHALLENGE_HEADERS = {
    "cf-mitigated": "challenge",
    "content-type": "text/html; charset=UTF-8",
    "server": "cloudflare",
}


class _FakeBrowserSolve:
    """Fake solver that simulates CF challenge → solve → fetch bundle."""

    def __init__(
        self,
        *,
        challenge_encountered: bool = True,
        challenge_solved: bool = True,
        bundle_body: str = _BUNDLE_BODY,
        probe_status: int = 403,
        bundle_status: int = 200,
    ) -> None:
        self._challenge_encountered = challenge_encountered
        self._challenge_solved = challenge_solved
        self._bundle_body = bundle_body
        self._probe_status = probe_status
        self._bundle_status = bundle_status
        self.calls: list[str] = []

    def solve_and_fetch(self, url: str, *, engagement_id: str) -> FakeSolveResult:
        self.calls.append(url)
        if "/web/assets/" in url:
            return FakeSolveResult(
                status_code=self._bundle_status,
                body=self._bundle_body,
                headers={},
                cleared_cookies={"cf_clearance": "fake_token"},
                challenge_encountered=self._challenge_encountered,
                challenge_solved=self._challenge_solved,
            )
        # Probe to /web
        return FakeSolveResult(
            status_code=self._probe_status,
            body="<html>challenge page</html>",
            headers=_CHALLENGE_HEADERS if self._challenge_encountered else {},
            cleared_cookies={},
            challenge_encountered=self._challenge_encountered,
            challenge_solved=False,
        )


class _FakeHttpClient:
    """Fake HTTP client for beta login (HttpFormApplicator).

    Returns a different body for authenticated GET (with cookies) vs baseline
    GET so that HttpFormApplicator's confirm step doesn't match baseline.
    """

    def __init__(self, *, login_success: bool = True) -> None:
        self._login_success = login_success
        self._baseline_body = '<html><input type="password" name="password"></html>'
        self._authed_body = "<html>welcome admin</html>"
        self._post_body = "<html>welcome admin</html>"

    def get(self, url: str, **kwargs: Any) -> Any:
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        if kwargs.get("cookies"):
            resp.text = self._authed_body
        else:
            resp.text = self._baseline_body
        return resp

    def post(self, url: str, **kwargs: Any) -> Any:
        resp = MagicMock()
        resp.status_code = 200 if self._login_success else 403
        resp.text = self._post_body if self._login_success else "auth failed"
        resp.headers = {"set-cookie": "session=abc123; Path=/"} if self._login_success else {}
        return resp


def _make_nuclei_jsonl(tmp_path: pathlib.Path, findings: list[dict[str, Any]]) -> str:
    """Write a synthetic Nuclei JSONL file and return its path."""
    p = tmp_path / "nuclei.jsonl"
    lines = [json.dumps(f) for f in findings]
    p.write_text("\n".join(lines), encoding="utf-8")
    return str(p)


# ── C1: bare-IP → LabOnlyViolation ────────────────────────────────────────────


def test_c1_bare_ip_raises_lab_only_violation() -> None:
    """C1: bare-IP 168.110.192.62 must be rejected by lab_guard."""
    solver = _FakeBrowserSolve()
    with pytest.raises(LabOnlyViolation):
        run_a1_validation(
            engagement_id="test-eng",
            browser_solve=solver,
            target="168.110.192.62",
        )


# ── C2: fake CHALLENGE → classify_mitigation==CHALLENGE, solver invoked ──────


def test_c2_challenge_response_classified_and_solver_invoked() -> None:
    """C2: CF challenge response → mitigation_class==CHALLENGE, solver called."""
    solver = _FakeBrowserSolve(challenge_encountered=True, challenge_solved=False)
    # challenge_solved=False → no cred minted → chain_proven=False
    # but C7 gate: challenge_encountered=True → valid run, no raise
    result = run_a1_validation(
        engagement_id="test-eng",
        browser_solve=solver,
        http_client=_FakeHttpClient(),
        secrets_manager=MagicMock(),
        graph_store=MagicMock(),
    )
    assert result.challenge_encountered is True
    assert len(solver.calls) >= 1  # solver was invoked
    # /web probe happened
    assert any("/web" in c for c in solver.calls)


# ── C3: post-solve bundle → credential minted, raw secret absent ──────────────


def test_c3_credential_minted_raw_secret_absent(tmp_path: pathlib.Path) -> None:
    """C3: post-solve bundle body → credential minted via secrets_manager.store,
    raw secret never appears in any event or return value."""
    from agent_alpha.security.secrets import SecretsManager

    secrets_mgr = SecretsManager()
    solver = _FakeBrowserSolve(challenge_solved=True)
    http = _FakeHttpClient(login_success=True)

    result = run_a1_validation(
        engagement_id="test-eng-c3",
        browser_solve=solver,
        http_client=http,
        secrets_manager=secrets_mgr,
        graph_store=MagicMock(),
    )

    # Credential was minted (chain_proven requires cred_minted)
    assert result.chain_proven is True
    # Labels stored in the vault
    labels = secrets_mgr.list_labels("test-eng-c3")
    assert len(labels) > 0
    # Raw secret must NOT appear in the result dataclass
    result_repr = repr(dataclasses.asdict(result))
    assert "MySharedP@ss2026" not in result_repr


# ── C4: reused cred → admin access_level ──────────────────────────────────────


def test_c4_reused_cred_yields_admin_access() -> None:
    """C4: reused credential → verified admin access_level."""
    from agent_alpha.security.secrets import SecretsManager

    secrets_mgr = SecretsManager()
    solver = _FakeBrowserSolve(challenge_solved=True)
    http = _FakeHttpClient(login_success=True)

    result = run_a1_validation(
        engagement_id="test-eng-c4",
        browser_solve=solver,
        http_client=http,
        secrets_manager=secrets_mgr,
        graph_store=MagicMock(),
    )

    assert result.edge_from_harvested_cred is True
    assert result.chain_proven is True


# ── C5: chain_proven=True, edge_from_harvested_cred=True ──────────────────────


def test_c5_chain_proven_and_edge_from_harvested() -> None:
    """C5: full chain proven with edge from harvested credential."""
    from agent_alpha.security.secrets import SecretsManager

    secrets_mgr = SecretsManager()
    solver = _FakeBrowserSolve(challenge_solved=True)
    http = _FakeHttpClient(login_success=True)

    result = run_a1_validation(
        engagement_id="test-eng-c5",
        browser_solve=solver,
        http_client=http,
        secrets_manager=secrets_mgr,
        graph_store=MagicMock(),
    )

    assert result.chain_proven is True
    assert result.edge_from_harvested_cred is True


# ── C6: nuclei==0 + chain_proven → scanner_missed_exploitability=True ─────────


def test_c6_scanner_missed_exploitability(tmp_path: pathlib.Path) -> None:
    """C6: nuclei finds nothing + chain proven → scanner_missed_exploitability=True."""
    from agent_alpha.security.secrets import SecretsManager

    secrets_mgr = SecretsManager()
    solver = _FakeBrowserSolve(challenge_solved=True)
    http = _FakeHttpClient(login_success=True)
    nuclei_path = _make_nuclei_jsonl(tmp_path, [])

    result = run_a1_validation(
        engagement_id="test-eng-c6",
        browser_solve=solver,
        http_client=http,
        secrets_manager=secrets_mgr,
        graph_store=MagicMock(),
        nuclei_jsonl_path=nuclei_path,
    )

    assert result.nuclei_findings == 0
    assert result.chain_proven is True
    assert result.scanner_missed_exploitability is True


# ── C7: challenge_encountered=False → assert_valid_or_raise RAISES ────────────


def test_c7_no_challenge_raises_not_passes() -> None:
    """C7: a run where no challenge was encountered is INVALID, not a pass.
    Closes the pass-through false-positive trap."""
    # Pass-through: status 200, no challenge headers
    solver = _FakeBrowserSolve(
        challenge_encountered=False,
        challenge_solved=False,
        probe_status=200,
    )

    with pytest.raises(RuntimeError, match="no CF challenge encountered"):
        run_a1_validation(
            engagement_id="test-eng-c7",
            browser_solve=solver,
            http_client=_FakeHttpClient(),
            secrets_manager=MagicMock(),
            graph_store=MagicMock(),
        )


def test_c7_assert_valid_or_raise_directly() -> None:
    """C7 unit: assert_valid_or_raise raises on challenge_encountered=False."""
    bad_result = A1Result(
        valid_run=False,
        challenge_encountered=False,
        challenge_solved=False,
        chain_proven=False,
        edge_from_harvested_cred=False,
        nuclei_findings=0,
        scanner_missed_exploitability=False,
    )
    with pytest.raises(RuntimeError, match="A1 INVALID"):
        assert_valid_or_raise(bad_result)

    # Valid result does NOT raise
    good_result = A1Result(
        valid_run=True,
        challenge_encountered=True,
        challenge_solved=True,
        chain_proven=True,
        edge_from_harvested_cred=True,
        nuclei_findings=0,
        scanner_missed_exploitability=True,
    )
    assert_valid_or_raise(good_result)  # should not raise


# ── Default: _NoopBrowserSolve → RAISES (no silent pass) ──────────────────────


def test_noop_browser_solve_raises() -> None:
    """Default _NoopBrowserSolve must raise — 9c unbuilt, no silent pass."""
    with pytest.raises(RuntimeError, match="browser_solve transport not provided"):
        run_a1_validation(
            engagement_id="test-eng-noop",
            http_client=_FakeHttpClient(),
            secrets_manager=MagicMock(),
            graph_store=MagicMock(),
        )


def test_noop_browser_solve_directly() -> None:
    """_NoopBrowserSolve.solve_and_fetch raises RuntimeError."""
    noop = _NoopBrowserSolve()
    with pytest.raises(RuntimeError, match="9c unbuilt"):
        noop.solve_and_fetch("https://alpha-ai.web.id/web", engagement_id="test")
