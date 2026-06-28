"""Phase-3 Step 1: the CredentialApplicator seam (refactor, behaviour unchanged).

cred_reuse.run is HTTP-shaped today. Before adding a DB transport (Lyndon #10/#4/#8),
extract the form-login into HttpFormApplicator behind a CredentialApplicator protocol.
This test PINS the seam: the applicator applies the credential to the wire, returns an
AuthResult with NO raw secret, declares its service + required_auth, and a selector picks
the right applicator by service. RED until applicator.py exists (correct reason: ImportError).

The full Alpha→Beta chain regression stays covered by test_cred_reuse_chain.py — this
file guards the seam unit so the refactor can't silently change behaviour.
Run on Oracle: .venv/bin/python3 -m pytest tests/phase_3/test_credential_applicator_seam.py
"""

from __future__ import annotations

from typing import Any

from agent_alpha.tools.contracts import ResourceBudget
from agent_alpha.tools.internal.access.applicator import (
    AuthResult,
    CredentialApplicator,
    HttpFormApplicator,
    select_applicator,
)

_SECRET = "S3cr3t-leaked-db-pass"


class _FakeResponse:
    def __init__(self, status_code: int, text: str, headers: dict[str, str]) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers


class _RecordingHttpClient:
    """Records the POSTed credential so the test can prove it reached the wire."""

    def __init__(self) -> None:
        self.posted_data: dict[str, Any] | None = None

    def get(self, url: str, *, cookies: Any = None) -> _FakeResponse:
        if cookies:
            return _FakeResponse(200, "<html>admin dashboard welcome</html>", {})
        return _FakeResponse(200, '<html><form><input type="password"></form></html>', {})

    def post(self, url: str, *, data: Any = None, **_: Any) -> _FakeResponse:
        self.posted_data = data
        return _FakeResponse(
            200,
            "<html>admin dashboard welcome</html>",
            {"set-cookie": "session=ABC123; Path=/; HttpOnly"},
        )


def test_http_form_applicator_conforms_and_declares_tier() -> None:
    applicator = HttpFormApplicator(http_client=_RecordingHttpClient())

    assert isinstance(applicator, CredentialApplicator)
    assert applicator.service == "http"
    assert applicator.required_auth == "ACTIVE_APPROVED"


def test_apply_puts_credential_on_the_wire_and_returns_no_raw_secret() -> None:
    http = _RecordingHttpClient()
    applicator = HttpFormApplicator(http_client=http)
    budget = ResourceBudget(max_requests=5, max_seconds=10, max_cost_usd=0.0)

    result = applicator.apply(
        username="admin", secret=_SECRET, target="http://lab.invalid/login", budget=budget
    )

    # The credential MUST reach the wire (anti-Lyndon #3: no proof-theatre).
    assert http.posted_data is not None
    assert http.posted_data.get("password") == _SECRET

    assert isinstance(result, AuthResult)
    assert result.success is True
    assert result.service == "http"
    assert result.access_level == "admin"

    # No raw secret may appear in the proof fields (vault is its only home).
    blob = repr(result.proof_request) + repr(result.proof_response)
    assert _SECRET not in blob
    assert result.session_cookie_name == "session"


def test_selector_picks_applicator_by_service() -> None:
    http = HttpFormApplicator(http_client=_RecordingHttpClient())

    class _FakeMySql:
        service = "mysql"
        required_auth = "OFFENSIVE_APPROVED"

        def applies_to(self, credential_service: str, target: str) -> bool:
            return credential_service == "mysql"

        def apply(self, **_: Any) -> AuthResult:  # pragma: no cover - not invoked here
            raise AssertionError("must not be selected for an http credential")

    chosen = select_applicator([http, _FakeMySql()], credential_service="http", target="http://x")

    assert chosen is http


def test_selector_returns_none_when_no_applicator_matches() -> None:
    http = HttpFormApplicator(http_client=_RecordingHttpClient())

    chosen = select_applicator([http], credential_service="ldap", target="ldap://x")

    assert chosen is None
