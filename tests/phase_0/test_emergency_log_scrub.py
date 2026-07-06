"""Contract: emergency kill-switch must neutralise CR/LF in the client-supplied
engagement_id before it reaches a log sink (py/log-injection).

engagement_id enters as a FastAPI path param; a crafted value with newlines could
forge or split lines in the audit log — which for the kill switch IS the legal audit
trail. The sanitiser is applied to LOG output only; real logic keeps the raw value.
"""

from __future__ import annotations

from agent_alpha.conductor.emergency import _scrub_log_id


def test_scrub_strips_crlf() -> None:
    forged = "eng_abc\r\n2026-01-01 FORGED audit line issued_by=attacker"
    scrubbed = _scrub_log_id(forged)
    assert "\n" not in scrubbed
    assert "\r" not in scrubbed
    # content is preserved minus the newlines (no data loss, just single-line)
    assert scrubbed == "eng_abc2026-01-01 FORGED audit line issued_by=attacker"


def test_scrub_is_identity_for_wellformed_id() -> None:
    assert _scrub_log_id("eng_9f3a2b") == "eng_9f3a2b"
