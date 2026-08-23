"""Fingerprint-first recon seed — ADR §12.65 / GAP-169 (fingerprint_all + seed_fingerprint_first).

The moat behaviour: an operator fingerprints the root BEFORE seeding probes, so a WordPress host
gets WP paths (not a blind `.git`/`.env` spray) and a Java/Odoo host gets ZERO WordPress paths.
`fingerprint_all` is proven against the REAL recon PlaybookEngine (not a stub) so the wiring to the
live rule tier + CAPABILITY_CATALOG is exercised, not mocked.
"""

from __future__ import annotations

import pathlib
from typing import Any

from agent_alpha.agents.http_client import HttpClientError
from agent_alpha.agents.planner import Planner
from agent_alpha.config import constants
from agent_alpha.recon.fingerprint import fingerprint_all, seed_fingerprint_first
from agent_alpha.tools.playbook import PlaybookEngine

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")


def _engine() -> PlaybookEngine:
    return PlaybookEngine.from_directory(_PLAYBOOK_DIR, phase="recon")


def _obs(body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {"body": body, "headers": headers or {}}


# ── fingerprint_all: multi-label header+body over the REAL rule tier ──────────


def test_fingerprint_all_wp_body() -> None:
    assert fingerprint_all(_obs(body="<link href='/wp-content/a.css'>"), _engine()) == (
        constants.STACK_WP,
    )


def test_fingerprint_all_odoo_body() -> None:
    assert fingerprint_all(_obs(body="odoo.define('x')"), _engine()) == ("odoo",)


def test_fingerprint_all_codeigniter_cookie() -> None:
    """A CI session cookie (Set-Cookie: ci_session=...) → ('codeigniter',)."""
    assert fingerprint_all(
        _obs(body="<html>plain</html>", headers={"Set-Cookie": "ci_session=abc123; path=/"}),
        _engine(),
    ) == (constants.STACK_CI,)


def test_plain_php_without_ci_marker_is_not_codeigniter() -> None:
    """A generic PHP host WITHOUT a CI marker must NOT be labeled codeigniter
    (anti over-detect, #3). Apache/PHP Server header + plain PHP body → no CI
    cookie, no csrf_test_name, no ci_csrf_token → 'codeigniter' NOT in labels."""
    labels = fingerprint_all(
        _obs(
            body="<html><body><?php echo 'hello'; ?></body></html>",
            headers={"Server": "Apache/2.4.6 (CentOS) PHP/7.1.33"},
        ),
        _engine(),
    )
    assert "codeigniter" not in labels


def test_fingerprint_all_codeigniter_csrf_markers() -> None:
    """Both body markers (csrf_test_name, ci_csrf_token) yield STACK_CI
    without needing the ci_session cookie — covers all evidence paths."""
    for marker in ("csrf_test_name", "ci_csrf_token"):
        assert fingerprint_all(
            _obs(body=f'<input name="{marker}">'),
            _engine(),
        ) == (constants.STACK_CI,)


def test_fingerprint_all_ci_session_substring_is_not_a_false_positive() -> None:
    """Anti-#3: a cookie whose name merely CONTAINS 'ci_session' (e.g.
    my_ci_session_helper) must NOT be labeled CI — the anchored regex
    (^|;\\s*)ci_session= requires ci_session= at cookie-name start."""
    labels = fingerprint_all(
        _obs(headers={"Set-Cookie": "my_ci_session_helper=x"}),
        _engine(),
    )
    assert constants.STACK_CI not in labels


def test_fingerprint_all_multistack_wp_behind_tomcat() -> None:
    """Decision C CARDINAL: a root that matches TWO capability rules (WP body + Tomcat Server
    header) yields BOTH labels — a single top-1 match would under-seed the multi-stack host."""
    labels = fingerprint_all(
        _obs(body="wp-content", headers={"Server": "Apache-Coyote/1.1"}), _engine()
    )
    assert set(labels) == {constants.STACK_WP, "tomcat"}


def test_fingerprint_all_cold_host_no_labels() -> None:
    assert fingerprint_all(_obs(body="<html>plain page</html>"), _engine()) == ()


def test_fingerprint_all_none_playbook_is_empty() -> None:
    """A test-stub orchestrator with no `.playbook` → no labels → DEFAULT baseline downstream
    (zero behaviour change for stub-orchestrator callers)."""
    assert fingerprint_all(_obs(body="wp-content"), None) == ()


# ── seed_fingerprint_first: the reorder + prime + D-2 edges ───────────────────


class _Resp:
    def __init__(self, text: str = "", headers: dict[str, str] | None = None) -> None:
        self.text = text
        self.headers = headers or {}
        self.status_code = 200


class _HttpOK:
    def __init__(self, resp: _Resp) -> None:
        self._resp = resp
        self.calls: list[str] = []

    def get(self, url: str) -> _Resp:
        self.calls.append(url)
        return self._resp


class _HttpDead:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url: str) -> _Resp:
        self.calls.append(url)
        raise HttpClientError("transport dead")


class _Intel:
    def __init__(self, protection: Any = None) -> None:
        self.protection_detected = protection
        self.historical_paths: tuple[str, ...] = ()


class _FakeAlpha:
    """Minimal Alpha recon-context double: the exact seam seed_fingerprint_first touches."""

    def __init__(self, http: Any, playbook: Any = None) -> None:
        self.http_client = http
        self.orchestrator = type("_O", (), {"playbook": playbook})()
        self._planner = Planner()  # real, PURE selector — no double for the seed algorithm
        self._prefetched: dict[str, Any] = {}
        self._dead_hosts: set[str] = set()
        self._work_queue: list[str] = ["https://t.x"]  # _reset_target_state seeds [target_url]
        self.enqueued: list[str] = []
        self.abandoned: list[str] = []
        # §12.61 transport-dead origin-flank seam: seed_fingerprint_first now routes a
        # root transport-dead through attempt_reach_transport_dead. With no engagement
        # profile the helper fail-closes (returns None) → the dead-root abandon path
        # below runs unchanged. A profile-bearing origin-flank is covered end-to-end in
        # tests/phase_2_5/test_alpha_autonomous_reach.py (not this pure seed unit).
        self._reach_attempted: set[str] = set()
        self._engagement_profile: Any = None

    def enqueue_discovered_url(self, url: str) -> bool:
        self.enqueued.append(url)
        return True

    def _persist_host_abandoned_event(self, host: str) -> None:
        self.abandoned.append(host)


def test_seed_wp_root_seeds_wp_not_blind_and_primes() -> None:
    """Decision A/B: a WP root → seed driven by the 'wp' label with the blind DEFAULT spray
    SUPPRESSED (bool(labels) → suppress_default), and the fetched root is PRIMED (Decision D)."""
    alpha = _FakeAlpha(_HttpOK(_Resp(text="wp-content marker")), playbook=_engine())
    seed_fingerprint_first(alpha, "https://t.x", "https://t.x", _Intel())

    assert alpha._prefetched.get("https://t.x") is not None  # primed → loop reuses, no 2nd GET
    assert alpha.http_client.calls == ["https://t.x"]  # fetched exactly once here
    wp_expected = alpha._planner.select_leak_paths([constants.STACK_WP], suppress_default=True)
    assert alpha.enqueued == [f"https://t.x{p}" for p in wp_expected]


def test_seed_cold_root_seeds_default_baseline() -> None:
    """Decision B: an unfingerprinted root still seeds DEFAULT_LEAK_PATHS (the honest
    stack-agnostic baseline — .env/.git/backups), primed for the loop."""
    alpha = _FakeAlpha(_HttpOK(_Resp(text="<html>plain</html>")), playbook=_engine())
    seed_fingerprint_first(alpha, "https://t.x", "https://t.x", _Intel())

    assert any("/.env" in u or "/.git" in u for u in alpha.enqueued)  # DEFAULT baseline present
    assert "https://t.x" in alpha._prefetched


def test_seed_waf_root_suppresses_blind_spray() -> None:
    """Decision D-2 (WAF): protection_detected → suppress_blind → the blind DEFAULT extras
    (.env / backups) are suppressed on a WAF host (only the universal .git hygiene probe stays,
    §12.25), and the (block) response is still primed for the loop's reach to handle."""
    alpha = _FakeAlpha(_HttpOK(_Resp(text="challenge")), playbook=_engine())
    seed_fingerprint_first(alpha, "https://t.x", "https://t.x", _Intel(protection="cloudflare"))

    assert not any("/.env" in u or "wp-config" in u for u in alpha.enqueued)  # DEFAULT suppressed
    assert alpha.enqueued == ["https://t.x/.git/config"]  # only universal hygiene remains
    assert "https://t.x" in alpha._prefetched  # still primed → loop reach uses it


def test_seed_dead_root_abandons_and_prunes_queue() -> None:
    """Decision D-2 (transport): a dead root → host marked dead, its pre-seeded target_url PRUNED
    from the queue (so the loop makes NO second GET), HOST_ABANDONED emitted, nothing primed."""
    alpha = _FakeAlpha(_HttpDead())
    seed_fingerprint_first(alpha, "https://t.x", "https://t.x", _Intel())

    assert "t.x" in alpha._dead_hosts
    assert alpha._work_queue == []  # target_url pruned → loop won't re-attempt the dead host
    assert alpha.abandoned == ["t.x"]
    assert alpha._prefetched == {}  # not primed on a dead root
    assert alpha.enqueued == []
