"""Phase 0 — CI workflow verbose/debug guard.

Ensures GitHub Actions workflows do not accidentally enable debug/verbose
mode (ACTIONS_RUNNER_DEBUG, --verbose flags, debug log level) which would
inflate CI logs and potentially leak secrets.

TEST CONTRACT:
  1. No workflow file sets ACTIONS_RUNNER_DEBUG=true
  2. No workflow file passes --verbose to CodeQL init/analyze
  3. No workflow file sets ACTIONS_STEP_DEBUG to true
  4. CodeQL query suite is security-extended (not security-and-quality,
     which doubles log volume with quality FPs)

Run on Oracle ARM64 only (Rule 10).
"""

from __future__ import annotations

from pathlib import Path

_WORKFLOWS_DIR = Path(__file__).resolve().parents[2] / ".github" / "workflows"


def _read_workflow(name: str) -> str:
    path = _WORKFLOWS_DIR / name
    assert path.exists(), f"workflow file {name} not found"
    return path.read_text(encoding="utf-8")


def test_no_actions_runner_debug_in_any_workflow() -> None:
    """ACTIONS_RUNNER_DEBUG=true would dump all internal GitHub Actions
    debug output — massive log inflation + potential secret exposure."""
    for yml in _WORKFLOWS_DIR.glob("*.yml"):
        content = yml.read_text(encoding="utf-8")
        assert (
            "ACTIONS_RUNNER_DEBUG" not in content
            or "ACTIONS_RUNNER_DEBUG" in content
            and "true" not in content.split("ACTIONS_RUNNER_DEBUG")[1].split("\n")[0]
        ), f"{yml.name} sets ACTIONS_RUNNER_DEBUG=true"


def test_no_actions_step_debug_in_any_workflow() -> None:
    """ACTIONS_STEP_DEBUG=true enables step-level debug tracing."""
    for yml in _WORKFLOWS_DIR.glob("*.yml"):
        content = yml.read_text(encoding="utf-8")
        assert (
            "ACTIONS_STEP_DEBUG" not in content
            or "ACTIONS_STEP_DEBUG" in content
            and "true" not in content.split("ACTIONS_STEP_DEBUG")[1].split("\n")[0]
        ), f"{yml.name} sets ACTIONS_STEP_DEBUG=true"


def test_codeql_no_verbose_flag() -> None:
    """CodeQL init/analyze steps must not pass --verbose flag."""
    content = _read_workflow("codeql.yml")
    # Check for --verbose in the CodeQL action steps
    lines = content.splitlines()
    in_codeql_step = False
    for line in lines:
        if "uses: github/codeql-action" in line:
            in_codeql_step = True
        elif in_codeql_step and line.strip().startswith("- name:"):
            in_codeql_step = False
        if in_codeql_step and "--verbose" in line:
            pytest_fail(f"codeql.yml has --verbose flag: {line.strip()}")


def test_codeql_query_suite_is_security_extended() -> None:
    """CodeQL must use security-extended, not security-and-quality
    (which doubles log volume with quality FPs — 55 of 68 alerts were FPs)."""
    content = _read_workflow("codeql.yml")
    # Extract the active queries: line (not comments)
    queries_lines = [
        line.strip() for line in content.splitlines() if line.strip().startswith("queries:")
    ]
    assert len(queries_lines) == 1, "codeql.yml must have exactly one queries: line"
    assert "security-extended" in queries_lines[0], (
        f"codeql.yml queries must be security-extended, got: {queries_lines[0]}"
    )
    assert "security-and-quality" not in queries_lines[0], (
        "codeql.yml queries must NOT use security-and-quality (quality FPs inflate logs)"
    )


def test_ci_no_debug_log_level() -> None:
    """CI workflow must not set log-level=debug or similar."""
    content = _read_workflow("ci.yml")
    assert (
        "log-level=debug" not in content.lower() and "--log-level debug" not in content.lower()
    ), "ci.yml sets debug log level"


def pytest_fail(msg: str) -> None:
    import pytest

    pytest.fail(msg)
