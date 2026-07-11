# RED test (slice-1c) — the REAL git-dumper WRAP recovers tracked files from an
# exposed /.git over HTTP, replacing the fail-loud _NoopGitDumper so git_exposure
# becomes PAYABLE end-to-end.
#
# TARGET PATH:  tests/phase_4/test_git_dumper.py
# AUTHORED BY:  Claude (test/gate lane). The WRAP body (shell out to the commodity
#               git-dumper — ADR §12.22 WRAP, do NOT rebuild a reconstructor) is
#               the IDE/infra lane. This pins the OBSERVABLE contract only:
#               GitDumper().dump(base_url) -> {relative_path: file_content}.
#
# Hermetic: a temp git repo is served over a localhost http.server — NO external
# network, NO lab. (The self-owned exposed-.git LAB field-prove is slice-1c-ii,
# separate, Oracle-live.)
#
# Run on Oracle ARM64 only (requires git + the git-dumper tool installed):
#   .venv312/bin/python3 -m pytest tests/phase_4/test_git_dumper.py -v

from __future__ import annotations

import http.server
import os
import platform
import socketserver
import subprocess
import threading
from pathlib import Path

import pytest

from agent_alpha.recon.git_exposure_probe import GitDumper  # RED: real wrap absent

# Skip on non-Oracle ARM64 (git-dumper not available on Windows dev environment)
pytestmark = pytest.mark.skipif(
    platform.system() != "Linux" or platform.machine() != "aarch64",
    reason="git-dumper test requires Oracle ARM64 with git-dumper installed"
)


def _git(root: Path, *args: str) -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t.lab",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t.lab",
    }
    subprocess.run(["git", *args], cwd=root, check=True, env=env, capture_output=True)


def _make_exposed_git_repo(root: Path) -> None:
    """A committed repo whose /.git will be served (the 'exposed' condition)."""
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "config" / "database.yml").write_text(
        "production:\n  username: appuser\n  password: sup3rs3cret\n  host: db.internal\n"
    )
    (root / ".env").write_text("APP_KEY=base64:abc\nDB_PASSWORD=another-secret\n")
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "init")


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a: object) -> None:  # keep test output clean
        pass


def _serve(directory: Path) -> tuple[socketserver.TCPServer, int]:
    def handler(*a: object, **k: object) -> _QuietHandler:
        return _QuietHandler(*a, directory=str(directory), **k)  # type: ignore[arg-type]

    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def test_dump_recovers_tracked_file_with_content(tmp_path: Path) -> None:
    repo = tmp_path / "site"
    _make_exposed_git_repo(repo)
    httpd, port = _serve(repo)
    try:
        recovered = GitDumper().dump(f"http://127.0.0.1:{port}/")
    finally:
        httpd.shutdown()

    assert "config/database.yml" in recovered, f"tracked file not recovered: {list(recovered)}"
    assert "sup3rs3cret" in recovered["config/database.yml"]


def test_dump_maps_all_tracked_paths(tmp_path: Path) -> None:
    # The contract is {relative_path: content} for EVERY tracked file, so the
    # downstream secret scan sees the whole recovered surface (not just one file).
    repo = tmp_path / "site"
    _make_exposed_git_repo(repo)
    httpd, port = _serve(repo)
    try:
        recovered = GitDumper().dump(f"http://127.0.0.1:{port}/")
    finally:
        httpd.shutdown()

    assert {"config/database.yml", ".env"} <= set(recovered)
    assert "another-secret" in recovered[".env"]
