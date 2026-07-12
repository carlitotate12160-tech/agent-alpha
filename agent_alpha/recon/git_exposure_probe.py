# agent_alpha/recon/git_exposure_probe.py
"""Commodity git-dumper WRAP for the exposed-``/.git`` leak vector (ADR §12.22).

The recon control flow (probe /.git/config -> classify -> dump -> extract -> mint)
now lives in the ONE data-driven engine ``agent_alpha.recon.path_probe`` (the
``git_exposure`` catalog entry, RecoverStrategy.DUMP). This module keeps ONLY the
git-specific commodity wrap: the dumper that reconstructs tracked files from an
exposed ``/.git`` over HTTP. FAIL-LOUD on any error or empty recovery (anti-#3).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class GitDumperProtocol(Protocol):
    """Interface for the wrapped commodity git-dumper.

    Implementations MUST:
      - Perform a read-only dump of the git repository rooted at *base_url*.
      - Return a mapping of ``{path: content}`` for recovered tracked files.
    """

    def dump(self, base_url: str) -> dict[str, str]: ...


class _NoopGitDumper:
    """Placeholder dumper used when no real git-dumper integration is configured.

    FAIL-LOUD (anti-#3): raises rather than returning an empty {} that would read as
    a silent 'no exposure'. Production wiring injects a real dumper.
    """

    def dump(self, base_url: str) -> dict[str, str]:  # noqa: ARG002
        raise RuntimeError("Git dumper integration not configured")


class GitDumper:
    """Commodity WRAP of the git-dumper tool (ADR §12.22).

    Shells out to git-dumper to recover tracked files from an exposed /.git over HTTP.
    Returns {relative_path: content} for all recovered files. FAIL-LOUD on any error
    or empty recovery (anti-#3).
    """

    def dump(self, base_url: str) -> dict[str, str]:
        if not shutil.which("git-dumper"):
            raise RuntimeError("git-dumper tool not found in PATH")

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "dumped"

            result = subprocess.run(
                ["git-dumper", base_url, str(output_dir)],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout for large repos
            )

            if result.returncode != 0:
                raise RuntimeError(f"git-dumper failed: {result.stderr}")

            recovered: dict[str, str] = {}
            if not output_dir.exists():
                raise RuntimeError("git-dumper produced no output directory")

            for file_path in output_dir.rglob("*"):
                if file_path.is_file():
                    rel_str = str(file_path.relative_to(output_dir)).replace("\\", "/")
                    if (
                        rel_str == ".git"
                        or rel_str.startswith(".git/")
                        or "/.git/" in rel_str
                        or rel_str.endswith("/.git")
                    ):
                        continue
                    try:
                        recovered[rel_str] = file_path.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue

            if not recovered:
                raise RuntimeError("git-dumper recovered no files")

            return recovered


def _default_git_dumper() -> GitDumperProtocol:
    return GitDumper()
