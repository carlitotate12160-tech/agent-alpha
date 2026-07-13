# agent_alpha/recon/capability_probe.py
"""Capability fingerprint catalog (Header-matcher slice-1).

RULE-tier capability detection derived from a response SIGNATURE (headers OR, for
GraphQL, a GET-response body marker) selected by a playbook rule. A playbook
rule fires on a header signature (e.g. ``Server: Apache-Coyote`` -> Tomcat) and
selects a per-capability tool name; this catalog maps that tool name back to the
canonical label plus any frontier seed paths.

DETECT ONLY. A fingerprint is NOT a payable finding (fingerprint != finding):
the handler persists a labeled ASSET node and optionally seeds the frontier, but
never mints a credential nor increments the findings count. Acting on a seeded
surface (e.g. /manager/html auth) stays a gated Gamma concern behind the
authorization gate (ADR §12.26 DETECT=recon / ACT=Gamma).

PURE DATA: no I/O. This catalog is the single source of truth for a capability
tool -> (label, seeds); adding a capability = one CapabilitySpec entry + one
YAML rule, zero engine code (anti-Lyndon #6/#7).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CapabilitySpec:
    """One header-fingerprintable capability.

    tool           the RULE-tier tool name a playbook rule selects.
    label          canonical tech_stack label persisted on the ASSET node.
    frontier_seeds relative paths to enqueue for later (gated) review; may be ().
    confidence     graph-node confidence for a deterministic header match.
    """

    tool: str
    label: str
    frontier_seeds: tuple[str, ...] = ()
    confidence: float = 0.9


CAPABILITY_CATALOG: tuple[CapabilitySpec, ...] = (
    CapabilitySpec(
        tool="tomcat_fingerprint",
        label="tomcat",
        frontier_seeds=("/manager/html", "/host-manager/html"),
    ),
    CapabilitySpec(
        tool="http_basic_auth_fingerprint",
        label="http_basic_auth",
    ),
    CapabilitySpec(
        tool="s3_bucket_fingerprint",
        label="s3_bucket",
    ),
    CapabilitySpec(
        tool="graphql_fingerprint",
        label="graphql",
        confidence=0.85,
    ),
)

_BY_TOOL: dict[str, CapabilitySpec] = {spec.tool: spec for spec in CAPABILITY_CATALOG}


def capability_for_tool(tool: str) -> CapabilitySpec | None:
    """Return the CapabilitySpec a playbook selected, or None if not a capability tool."""
    return _BY_TOOL.get(tool)
