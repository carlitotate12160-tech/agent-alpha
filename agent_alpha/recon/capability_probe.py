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

from agent_alpha.config import constants


@dataclass(frozen=True)
class CapabilitySpec:
    """One header-fingerprintable capability.

    tool           the RULE-tier tool name a playbook rule selects.
    label          canonical tech_stack label persisted on the ASSET node.
    frontier_seeds relative paths to enqueue for later (gated) review; may be ().
    confidence     graph-node confidence for a deterministic header match.
    follow_up_tools handler names to invoke immediately on the SAME response,
                   after frontier seeds are enqueued; may be ().
    """

    tool: str
    label: str
    frontier_seeds: tuple[str, ...] = ()
    confidence: float = 0.9
    follow_up_tools: tuple[str, ...] = ()


CAPABILITY_CATALOG: tuple[CapabilitySpec, ...] = (
    CapabilitySpec(
        tool="tomcat_fingerprint",
        label="tomcat",
        # ACTUATOR_PATHS moved here from the unconditional run_recon seed
        # (was fired at every host regardless of stack). Gated behind Tomcat
        # header detection since that's the cheapest existing Spring-adjacent
        # signal — tradeoff: a target that suppresses its Server header will
        # not get an Actuator check this way.
        frontier_seeds=("/manager/html", "/host-manager/html", *constants.ACTUATOR_PATHS),
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
    CapabilitySpec(
        tool="odoo_fingerprint",
        label="odoo",
        frontier_seeds=("/web/database/manager",),
    ),
    # CodeIgniter fingerprint: detects a CI surface via session cookie or CSRF
    # markers and labels the asset. CI config paths (application/config/database.php)
    # are seeded via PATH_PROBE_CATALOG's codeigniter_config spec (applies_to_stacks
    # gate), NOT here — frontier_seeds stay empty to mirror the actuator pattern
    # (path selection is the Planner's job, not the capability fingerprint's).
    CapabilitySpec(
        tool="codeigniter_fingerprint",
        label=constants.STACK_CI,
    ),
    # WordPress fingerprint: detects a WP surface and seeds /wp-json/ +
    # /readme.html so the full WP battery (wp_rest_routes, wp_rest_users,
    # woocommerce, wp_version) fires through the autonomous recon path.
    # The 4 action specs below intentionally have NO frontier_seeds — deeper
    # routes stay data-derived from the live /wp-json/ index (unchanged).
    CapabilitySpec(
        tool="wp_fingerprint",
        label=constants.STACK_WP,
        # WP_CONFIG_BACKUP_PATHS (9 paths) moved here from the unconditional
        # run_recon seed / BACKUP_FILE_PATHS union — previously fired at every
        # non-WP host too (pure noise, guaranteed 404). Now fires the instant
        # WP is confirmed, same as /wp-json/ + /readme.html already did.
        frontier_seeds=("/wp-json/", "/readme.html", *constants.WP_CONFIG_BACKUP_PATHS),
        follow_up_tools=("wp_plugins",),
    ),
    # WordPress recon-depth battery (STACK_WP). Each is keyed on the stack
    # fingerprint via its own playbook; the label is the single WP tech_stack
    # SSOT (constants.STACK_WP). Route-surface escalation is filtered by
    # constants.WP_REST_INTERESTING_ROUTES inside the handler, so no static
    # frontier_seeds here (the seeds are data-derived from the live index).
    CapabilitySpec(
        tool="wp_rest_routes",
        label=constants.STACK_WP,
    ),
    CapabilitySpec(
        tool="wp_rest_users",
        label=constants.STACK_WP,
    ),
    CapabilitySpec(
        tool="woocommerce",
        label=constants.STACK_WP,
    ),
    CapabilitySpec(
        tool="wp_version",
        label=constants.STACK_WP,
    ),
)

_BY_TOOL: dict[str, CapabilitySpec] = {spec.tool: spec for spec in CAPABILITY_CATALOG}


def capability_for_tool(tool: str) -> CapabilitySpec | None:
    """Return the CapabilitySpec a playbook selected, or None if not a capability tool."""
    return _BY_TOOL.get(tool)
