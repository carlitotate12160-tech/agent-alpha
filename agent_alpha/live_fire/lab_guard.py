"""Lab-only guard for field-prove harnesses.

PERMANENT safety control — never removed, not even in full production.

A field-prove harness validates a TOOL against KNOWN ground truth (a planted
synthetic secret in a self-owned lab). It self-authorizes: it builds its own
AuthorizationStateMachine and takes scope from a hand-edited YAML, bypassing the
Conductor. That is legitimate ONLY for a self-owned lab and MUST NEVER touch a
client or production target. Client engagements run exclusively through the
Conductor's non-bypassable SOW auth gate — a different code path entirely.

This guard makes that rule enforced-by-code, not by discipline: the harness
refuses any target not in an explicit self-owned lab allowlist. Fail-closed — an
empty allowlist or an unrecognised target is refused, never allowed.

Why the allowlist is a CODE constant, not engagement config: if it lived in the
YAML, it could be edited to add a client host — which is exactly the bypass we
are closing. It must not be overridable from the same file that sets scope.
"""

from __future__ import annotations

# Self-owned field-prove lab hosts ONLY. Add a lab you own and control.
# NEVER add a client or production domain here.
LAB_TARGET_ALLOWLIST: frozenset[str] = frozenset(
    {
        "agentalpha.duckdns.org",
        # WP lab (wp_lab/) — 6 vhosts on 127.0.0.1:443 via nginx
        "vuln.wp.lab",
        "rotated.wp.lab",
        "decoy.wp.lab",
        "waf.wp.lab",
        "hardened.wp.lab",
        "cotenant.wp.lab",
        # Laravel lab (targets/laravel-lab/) — 2 containers on :9090/:9091
        "laravel-vuln.lab",
        "laravel-hardened.lab",
        # SPA lab (js_lab/) — Caddy, 2 vhosts
        "spa-vuln.lab",
        "spa-hardened.lab",
        # Chain lab (infra/chain_lab_app.py) — mock server on :9201
        "chain-lab.lab",
        # Odoo lab (odoo_lab/) — 2 vhosts on 127.0.0.1:443 via nginx
        # "odoo.lab" is the apex used by the Layer V root-only seal (R1+R2 discovery).
        "odoo.lab",
        "vuln.odoo.lab",
        "hardened.odoo.lab",
        # Git exposure lab (git_lab/) — 2 vhosts on 127.0.0.1:443 via nginx
        "vuln.git.lab",
        "hardened.git.lab",
        # Backup-file exposure lab (backup_lab/) — 2 vhosts on 127.0.0.1:443 via nginx
        "vuln.backup.lab",
        "hardened.backup.lab",
        # Actuator exposure lab (actuator_lab/) — 2 vhosts on 127.0.0.1:443 via nginx
        "vuln.actuator.lab",
        "hardened.actuator.lab",
        # Layer V-B — real-TLD self-owned lab (DuckDNS) for the crt.sh-on-real-CT
        # proof. Per-host FQDNs (NOT a wildcard): each must appear in CT logs
        # individually, because parse_crtsh_names collapses "*." to the apex.
        "vuln.agentalpha.duckdns.org",
        "hardened.agentalpha.duckdns.org",
        # CDN-fronted (Cloudflare-proxied) self-owned Odoo stack — validation
        # vs scanner harness (A1 success-condition). Same self-owned infra as
        # agentalpha.duckdns.org, fronted by a real CDN for WAF/challenge tests.
        "odoo.agentalpha.duckdns.org",
        # Self-owned lab/test environment — Quantum Laboratories
        "quantum-laboratories.com",
        # Recon try-harder field-prove lab hosts
        "apex.recon.lab",
        "late.recon.lab",
        "waf.recon.lab",
        "decoy.recon.lab",
        "dead.recon.lab",
        "hardened.recon.lab",
    }
)


class LabOnlyViolation(RuntimeError):
    """Raised when a field-prove harness is pointed at a non-lab target."""


def _normalise_host(target: str) -> str:
    """Reduce a target string to a bare, lowercased host for exact comparison.

    Strips scheme, path, credentials, and port so that
    ``https://user@lab.example:443/path`` compares as ``lab.example``.
    """
    host = target.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if ":" in host:
        host = host.split(":", 1)[0]
    return host


def assert_lab_only_target(
    target: str,
    allowlist: frozenset[str] = LAB_TARGET_ALLOWLIST,
) -> None:
    """Fail-closed: raise ``LabOnlyViolation`` unless *target* is a self-owned lab.

    Call this before ANY network activity in a field-prove harness, for every
    target in scope. Exact host match only — a look-alike such as
    ``lab.example.evil.com`` is refused.
    """
    normalised = _normalise_host(target)
    if not normalised:
        raise LabOnlyViolation(f"empty/invalid field-prove target: {target!r}")
    if normalised not in allowlist:
        raise LabOnlyViolation(
            f"refusing non-lab target {normalised!r}: the field-prove harness is "
            f"self-owned-lab ONLY (allowlist={sorted(allowlist)}). Client/prod "
            f"engagements run through the Conductor SOW gate, never this harness."
        )
