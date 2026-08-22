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

Provenance: every entry in ``_LAB_HOSTS`` carries an ownership proof (PR number
or lab directory). Entries without proof are rejected at construction time.
Ephemeral hosts (quick tunnels) carry an expiry date — expired entries are
refused at assertion time (fail-closed).
"""

from __future__ import annotations

import dataclasses
import datetime as _dt


@dataclasses.dataclass(frozen=True)
class LabHost:
    """A self-owned lab host with provenance.

    Attributes:
        host: Bare hostname (lowercase, no scheme/port).
        owner: Person or entity that owns the host.
        ownership_proof: Non-empty string — PR number, lab dir, or other
            verifiable proof that the host is self-owned.
        added_in_pr: PR number that added this entry.
        expires: Optional expiry date. If set and past, the host is refused
            at assertion time (fail-closed). Used for ephemeral hosts like
            Cloudflare quick tunnels.
    """

    host: str
    owner: str
    ownership_proof: str
    added_in_pr: str
    expires: _dt.date | None = None

    def __post_init__(self) -> None:
        if not self.ownership_proof:
            raise ValueError(f"LabHost {self.host!r}: ownership_proof must be non-empty")

        # Validate proof format by host class
        if self.host.endswith(".lab"):
            # *.lab hosts must use localhost: proof
            if not self.ownership_proof.startswith("localhost:"):
                raise ValueError(
                    f"LabHost {self.host!r}: *.lab hosts must use 'localhost:' proof, "
                    f"got {self.ownership_proof!r}"
                )
        elif self.host.endswith(".trycloudflare.com"):
            # Ephemeral hosts MUST have expires
            if self.expires is None:
                raise ValueError(f"LabHost {self.host!r}: ephemeral hosts must have expires set")
            # Proof must be dns-txt or acme
            if not (
                self.ownership_proof.startswith("dns-txt:")
                or self.ownership_proof.startswith("acme:")
            ):
                raise ValueError(
                    f"LabHost {self.host!r}: ephemeral hosts must use 'dns-txt:' or "
                    f"'acme:' proof, got {self.ownership_proof!r}"
                )
        else:
            # Routable domains must use dns-txt, acme, or public-test proof.
            # - dns-txt/acme: self-owned or client-approved (cryptographic proof).
            # - public-test: platform that explicitly authorizes security testing
            #   in its ToS (e.g. PortSwigger Academy, Acunetix vulnweb, OWASP
            #   Juice Shop). Authorization comes from the platform's ToS, not
            #   from client consent — so no DNS-TXT needed. The proof string
            #   MUST name the platform (e.g. "public-test:portswigger-academy")
            #   so provenance is auditable.
            if not (
                self.ownership_proof.startswith("dns-txt:")
                or self.ownership_proof.startswith("acme:")
                or self.ownership_proof.startswith("public-test:")
            ):
                raise ValueError(
                    f"LabHost {self.host!r}: routable domains must use 'dns-txt:', "
                    f"'acme:', or 'public-test:' proof (prose-only proofs rejected), "
                    f"got {self.ownership_proof!r}"
                )
            if self.ownership_proof == "public-test:":
                raise ValueError(
                    f"LabHost {self.host!r}: public-test proof must name the platform "
                    f"(e.g. 'public-test:portswigger-academy'), got {self.ownership_proof!r}"
                )


# ---------------------------------------------------------------------------
# Single source of truth — _LAB_HOSTS.
# LAB_TARGET_ALLOWLIST is DERIVED from this; callers are unchanged.
# ---------------------------------------------------------------------------
_LAB_HOSTS: tuple[LabHost, ...] = (
    LabHost("agentalpha.duckdns.org", "natanael", "dns-txt:agent-alpha=verified", "#207"),
    # WP lab (wp_lab/) — 6 vhosts on 127.0.0.1:443 via nginx
    LabHost("vuln.wp.lab", "natanael", "localhost:wp_lab/", "#207"),
    LabHost("rotated.wp.lab", "natanael", "localhost:wp_lab/", "#207"),
    LabHost("decoy.wp.lab", "natanael", "localhost:wp_lab/", "#207"),
    LabHost("waf.wp.lab", "natanael", "localhost:wp_lab/", "#207"),
    LabHost("hardened.wp.lab", "natanael", "localhost:wp_lab/", "#207"),
    LabHost("cotenant.wp.lab", "natanael", "localhost:wp_lab/", "#207"),
    # Laravel lab (targets/laravel-lab/) — 2 containers on :9090/:9091
    LabHost("laravel-vuln.lab", "natanael", "localhost:targets/laravel-lab/", "#207"),
    LabHost("laravel-hardened.lab", "natanael", "localhost:targets/laravel-lab/", "#207"),
    # SPA lab (js_lab/) — Caddy, 2 vhosts
    LabHost("spa-vuln.lab", "natanael", "localhost:js_lab/", "#207"),
    LabHost("spa-hardened.lab", "natanael", "localhost:js_lab/", "#207"),
    # Chain lab (infra/chain_lab_app.py) — mock server on :9201
    LabHost("chain-lab.lab", "natanael", "localhost:infra/chain_lab_app.py", "#207"),
    # WAF lab (infra/waf_lab_docker.yml) — ModSecurity CRS in front of chain_lab on :9080
    LabHost("waf.chain-lab.lab", "natanael", "localhost:infra/waf_lab_docker.yml", "#458"),
    # Odoo lab (odoo_lab/) — 2 vhosts on 127.0.0.1:443 via nginx
    LabHost("odoo.lab", "natanael", "localhost:odoo_lab/", "#207"),
    LabHost("vuln.odoo.lab", "natanael", "localhost:odoo_lab/", "#207"),
    LabHost("hardened.odoo.lab", "natanael", "localhost:odoo_lab/", "#207"),
    # Git exposure lab (git_lab/) — 2 vhosts on 127.0.0.1:443 via nginx
    LabHost("vuln.git.lab", "natanael", "localhost:git_lab/", "#207"),
    LabHost("hardened.git.lab", "natanael", "localhost:git_lab/", "#207"),
    # Backup-file exposure lab (backup_lab/) — 2 vhosts on 127.0.0.1:443 via nginx
    LabHost("vuln.backup.lab", "natanael", "localhost:backup_lab/", "#207"),
    LabHost("hardened.backup.lab", "natanael", "localhost:backup_lab/", "#207"),
    # Actuator exposure lab (actuator_lab/) — 2 vhosts on 127.0.0.1:443 via nginx
    LabHost("vuln.actuator.lab", "natanael", "localhost:actuator_lab/", "#207"),
    LabHost("hardened.actuator.lab", "natanael", "localhost:actuator_lab/", "#207"),
    # CodeIgniter config-leak lab (codeigniter_lab/) — 2 vhosts on 127.0.0.1:8444
    LabHost("vuln.codeigniter.lab", "natanael", "localhost:codeigniter_lab/", "#470"),
    LabHost("hardened.codeigniter.lab", "natanael", "localhost:codeigniter_lab/", "#470"),
    # Layer V-B — real-TLD self-owned lab (DuckDNS) for crt.sh-on-real-CT proof.
    LabHost("vuln.agentalpha.duckdns.org", "natanael", "dns-txt:agent-alpha=verified", "#207"),
    LabHost("hardened.agentalpha.duckdns.org", "natanael", "dns-txt:agent-alpha=verified", "#207"),
    # CDN-fronted (Cloudflare-proxied) self-owned Odoo stack — A1 validation.
    LabHost("odoo.agentalpha.duckdns.org", "natanael", "dns-txt:agent-alpha=verified", "#207"),
    # External self-owned domain (alpha-ai.web.id) — Oracle ARM64 behind Cloudflare
    LabHost(
        "alpha-ai.web.id",
        "natanael",
        "dns-txt:agentalpha-lab-proof=bc90b41d578cbf3c66512495d2e9aaaa",
        "#214",
    ),
    # alpha-ai.web.id subdomains — self-owned lab stacks (DNS-only for dev; Phase B: CF Origin cert)
    LabHost(
        "wp.alpha-ai.web.id",
        "natanael",
        "dns-txt:agentalpha-lab-proof=bc90b41d578cbf3c66512495d2e9aaaa",
        "#272",
    ),
    LabHost(
        "laravel.alpha-ai.web.id",
        "natanael",
        "dns-txt:agentalpha-lab-proof=bc90b41d578cbf3c66512495d2e9aaaa",
        "#272",
    ),
    LabHost(
        "odoo.alpha-ai.web.id",
        "natanael",
        "dns-txt:agentalpha-lab-proof=bc90b41d578cbf3c66512495d2e9aaaa",
        "#272",
    ),
    # Direct (non-CF) sibling — self-owned; domain-level DNS-TXT proof (same token as
    # the other alpha-ai.web.id subdomains). Used as an origin-exposure target in the
    # integrated recon field-prove.
    LabHost(
        "direct.alpha-ai.web.id",
        "natanael",
        "dns-txt:agentalpha-lab-proof=bc90b41d578cbf3c66512495d2e9aaaa",
        "#364",
    ),
    # Vercel edge lab — same alpha-ai.web.id proof, but hosted on Vercel edge
    # (IP 216.198.79.65 / 64.29.17.65) which differs from Oracle (168.110.192.62).
    # Used for multi-origin / origin-discovery field-prove (GAP-018, GAP-038, GAP-042).
    # TLS is managed by Vercel via ACME; the DNS-TXT proof is on the alpha-ai.web.id
    # apex and inherited for all subdomains.
    LabHost(
        "vercel-lab.alpha-ai.web.id",
        "natanael",
        "dns-txt:agentalpha-lab-proof=bc90b41d578cbf3c66512495d2e9aaaa",
        "#399",
    ),
    # Cloudflare quick tunnel — ephemeral, expires. Changes per tunnel start.
    LabHost(
        "responding-yards-adaptation-floors.trycloudflare.com",
        "natanael",
        "dns-txt:agent-alpha=verified",
        "#211",
        expires=_dt.date(2026, 7, 27),
    ),
    # Recon try-harder field-prove lab hosts
    LabHost("apex.recon.lab", "natanael", "localhost:recon_lab/", "#207"),
    LabHost("late.recon.lab", "natanael", "localhost:recon_lab/", "#207"),
    LabHost("waf.recon.lab", "natanael", "localhost:recon_lab/", "#207"),
    LabHost("decoy.recon.lab", "natanael", "localhost:recon_lab/", "#207"),
    LabHost("dead.recon.lab", "natanael", "localhost:recon_lab/", "#207"),
    LabHost("hardened.recon.lab", "natanael", "localhost:recon_lab/", "#207"),
    # GAP-044 field-prove: catch-all 200 lab (nginx :8444, all paths → 200)
    LabHost("catchall.lab", "natanael", "localhost:nginx/catchall.lab", "#386"),
    # Client-approved external target (Odoo behind Cloudflare)
    LabHost(
        "quantum-laboratories.com",
        "natanael",
        "dns-txt:agent-alpha=client-approved",
        "#335",
    ),
    # Client-approved external target (Odoo behind Cloudflare)
    LabHost(
        "niagamas.com",
        "natanael",
        "dns-txt:agent-alpha=client-approved",
        "#367",
    ),
    # Client-approved external target (WP + WooCommerce)
    LabHost(
        "bernofarm.com",
        "natanael",
        "dns-txt:agent-alpha=client-approved",
        "#TBD",
    ),
    # Client-approved external target (WP, previously tested in Lyndon)
    LabHost(
        "solusibersama.co.id",
        "natanael",
        "dns-txt:agent-alpha=client-approved",
        "#TBD",
    ),
    # Client-approved external target (CodeIgniter + PHP 7.4 on Hostinger/LiteSpeed)
    LabHost(
        "ingco.co.id",
        "natanael",
        "dns-txt:agent-alpha=client-approved",
        "#378",
    ),
    # Client-approved external target (WP + Apache, Nigeria ISP).
    LabHost(
        "spectranet.com.ng",
        "natanael",
        "dns-txt:agent-alpha=client-approved",
        "#398",
    ),
    # -----------------------------------------------------------------------
    # Public test targets — platforms that EXPLICITLY authorize security
    # testing in their ToS. Authorization comes from the platform, not from
    # client consent. Used for T3-lite (real internet, no WAF/CF) testing of
    # GAP-001 (new stack playbooks) and handler logic against real responses.
    # Does NOT replace docker-compose lab stacks (T2) or self-owned CF domains
    # (T3-real). Cannot test WAF/CF evasion, origin discovery, or cred-reuse.
    # -----------------------------------------------------------------------
    # PortSwigger Academy — explicitly for learning/testing (ToS permits).
    LabHost(
        "demo.testfire.net",
        "public-test",
        "public-test:ibm-alfresco-demo",
        "#TBD",
    ),
    # Acunetix vulnweb test sites — explicitly for testing (Acunetix ToS).
    LabHost(
        "testaspnet.vulnweb.com",
        "public-test",
        "public-test:acunetix-vulnweb",
        "#TBD",
    ),
    LabHost(
        "testasp.vulnweb.com",
        "public-test",
        "public-test:acunetix-vulnweb",
        "#TBD",
    ),
    LabHost(
        "testphp.vulnweb.com",
        "public-test",
        "public-test:acunetix-vulnweb",
        "#TBD",
    ),
    # OWASP Juice Shop — OWASP project, explicitly for testing.
    LabHost(
        "juice-shop.herokuapp.com",
        "public-test",
        "public-test:owasp-juice-shop",
        "#TBD",
    ),
    # Google Gruyere — Google Code University, explicitly for learning.
    LabHost(
        "google-gruyere.appspot.com",
        "public-test",
        "public-test:google-gruyere",
        "#TBD",
    ),
)

# Derived allowlist — backward compatible with all 13 callers.
LAB_TARGET_ALLOWLIST: frozenset[str] = frozenset(h.host for h in _LAB_HOSTS)


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


def _is_expired(host: str) -> bool:
    """Check if a host's LabHost entry has expired."""
    for h in _LAB_HOSTS:
        if h.host == host and h.expires is not None:
            return _dt.date.today() > h.expires
    return False


def assert_lab_only_target(
    target: str,
    allowlist: frozenset[str] = LAB_TARGET_ALLOWLIST,
) -> None:
    """Fail-closed: raise ``LabOnlyViolation`` unless *target* is a self-owned lab.

    Call this before ANY network activity in a field-prove harness, for every
    target in scope. Exact host match only — a look-alike such as
    ``lab.example.evil.com`` is refused. Expired entries are also refused
    (fail-closed for ephemeral hosts like quick tunnels).
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
    if _is_expired(normalised):
        raise LabOnlyViolation(
            f"refusing expired lab target {normalised!r}: the entry has passed "
            f"its expiry date. Renew or remove it from _LAB_HOSTS."
        )
