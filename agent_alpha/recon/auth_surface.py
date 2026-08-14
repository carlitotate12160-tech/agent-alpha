# agent_alpha/recon/auth_surface.py
"""Universal auth-surface recognition - technology-agnostic.

A reachable login / authentication surface is a first-class objective for the
access phase (Beta), independent of any framework-specific vuln probe. This
recognizer keys ONLY on universal HTTP signals (auth-challenge header, a
password input) - NEVER a per-target or per-framework catalog (anti-Lyndon #11:
no hardcoded per-client behaviour). Labels are drawn from the same semantic set
the router's has_web_auth_surface() consumes.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

# Fallback 1: static type="password" (existing)
_PASSWORD_INPUT = re.compile(r"<input[^>]*type\s*=\s*['\"]?password\b['\"]?", re.IGNORECASE)

# Fallback 2: autocomplete attribute (WHATWG standard — strongest, SPA-proof)
_AUTOCOMPLETE_PASSWORD = re.compile(
    r'autocomplete\s*=\s*["\'](?:current-password|new-password)["\']', re.IGNORECASE
)

# Fallback 3: name="password" or id="password" within <input ...> tag (any framework)
_NAME_ID_PASSWORD = re.compile(r'<input[^>]*(?:name|id)\s*=\s*["\']?password["\']?', re.IGNORECASE)


# ── Auth-type label vocabulary (SINGLE source, anti-#7) ─────────────────────────
# Beta can bind a credential applicator to STRIKABLE labels NOW. The others are
# classified-but-not-attacked (GAP-030): token/digest/api need Gamma-tier tools
# (JWT confusion, API abuse) or no applicator exists — labelling them precisely
# stops false ``http_basic_auth`` from routing a strike at a non-basic surface.
HTTP_BASIC_AUTH = "http_basic_auth"
HTTP_DIGEST_AUTH = "http_digest_auth"
TOKEN_AUTH = "token_auth"
API_AUTH = "api_auth"
UNKNOWN_AUTH = "unknown_auth"
LOGIN_FORM = "login-form"

# WWW-Authenticate scheme (RFC 7235 token, case-insensitive) -> auth-type label.
_WWW_AUTH_SCHEME: dict[str, str] = {
    "basic": HTTP_BASIC_AUTH,
    "digest": HTTP_DIGEST_AUTH,
    "bearer": TOKEN_AUTH,
}

# GAP-030 Slice 1b: SPA login surface rendered by JS. A pure SPA shell
# (<div id="app">) carries NO password input in the initial HTML, so the HTML
# regexes above miss it — the login <input> lives in the JS bundle. This label is
# now STRIKABLE via SpaLoginApplicator (Slice-B): a JSON-API login reuse tool that
# POSTs JSON credentials, extracts a JWT from the 2xx response, and cross-verifies
# via Bearer replay. Previously classify-only; strikable once SpaLoginApplicator
# was wired into the factory.
SPA_LOGIN_FORM = "spa-login-form"

# GAP-074 auth MECHANISM labels (mech_* — ride the same tech_stack persist path as the
# auth-type labels; feed the coverage denominator + later Beta mechanism-aware tool
# selection, fixing "XML-RPC tool on a JSON-RPC target"). Universal, no framework catalog.
MECH_HTTP_BASIC = "mech_http_basic"
MECH_JSON_RPC = "mech_json_rpc"
MECH_JWT = "mech_jwt"
MECH_SAML = "mech_saml"
MECH_OAUTH = "mech_oauth"
MECH_FORM_POST = "mech_form_post"

_ALL_MECH_LABELS: frozenset[str] = frozenset(
    {MECH_HTTP_BASIC, MECH_JSON_RPC, MECH_JWT, MECH_SAML, MECH_OAUTH, MECH_FORM_POST}
)

# GAP-074 slice 2a: mechanism -> the applicator.service value(s) fit to strike it.
# SINGLE source (anti-#7): both Beta selection (applicator_factory) and any future
# consumer read the mech->tool mapping here, never a second hardcoded copy.
#   mech_form_post -> "http"  (WpLoginApplicator + HttpFormApplicator, both service="http")
#   mech_json_rpc  -> "spa"   (SpaLoginApplicator, service="spa")
#   mech_http_basic-> {}      (GAP-046: NO credential-reuse applicator exists → strike nothing)
# jwt/saml/oauth are deliberately ABSENT (GAP-114 capability_absent) → resolve to {} =
# fail-CLOSED, never fail-open: a present-but-unstrikable mechanism binds no web tool.
MECH_TO_APPLICATOR_SERVICES: dict[str, frozenset[str]] = {
    MECH_FORM_POST: frozenset({"http"}),
    MECH_JSON_RPC: frozenset({"spa"}),
    MECH_HTTP_BASIC: frozenset(),
}


def applicator_services_for_mechanisms(labels: Iterable[str]) -> frozenset[str] | None:
    """Given a host's tech_stack labels, return the applicator.service values whose tools
    fit the host's auth MECHANISM.

    Return values (the fail-open/closed contract, single source):
      * ``None``  -> NO mech_* label present -> FAIL-OPEN (caller binds every candidate;
                     preserves pre-GAP-074 behaviour, no regression).
      * frozenset -> one or more mech_* labels present -> bind ONLY these services
                     (may be EMPTY = fail-CLOSED: a classified surface with no strikable
                     tool binds nothing, so no wrong tool fires at it).
    """
    present = [label for label in labels if label.startswith("mech_")]
    if not present:
        return None
    allowed: set[str] = set()
    for label in present:
        allowed |= MECH_TO_APPLICATOR_SERVICES.get(label, frozenset())
    return frozenset(allowed)


_MECH_PREFIX = "mech_"


def bare_mechanisms(labels: Iterable[str]) -> frozenset[str]:
    """Map a host's ``mech_*`` tech_stack labels to the BARE mechanism tokens the
    coverage catalog (techniques.yaml ``auth_mechanism``) uses — ``mech_json_rpc`` ->
    ``json_rpc``. SINGLE source reconciling the two spellings of one concept (anti-#7):
    persist/selection use the prefixed label, the catalog uses the bare token, and this
    is the ONE place that bridges them. Empty result = mechanism unknown for this host."""
    return frozenset(
        label[len(_MECH_PREFIX) :] for label in labels if label.startswith(_MECH_PREFIX)
    )


_FORM_POST_RE = re.compile(r"<form[^>]*method\s*=\s*['\"]?post", re.IGNORECASE)
_SAML_RE = re.compile(r"SAMLRequest|SAMLResponse|urn:oasis:names:tc:SAML", re.IGNORECASE)
_OAUTH_RE = re.compile(
    r"/oauth/(?:authorize|token)|response_type=code|[?&]client_id=", re.IGNORECASE
)
_JWT_HINT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\."  # a JWT literal in the page/JS
    r"|(?:localStorage|sessionStorage)\.[gs]etItem\(\s*['\"](?:token|jwt|access_token)",
    re.IGNORECASE,
)

# The subset Beta may actually strike this phase (auth-type only; the router adds
# tech-stack fingerprints like wp/odoo that also imply a strikable login surface).
# SPA_LOGIN_FORM added when SpaLoginApplicator landed (Slice-B) — JSON-API login
# reuse is now a real strike capability, no longer classify-only.
STRIKABLE_AUTH_LABELS: frozenset[str] = frozenset({HTTP_BASIC_AUTH, LOGIN_FORM, SPA_LOGIN_FORM})

_JS_LOGIN_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Quote char class includes backtick: Vite/esbuild minified bundles use
    # template-literal quotes (type:`password`) instead of ' or ". A named
    # backreference (?P=quote) requires the closing delimiter to match the
    # opening one, preventing mixed-quote false positives (type:'password"`).
    re.compile(r"""type\s*[:=]\s*(?P<quote>['"`])password(?P=quote)""", re.IGNORECASE),
    re.compile(
        r"""autocomplete\s*[:=]\s*(?P<quote>['"`])(?:current-password|new-password)(?P=quote)""",
        re.IGNORECASE,
    ),
    re.compile(r"""(?:name|id)\s*[:=]\s*(?P<quote>['"`])password(?P=quote)""", re.IGNORECASE),
    re.compile(r"""<input[^>]*type\s*=\s*(?P<quote>['"`]?)password""", re.IGNORECASE),
)


def scan_js_for_login_surface(js_body: str) -> bool:
    """True iff a JS bundle body advertises a login/password INPUT (SPA login form).

    Pure + deterministic; no I/O. The caller (verify_js_secret_leak) already has the
    bundle body in hand, so this reuses that fetch — no second network round-trip.
    """
    if not js_body:
        return False
    return any(pattern.search(js_body) for pattern in _JS_LOGIN_PATTERNS)


def _body_is_json(headers: Mapping[str, str], body: str) -> bool:
    for k, v in headers.items():
        if k.lower() == "content-type" and "json" in v.lower():
            return True
    stripped = (body or "").lstrip()
    return stripped[:1] in ("{", "[")


def _parse_www_authenticate_schemes(headers: Mapping[str, str]) -> list[str]:
    """Extract all WWW-Authenticate scheme tokens from response headers.

    Handles comma-joined single-header form (legacy). Comma inside quoted strings
    (realm="x,y") is NOT split. Mapping[str, str] already flattens separate headers.
    """
    raw_values = [v for k, v in headers.items() if k.lower() == "www-authenticate"]
    schemes: list[str] = []
    for raw in raw_values:
        parts: list[str] = []
        current = ""
        in_quote = False
        for ch in raw:
            if ch in ('"', "'"):
                in_quote = not in_quote
            if ch == "," and not in_quote:
                parts.append(current.strip())
                current = ""
            else:
                current += ch
        if current.strip():
            parts.append(current.strip())
        for part in parts:
            scheme = part.split(None, 1)[0].lower() if part else ""
            # Skip parts that are parameters of the previous challenge (e.g.
            # nonce="y" after Digest realm="x",). A valid scheme token is a
            # bare word that is NOT a key=value pair.
            if scheme and "=" not in part.split(None, 1)[0]:
                schemes.append(scheme)
    return schemes


def fingerprint_auth_mechanism(
    *, status_code: int, headers: Mapping[str, str], body: str
) -> str | None:
    """GAP-074: classify the AUTH MECHANISM of a login surface (not just its presence).

    Returns one mech_* label or None. Pure + deterministic; universal signals only.
    Precedence: HTTP Basic challenge > SAML/OAuth SSO markers > JWT/JSON API > HTML form POST.
    (SPA/Vue json_rpc logins are labelled at the JS-bundle stage — the shell HTML carries
    no form; see js_secret_probe SPA-login persist.)
    """
    body = body or ""
    if any(scheme == "basic" for scheme in _parse_www_authenticate_schemes(headers)):
        return MECH_HTTP_BASIC
    if _SAML_RE.search(body):
        return MECH_SAML
    if _OAUTH_RE.search(body):
        return MECH_OAUTH
    if _JWT_HINT_RE.search(body):
        return MECH_JWT
    if _body_is_json(headers, body):
        return MECH_JSON_RPC
    if _FORM_POST_RE.search(body) and (
        _PASSWORD_INPUT.search(body) or _NAME_ID_PASSWORD.search(body)
    ):
        return MECH_FORM_POST
    return None


def detect_auth_surface_labels(
    *, status_code: int, headers: Mapping[str, str], body: str
) -> list[str]:
    """Return auth-surface labels for a fetched response (order-stable, deduped).

    * HTTP auth challenge (401 or WWW-Authenticate header) -> "http_basic_auth"
    * a password input anywhere in the body                -> "login-form"

    Password input detection (universal, framework-agnostic):
      1. <input type="password"> (static)
      2. autocomplete="current-password" | "new-password" (WHATWG standard)
      3. <input name="password"> | <input id="password"> (any framework)

    Empty list = no auth surface observed. Pure + deterministic; no I/O; works
    for ANY stack (Laravel, WP, custom, Tomcat, Vue, React) because it keys on
    universal HTML attributes, not framework-specific patterns.
    """
    labels: list[str] = []
    # ── Auth-challenge classification (GAP-030): discriminate by WWW-Authenticate
    #    scheme. A bare 401 without a Basic challenge is NOT assumed basic-auth —
    #    that false positive would route a basic-auth strike at a token/api surface.
    #    Multiple WWW-Authenticate challenges (RFC 7235) are ALL parsed — a server
    #    may advertise "Bearer, Basic" and both labels are emitted.
    www_auth_schemes = _parse_www_authenticate_schemes(headers)
    if www_auth_schemes:
        for scheme in www_auth_schemes:
            labels.append(_WWW_AUTH_SCHEME.get(scheme, UNKNOWN_AUTH))
    elif status_code == 401:
        # 401 with no challenge header: JSON body => api_auth, else unknown_auth.
        labels.append(API_AUTH if _body_is_json(headers, body) else UNKNOWN_AUTH)
    if body:
        # Check all three fallbacks; any match = login-form
        has_password_input = (
            _PASSWORD_INPUT.search(body) is not None
            or _AUTOCOMPLETE_PASSWORD.search(body) is not None
            or _NAME_ID_PASSWORD.search(body) is not None
        )
        if has_password_input:
            labels.append(LOGIN_FORM)
    # Dedup while preserving order (first occurrence wins)
    seen: set[str] = set()
    deduped: list[str] = []
    for label in labels:
        if label not in seen:
            seen.add(label)
            deduped.append(label)
    return deduped
