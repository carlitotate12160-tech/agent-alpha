"""Universal, source-general product/version extractor for SERVICE nodes."""

from __future__ import annotations

from dataclasses import dataclass

from agent_alpha.graph.nodes import ServiceProperties


@dataclass(frozen=True)
class ProductEvidence:
    """A product and optional version extracted from an observation."""
    product: str
    version: str | None
    source: str
    confidence: float


# Anti-#6/7: Where a capability already exists, use its canonical label.
# These maps carry PRODUCT names, never TARGET hostnames (Universal-by-Design).
COOKIE_NAME_PRODUCT: dict[str, str] = {
    "metabase.": "Metabase",
}

CSP_DOMAIN_PRODUCT: dict[str, str] = {
    "metabase.com": "Metabase",
}


def is_cve_correlation_eligible(svc: ServiceProperties) -> bool:
    """§12.67 anti-#3: version-inference needs a VERSION. product-without-version
    (nginx/Metabase-from-cookie) is an OBSERVATION, never a CVE hypothesis."""
    return bool(svc.version) and svc.confidence > 0.0


def _parse_version_optional_header(header_value: str, source: str) -> list[ProductEvidence]:
    """Parse a server identity string which may or may not contain a version.
    E.g. 'Apache/2.4.6' -> (Apache, 2.4.6), 'nginx' -> (nginx, None)."""
    results = []
    # Can contain multiple tokens separated by space, e.g., "Apache/2.4.6 OpenSSL/1.0.2"
    for token in header_value.split():
        if not token.strip():
            continue
        if "/" in token:
            product, version = token.split("/", 1)
            results.append(ProductEvidence(product.strip().lower(), version.strip(), source, 0.8))
        else:
            results.append(ProductEvidence(token.strip().lower(), None, source, 0.6))
    return results


def extract_service_evidence(
    headers: dict[str, str], set_cookies: list[str], csp_header: str, body: str  # noqa: ARG001
) -> list[ProductEvidence]:
    """Extract product/version evidence from multiple heterogenous sources."""
    evidence = []

    # 1. Server header
    server = headers.get("server", "")
    if server:
        evidence.extend(_parse_version_optional_header(server, "server_header"))

    # 2. X-Powered-By header
    xpb = headers.get("x-powered-by", "")
    if xpb:
        evidence.extend(_parse_version_optional_header(xpb, "x_powered_by"))

    # 3. Cookie names
    for cookie in set_cookies:
        # Simplistic parsing of cookie name before '='
        if "=" in cookie:
            name = cookie.split("=", 1)[0].strip()
        else:
            name = cookie.strip()
        for prefix, product in COOKIE_NAME_PRODUCT.items():
            if name.startswith(prefix):
                evidence.append(ProductEvidence(product, None, "cookie_name", 0.7))

    # 4. CSP domain
    if csp_header:
        for domain, product in CSP_DOMAIN_PRODUCT.items():
            if domain in csp_header:
                evidence.append(ProductEvidence(product, None, "csp_domain", 0.7))

    return evidence
