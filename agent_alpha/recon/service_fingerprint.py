"""Universal, source-general product/version extractor for SERVICE nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_alpha.graph.nodes import AttackNode, NodeType, ServiceProperties


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
    headers: dict[str, str],
    set_cookies: list[str],
    csp_header: str,
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


def _merge_evidences(evidences: list[ProductEvidence]) -> list[tuple[str, str | None, float, list[str]]]:
    """Helper to group evidences by product and calculate merged confidence."""
    from collections import defaultdict

    grouped = defaultdict(list)
    for ev in evidences:
        grouped[ev.product].append(ev)

    results = []
    for product, ev_list in grouped.items():
        best_version = None
        max_confidence = 0.0
        sources = []

        for ev in ev_list:
            if ev.version and (best_version is None or ev.confidence > max_confidence):
                best_version = ev.version
            sources.append(ev.source)
            max_confidence = max(max_confidence, ev.confidence)

        if len(set(sources)) > 1:
            max_confidence = min(1.0, max_confidence + 0.1)

        results.append((product, best_version, max_confidence, list(set(sources))))

    return results


def get_merged_service_nodes(resp: Any, url: str) -> list[AttackNode]:
    """Consumes HTTP metadata, extracts product evidences, groups and dedups them,
    and returns a list of AttackNodes (SERVICE) ready for persistence."""
    import datetime
    from urllib.parse import urlparse

    host = urlparse(url).hostname or urlparse(url).netloc
    if not host:
        return []

    headers = dict(getattr(resp, "headers", {}))
    set_cookies: list[str] = []
    if hasattr(resp, "headers") and hasattr(resp.headers, "get_all"):
        set_cookies = resp.headers.get_all("set-cookie", [])
    elif "set-cookie" in headers:
        set_cookies = [headers["set-cookie"]]

    csp_header = headers.get("content-security-policy", "")

    evidences = extract_service_evidence(headers, set_cookies, csp_header)
    if not evidences:
        return []

    merged_data = _merge_evidences(evidences)

    parsed_url = urlparse(url)
    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
    now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"

    nodes = []
    for product, best_version, max_confidence, sources in merged_data:
        nodes.append(
            AttackNode(
                id=f"service:{host}:{port}:{product}",
                type=NodeType.SERVICE,
                properties=ServiceProperties(
                    name=product,
                    version=best_version or "",
                    port=port,
                    protocol=parsed_url.scheme,
                    source=",".join(sources),
                    confidence=max_confidence,
                ),
                confidence=max_confidence,
                timestamp_utc=now_utc,
                agent="alpha",
            )
        )
    return nodes
