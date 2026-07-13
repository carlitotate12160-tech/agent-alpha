# agent_alpha/recon/surface_discovery.py
"""Surface-discovery: OpenAPI/Swagger spec -> frontier endpoints (slice-1).

A frontier FEEDER, not a payable content-probe. When Alpha fetches an exposed API
specification (/openapi.json, /swagger.json, ...), this parses the declared REST
paths into concrete same-origin URLs and hands them back so the scout can enqueue
them through its existing in-scope guard. Those new URLs are then probed by the
already-payable vectors (git/backup/actuator/wp/laravel/header) -- surface-discovery
MULTIPLIES the reach of payable probes; it mints nothing itself (ADR §12.26 separate
frontier-feeder catalog; DETECT/enumerate only, ACT stays gated).

PURE: no I/O. Parses an already-fetched body. Returns [] on non-spec / unparseable /
empty (anti-Lyndon #3: [] is 'nothing discovered', never dressed as success).

slice-1 scope: OpenAPI 3 (``openapi``) + Swagger 2 (``swagger``), concrete paths only.
Templated paths ('/users/{id}') are skipped -- they need parameter synthesis to be
probeable, deferred to a follow-up. GraphQL introspection (a schema, not URL paths)
is a separate slice-2 concern.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin, urlparse


def extract_api_surface(body: str, base_url: str) -> list[str]:
    """Parse an OpenAPI/Swagger JSON body into concrete same-origin endpoint URLs.

    Returns a de-duplicated, order-preserving list of absolute URLs for every
    concrete (non-templated) path the spec declares, rooted at *base_url*'s origin
    (plus a Swagger-2 ``basePath`` when present). Returns [] for anything that is
    not a parseable OpenAPI/Swagger document.
    """
    if not body or not body.strip():
        return []
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(doc, dict):
        return []
    # Must self-identify as OpenAPI 3 or Swagger 2; otherwise not our document.
    if "openapi" not in doc and "swagger" not in doc:
        return []

    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    raw_base = doc.get("basePath")
    base_path = raw_base if isinstance(raw_base, str) else ""

    seen: set[str] = set()
    endpoints: list[str] = []
    for raw_path in paths:
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            continue
        if "{" in raw_path or "}" in raw_path:
            continue  # templated -> needs param synthesis (deferred)
        joined = (base_path.rstrip("/") + raw_path) if base_path else raw_path
        url = urljoin(origin + "/", joined.lstrip("/"))
        if url not in seen:
            seen.add(url)
            endpoints.append(url)
    return endpoints
