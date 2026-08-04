# agent_alpha/config/constants.py
# SINGLE SOURCE OF TRUTH for all threshold and configuration values.
# All other files import from this module — never define magic numbers elsewhere.

__all__ = [
    "LLM_REASONING_PROVIDER",
    "LLM_REASONING_CONSENSUS",
    "LLM_PAYLOAD_PROVIDER",
    "STACK_WP",
    "LLM_PAYLOAD_FALLBACK",
    "LLM_PAYLOAD_TRANSPORT",
    "LLM_PAYLOAD_NEVER",
    "LLM_PAYLOAD_ALLOWED",
    "LLM_TIER_RULE",
    "LLM_TIER_SINGLE",
    "LLM_TIER_CONSENSUS",
    "LLM_TOOL_SELECT_MAX_TOKENS",
    "BLAST_GATE_SEVERITY_THRESHOLD",
    "DEEPSEEK_HTTP_TIMEOUT_SEC",
    "LLM_MAX_UNTRUSTED_BODY_CHARS",
    "CONSENSUS_AGREE_THRESHOLD",
    "CONSENSUS_ESCALATE_THRESHOLD",
    "EMERGENCY_STOP_TIMEOUT_SEC",
    "MAX_SCOPE_IPS",
    "MAX_WORKERS_PER_ROLE",
    "DEFAULT_MAX_WORKERS",
    "JWT_ALGORITHM",
    "JWT_SECRET_ENV",
    "HTTP_REQUEST_TIMEOUT_SEC",
    "HTTP_DEFAULT_ACCEPT_HEADER",
    "DEFAULT_RATE_LIMIT_RPS",
    "DEFAULT_OPSEC_PROFILE",
    "SOW_MAX_FILE_SIZE_MB",
    "SOW_HASH_ALGORITHM",
    "EVENT_SEQUENCE_GAP_ALLOWED",
    "MAX_EVENTS_PER_ENGAGEMENT",
    "EVENT_STORE_TABLE",
    "ENGAGEMENT_MEMORY_TABLE",
    "VAULT_SECRETS_TABLE",
    "MAX_ITERATIONS_PER_AGENT",
    "MAX_TIME_BUDGET_SECONDS",
    "MAX_COST_BUDGET_USD",
    "NO_PROGRESS_THRESHOLD_ITERS",
    "ALPHA_RECON_NO_PROGRESS_ITERS",
    "CELERY_TASK_SOFT_LIMIT_SEC",
    "CELERY_TASK_HARD_LIMIT_SEC",
    "CELERY_QUEUE_PREFIX",
    "CELERY_RESULT_EXPIRES_SEC",
    "CELERY_TASK_MAX_RETRIES",
    "SECRETS_ENCRYPTION_ALGO",
    "LOG_SCRUB_PATTERNS",
    "SCOPE_ALWAYS_EXCLUDED",
    "REPORT_FORMATS",
    "MITRE_ATTACK_VERSION",
    "CDN_INFRA_EXCLUDE_PREFIXES",
    "LARAVEL_CREDENTIAL_ENV_KEYS",
    "LARAVEL_CREDENTIAL_SERVICE_MAP",
    "LARAVEL_CREDENTIAL_USERNAME_KEYS",
    "LARAVEL_CREDENTIAL_LOGIN_PAIRS",
    "WP_CREDENTIAL_LOGIN_PAIRS",
    "WP_CREDENTIAL_USERNAME_KEYS",
    "WP_CREDENTIAL_SECRET_KEYS",
    "WP_CREDENTIAL_SERVICE_MAP",
    "WP_CONFIG_BACKUP_PATHS",
    "WP_REST_INTERESTING_ROUTES",
    "WP_VERSION_PATHS",
    "WP_PLUGIN_DANGEROUS_NAMESPACES",
    "WP_CRAWL_ALLOW_PATH_PREFIXES",
    "BACKUP_FILE_PATHS",
    "ACTUATOR_PATHS",
    "GIT_LEAK_PATHS",
    "WELL_KNOWN_LEAK_PATHS",
    "SURFACE_DISCOVERY_PATHS",
    "DEFAULT_LEAK_PATHS",
    "SURFACE_APPLIES_TO",
    "MIN_SAMPLES_BEFORE_SKIP",
    "DEEPSEEK_PRICING_USD_PER_1K",
    "MAX_FP_RATE",
    "RECON_TOOL_CATALOG",
    "JSON_BODY_TOOLS",
    "EVASION_CONSECUTIVE_BLOCKED_N",
    "EVASION_MAX_ESCALATIONS_PER_HOST",
    "CRED_LOCKOUT_MAX_ATTEMPTS_PER_USERNAME",
    "CRED_LOCKOUT_MAX_ATTEMPTS_PER_HOST",
    "USER_DERIVED_MAX_CANDIDATES_PER_USER",
    "TECHNIQUE_FOR_MITIGATION_CLASS",
    "ODOO_VERSION_INFO_PATH",
    "ODOO_VERSION_JSONRPC_BODY",
    "REACH_TIMEOUT_S",
    "MAX_ORGANIC_CRAWL_PER_HOST",
    "ODOO_DBMANAGER_EXPOSURE_CVSS",
]

# ── LLM Providers ──────────────────────────────────────────
# ADR §12.15: roles canonical, providers configurable.
# REASONING = ORIENT / PLAN / narrative. PAYLOAD = offensive tool & exploit-body generation.
# The ROLE is the architectural invariant; the PROVIDER behind each role is configuration.

# Reasoning provider (TEMPORARY testing value; production target: Claude / GPT-class)
# See ADR §12.15 switch gate: must be Claude/GPT-class before first paid client engagement.
LLM_REASONING_PROVIDER = "deepseek-v4-flash"  # Current testing provider
LLM_REASONING_CONSENSUS = "claude-sonnet-4-20250514"  # Consensus secondary (Claude-class)

# Payload provider (direct open-weight provider ONLY; NEVER aggregator/router)
LLM_PAYLOAD_PROVIDER = "deepseek-v4-pro"  # Primary payload provider
LLM_PAYLOAD_FALLBACK = "claude-sonnet-4-20250514"  # Fallback when primary refuses

# Transport policy (ADR §12.15)
LLM_PAYLOAD_TRANSPORT = "direct"  # Payload MUST use direct provider API ONLY
# Valid values: "direct" (vendor API), "gateway" (aggregator like OpenRouter/Bedrock)
# Payload role enforces "direct" only; reasoning role allows both with zero-retention contract.

# Provider allowlists (hard guards)
LLM_PAYLOAD_NEVER = [
    "gpt",
]  # HARD GUARD: never allow GPT for payload generation (ADR §12.10)
LLM_PAYLOAD_ALLOWED = [
    "deepseek-v4-pro",
    "kimi-2.6",
    "claude-sonnet-4-20250514",
]  # Allowed payload providers
# NOTE: there is intentionally no "TESTING_MODE" flag here. Payload-prompt
# permissiveness must never vary by a boolean switch — see
# config/payload_prompt_template.md ("Enforcement note"). The only thing
# that gates payload generation is a live AuthorizationStateMachine query
# (engagement_id -> EngagementRecord.state == OFFENSIVE_APPROVED, sow_hash
# present). If you find yourself wanting to add a mode flag here, that is
# the signal to stop and re-read this note.

# ── LLM Tier Labels ─────────────────────────────────────────
LLM_TIER_RULE = "rule"
LLM_TIER_SINGLE = "single_llm"
LLM_TIER_CONSENSUS = "consensus"

# ── LLM Orchestrator ────────────────────────────────────────
LLM_TOOL_SELECT_MAX_TOKENS = 512  # headroom for reasoning model JSON reply
# DeepSeek HTTP round-trip timeout — its own concept (LLM inference is
# slower than a recon GET), kept distinct from HTTP_REQUEST_TIMEOUT_SEC.
DEEPSEEK_HTTP_TIMEOUT_SEC = 30.0
# Max chars of untrusted target body forwarded to an LLM (token + injection bound).
LLM_MAX_UNTRUSTED_BODY_CHARS = 4000

# ── Consensus Thresholds ────────────────────────────────────
CONSENSUS_AGREE_THRESHOLD = 0.80
CONSENSUS_ESCALATE_THRESHOLD = 0.50

# ── Conductor Gates ──────────────────────────────────────────
BLAST_GATE_SEVERITY_THRESHOLD = "high"

# ── Authorization ────────────────────────────────────────────
EMERGENCY_STOP_TIMEOUT_SEC = 5
MAX_SCOPE_IPS = 256
JWT_ALGORITHM = "HS256"
JWT_SECRET_ENV = "AGENT_ALPHA_JWT_SECRET"

# ── HTTP Client ──────────────────────────────────────────────
HTTP_REQUEST_TIMEOUT_SEC = 30.0
# Bug #10: without an Accept header, some origins (observed: Cloudways/WP)
# reject the request with HTTP 415 instead of serving real HTML — the agent
# was analysing the origin's generic error page, not the target's content.
# Single source (anti-Lyndon #7): every HttpClient instance uses this value.
HTTP_DEFAULT_ACCEPT_HEADER = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
# Default egress rate limit (requests/sec) per engagement HttpClient. Safe RoE
# default = the policy.yaml "quiet" OPSEC profile (2 rps); per-engagement OPSEC
# profile selection (policy.yaml normal=10/loud=50) overrides via the ctor when
# that feature lands. Single source for the code-level default (anti-Lyndon #7).
DEFAULT_RATE_LIMIT_RPS = 2.0
# Default OPSEC profile name for recon — "announced" = honest identifying UA,
# no evasion, fail-closed.  Per-engagement profile selection (slice-2b) will
# override this via the ctor; until then all recon paths use this profile.
# Single source for the profile name (anti-Lyndon #7).
DEFAULT_OPSEC_PROFILE: str = "announced"
SOW_MAX_FILE_SIZE_MB = 50
SOW_HASH_ALGORITHM = "sha256"

# ── Event Store ──────────────────────────────────────────────
EVENT_SEQUENCE_GAP_ALLOWED = False
MAX_EVENTS_PER_ENGAGEMENT = 100_000
EVENT_STORE_TABLE = "agent_events"
ENGAGEMENT_MEMORY_TABLE = "engagement_memory"
VAULT_SECRETS_TABLE = "vault_secrets"

# ── Stop Conditions (enforced Phase 2+, defined here) ────────
MAX_ITERATIONS_PER_AGENT = 500
MAX_TIME_BUDGET_SECONDS = 14_400
MAX_COST_BUDGET_USD = 50.0
NO_PROGRESS_THRESHOLD_ITERS = 20
ALPHA_RECON_NO_PROGRESS_ITERS = 5  # R1: raised from 1 so frontier URLs enqueued by step() can run

# ── Celery ───────────────────────────────────────────────────
CELERY_TASK_SOFT_LIMIT_SEC = 3_600
CELERY_TASK_HARD_LIMIT_SEC = 14_400
CELERY_QUEUE_PREFIX = "engagement_"
CELERY_RESULT_EXPIRES_SEC = 3_600
CELERY_TASK_MAX_RETRIES = 3

# ── Security ─────────────────────────────────────────────────
SECRETS_ENCRYPTION_ALGO = "AES-256-GCM"
LOG_SCRUB_PATTERNS = [
    r"password['\"]?\s*[:=]\s*\S+",
    r"token['\"]?\s*[:=]\s*\S+",
    r"api_key['\"]?\s*[:=]\s*\S+",
    r"secret['\"]?\s*[:=]\s*\S+",
    r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
]

# ── Scope Enforcement ────────────────────────────────────────
SCOPE_ALWAYS_EXCLUDED = [
    "169.254.0.0/16",  # link-local
    "224.0.0.0/4",  # multicast
    "0.0.0.0/8",  # reserved
]

# ── Reporting ────────────────────────────────────────────────
REPORT_FORMATS = ["pdf", "json", "sarif", "md"]
MITRE_ATTACK_VERSION = "v14"

# ── Laravel Credential Env Keys (SSOT — anti-Lyndon #7) ─────
# Bounded set of .env keys that constitute leaked credentials when
# exposed through a Laravel Whoops/Ignition debug page. Alpha scans
# for these keys; all consumers import from here.
LARAVEL_CREDENTIAL_ENV_KEYS: frozenset[str] = frozenset(
    {
        "DB_PASSWORD",
        "DB_USERNAME",
        "APP_KEY",
        "REDIS_PASSWORD",
        "MAIL_PASSWORD",
    }
)

# Mapping of env-key prefix → service label for CredentialProperties.service.
LARAVEL_CREDENTIAL_SERVICE_MAP: dict[str, str] = {
    "DB_": "database",
    "REDIS_": "redis",
    "MAIL_": "mail",
    "APP_": "laravel_app",
}

# Keys that represent a username rather than a secret.
LARAVEL_CREDENTIAL_USERNAME_KEYS: frozenset[str] = frozenset(
    {
        "DB_USERNAME",
    }
)

# Per-service (username_key, secret_key): co-located leaked keys that form ONE login
# credential. The co-location IS the pairing evidence (anti-fragmentation, anti-#3).
# Only services listed here are assembled into a paired login; everything else stays a
# standalone secret node. SSOT — the extractor imports this, never re-declares (#7).
LARAVEL_CREDENTIAL_LOGIN_PAIRS: dict[str, tuple[str, str]] = {
    "database": ("DB_USERNAME", "DB_PASSWORD"),
}

# ── WordPress Credential Keys (SSOT — mirrors Laravel pattern for WP) ────
# Canonical WordPress tech_stack label (anti-#7).
STACK_WP: str = "wp"

# WordPress wp-config.php uses define() constants, not .env. Key names differ:
# DB_USER (not DB_USERNAME), DB_PASSWORD (same). Salts (AUTH_KEY, NONCE_SALT,
# etc.) are NOT reusable credentials — excluded from all sets.

WP_CREDENTIAL_LOGIN_PAIRS: dict[str, tuple[str, str]] = {
    "database": ("DB_USER", "DB_PASSWORD"),
}

WP_CREDENTIAL_USERNAME_KEYS: frozenset[str] = frozenset({"DB_USER"})

# Only DB_PASSWORD is a reusable secret. DB_NAME and DB_HOST are metadata.
WP_CREDENTIAL_SECRET_KEYS: frozenset[str] = frozenset({"DB_PASSWORD"})

WP_CREDENTIAL_SERVICE_MAP: dict[str, str] = {"DB_": "database"}

# Candidate backup paths for wp-config.php (passive GET, RECON_ONLY).
WP_CONFIG_BACKUP_PATHS: tuple[str, ...] = (
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/wp-config.php.save",
    "/wp-config.php.orig",
    "/wp-config.php.swp",
    "/.wp-config.php.swp",
    "/wp-config.php.old",
    "/wp-config.php.dist",
    "/wp-config.txt",
)

# WordPress REST route surface (SSOT). The /wp-json/ index is DETECT-only
# (persisted as an AssetProperties.rest_routes inventory, never a finding). Only
# routes present in this allowlist are ESCALATED (enqueued) for a follow-up probe
# through the existing in-scope guard; every other discovered route sits inert on
# the asset (anti-#3 over-probe). Paths are the full /wp-json-rooted form.
WP_REST_INTERESTING_ROUTES: tuple[str, ...] = (
    "/wp-json/wp/v2/users",
    "/wp-json/wc/v3",
)

# Maximum number of REST routes stored on an asset (anti-unbounded-graph). Beyond
# this the inventory is truncated and total_count records the real size.
WP_REST_ROUTES_CAP: int = 200

# High-risk WP plugin REST namespaces curated for targeted unauthenticated probing.
# Value: (probe_path_relative_to_root, affected_service, cvss_score)
# probe_path must be the full absolute path starting with /wp-json/.
# CVSSv3 base scores from published CVEs; scores are conservative (public
# disclosure severity, not exploitability on a hardened site).
WP_PLUGIN_DANGEROUS_NAMESPACES: dict[str, tuple[str, str, float]] = {
    "string-locator/v1": (
        "/wp-json/string-locator/v1/search",
        "string-locator",
        8.8,
    ),
    "duplicator/v1": (
        "/wp-json/duplicator/v1/packages",
        "duplicator",
        7.5,
    ),
    "wp-file-manager-remote/v1": (
        "/wp-json/wp-file-manager-remote/v1/",
        "wp-file-manager",
        9.8,
    ),
}

# WordPress version-disclosure surfaces (passive GET, RECON_ONLY). readme.html
# carries the "Semantic Personal Publishing Platform" tagline + a Version line;
# the site root's <meta generator> is the corroborating second request. Version
# is taken from the body SIGNATURE, never status alone (WP soft-404 = 200 HTML).
WP_VERSION_PATHS: tuple[str, ...] = ("/readme.html",)

# Selective-crawl allowlist for a host already fingerprinted as WordPress
# (STACK_WP). Applied ONLY to organically-discovered hrefs (Alpha's
# frontier-expansion loop, scout.py _step_once) — NEVER to deterministic
# catalog seeds (WP_VERSION_PATHS, wp_fingerprint.frontier_seeds,
# WP_REST_INTERESTING_ROUTES escalation), which enqueue directly via
# enqueue_discovered_url() and are already curated. Without this allowlist,
# a same-origin href filter has no domain intelligence: every product/blog/
# category page on the site queues for LLM-tier probing at the same priority
# as an actual WP surface (field evidence: unibis.co.id, 2026-07-29 — 20min /
# ~30 product-page probes / 0 findings from any of them). Content pages
# (product/blog/category/about/contact) are intentionally NOT enumerated here
# (unbounded — WP permalink structures vary per site); this is a positive
# allowlist of the bounded, known WP-internal surface instead.
WP_CRAWL_ALLOW_PATH_PREFIXES: tuple[str, ...] = (
    "/wp-content/plugins/",
    "/wp-content/themes/",
    "/wp-json/",
    "/wp-admin/",
    "/xmlrpc.php",
)

BACKUP_FILE_PATHS: tuple[str, ...] = (
    "/.env.bak",
    "/.env.save",
    "/.env~",
    "/.env.old",
    "/.env.orig",
    "/config/database.yml.bak",
    *WP_CONFIG_BACKUP_PATHS,  # single source — no duplicated wp-config literals
)

GIT_LEAK_PATHS: tuple[str, ...] = ("/.git/config",)

# Spring Boot Actuator env-disclosure endpoints (read-only info disclosure -> RECON).
ACTUATOR_PATHS: tuple[str, ...] = ("/actuator/env", "/env")

WELL_KNOWN_LEAK_PATHS: tuple[str, ...] = (*GIT_LEAK_PATHS, *BACKUP_FILE_PATHS, *ACTUATOR_PATHS)

# CDN-infrastructure path prefixes to exclude from frontier crawl (loop prevention).
# Cloudflare and other CDNs inject /cdn-cgi/* paths that link to each other indefinitely,
# causing a crawl loop that burns DeepSeek reasoning tokens for zero recon value.
CDN_INFRA_EXCLUDE_PREFIXES: tuple[str, ...] = ("/cdn-cgi/",)

# API-specification endpoints (passive GET, RECON_ONLY). A frontier FEEDER catalog,
# deliberately SEPARATE from WELL_KNOWN_LEAK_PATHS: surface-discovery is not a leak
# (ADR §12.26), and WELL_KNOWN_LEAK_PATHS is pinned to the path_probe catalog union
# (test N3). Seeded into the frontier on its own loop in run_recon.
SURFACE_DISCOVERY_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/v2/api-docs",
    "/api-docs",
    "/graphql",
    "/graphiql",
)
# Small, high-signal default leak set for UNKNOWN / unfingerprinted hosts.
# MUST include .env.bak so a boring generic host like late.recon.lab still
# gets coverage (field-prove guard). Seeded by try_harder when NO catalog spec
# (beyond universal) matches the host's tech_stack.
#
# Cross-stack backup paths (wp-config.php.bak, config/database.yml.bak) are
# included here because backup files can be left on ANY server regardless of
# stack — field-proven on alpha-ai.web.id (Odoo) which had a real wp-config.php.bak
# with DB credentials. The remaining WP_CONFIG_BACKUP_PATHS (~, .save, .orig,
# .swp, .old, .dist, .txt) stay stack-gated behind wp_fingerprint frontier_seeds
# since they are lower-signal and WP-specific patterns.
DEFAULT_LEAK_PATHS: tuple[str, ...] = (
    *GIT_LEAK_PATHS,
    "/.env.bak",
    "/.env",
    "/wp-config.php.bak",
    "/config/database.yml.bak",
)

# Tech-stack markers that gate SURFACE_DISCOVERY_PATHS in try_harder.
# If a host has a tech_stack label whose substring matches one of these,
# try_harder also seeds SURFACE_DISCOVERY_PATHS for that host.
SURFACE_APPLIES_TO: frozenset[str] = frozenset({"openapi", "swagger", "graphql", "api"})
# SINGLE source (anti-#7): BACKUP_FILE_PATHS is the one definition; this baseline
# seed composes it — backup paths join the target-independent recon frontier so
# Alpha.run_recon reaches the backup_file_probe vector without per-target hand-feed.

# ── IntelligenceBase / Tool Reliability (K19, ADR §12.8) ─────
# Single source of truth for K19 "decision threshold". Score itself
# is computed adaptively from event-stream data; this threshold is NOT.
# Agent must never change this value itself (ADR §8o-6).
# K19 only — NOT K20 (playbook promotion, deferred Phase 6).
# Value = 3: acceptable because Wilson lower-bound in
# intelligence.py::_wilson_lower_bound already guards overconfidence
# at small N. This threshold only gates "informative at all".
MIN_SAMPLES_BEFORE_SKIP = 3

# ── Fan-out concurrency caps (§12.13 / C5) ──────────────────
# Single source of truth for per-engagement fan-out degree per role
# (anti-Lyndon #7: no scattered literals). The Conductor partitions a phase's
# scope into bounded units and never dispatches more than this many concurrently
# for one engagement. Bounded autonomy (§12.13 invariant 2): degree is never
# unbounded. Gamma (exploitation) is deliberately the tightest — blast radius.
# Roles are keyed by lowercase name; unknown roles fall back to DEFAULT.
DEFAULT_MAX_WORKERS = 4
MAX_WORKERS_PER_ROLE = {
    "alpha": 10,  # SCOUT — recon fans out widest
    "beta": 4,  # STRIKE
    "gamma": 2,  # ANCHOR — exploitation kept tight (blast radius)
    "delta": 4,  # HUNTER
    "epsilon": 4,  # SCOUT-HUNTER
}

# ── Pricing ──────────────────────────────────────────────────
DEEPSEEK_PRICING_USD_PER_1K = {
    "deepseek-v4-pro": {"input": 0.001, "output": 0.002},
    "deepseek-v4-flash": {"input": 0.0001, "output": 0.0002},
    # deepseek-chat is the legacy alias for deepseek-v4-flash (same pricing).
    # Without this entry the cost_budget stop-condition under-counts when
    # LLM_REASONING_PROVIDER == "deepseek-chat".
    "deepseek-chat": {"input": 0.0001, "output": 0.0002},
}

# ── Recon Tool Catalog (SSOT — anti-Lyndon #6/#7) ────────────
# Canonical set of valid recon tool names.  The LLM tool-select prompt
# enumerates this set and _parse_tool_response coerces any out-of-catalog
# name to "generic_http_probe" (the safe no-op).  Alpha's dispatch
# registry keys MUST remain a subset of this catalog.
RECON_TOOL_CATALOG: frozenset[str] = frozenset(
    {
        "laravel_debug_probe",
        "wp_config_probe",
        "js_secret_probe",
        "odoo_dbmanager_probe",
        "git_exposure_probe",
        "backup_file_probe",
        "wp_rest_routes",
        "wp_rest_users",
        "woocommerce",
        "wp_version",
        "wp_plugins",
        "generic_http_probe",
    }
)

# Recon tools whose handler json.loads() the body — INAPPLICABLE to a
# non-JSON response. Consulted at BOTH enforcement points (ORIENT catalog
# filter + pre-dispatch gate). Single source of truth (anti-#6/#7).
JSON_BODY_TOOLS: frozenset[str] = frozenset({"wp_rest_routes", "wp_rest_users", "woocommerce"})

# ── Live-Fire Scoring (Phase 2) ───────────────────────────────
# Phase 2 exit criterion: "<20% FP rate in findings"
# FP rate in findings = FP / (TP + FP) — fraction of REPORTED findings that are false
MAX_FP_RATE = 0.20

# ── JS Secret Detection Patterns (Phase 3, js_secret_probe) ──
# High-confidence, provider-agnostic starter set. Extend via config, never
# inline per-client (#7). Each entry: (name, compiled_regex, service_label).
# The generic_assign pattern captures a value that MUST pass _looks_like_secret().
JS_SECRET_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", "aws"),
    ("google_api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "google_api"),
    ("stripe_live", r"\bsk_live_[0-9A-Za-z]{24,}\b", "stripe"),
    ("slack_token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "slack"),
    ("github_pat", r"\bghp_[0-9A-Za-z]{36}\b", "github"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "jwt"),
    (
        "generic_assign",
        r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"']([^\"']{16,})[\"']",
        "generic",
    ),
)

# Placeholder denylist for _looks_like_secret() — anti-#3 discriminator.
JS_SECRET_PLACEHOLDER_DENYLIST: frozenset[str] = frozenset(
    {
        "your_api_key",
        "your_api_key_here",
        "example",
        "changeme",
        "placeholder",
        "xxxx",
        "xxxxxxxxxxxxxxxx",
        "<",
        "test",
        "dummy",
    }
)

# Minimum Shannon entropy for generic_assign captured values (anti-#3).
JS_SECRET_MIN_ENTROPY = 3.5

# Minimum length for generic_assign captured values.
JS_SECRET_MIN_LENGTH = 16

# ── Transport Resilience / Adaptive Evasion (§12.33, §12.22 D2) ────
# Consecutive BLOCKED verdicts on the same host before the Planner proposes
# an evasion technique switch. Single source (anti-#7).
EVASION_CONSECUTIVE_BLOCKED_N = 5
# Maximum escalation attempts per host before the LockoutGovernor forces ABORT.
# Bounded autonomy: the agent CANNOT retry indefinitely (§12.22 D2).
EVASION_MAX_ESCALATIONS_PER_HOST = 3
# ── Credential-attempt lockout (§12.22 D2 — cred-spray safety) ───────────────
# Distinct concept from EVASION_MAX_ESCALATIONS_PER_HOST (that bounds reach
# escalations); these bound LOGIN attempts so Beta never locks out a client's
# real accounts. Single source (anti-#7).
# Per-username: kept BELOW the common provider lockout threshold (~5) so a real
# account is never driven into lockout by our own attempts.
CRED_LOCKOUT_MAX_ATTEMPTS_PER_USERNAME = 4  # = USER_DERIVED max candidates; still < ~5 lockout
# Per-host aggregate: bounds total login noise across ALL usernames on a host
# (IP-ban / WAF-trip safety), even when each account stays under its own cap.
CRED_LOCKOUT_MAX_ATTEMPTS_PER_HOST = 20
# Max login candidates DERIVED per enumerated username (GAP-015 derive-not-spray).
# Bounds the candidate space per account so there is no combinatorial blow-up;
# candidates are context-derived only (no static wordlist). Single source (#7).
USER_DERIVED_MAX_CANDIDATES_PER_USER = 4
# Class-driven technique selection (anti-#11: class drives technique, NOT a
# fixed ladder). Key = MitigationClass.value, value = EvasionTechnique.value.
# "abort" → "none" means never escalate on that class.
TECHNIQUE_FOR_MITIGATION_CLASS: dict[str, str] = {
    "rate_limit": "rate_throttle",
    "challenge": "browser_solve",
    "fingerprint": "tls_impersonate",
    "rule_deny": "none",
    "abort": "none",
}
# Reach-transport HTTP timeout (seconds). Single source (anti-#7): used by
# origin_direct_fetch (httpx) and tls_impersonate_fetch (curl_cffi). Distinct
# from HTTP_REQUEST_TIMEOUT_SEC (recon client) — reach transports may traverse
# additional TLS negotiation or CDN edge hops.
REACH_TIMEOUT_S: float = 15.0

# Cloudflare published IPv4 CIDR ranges (https://www.cloudflare.com/ips/).
# Single source for CF edge IP detection (anti-#7). Update when CF publishes
# new ranges. Used by is_cloudflare_ip() to filter edge IPs from origin
# candidates — hitting a CF edge with Host-header spoofing is NOT origin-direct.
CF_IP_RANGES: tuple[str, ...] = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)

# ── Organic-Crawl Budget (stack-agnostic backstop) ───────────────
# Universal per-host cap on ORGANIC-crawl hrefs (hrefs parsed from page HTML
# by _extract_hrefs).  Catalog seeds (WELL_KNOWN_LEAK_PATHS,
# SURFACE_DISCOVERY_PATHS, fingerprint frontier_seeds, WP_REST_INTERESTING_ROUTES
# escalation) call enqueue_discovered_url() directly and are NOT counted —
# they are already-curated security surface, not organic crawl.
# Field evidence: unibis.co.id 2026-07-29 — 20min / 30+ product-page probes /
# 0 findings from any of them; Laravel/Odoo/unknown hosts had no backstop.
MAX_ORGANIC_CRAWL_PER_HOST: int = 25

# ── Odoo ───────────────────────────────────────────────────────
ODOO_VERSION_INFO_PATH = "/web/webclient/version_info"
ODOO_VERSION_JSONRPC_BODY = {"jsonrpc": "2.0", "method": "call", "params": {}}

# CVSS v3.1 vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
# I/A stay N because create/backup/drop is master_pwd-gated and UNPROVEN at
# RECON tier; escalates to CRITICAL only once the master_pwd oracle proves it
# (Improvement 2). Single source (anti-#7).
ODOO_DBMANAGER_EXPOSURE_CVSS: float = 7.5
