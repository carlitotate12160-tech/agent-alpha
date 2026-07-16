# agent_alpha/config/constants.py
# SINGLE SOURCE OF TRUTH for all threshold and configuration values.
# All other files import from this module — never define magic numbers elsewhere.

__all__ = [
    "LLM_REASONING_PROVIDER",
    "LLM_REASONING_CONSENSUS",
    "LLM_PAYLOAD_PROVIDER",
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
    "BACKUP_FILE_PATHS",
    "ACTUATOR_PATHS",
    "GIT_LEAK_PATHS",
    "WELL_KNOWN_LEAK_PATHS",
    "SURFACE_DISCOVERY_PATHS",
    "MIN_SAMPLES_BEFORE_SKIP",
    "DEEPSEEK_PRICING_USD_PER_1K",
    "MAX_FP_RATE",
    "RECON_TOOL_CATALOG",
]

# ── LLM Providers ──────────────────────────────────────────
# ADR §12.15: roles canonical, providers configurable.
# REASONING = ORIENT / PLAN / narrative. PAYLOAD = offensive tool & exploit-body generation.
# The ROLE is the architectural invariant; the PROVIDER behind each role is configuration.

# Reasoning provider (TEMPORARY testing value; production target: Claude / GPT-class)
# See ADR §12.15 switch gate: must be Claude/GPT-class before first paid client engagement.
LLM_REASONING_PROVIDER = "deepseek-chat"  # Current testing provider
LLM_REASONING_CONSENSUS = "mimo-v2.5-pro"  # Consensus secondary

# Payload provider (direct open-weight provider ONLY; NEVER aggregator/router, NEVER Claude)
LLM_PAYLOAD_PROVIDER = "deepseek-v4-pro"  # Primary payload provider
LLM_PAYLOAD_FALLBACK = "kimi-2.6"  # Fallback when primary refuses

# Transport policy (ADR §12.15)
LLM_PAYLOAD_TRANSPORT = "direct"  # Payload MUST use direct provider API ONLY
# Valid values: "direct" (vendor API), "gateway" (aggregator like OpenRouter/Bedrock)
# Payload role enforces "direct" only; reasoning role allows both with zero-retention contract.

# Provider allowlists (hard guards)
LLM_PAYLOAD_NEVER = [
    "claude",
    "sonnet",
    "opus",
    "gpt",
]  # HARD GUARD: never allow these for payload generation (ADR §12.10)
LLM_PAYLOAD_ALLOWED = ["deepseek-v4-pro", "kimi-2.6"]  # Allowed payload providers
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

BACKUP_FILE_PATHS: tuple[str, ...] = (
    "/.env.bak",
    "/.env.save",
    "/.env~",
    "/.env.old",
    "/.env.orig",
    "/config/database.yml.bak",
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/wp-config.php.save",
    "/wp-config.php.orig",
    "/wp-config.php.old",
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
        "generic_http_probe",
    }
)

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
