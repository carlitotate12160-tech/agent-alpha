# agent_alpha/config/constants.py
# SINGLE SOURCE OF TRUTH for all threshold and configuration values.
# All other files import from this module — never define magic numbers elsewhere.

# ── LLM Providers ──────────────────────────────────────────
LLM_REASONING_PRIMARY = "deepseek-v4-pro"
LLM_REASONING_CONSENSUS = "mimo-v2.5-pro"
LLM_PAYLOAD_NEVER = [
    "claude",
    "sonnet",
    "opus",
    "gpt",
]  # HARD GUARD: never allow these for payload generation
LLM_PAYLOAD_ALLOWED = ["deepseek-v4-pro", "kimi-2.6"]  # Allowed payload providers
LLM_PAYLOAD_GEN = "deepseek-v4-pro"  # Primary payload provider
LLM_PAYLOAD_FALLBACK = "kimi-2.6"  # Fallback when primary refuses
TESTING_MODE = True  # Indicates this is still testing phase; models may be more permissive

# ── LLM Tier Labels ─────────────────────────────────────────
LLM_TIER_RULE = "rule"
LLM_TIER_SINGLE = "single_llm"
LLM_TIER_CONSENSUS = "consensus"

# ── Consensus Thresholds ────────────────────────────────────
CONSENSUS_AGREE_THRESHOLD = 0.80
CONSENSUS_ESCALATE_THRESHOLD = 0.50

# ── Authorization ────────────────────────────────────────────
EMERGENCY_STOP_TIMEOUT_SEC = 5
MAX_SCOPE_IPS = 256
SOW_MAX_FILE_SIZE_MB = 50
SOW_HASH_ALGORITHM = "sha256"

# ── Event Store ──────────────────────────────────────────────
EVENT_SEQUENCE_GAP_ALLOWED = False
MAX_EVENTS_PER_ENGAGEMENT = 100_000
EVENT_STORE_TABLE = "agent_events"

# ── Stop Conditions (enforced Phase 2+, defined here) ────────
MAX_ITERATIONS_PER_AGENT = 500
MAX_TIME_BUDGET_SECONDS = 14_400
MAX_COST_BUDGET_USD = 50.0
NO_PROGRESS_THRESHOLD_ITERS = 20

# ── Celery ───────────────────────────────────────────────────
CELERY_TASK_SOFT_LIMIT_SEC = 3_600
CELERY_TASK_HARD_LIMIT_SEC = 14_400
CELERY_QUEUE_PREFIX = "engagement_"

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
