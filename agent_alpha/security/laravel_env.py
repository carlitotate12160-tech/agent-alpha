"""Single source of truth for parsing + redacting Laravel debug-page env leaks.

A Laravel/Ignition "Whoops" page renders the environment as an HTML table:

    <td>APP_KEY</td><td>base64:...</td>

The generic LOG_SCRUB_PATTERNS (key=value / Bearer) DO NOT match this table form, so
without this module a captured proof snippet leaks DB_PASSWORD, APP_KEY, etc. verbatim.
ONE regex, driven by constants.LARAVEL_CREDENTIAL_ENV_KEYS, is shared by BOTH the
credential extractor (Alpha) and the redactor (proof + LLM path) — anti-Lyndon #7
(no second regex for the same concept).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from agent_alpha.config import constants

_REDACTED = "[REDACTED]"

# <td>KEY</td><td>VALUE</td>, whitespace-tolerant; KEY bounded to the SSOT key set.
#   group 1 = leading "<td>KEY</td><td>"   (kept)
#   group "value" = the secret cell        (masked)
#   group 4 = trailing "</td>"             (kept)
_KEY_ALT = "|".join(re.escape(k) for k in sorted(constants.LARAVEL_CREDENTIAL_ENV_KEYS))
LARAVEL_ENV_TABLE_RE = re.compile(
    rf"(<td>\s*(?P<key>{_KEY_ALT})\s*</td>\s*<td>\s*)(?P<value>[^<]+?)(\s*</td>)",
    re.IGNORECASE,
)


def iter_env_leaks(body: str) -> Iterator[tuple[str, str]]:
    """Yield (KEY_UPPER, raw_value) for each leaked credential env key in *body*.

    The credential extractor uses this to build CREDENTIAL nodes (key name + a
    secret_ref pointer); it must read the RAW body, never the redacted snippet.
    """
    for match in LARAVEL_ENV_TABLE_RE.finditer(body):
        yield match.group("key").upper(), match.group("value").strip()


def redact_env_table(text: str) -> str:
    """Mask the VALUE cell of every leaked credential env key, keeping the key name.

    Over-redaction is safe here: even DB_USERNAME's value is masked in the snippet,
    while the extractor still records the username from the raw body separately.
    """
    return LARAVEL_ENV_TABLE_RE.sub(rf"\1{_REDACTED}\4", text)
