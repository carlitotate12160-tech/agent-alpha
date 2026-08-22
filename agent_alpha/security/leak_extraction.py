from __future__ import annotations

import json
import re
import string


def _merge_in(target: dict[str, str], source: dict[str, str]) -> None:
    for key, value in source.items():
        target[key] = value


def _extract_from_database_yml(body: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key == "username":
            result["DB_USER"] = value
        elif key == "password":
            result["DB_PASSWORD"] = value
        elif key == "database":
            result["DB_NAME"] = value
        elif key == "host":
            result["DB_HOST"] = value
    return result


def _extract_from_env_file(body: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().upper()
        value = value.strip().strip('"').strip("'")
        if not value:
            continue
        if key in ("DB_USER", "DB_USERNAME"):
            result["DB_USER"] = value
        elif key == "DB_PASSWORD":
            result["DB_PASSWORD"] = value
        elif key in ("DB_NAME", "DB_DATABASE"):
            result["DB_NAME"] = value
        elif key == "DB_HOST":
            result["DB_HOST"] = value
    return result


def _is_masked(value: str) -> bool:
    """Spring Boot masks sensitive env values as ``******`` by default. A masked
    value is NOT a recoverable secret (presence != payable — anti-#3)."""
    v = value.strip()
    return not v or set(v) == {"*"}


# PHP double-quoted single-char escapes (C-style + \$ variable-escape + delimiters).
_PHP_DQ_SIMPLE_ESCAPES = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "f": "\f",
    "e": "\x1b",
    "\\": "\\",
    '"': '"',
    "$": "$",
}


def _read_php_hex_escape(value: str, i: int) -> tuple[str, int]:
    r"""``value[i:i+2] == '\x'``. PHP hex escape: 1–2 hex digits. Zero digits =>
    PHP leaves the sequence literal (``\x`` stays)."""
    j = i + 2
    digits = ""
    while j < len(value) and len(digits) < 2 and value[j] in string.hexdigits:
        digits += value[j]
        j += 1
    if not digits:
        return "\\x", j
    return chr(int(digits, 16)), j


def _read_php_octal_escape(value: str, i: int) -> tuple[str, int]:
    r"""``value[i] == '\'`` and ``value[i+1]`` is an octal digit. PHP octal:
    1–3 digits, value taken mod 256."""
    j = i + 1
    digits = ""
    while j < len(value) and len(digits) < 3 and value[j] in "01234567":
        digits += value[j]
        j += 1
    return chr(int(digits, 8) % 256), j


def _read_php_unicode_escape(value: str, i: int) -> tuple[str, int]:
    r"""``value[i:i+3] == '\u{'``. PHP 7+ ``\u{HHHH}``. Malformed (no ``}`` or
    bad hex) is left literal, matching PHP's defined-but-lenient handling."""
    end = value.find("}", i + 3)
    if end != -1:
        try:
            return chr(int(value[i + 3 : end], 16)), end + 1
        except ValueError:
            pass
    return "\\u{", i + 3


def _read_php_dq_escape(value: str, i: int) -> tuple[str, int]:
    r"""Resolve ONE PHP double-quoted escape at ``value[i] == '\'``. Returns
    ``(decoded_text, next_index)``. An unrecognised ``\X`` keeps its backslash
    (PHP: a non-special ``\X`` is a literal backslash followed by ``X``)."""
    n = len(value)
    if i + 1 >= n:
        return "\\", i + 1
    nxt = value[i + 1]
    if nxt in _PHP_DQ_SIMPLE_ESCAPES:
        return _PHP_DQ_SIMPLE_ESCAPES[nxt], i + 2
    if nxt == "x":
        return _read_php_hex_escape(value, i)
    if nxt == "u" and i + 2 < n and value[i + 2] == "{":
        return _read_php_unicode_escape(value, i)
    if nxt in "01234567":
        return _read_php_octal_escape(value, i)
    return "\\", i + 1


def _unescape_php_string(value: str, quote: str) -> str:
    r"""Undo PHP string escapes for the captured delimiter.

    Single-quoted strings recognize ONLY ``\'`` and ``\\``; every other ``\X``
    is a literal backslash + X. Double-quoted strings recognize ``\"``, ``\\``,
    ``\$``, the C-style set (``\n \r \t \v \f \e``) and numeric escapes
    (octal ``\ooo``, hex ``\xHH``, Unicode ``\u{HHHH}``). Passing ``quote`` means
    an escape valid for one string type is left untouched in the other (an
    escaped single quote in a double-quoted string keeps its backslash, etc.).
    """
    out: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        if value[i] != "\\" or i + 1 >= n:
            out.append(value[i])
            i += 1
            continue
        if quote == "'":
            nxt = value[i + 1]
            if nxt in ("'", "\\"):
                out.append(nxt)
                i += 2
            else:
                out.append(value[i])
                i += 1
            continue
        decoded, i = _read_php_dq_escape(value, i)
        out.append(decoded)
    return "".join(out)


def _scan_string_literal(body: str, start: int, quote: str, out: list[str]) -> int:
    """Copy the quoted string literal at ``body[start] == quote`` into ``out``
    verbatim and return the index just past the closing quote. An unterminated
    literal consumes to end-of-input (mirrors the original loop simply ending).

    Escapes are copied literally, not resolved: comment stripping must never
    alter string *contents*. ``_unescape_php_string`` resolves them later, and
    only for the delimiter that actually applies. A ``\\`` consumes the next
    char (so an escaped quote never ends the string); a trailing ``\\`` at
    end-of-input is tolerated.
    """
    n = len(body)
    out.append(quote)
    i = start + 1
    while i < n:
        ch = body[i]
        out.append(ch)
        if ch == "\\":
            if i + 1 < n:
                out.append(body[i + 1])
                i += 2
            else:
                i += 1
            continue
        if ch == quote:
            return i + 1
        i += 1
    return i


def _skip_block_comment(body: str, start: int) -> int:
    """``body[start:start + 2] == '/*'``. Return the index past the closing
    ``*/``, or ``-1`` when the comment is unterminated (the caller stops
    stripping there, mirroring the original ``break``)."""
    end = body.find("*/", start + 2)
    return -1 if end == -1 else end + 2


def _skip_to_line_end(body: str, start: int) -> int:
    """Return the index of the next newline at/after ``start`` (or end-of-input).
    The newline itself is left for the dispatch loop to emit."""
    n = len(body)
    i = start
    while i < n and body[i] != "\n":
        i += 1
    return i


def _is_line_comment_start(body: str, i: int) -> bool:
    """A ``//`` that is not the ``://`` of a stream-wrapper / URL prefix."""
    return body.startswith("//", i) and (i == 0 or body[i - 1] != ":")


def _strip_php_comments(body: str) -> str:
    """Remove PHP ``//``, ``#``, and ``/* */`` comments while preserving string
    literals, and without stripping ``://`` stream-wrapper prefixes.

    Thin dispatch loop over single-purpose scanners (anti-god-object §12.47):
    each branch delegates the actual consumption, so this stays a readable
    state selector rather than a nested char-by-char machine. Behavior is
    identical to the pre-decomposition version — locked by
    ``test_strip_php_comments_behavior_preserving``.
    """
    out: list[str] = []
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch in ("'", '"'):
            i = _scan_string_literal(body, i, ch, out)
        elif body.startswith("/*", i):
            i = _skip_block_comment(body, i)
            if i == -1:
                break
        elif _is_line_comment_start(body, i):
            i = _skip_to_line_end(body, i)
        elif body.startswith("#", i):
            i = _skip_to_line_end(body, i)
        else:
            out.append(ch)
            i += 1
    return "".join(out)


# Match a PHP single/double-quoted string, including escaped quotes and \\.
_PHP_STRING_RE = r"(?P<quote>['\"])(?P<value>(?:[^'\"\\]|\\.)*?)(?P=quote)"


def _extract_from_codeigniter_database(body: str) -> dict[str, str]:
    """Parse a CodeIgniter ``application/config/database.php`` body.

    Supports the two common CI 3 forms:
      - ``$db['default'] = array('username' => '...', ...);``
      - ``$db['default']['username'] = '...';`` (per-key assignment)
    and short-array syntax ``[ ... ]``. Comments are stripped without touching
    string literals, and escaped quotes (``\\'``, ``\\"``) are unescaped before
    vaulting. Masked/empty values are dropped (anti-#3).
    """
    result: dict[str, str] = {}
    source = _strip_php_comments(body)

    # 1) Try per-key assignments first: $db['default']['username'] = '...';
    for m in re.finditer(
        r"\$db\s*\[\s*['\"]default['\"]\s*\]\s*\[\s*['\"](?P<key>\w+)['\"]\s*\]\s*=\s*"
        + _PHP_STRING_RE,
        source,
        re.IGNORECASE,
    ):
        _store_ci_value(
            result, m.group("key"), _unescape_php_string(m.group("value"), m.group("quote"))
        )

    if result:
        return result

    # 2) Fall back to $db['default'] = array(...) or $db['default'] = [...]
    match = re.search(
        r"\$db\s*\[\s*['\"]default['\"]\s*\]\s*=\s*(?:array\s*\((.*?)\)\s*;|\[\s*(.*?)\s*\]\s*;)",
        source,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return result

    block = match.group(1) if match.group(1) is not None else match.group(2)
    # 3) Key => value pairs inside the array: 'username' => 'ci_user',
    for m in re.finditer(
        r"['\"](?P<key>\w+)['\"]\s*=>\s*" + _PHP_STRING_RE,
        block,
        re.IGNORECASE,
    ):
        _store_ci_value(
            result, m.group("key"), _unescape_php_string(m.group("value"), m.group("quote"))
        )

    return result


def _store_ci_value(result: dict[str, str], key: str, value: str) -> None:
    """Map a parsed CodeIgniter key/value into canonical DB_* keys."""
    value = value.strip()
    if not value or _is_masked(value):
        return
    lkey = key.lower()
    if lkey == "username":
        result["DB_USER"] = value
    elif lkey == "password":
        result["DB_PASSWORD"] = value
    elif lkey == "database":
        result["DB_NAME"] = value
    elif lkey == "hostname":
        result["DB_HOST"] = value


def _extract_from_actuator_env(body: str) -> dict[str, str]:
    """Parse a Spring Boot ``/actuator/env`` JSON body into canonical DB_* keys.

    Handles the 2.x/3.x shape (propertySources[].properties[key] = {"value": v})
    and the flat 1.x shape (properties[key] = v). Masked (``******``) values are
    dropped so a redacted endpoint never mints a false credential (anti-#3).
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}

    result: dict[str, str] = {}

    def _consume(key: str, raw: object) -> None:
        value = raw.get("value") if isinstance(raw, dict) else raw
        if not isinstance(value, str) or _is_masked(value):
            return
        lkey = key.lower()
        if lkey.endswith("datasource.username") or lkey.endswith("datasource.user"):
            result.setdefault("DB_USER", value)
        elif lkey.endswith("datasource.password"):
            result.setdefault("DB_PASSWORD", value)

    sources = data.get("propertySources")
    if isinstance(sources, list):  # 2.x / 3.x
        for src in sources:
            props = src.get("properties") if isinstance(src, dict) else None
            if isinstance(props, dict):
                for key, raw in props.items():
                    _consume(str(key), raw)
    else:  # flat 1.x fallback
        for _name, props in data.items():
            if isinstance(props, dict):
                for key, raw in props.items():
                    _consume(str(key), raw)

    return result


def extract_secrets(recovered: dict[str, str]) -> dict[str, str]:
    from agent_alpha.recon.wp_config_probe import parse_wp_config

    leaked: dict[str, str] = {}

    for path, content in recovered.items():
        lower_path = path.lower()

        if lower_path.endswith("database.yml"):
            _merge_in(leaked, _extract_from_database_yml(content))
        elif lower_path.endswith(".env") or "/.env" in lower_path:
            _merge_in(leaked, _extract_from_env_file(content))
        elif "wp-config" in lower_path:
            _merge_in(leaked, parse_wp_config(content))
        elif "codeigniter" in lower_path or "/application/config/database" in lower_path:
            _merge_in(leaked, _extract_from_codeigniter_database(content))
        elif "actuator" in lower_path or lower_path.endswith("/env"):
            _merge_in(leaked, _extract_from_actuator_env(content))

    return leaked


def canonical_leak_vuln_suffix(logical_path: str, *, default: str) -> str:
    """SINGLE source (anti-#6/#7) for the vuln-node suffix a leaked-file path maps to,
    so the SAME physical artifact never mints two vuln nodes under different probes.
    wp-config backups are the SPECIFIC class and WIN over the generic backup_file class;
    .git wins as git_exposure. Anything else falls back to the caller's own `default`
    so non-leak-file specs (actuator, etc.) are never hijacked."""
    p = logical_path.lower()
    if "wp-config.php" in p:
        return "wp_config_leak"
    if "/.git/" in p or p.rstrip("/").endswith("/.git/config"):
        return "git_exposure"
    return default


# SINGLE source of truth (#7) for the CVSS a leaked-file vuln carries, keyed by the
# SAME canonical suffix canonical_leak_vuln_suffix() mints — so every probe that
# converges on one canonical node (wp_config_probe, path_probe) reports one
# consistent severity, not a per-probe literal that can drift. All three are
# credential-bearing info-disclosure (CWE-200): a recovered secret is the payable
# entry point of a proven chain, hence HIGH, not the 0.0 the dataclass defaults to.
LEAK_VULN_CVSS: dict[str, float] = {
    "wp_config_leak": 7.5,
    "git_exposure": 7.5,
    "backup_file_leak": 7.5,
    "actuator_exposure": 7.5,
    "ci_config_leak": 7.5,
}

# Conservative floor for a recovered-secret leak whose class is not individually
# scored above (path_probe only mints a node once extract_secrets is non-empty, so
# the artifact IS a real disclosure — never 0.0).
LEAK_VULN_CVSS_DEFAULT: float = 5.3


def cvss_for_leak_suffix(suffix: str) -> float:
    """CVSS for a leak vuln node, keyed by its canonical suffix (single source)."""
    return LEAK_VULN_CVSS.get(suffix, LEAK_VULN_CVSS_DEFAULT)
