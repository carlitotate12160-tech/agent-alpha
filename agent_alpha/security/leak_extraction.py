from __future__ import annotations

import json

from agent_alpha.recon.wp_config_probe import parse_wp_config


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
    leaked: dict[str, str] = {}

    for path, content in recovered.items():
        lower_path = path.lower()

        if lower_path.endswith("database.yml"):
            _merge_in(leaked, _extract_from_database_yml(content))
        elif lower_path.endswith(".env") or "/.env" in lower_path:
            _merge_in(leaked, _extract_from_env_file(content))
        elif "wp-config" in lower_path:
            _merge_in(leaked, parse_wp_config(content))
        elif "actuator" in lower_path or lower_path.endswith("/env"):
            _merge_in(leaked, _extract_from_actuator_env(content))

    return leaked
