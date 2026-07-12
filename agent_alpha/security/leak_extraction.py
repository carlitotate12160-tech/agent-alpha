from __future__ import annotations

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

    return leaked
