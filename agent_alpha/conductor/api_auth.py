from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import typing

from fastapi import HTTPException, Request, status

from agent_alpha.config.constants import JWT_ALGORITHM, JWT_SECRET_ENV


class JWTError(Exception):
    pass


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _get_jwt_secret() -> bytes:
    secret = os.environ.get(JWT_SECRET_ENV)
    if not secret:
        raise RuntimeError(f"{JWT_SECRET_ENV} is not set")
    return secret.encode("utf-8")


def _decode_and_verify_jwt(token: str) -> dict[str, typing.Any]:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError as exc:
        raise JWTError("invalid token format") from exc
    try:
        header_bytes = _b64url_decode(header_b64)
        payload_bytes = _b64url_decode(payload_b64)
        signature = _b64url_decode(signature_b64)
    except Exception as exc:  # noqa: BLE001
        raise JWTError("invalid base64 encoding") from exc
    try:
        header = typing.cast(dict[str, typing.Any], json.loads(header_bytes))
        payload = typing.cast(dict[str, typing.Any], json.loads(payload_bytes))
    except Exception as exc:  # noqa: BLE001
        raise JWTError("invalid JSON in token") from exc
    alg = header.get("alg")
    if alg != JWT_ALGORITHM:
        raise JWTError("unsupported signing algorithm")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    key = _get_jwt_secret()
    expected_sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_sig, signature):
        raise JWTError("invalid token signature")
    return payload


@dataclasses.dataclass(frozen=True)
class Principal:
    tenant_id: str
    subject: str


async def require_principal(request: Request) -> Principal:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )
    token = auth_header[len("Bearer ") :].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )
    try:
        payload = _decode_and_verify_jwt(token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
        )
    tenant_id = payload.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant_id claim missing",
        )
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="subject claim missing",
        )
    return Principal(tenant_id=tenant_id, subject=subject)
