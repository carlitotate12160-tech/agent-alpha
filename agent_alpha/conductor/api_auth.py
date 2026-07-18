from __future__ import annotations

import dataclasses
import os
import re
import typing

import jwt as pyjwt
from fastapi import HTTPException, Request, status

from agent_alpha.config.constants import JWT_ALGORITHM, JWT_SECRET_ENV


def valid_engagement_id(engagement_id: str) -> str:
    if not re.match(r"^eng_[0-9a-f]{4,}$", engagement_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    return engagement_id


class JWTError(Exception):
    pass


def _get_jwt_secret() -> str:
    secret = os.environ.get(JWT_SECRET_ENV)
    if not secret:
        raise RuntimeError(f"{JWT_SECRET_ENV} is not set")
    if len(secret) < 32:
        raise RuntimeError(
            f"{JWT_SECRET_ENV} must be at least 32 characters for HS256 (RFC 7518 §3.2)"
        )
    return secret


def _decode_and_verify_jwt(token: str) -> dict[str, typing.Any]:
    try:
        payload = pyjwt.decode(
            token,
            _get_jwt_secret(),
            algorithms=[JWT_ALGORITHM],
        )
    except pyjwt.ExpiredSignatureError as exc:
        raise JWTError("token expired") from exc
    except pyjwt.InvalidTokenError as exc:
        raise JWTError("invalid token") from exc
    return payload


@dataclasses.dataclass(frozen=True)
class Principal:
    tenant_id: str
    subject: str


def principal_from_token(token: str) -> Principal:
    """Decode a raw JWT (no Bearer prefix) into a Principal. Raises JWTError on an
    invalid/expired token or a missing tenant_id/subject claim. Shared by the HTTP
    dependency (require_principal) and the WS route — one place maps token -> tenant
    (anti-Lyndon #6/#7)."""
    payload = _decode_and_verify_jwt(token)
    tenant_id = payload.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id:
        raise JWTError("tenant_id claim missing")
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise JWTError("subject claim missing")
    return Principal(tenant_id=tenant_id, subject=subject)


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
        return principal_from_token(token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
        ) from None
