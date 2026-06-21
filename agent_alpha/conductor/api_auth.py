from __future__ import annotations

import dataclasses
import os
import typing

import jwt as pyjwt
from fastapi import HTTPException, Request, status

from agent_alpha.config.constants import JWT_ALGORITHM, JWT_SECRET_ENV


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
        ) from None
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
