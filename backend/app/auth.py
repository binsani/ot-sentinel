import hmac
import json
from dataclasses import dataclass
from enum import IntEnum
from functools import lru_cache
from pathlib import Path
from typing import Any

import jwt
from fastapi import Depends, Header, HTTPException, status
from jwt import InvalidTokenError, PyJWKClient, PyJWKSet, PyJWTError
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.audit import append_audit_log
from app.config import Settings, get_settings
from app.database import get_session
from app.models import User, UserRole


class AccessLevel(IntEnum):
    VIEWER = 1
    ADMIN = 2


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    level: AccessLevel
    user_id: str | None = None


def require_viewer(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> Principal:
    settings = get_settings()
    if authorization:
        return _oidc_principal(authorization, session, settings)
    if settings.bootstrap_api_keys_enabled and x_api_key:
        if hmac.compare_digest(x_api_key, settings.admin_api_key.get_secret_value()):
            return Principal(subject="bootstrap:admin", level=AccessLevel.ADMIN)
        if hmac.compare_digest(x_api_key, settings.viewer_api_key.get_secret_value()):
            return Principal(subject="bootstrap:viewer", level=AccessLevel.VIEWER)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")


def require_admin(principal: Principal = Depends(require_viewer)) -> Principal:
    if principal.level < AccessLevel.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin access required")
    return principal


def _oidc_principal(authorization: str, session: Session, settings: Settings) -> Principal:
    scheme, separator, token = authorization.partition(" ")
    if separator != " " or scheme.casefold() != "bearer" or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid bearer token")
    if not settings.oidc_issuer or not settings.oidc_audience:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC is not configured",
        )
    try:
        claims = _decode_token(token, settings)
    except (PyJWTError, OSError, ValueError, json.JSONDecodeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid bearer token"
        ) from None
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token has no subject")
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:subject, 0))"),
        {"subject": f"oidc-user:{subject}"},
    )
    user = session.scalar(select(User).where(User.subject == subject))
    if user is None:
        user = User(
            subject=subject,
            email=_string_claim(claims, "email"),
            display_name=_string_claim(claims, "name"),
            role=UserRole.VIEWER,
        )
        session.add(user)
        session.flush()
        append_audit_log(
            session,
            action="user.created",
            object_type="user",
            object_id=str(user.id),
            details={"role": UserRole.VIEWER.value},
            actor_subject=user.subject,
        )
        session.commit()
        session.refresh(user)
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="user is disabled")
    level = AccessLevel.ADMIN if user.role == UserRole.ADMIN else AccessLevel.VIEWER
    return Principal(subject=user.subject, level=level, user_id=str(user.id))


def _decode_token(token: str, settings: Settings) -> dict[str, Any]:
    if settings.oidc_jwks_file:
        document = json.loads(Path(settings.oidc_jwks_file).read_text(encoding="utf-8"))
        key_set = PyJWKSet.from_dict(document)
        key_id = jwt.get_unverified_header(token).get("kid")
        candidates = [key for key in key_set.keys if key.key_id == key_id]
        if len(candidates) != 1:
            raise InvalidTokenError("signing key not found")
        key = candidates[0]
    elif settings.oidc_jwks_url:
        key = _jwk_client(settings.oidc_jwks_url).get_signing_key_from_jwt(token)
    else:
        raise ValueError("no OIDC JWKS source configured")
    return jwt.decode(
        token,
        key=key.key,
        algorithms=["RS256", "ES256"],
        audience=settings.oidc_audience,
        issuer=settings.oidc_issuer,
        options={"require": ["exp", "iat", "iss", "sub", "aud"]},
    )


@lru_cache(maxsize=4)
def _jwk_client(url: str) -> PyJWKClient:
    return PyJWKClient(url, cache_keys=True, cache_jwk_set=True, lifespan=300, timeout=5)


def _string_claim(claims: dict[str, Any], name: str) -> str | None:
    value = claims.get(name)
    return value if isinstance(value, str) else None
