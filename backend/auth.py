"""Password hashing, JWT access tokens, refresh-token rotation, rate limiting,
and the ``current_user`` dependency."""
from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.database import get_db, utcnow
from backend.models import RateLimitHit, RefreshToken, User

# --- Passwords ---


def _prehash(password: str) -> bytes:
    """Collapse to a fixed 44-byte value so bcrypt's 72-byte input limit never
    silently truncates a long passphrase."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    rounds = get_settings().bcrypt_rounds
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(rounds=rounds)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_prehash(password), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


# Verified against when the account does not exist, so a login attempt takes
# the same time either way and does not reveal whether an account exists.
_DUMMY_HASH = hash_password("dummy-password-for-constant-time-0")


# --- Access tokens ---


def create_access_token(user_id: str) -> tuple[str, int]:
    settings = get_settings()
    now = utcnow()
    ttl = settings.access_token_ttl_seconds
    payload = {
        "sub": user_id,
        "type": "access",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(seconds=ttl),
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, ttl


def _decode_access_token(token: str) -> dict:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "sub"]},
        )
    except jwt.PyJWTError:
        raise _unauthorized()
    if payload.get("type") != "access":
        raise _unauthorized()
    return payload


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


# --- Refresh tokens ---


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def issue_refresh_token(db: Session, user_id: str) -> str:
    settings = get_settings()
    raw = secrets.token_urlsafe(32)
    row = RefreshToken(
        user_id=user_id,
        token_hash=_hash_token(raw),
        expires_at=utcnow() + timedelta(seconds=settings.refresh_token_ttl_seconds),
    )
    db.add(row)
    db.flush()
    return raw


def revoke_all_for_user(db: Session, user_id: str) -> None:
    rows = db.scalars(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)
        )
    ).all()
    for row in rows:
        row.revoked_at = utcnow()


def rotate_refresh_token(db: Session, raw: str) -> tuple[str, User]:
    """Consume ``raw`` and issue a replacement. Reusing an already-revoked token
    revokes the whole chain for that user (theft response)."""
    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == _hash_token(raw)))
    if row is None:
        raise _unauthorized()

    if row.revoked_at is not None:
        revoke_all_for_user(db, row.user_id)
        db.commit()
        raise _unauthorized()

    if row.expires_at <= utcnow():
        raise _unauthorized()

    user = db.get(User, row.user_id)
    if user is None:
        raise _unauthorized()

    new_raw = issue_refresh_token(db, user.id)
    row.revoked_at = utcnow()
    row.replaced_by_id = db.scalar(
        select(RefreshToken.id).where(RefreshToken.token_hash == _hash_token(new_raw))
    )
    return new_raw, user


def revoke_refresh_token(db: Session, raw: str, user_id: str) -> None:
    """Revoke `raw`, but only if it belongs to `user_id`."""
    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == _hash_token(raw)))
    if row is not None and row.user_id == user_id and row.revoked_at is None:
        row.revoked_at = utcnow()


# --- Rate limiting ---


def client_ip(request: Request) -> str:
    """The socket peer address. `X-Forwarded-For` is ignored: there is no
    reverse proxy in front of this app, and trusting the header would let a
    caller choose its own rate-limit bucket."""
    return request.client.host if request.client else "unknown"


def enforce_rate_limit(db: Session, action: str, ip: str, identifier: str) -> None:
    """Count this attempt for (action, ip, identifier) and raise 429 once the
    window's limit is passed. One upsert statement, so concurrent requests
    cannot lose an increment."""
    settings = get_settings()
    window = settings.rate_limit_window_seconds
    now = utcnow()
    epoch = int(now.timestamp())
    window_start_ts = epoch - (epoch % window)
    window_start = datetime.fromtimestamp(window_start_ts, tz=timezone.utc).replace(tzinfo=None)
    bucket = f"{action}:{ip}:{identifier.lower()}"

    stmt = (
        sqlite_insert(RateLimitHit)
        .values(bucket_key=bucket, window_start=window_start, count=1)
        .on_conflict_do_update(
            index_elements=[RateLimitHit.bucket_key, RateLimitHit.window_start],
            set_={"count": RateLimitHit.count + 1},
        )
        .returning(RateLimitHit.count)
    )
    count = db.execute(stmt).scalar_one()
    db.commit()

    if count > settings.rate_limit_max_attempts:
        retry_after = window - (epoch % window)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )


# --- current_user dependency ---

_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()
    payload = _decode_access_token(credentials.credentials)
    user = db.get(User, payload["sub"])
    if user is None:
        raise _unauthorized()
    return user
