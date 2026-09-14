"""Authentication endpoints.

    POST /api/auth/register
    POST /api/auth/login
    POST /api/auth/refresh
    POST /api/auth/logout
    GET  /api/auth/me
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.auth import (
    _DUMMY_HASH,
    client_ip,
    create_access_token,
    enforce_rate_limit,
    get_current_user,
    hash_password,
    issue_refresh_token,
    revoke_refresh_token,
    rotate_refresh_token,
    verify_password,
)
from backend.config import get_settings
from backend.database import get_db
from backend.models import User
from backend.schemas import (
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

_GENERIC_LOGIN_ERROR = "Invalid email or password."


def _set_refresh_cookie(response: Response, raw: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=raw,
        max_age=settings.refresh_token_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/api/auth",
    )


def _clear_refresh_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/api/auth",
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> User:
    email = payload.email.lower()
    enforce_rate_limit(db, "register", client_ip(request), email)

    exists = db.scalar(select(User.id).where(User.email == email))
    if exists is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with that email already exists.",
        )

    user = User(email=email, password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)
) -> TokenResponse:
    email = payload.email.lower()
    enforce_rate_limit(db, "login", client_ip(request), email)

    user = db.scalar(select(User).where(User.email == email))
    # Always verify a hash, and give the same error for a wrong password and
    # an unknown account.
    password_ok = verify_password(payload.password, user.password_hash if user else _DUMMY_HASH)
    if user is None or not password_ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_GENERIC_LOGIN_ERROR)

    access, ttl = create_access_token(user.id)
    raw_refresh = issue_refresh_token(db, user.id)
    db.commit()
    _set_refresh_cookie(response, raw_refresh)
    return TokenResponse(access_token=access, expires_in=ttl)


@router.post("/refresh", response_model=TokenResponse)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)) -> TokenResponse:
    settings = get_settings()
    raw = request.cookies.get(settings.refresh_cookie_name)
    if not raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    new_raw, user = rotate_refresh_token(db, raw)
    access, ttl = create_access_token(user.id)
    db.commit()
    _set_refresh_cookie(response, new_raw)
    return TokenResponse(access_token=access, expires_in=ttl)


@router.post("/logout", response_model=MessageResponse)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> MessageResponse:
    settings = get_settings()
    raw = request.cookies.get(settings.refresh_cookie_name)
    if raw:
        revoke_refresh_token(db, raw, user.id)
        db.commit()
    _clear_refresh_cookie(response)
    return MessageResponse(detail="Logged out.")


@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(get_current_user)) -> User:
    return user
