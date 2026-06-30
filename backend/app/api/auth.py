# mypy: ignore-errors
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.auth.jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password,
)
from app.db import get_session
from app.models.models import User, RefreshToken

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("id", mode="before")
    @classmethod
    def _coerce_uuid(cls, value):
        if hasattr(value, "hex"):
            return str(value)
        return value


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(User).where(User.email == request.email))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(request.password, user.password_hash or ""):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Disabled account"
        )

    user.last_login_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(user)

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    payload = decode_token(refresh_token)
    session.add(
        RefreshToken(
            user_id=user.id,
            token_jti=payload.jti or "",
            expires_at=payload.exp,
        )
    )
    await session.commit()
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshRequest,
    session: AsyncSession = Depends(get_session),
):
    refresh_token = payload.refresh_token
    decoded = decode_token(refresh_token)
    if decoded is None or decoded.type != "refresh" or not decoded.jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )

    result = await session.execute(
        select(RefreshToken).where(RefreshToken.token_jti == decoded.jti)
    )
    stored = result.scalar_one_or_none()
    if (
        stored is None
        or stored.revoked
        or stored.expires_at < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token revoked or expired",
        )

    user_result = await session.execute(select(User).where(User.id == decoded.sub))
    user = user_result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or disabled",
        )

    access_token = create_access_token(user.id)
    new_refresh_token = create_refresh_token(user.id)
    new_payload = decode_token(new_refresh_token)

    stored.revoked = True
    stored.revoked_at = datetime.now(timezone.utc)
    stored.replaced_by = new_payload.jti
    session.add(
        RefreshToken(
            user_id=user.id,
            token_jti=new_payload.jti or "",
            expires_at=new_payload.exp,
        )
    )
    await session.commit()
    return TokenResponse(access_token=access_token, refresh_token=new_refresh_token)


@router.post("/logout")
async def logout(
    session: AsyncSession = Depends(get_session),
    refresh_token: Optional[str] = None,
):
    if refresh_token:
        decoded = decode_token(refresh_token)
        if decoded and decoded.jti:
            result = await session.execute(
                select(RefreshToken).where(RefreshToken.token_jti == decoded.jti)
            )
            stored = result.scalar_one_or_none()
            if stored and not stored.revoked:
                stored.revoked = True
                stored.revoked_at = datetime.now(timezone.utc)
                await session.commit()
    return {"detail": "Logged out"}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user
