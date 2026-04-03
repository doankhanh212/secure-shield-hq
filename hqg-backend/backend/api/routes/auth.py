from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator

from backend.api.deps import get_current_user
from backend.core.auth import create_access_token, verify_password
from backend.core.user_store import create_user, get_user, update_password


router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("New password must be at least 8 characters")
        return v


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3 or len(v) > 32:
            raise ValueError("Username must be 3–32 characters")
        if not v.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Username may only contain letters, numbers, hyphens, underscores")
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @field_validator("role")
    @classmethod
    def role_valid(cls, v: str) -> str:
        if v not in ("admin", "analyst", "viewer"):
            raise ValueError("Role must be admin, analyst, or viewer")
        return v


# ── POST /auth/login ─────────────────────────────────────────────────────────

@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest) -> LoginResponse:
    user = await get_user(payload.username)
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token({"sub": user["username"], "role": user["role"]})
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        role=user["role"],
        username=user["username"],
    )


# ── GET /auth/me ─────────────────────────────────────────────────────────────

@router.get("/me")
async def read_me(current_user: dict = Depends(get_current_user)) -> dict[str, str]:
    return {
        "username": current_user["username"],
        "role": current_user["role"],
    }


# ── POST /auth/change-password ───────────────────────────────────────────────

@router.post("/change-password", summary="Change current user password")
async def change_password(
    body: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user),
) -> dict[str, str]:
    if not verify_password(body.current_password, current_user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    updated = await update_password(current_user["username"], body.new_password)
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update password")
    return {"message": "Password changed successfully"}


# ── POST /auth/users ─────────────────────────────────────────────────────────
# Admin-only: create a new platform user

@router.post("/users", status_code=201, summary="Create a new user (admin only)")
async def create_platform_user(
    body: CreateUserRequest,
    current_user: dict = Depends(get_current_user),
) -> dict[str, str]:
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    existing = await get_user(body.username)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User {body.username!r} already exists",
        )
    await create_user(username=body.username, password=body.password, role=body.role)
    return {"username": body.username, "role": body.role, "message": "User created"}
