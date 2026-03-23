from pydantic import BaseModel

from fastapi import APIRouter, Depends, HTTPException, status

from backend.api.deps import get_current_user
from backend.core.auth import create_access_token, verify_password
from backend.core.user_store import get_user


router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str


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


@router.get("/me")
async def read_me(current_user: dict = Depends(get_current_user)) -> dict[str, str]:
    return {
        "username": current_user["username"],
        "role": current_user["role"],
    }