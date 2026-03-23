from collections.abc import AsyncGenerator

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.auth import verify_token
from backend.core.user_store import get_user
from backend.db.session import get_db_session


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def db_session_dependency() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_db_session():
        yield session


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = verify_token(token)
    if not payload:
        raise credentials_exception

    username = payload.get("sub")
    if not username:
        raise credentials_exception

    user = await get_user(username)
    if not user:
        raise credentials_exception

    return user
