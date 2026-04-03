from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.config import get_settings

logger = logging.getLogger(__name__)

# Engine and session factory are created lazily on first use so that a missing
# or placeholder POSTGRES_DSN does not crash the application at import time.
# The app currently stores all data in Redis; PostgreSQL is optional scaffolding.
_engine = None
_SessionLocal = None


def _get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _engine, _SessionLocal
    if _SessionLocal is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.postgres_dsn, echo=settings.app_debug, future=True
        )
        _SessionLocal = async_sessionmaker(
            bind=_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        logger.info("SQLAlchemy engine created for %s", settings.postgres_dsn)
    return _SessionLocal


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    factory = _get_session_factory()
    async with factory() as session:
        yield session
