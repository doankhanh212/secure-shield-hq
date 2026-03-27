from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routes import assets, auth, dashboard, scans, vulnerabilities
from backend.api.routes import reports, settings as settings_routes, ws
from backend.config import get_settings
from backend.core.logging import configure_logging
from backend.core.redis import redis_client
from backend.core.search import es_client
from backend.core.user_store import seed_admin_user

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Startup: probe infrastructure clients.
    await redis_client.ping()
    await seed_admin_user()
    try:
        await es_client.ping()
        logger.info("Elasticsearch connected")
    except Exception:
        logger.warning("Elasticsearch unavailable — search features disabled")
    yield
    # Shutdown: close async clients.
    await redis_client.aclose()
    try:
        await es_client.close()
    except Exception:
        pass


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging()

    app = FastAPI(
        title=settings.app_name,
        debug=settings.app_debug,
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth.router, prefix=settings.api_v1_prefix)
    app.include_router(scans.router, prefix=settings.api_v1_prefix)
    app.include_router(dashboard.router, prefix=settings.api_v1_prefix)
    app.include_router(assets.router, prefix=settings.api_v1_prefix)
    app.include_router(vulnerabilities.router, prefix=settings.api_v1_prefix)
    app.include_router(reports.router, prefix=settings.api_v1_prefix)
    app.include_router(settings_routes.router, prefix=settings.api_v1_prefix)
    app.include_router(ws.router, prefix=settings.api_v1_prefix)

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "hqg-backend"}

    return app


app = create_app()
