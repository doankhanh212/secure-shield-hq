from contextlib import asynccontextmanager
import logging
import time

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routes import assets, auth, dashboard, domains, findings, scans, vulnerabilities
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
    # Wrapped in retries so the app survives if Redis takes a moment
    # to accept connections after Docker reports it "healthy".
    for attempt in range(1, 6):
        try:
            await redis_client.ping()
            logger.info("Redis connected (attempt %d)", attempt)
            break
        except Exception as exc:
            if attempt < 5:
                logger.warning("Redis ping failed (attempt %d): %s — retrying in 3s", attempt, exc)
                import asyncio
                await asyncio.sleep(3)
            else:
                logger.error("Redis unreachable after 5 attempts — starting without seed")

    try:
        await seed_admin_user()
    except Exception as exc:
        logger.error("Could not seed admin user: %s", exc)

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
        # Hide schema endpoints in production
        docs_url="/docs" if settings.app_debug else None,
        redoc_url="/redoc" if settings.app_debug else None,
        openapi_url="/openapi.json" if settings.app_debug else None,
    )

    # ── Security headers middleware ───────────────────────────────────────
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if not settings.app_debug:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    # ── In-process rate limiting (login endpoint) ─────────────────────────
    # Simple sliding-window counter stored in a module-level dict.
    # For multi-process deployments use a Redis-backed solution instead.
    _rate_store: dict[str, list[float]] = {}
    _RATE_WINDOW = 60.0   # seconds
    _RATE_LIMIT   = 20    # requests per window per IP

    @app.middleware("http")
    async def rate_limit_login(request: Request, call_next) -> Response:
        if request.url.path == f"{settings.api_v1_prefix}/auth/login":
            ip = request.client.host if request.client else "unknown"
            now = time.monotonic()
            window = _rate_store.setdefault(ip, [])
            # Evict timestamps outside the current window
            _rate_store[ip] = [t for t in window if now - t < _RATE_WINDOW]
            if len(_rate_store[ip]) >= _RATE_LIMIT:
                return Response(
                    content='{"detail":"Too many login attempts. Try again later."}',
                    status_code=429,
                    media_type="application/json",
                )
            _rate_store[ip].append(now)
        return await call_next(request)

    # ALLOWED_ORIGINS env var: comma-separated list of permitted origins.
    # Falls back to localhost defaults for local development.
    _raw_origins = settings.allowed_origins or "http://localhost:3000,http://localhost:5173"
    _origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth.router, prefix=settings.api_v1_prefix)
    app.include_router(scans.router, prefix=settings.api_v1_prefix)
    app.include_router(dashboard.router, prefix=settings.api_v1_prefix)
    app.include_router(assets.router, prefix=settings.api_v1_prefix)
    app.include_router(domains.router, prefix=settings.api_v1_prefix)
    app.include_router(vulnerabilities.router, prefix=settings.api_v1_prefix)
    app.include_router(findings.router, prefix=settings.api_v1_prefix)
    app.include_router(reports.router, prefix=settings.api_v1_prefix)
    app.include_router(settings_routes.router, prefix=settings.api_v1_prefix)
    app.include_router(ws.router, prefix=settings.api_v1_prefix)

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "hqg-backend"}

    return app


app = create_app()
