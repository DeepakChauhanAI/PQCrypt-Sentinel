from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, inspect, text

from app.api import register_routes as register_api_routes
from app.config import settings
from app.db import engine as async_engine
from app.models.models import Base
from app.utils.cache import close_redis_cache, get_redis_cache


def _sync_url(async_url: str) -> str:
    return async_url.replace("+asyncpg", "").replace("+aiosqlite", "")


def _sync_missing_columns(sync_engine) -> None:
    """Add columns that were introduced after the initial schema creation.
    Runs after ``create_all`` so only *missing* columns are added.
    """
    inspector = inspect(sync_engine)
    tables = inspector.get_table_names()

    with sync_engine.begin() as conn:
        if "findings" in tables:
            existing = {c["name"] for c in inspector.get_columns("findings")}
            if "layer" not in existing:
                conn.execute(text("ALTER TABLE findings ADD COLUMN layer VARCHAR(5)"))
            if "hndl_exposure" not in existing:
                conn.execute(text("ALTER TABLE findings ADD COLUMN hndl_exposure VARCHAR(10)"))

        if "scans" in tables:
            existing = {c["name"] for c in inspector.get_columns("scans")}
            if "created_by" not in existing:
                conn.execute(text("ALTER TABLE scans ADD COLUMN created_by UUID"))
            # Phase B — correlation model
            if "scan_group_id" not in existing:
                conn.execute(text("ALTER TABLE scans ADD COLUMN scan_group_id UUID"))
            if "target_label" not in existing:
                conn.execute(text("ALTER TABLE scans ADD COLUMN target_label VARCHAR(255)"))
            if "target_kind" not in existing:
                conn.execute(text("ALTER TABLE scans ADD COLUMN target_kind VARCHAR(30)"))

        if "algorithms" in tables:
            existing = {c["name"] for c in inspector.get_columns("algorithms")}
            if "scan_id" not in existing:
                conn.execute(text("ALTER TABLE algorithms ADD COLUMN scan_id UUID"))


@asynccontextmanager
async def _lifespan(application: FastAPI):
    """FastAPI lifespan: init on startup, close on shutdown."""
    # Eagerly init the Redis cache so the first request doesn't pay the
    # connection cost and so any startup-time failures are logged.
    cache = await get_redis_cache()
    healthy = await cache.ping()
    if not healthy:
        # Don't fail startup; cache is optional.
        application.state.redis_healthy = False
    else:
        application.state.redis_healthy = True

    sync_url = _sync_url(settings.DATABASE_URL)
    sync_engine = create_engine(sync_url)
    Base.metadata.create_all(sync_engine)
    _sync_missing_columns(sync_engine)
    sync_engine.dispose()

    try:
        yield
    finally:
        await close_redis_cache()
        try:
            await async_engine.dispose()
        except Exception:
            pass


def create_app() -> FastAPI:
    application = FastAPI(
        title="PQCrypt Sentinel API",
        description="Post-Quantum Cryptography Discovery Platform",
        version="0.1.0",
        lifespan=_lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from app.middleware.rate_limit import RateLimitMiddleware
    application.add_middleware(RateLimitMiddleware)

    @application.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        cache = await get_redis_cache()
        redis_ok = await cache.ping()
        return {
            "status": "ok",
            "redis": "ok" if redis_ok else "degraded",
        }

    @application.get("/api/v1/auth/docs", include_in_schema=False)
    async def docs() -> dict[str, str]:
        return {"status": "ok"}

    register_api_routes(application)
    return application


app = create_app()
