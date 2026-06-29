from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings

_db_url = settings.DATABASE_URL
_engine_kwargs: dict = {"echo": False, "future": True}
if "sqlite" not in _db_url.lower():
    _engine_kwargs["pool_size"] = settings.DB_POOL_SIZE
    _engine_kwargs["max_overflow"] = settings.DB_MAX_OVERFLOW
engine = create_async_engine(_db_url, **_engine_kwargs)
AsyncSessionLocal = sessionmaker(
    bind=engine,  # type: ignore[call-overload]
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
