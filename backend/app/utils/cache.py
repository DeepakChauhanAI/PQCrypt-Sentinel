"""
Async Redis cache wrapper with proper lifecycle management.

Provides a single :class:`RedisCache` class used throughout the app
(dashboard, risk recalculation, etc.) and a small ``get_redis_cache``
factory that returns a lazily-initialised singleton.

The class:
  * Lazily connects (so module import doesn't fail when Redis is down).
  * Exposes a ``ping`` health probe.
  * Exposes an explicit ``aclose()`` for FastAPI lifespan shutdown.
  * Silently degrades to no-ops on transient errors — caching must never
    take down a request.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from app.config import settings

logger = logging.getLogger(__name__)


class RedisCache:
    """Thin async wrapper around redis.asyncio with graceful degradation."""

    def __init__(self, url: str, namespace: str = "pqc") -> None:
        self._url = url
        self._namespace = namespace
        self._client: Optional[aioredis.Redis] = None
        self._lock = asyncio.Lock()

    async def _get_client(self) -> Optional[aioredis.Redis]:
        if self._client is not None:
            return self._client
        async with self._lock:
            if self._client is None:
                try:
                    self._client = aioredis.from_url(
                        self._url,
                        decode_responses=True,
                        socket_connect_timeout=2,
                        socket_timeout=2,
                    )
                except Exception as exc:
                    logger.warning(f"Redis init failed: {exc}")
                    self._client = None
        return self._client

    def _key(self, key: str) -> str:
        return f"{self._namespace}:{key}"

    async def get(self, key: str) -> Optional[Any]:
        client = await self._get_client()
        if client is None:
            return None
        try:
            raw = await client.get(self._key(key))
        except RedisError as exc:
            logger.warning(f"Redis GET error: {exc}")
            return None
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return raw

    async def set(self, key: str, value: Any, ttl: int = 300) -> None:
        client = await self._get_client()
        if client is None:
            return
        try:
            payload = json.dumps(value)
            await client.set(self._key(key), payload, ex=ttl)
        except (RedisError, TypeError, ValueError) as exc:
            logger.warning(f"Redis SET error: {exc}")

    async def clear_namespace(self) -> int:
        client = await self._get_client()
        if client is None:
            return 0
        deleted = 0
        try:
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match=f"{self._namespace}:*",
                    count=100,
                )
                if keys:
                    deleted += await client.delete(*keys)
                if cursor == 0:
                    break
        except RedisError as exc:
            logger.warning(f"Redis CLEAR error: {exc}")
        return deleted

    async def ping(self) -> bool:
        """Return True if the Redis connection is healthy."""
        client = await self._get_client()
        if client is None:
            return False
        try:
            return bool(await client.ping())
        except RedisError:
            return False

    async def aclose(self) -> None:
        """Close the underlying connection pool. Safe to call multiple times."""
        if self._client is None:
            return
        try:
            await self._client.aclose()
        except Exception as exc:
            logger.warning(f"Redis aclose error: {exc}")
        finally:
            self._client = None


_singleton: Optional[RedisCache] = None
_singleton_lock = asyncio.Lock()


async def get_redis_cache() -> RedisCache:
    """Return the lazily-initialised process-wide Redis cache."""
    global _singleton
    if _singleton is not None:
        return _singleton
    async with _singleton_lock:
        if _singleton is None:
            _singleton = RedisCache(settings.REDIS_URL, namespace="pqc")
    return _singleton


async def close_redis_cache() -> None:
    """Tear down the singleton; called from FastAPI lifespan shutdown."""
    global _singleton
    if _singleton is None:
        return
    await _singleton.aclose()
    _singleton = None
