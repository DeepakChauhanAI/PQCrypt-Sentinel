"""
Token-bucket rate-limiting middleware backed by Redis.

Mounts as a Starlette BaseHTTPMiddleware. Skips /health and /api/v1/auth/docs.
Uses Redis JSON strings to keep the bucket state: ``{"tokens": float, "ts": float}``.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config import settings
from app.utils.cache import get_redis_cache

logger = logging.getLogger(__name__)

RATE_LIMIT_SKIP_PATHS = {"/health", "/api/v1/auth/docs", "/docs", "/openapi.json"}
RATE_LIMIT_REDIS_PREFIX = "ratelimit:"
RATE_LIMIT_TTL_SECONDS = 60


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Token-bucket rate limiter using Redis."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path in RATE_LIMIT_SKIP_PATHS:
            return await call_next(request)

        client_ip = self._client_ip(request)
        allowed, retry_after = await self._check_bucket(client_ip)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)

    @staticmethod
    def _client_ip(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
        if request.client and request.client.host:
            return request.client.host
        return "unknown"

    async def _check_bucket(self, client_ip: str) -> tuple[bool, int]:
        rps = settings.RATE_LIMIT_RPS
        burst = settings.RATE_LIMIT_BURST
        key = f"{RATE_LIMIT_REDIS_PREFIX}{client_ip}"

        cache = await get_redis_cache()
        try:
            client = await cache._get_client()
        except Exception:
            client = None
        if client is None:
            # Redis unavailable; degrade open (allow request)
            return True, 0

        now = time.time()
        raw: Optional[Any] = None
        try:
            raw = await client.get(key)
        except Exception as exc:
            logger.warning("Rate-limit Redis GET error: %s", exc)
            return True, 0

        if raw:
            try:
                bucket = json.loads(raw)
                tokens: float = float(bucket.get("tokens", burst))
                last_ts: float = float(bucket.get("ts", now))
            except (ValueError, TypeError):
                tokens, last_ts = float(burst), now
            elapsed = now - last_ts
            tokens = min(float(burst), tokens + elapsed * float(rps))
        else:
            tokens, last_ts = float(burst), now

        if tokens >= 1.0:
            tokens -= 1.0
            try:
                await client.set(
                    key,
                    json.dumps({"tokens": tokens, "ts": now}),
                    ex=RATE_LIMIT_TTL_SECONDS,
                )
            except Exception as exc:
                logger.warning("Rate-limit Redis SET error: %s", exc)
            return True, 0

        retry_after = max(1, int((1.0 - tokens) / float(rps))) if rps > 0 else 1
        return False, retry_after
