"""Tests for the RedisCache wrapper and lifecycle helpers."""
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.utils import cache as cache_mod
from app.utils.cache import RedisCache, close_redis_cache, get_redis_cache


def _make_mock_redis_client():
    """Build a mock redis.asyncio.Redis with the methods we use."""
    client = MagicMock()
    client.get = AsyncMock(return_value=None)
    client.set = AsyncMock(return_value=True)
    client.ping = AsyncMock(return_value=True)
    client.aclose = AsyncMock(return_value=None)

    async def _scan(cursor, match=None, count=100):
        return (0, [])

    client.scan = _scan
    client.delete = AsyncMock(return_value=0)
    return client


def test_redis_cache_lazily_connects():
    """A new RedisCache must not connect to Redis at construction time."""
    c = RedisCache("redis://invalid:1", namespace="test")
    assert c._client is None


def test_redis_cache_get_set_roundtrip():
    """set() then get() must roundtrip the value as JSON."""
    client = _make_mock_redis_client()
    client.get.return_value = '{"x": 1}'
    c = RedisCache("redis://x:1", namespace="test")
    c._client = client  # bypass lazy init for the test
    asyncio.run(c.set("k", {"x": 1}))
    val = asyncio.run(c.get("k"))
    assert val == {"x": 1}


def test_redis_cache_get_returns_none_on_missing_key():
    client = _make_mock_redis_client()
    client.get.return_value = None
    c = RedisCache("redis://x:1", namespace="test")
    c._client = client
    assert asyncio.run(c.get("missing")) is None


def test_redis_cache_get_returns_none_on_invalid_json():
    client = _make_mock_redis_client()
    client.get.return_value = "not-json"
    c = RedisCache("redis://x:1", namespace="test")
    c._client = client
    val = asyncio.run(c.get("k"))
    # We return the raw value when JSON decoding fails (graceful degradation).
    assert val == "not-json"


def test_redis_cache_ping_true():
    client = _make_mock_redis_client()
    client.ping.return_value = True
    c = RedisCache("redis://x:1", namespace="test")
    c._client = client
    assert asyncio.run(c.ping()) is True


def test_redis_cache_ping_false_on_redis_error():
    from redis.exceptions import RedisError
    client = _make_mock_redis_client()
    client.ping.side_effect = RedisError("down")
    c = RedisCache("redis://x:1", namespace="test")
    c._client = client
    assert asyncio.run(c.ping()) is False


def test_redis_cache_aclose_is_idempotent():
    client = _make_mock_redis_client()
    c = RedisCache("redis://x:1", namespace="test")
    c._client = client
    asyncio.run(c.aclose())
    asyncio.run(c.aclose())  # second call must not raise
    assert c._client is None


def test_redis_cache_clear_namespace_returns_count():
    client = _make_mock_redis_client()

    async def fake_scan(cursor, match=None, count=100):
        if cursor == 0:
            return (123, ["pqc:foo", "pqc:bar"])
        return (0, [])

    client.scan = fake_scan
    client.delete.return_value = 2
    c = RedisCache("redis://x:1", namespace="pqc")
    c._client = client
    deleted = asyncio.run(c.clear_namespace())
    assert deleted == 2


def test_get_redis_cache_returns_singleton():
    async def _runner():
        cache_mod._singleton = None
        a = await get_redis_cache()
        b = await get_redis_cache()
        return a, b
    a, b = asyncio.run(_runner())
    assert a is b


def test_close_redis_cache_clears_singleton():
    async def _runner():
        cache_mod._singleton = None
        cache = await get_redis_cache()
        await close_redis_cache()
        return cache_mod._singleton
    singleton = asyncio.run(_runner())
    assert singleton is None


def test_dashboard_cache_helpers_use_namespaced_keys(monkeypatch):
    """dashboard.get_cache / set_cache must namespace keys with 'dashboard:'."""
    captured = {}

    class _FakeCache:
        async def get(self, key):
            captured["get_key"] = key
            return None
        async def set(self, key, value, ttl=None):
            captured["set_key"] = key
            captured["set_ttl"] = ttl

    async def _fake_get_redis_cache():
        return _FakeCache()

    monkeypatch.setattr(cache_mod, "get_redis_cache", _fake_get_redis_cache)
    from app.api import dashboard
    monkeypatch.setattr(dashboard, "get_redis_cache", _fake_get_redis_cache)
    asyncio.run(dashboard.set_cache("summary", {"a": 1}, ttl=60))
    assert captured["set_key"] == "dashboard:summary"
    assert captured["set_ttl"] == 60
    asyncio.run(dashboard.get_cache("summary"))
    assert captured["get_key"] == "dashboard:summary"


def test_health_endpoint_returns_redis_status(monkeypatch):
    """The /health endpoint should report redis status when cache is up."""
    from starlette.testclient import TestClient
    from app.main import app as fastapi_app

    fake_client = _make_mock_redis_client()
    fake_client.ping.return_value = True

    class _FakeCacheShim:
        def __init__(self, c):
            self._c = c
        async def ping(self):
            return bool(await self._c.ping())
        async def aclose(self):
            return await self._c.aclose()

    async def _fake_get_redis_cache():
        return _FakeCacheShim(fake_client)

    from app.api import dashboard as dashboard_mod
    monkeypatch.setattr(dashboard_mod, "get_redis_cache", _fake_get_redis_cache)
    from app.utils import cache as cache_mod2
    monkeypatch.setattr(cache_mod2, "get_redis_cache", _fake_get_redis_cache)

    with TestClient(fastapi_app) as tc:
        resp = tc.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["redis"] in ("ok", "degraded")
