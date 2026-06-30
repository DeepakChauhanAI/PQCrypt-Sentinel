from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse

from app.middleware.rate_limit import RateLimitMiddleware, RATE_LIMIT_SKIP_PATHS


# --- _client_ip ---


def _make_request(headers=None, client_host=None):
    request = MagicMock()
    request.headers = headers or {}
    request.url.path = "/api/v1/test"
    if client_host is not None:
        request.client = SimpleNamespace(host=client_host)
    else:
        request.client = None
    return request


def test_client_ip_x_forwarded_for():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    req = _make_request(headers={"x-forwarded-for": "1.2.3.4, 5.6.7.8"})
    assert mw._client_ip(req) == "1.2.3.4"


def test_client_ip_x_real_ip():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    req = _make_request(headers={"x-real-ip": "9.8.7.6"})
    assert mw._client_ip(req) == "9.8.7.6"


def test_client_ip_from_client_host():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    req = _make_request(client_host="127.0.0.1")
    assert mw._client_ip(req) == "127.0.0.1"


def test_client_ip_no_client():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    req = _make_request()
    assert mw._client_ip(req) == "unknown"


# --- _check_bucket ---


@pytest.mark.asyncio
async def test_check_bucket_redis_unavailable():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(side_effect=Exception("no redis"))
    with patch("app.middleware.rate_limit.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        allowed, retry = await mw._check_bucket("1.2.3.4")
    assert allowed is True
    assert retry == 0


@pytest.mark.asyncio
async def test_check_bucket_client_none():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(return_value=None)
    with patch("app.middleware.rate_limit.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        allowed, retry = await mw._check_bucket("1.2.3.4")
    assert allowed is True
    assert retry == 0


@pytest.mark.asyncio
async def test_check_bucket_get_exception():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    fake_client = MagicMock()
    fake_client.get = AsyncMock(side_effect=Exception("redis get error"))
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(return_value=fake_client)
    with patch("app.middleware.rate_limit.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        allowed, retry = await mw._check_bucket("1.2.3.4")
    assert allowed is True
    assert retry == 0


@pytest.mark.asyncio
async def test_check_bucket_tokens_available():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    import time
    fake_client = MagicMock()
    fake_client.get = AsyncMock(return_value=json.dumps({"tokens": 5.0, "ts": time.time()}))
    fake_client.set = AsyncMock()
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(return_value=fake_client)
    with patch("app.middleware.rate_limit.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        with patch("app.middleware.rate_limit.settings") as mock_settings:
            mock_settings.RATE_LIMIT_RPS = 10
            mock_settings.RATE_LIMIT_BURST = 20
            allowed, retry = await mw._check_bucket("1.2.3.4")
    assert allowed is True
    assert retry == 0
    fake_client.set.assert_called_once()


@pytest.mark.asyncio
async def test_check_bucket_tokens_exhausted():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    import time
    fake_client = MagicMock()
    fake_client.get = AsyncMock(return_value=json.dumps({"tokens": 0.0, "ts": time.time()}))
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(return_value=fake_client)
    with patch("app.middleware.rate_limit.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        with patch("app.middleware.rate_limit.settings") as mock_settings:
            mock_settings.RATE_LIMIT_RPS = 10
            mock_settings.RATE_LIMIT_BURST = 20
            allowed, retry = await mw._check_bucket("1.2.3.4")
    assert allowed is False
    assert retry >= 1


@pytest.mark.asyncio
async def test_check_bucket_malformed_json():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    fake_client = MagicMock()
    fake_client.get = AsyncMock(return_value="not-json{{{")
    fake_client.set = AsyncMock()
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(return_value=fake_client)
    with patch("app.middleware.rate_limit.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        with patch("app.middleware.rate_limit.settings") as mock_settings:
            mock_settings.RATE_LIMIT_RPS = 10
            mock_settings.RATE_LIMIT_BURST = 20
            allowed, retry = await mw._check_bucket("1.2.3.4")
    assert allowed is True
    assert retry == 0


@pytest.mark.asyncio
async def test_check_bucket_no_existing_state():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    fake_client = MagicMock()
    fake_client.get = AsyncMock(return_value=None)
    fake_client.set = AsyncMock()
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(return_value=fake_client)
    with patch("app.middleware.rate_limit.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        with patch("app.middleware.rate_limit.settings") as mock_settings:
            mock_settings.RATE_LIMIT_RPS = 10
            mock_settings.RATE_LIMIT_BURST = 20
            allowed, retry = await mw._check_bucket("1.2.3.4")
    assert allowed is True
    assert retry == 0


# --- dispatch ---


@pytest.mark.asyncio
async def test_dispatch_skips_exempt_paths():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    for path in RATE_LIMIT_SKIP_PATHS:
        request = MagicMock()
        request.url.path = path
        call_next = AsyncMock(return_value=JSONResponse(content={"ok": True}))
        resp = await mw.dispatch(request, call_next)
        call_next.assert_called_once_with(request)


@pytest.mark.asyncio
async def test_dispatch_returns_429_when_limited():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    request = MagicMock()
    request.url.path = "/api/v1/scan"
    request.headers = {}
    request.client = SimpleNamespace(host="10.0.0.1")

    with patch.object(mw, "_client_ip", return_value="10.0.0.1"):
        with patch.object(mw, "_check_bucket", new=AsyncMock(return_value=(False, 5))):
            call_next = AsyncMock()
            resp = await mw.dispatch(request, call_next)

    assert resp.status_code == 429
    body = json.loads(resp.body)
    assert body["detail"] == "Rate limit exceeded"
    assert body["retry_after"] == 5
    call_next.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_passes_when_allowed():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    request = MagicMock()
    request.url.path = "/api/v1/scan"
    request.headers = {}
    request.client = SimpleNamespace(host="10.0.0.1")

    expected_response = JSONResponse(content={"ok": True})
    with patch.object(mw, "_client_ip", return_value="10.0.0.1"):
        with patch.object(mw, "_check_bucket", new=AsyncMock(return_value=(True, 0))):
            call_next = AsyncMock(return_value=expected_response)
            resp = await mw.dispatch(request, call_next)

    assert resp == expected_response
    call_next.assert_called_once_with(request)


@pytest.mark.asyncio
async def test_check_bucket_set_exception():
    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    import time
    fake_client = MagicMock()
    fake_client.get = AsyncMock(return_value=json.dumps({"tokens": 5.0, "ts": time.time()}))
    fake_client.set = AsyncMock(side_effect=Exception("redis set error"))
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(return_value=fake_client)
    with patch("app.middleware.rate_limit.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        with patch("app.middleware.rate_limit.settings") as mock_settings:
            mock_settings.RATE_LIMIT_RPS = 10
            mock_settings.RATE_LIMIT_BURST = 20
            allowed, retry = await mw._check_bucket("1.2.3.4")
    assert allowed is True
    assert retry == 0
