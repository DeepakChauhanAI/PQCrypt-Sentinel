"""Tests for the async retry helper."""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.utils.retry import async_retry


def test_async_retry_succeeds_first_try():
    @async_retry(attempts=3)
    async def ok():
        return 42

    assert asyncio.run(ok()) == 42


def test_async_retry_eventually_succeeds():
    calls = {"n": 0}

    @async_retry(attempts=4, initial_delay=0.01, retry_on=(ValueError,))
    async def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ValueError("nope")
        return "ok"

    assert asyncio.run(flaky()) == "ok"
    assert calls["n"] == 3


def test_async_retry_gives_up_after_attempts():
    calls = {"n": 0}

    @async_retry(attempts=3, initial_delay=0.01, retry_on=(ValueError,))
    async def always_fails():
        calls["n"] += 1
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        asyncio.run(always_fails())
    assert calls["n"] == 3


def test_async_retry_does_not_catch_other_errors():
    calls = {"n": 0}

    @async_retry(attempts=5, initial_delay=0.01, retry_on=(ValueError,))
    async def type_error():
        calls["n"] += 1
        raise TypeError("nope")

    with pytest.raises(TypeError):
        asyncio.run(type_error())
    assert calls["n"] == 1


def test_async_retry_cancelled_error_propagates():
    @async_retry(attempts=5, initial_delay=0.01)
    async def cancels():
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(cancels())


def test_async_retry_passes_args():
    @async_retry(attempts=2, initial_delay=0.01)
    async def add(a, b):
        return a + b

    assert asyncio.run(add(2, 3)) == 5
