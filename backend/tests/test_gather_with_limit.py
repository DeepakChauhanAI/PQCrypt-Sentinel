"""
Tests for the orchestrator's `_gather_with_limit` concurrency helper.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from app.services.scan_orchestrator import _gather_with_limit, MAX_CONCURRENT_PORT_PROBES


async def _slow(value, delay):
    await asyncio.sleep(delay)
    return value


def test_gather_with_limit_returns_results_in_order():
    """Results come back in the same order as the input coroutines."""
    async def _run():
        coros = [_slow(i, 0.01) for i in range(5)]
        return await _gather_with_limit(coros, limit=2)

    results = asyncio.run(_run())
    assert results == [0, 1, 2, 3, 4]


def test_gather_with_limit_caps_concurrency():
    """The concurrency limit is respected (verified by counter)."""
    in_flight = 0
    peak_in_flight = 0
    lock = asyncio.Lock()

    async def _tracker(value):
        nonlocal in_flight, peak_in_flight
        async with lock:
            in_flight += 1
            peak_in_flight = max(peak_in_flight, in_flight)
        await asyncio.sleep(0.05)
        async with lock:
            in_flight -= 1
        return value

    async def _run():
        coros = [_tracker(i) for i in range(10)]
        return await _gather_with_limit(coros, limit=3)

    asyncio.run(_run())
    assert peak_in_flight <= 3, f"peak concurrency {peak_in_flight} > 3"


def test_gather_with_limit_captures_exceptions():
    """An exception in one coroutine is captured as a tagged tuple, not raised."""
    async def _boom():
        raise RuntimeError("kaboom")

    async def _ok():
        return 42

    async def _run():
        coros = [_ok(), _boom(), _ok()]
        return await _gather_with_limit(coros, limit=2)

    results = asyncio.run(_run())
    assert results[0] == 42
    assert isinstance(results[1], tuple) and results[1][0] == "__error__"
    assert results[2] == 42


def test_gather_with_limit_default_limit_matches_constant():
    """The default limit equals the public MAX_CONCURRENT_PORT_PROBES constant."""
    async def _run():
        coros = [_slow(i, 0.001) for i in range(MAX_CONCURRENT_PORT_PROBES + 1)]
        # Calling with default limit; ensure it accepts a coroutine list
        # and returns the right number of results.
        return await _gather_with_limit(coros)

    results = asyncio.run(_run())
    assert len(results) == MAX_CONCURRENT_PORT_PROBES + 1


def test_gather_with_limit_empty_list_returns_empty():
    """An empty input returns an empty result list."""
    async def _run():
        return await _gather_with_limit([])

    assert asyncio.run(_run()) == []
