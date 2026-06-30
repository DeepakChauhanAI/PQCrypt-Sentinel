"""
Tests for the helpers and orchestration glue in
`app.services.scan_orchestrator`.

The big `run_scan` function is heavy; this file focuses on the
helpers (`started_at_fallback`, `_run_host_tasks` aggregation) so we
gain coverage without spinning up a full Postgres.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch


from app.services import scan_orchestrator as so
from app.services.scan_orchestrator import (
    MAX_CONCURRENT_HOSTS,
    _gather_with_limit,
    started_at_fallback,
)


# ----------------------------------------------- started_at_fallback --


def test_started_at_fallback_none_returns_now():
    result = started_at_fallback(None)
    assert result.tzinfo is not None
    # within the last few seconds
    assert (datetime.now(timezone.utc) - result).total_seconds() < 5


def test_started_at_fallback_naive_assumes_utc():
    naive = datetime(2026, 1, 1, 12, 0, 0)
    result = started_at_fallback(naive)
    assert result.tzinfo is timezone.utc
    assert result.year == 2026


def test_started_at_fallback_aware_unchanged():
    aware = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    result = started_at_fallback(aware)
    assert result is aware  # no copy


# ----------------------------------------------- _gather_with_limit ----


def test_gather_with_limit_returns_all_results():
    async def main():
        async def one(n):
            return n * 2

        results = await _gather_with_limit([one(1), one(2), one(3)], limit=2)
        return results

    out = asyncio.run(main())
    assert sorted(out) == [2, 4, 6]


def test_gather_with_limit_captures_exceptions():
    async def main():
        async def good():
            return "ok"

        async def bad():
            raise RuntimeError("nope")

        results = await _gather_with_limit([good(), bad(), good()], limit=3)
        return results

    out = asyncio.run(main())
    # Index 1 should be the error tuple
    assert out[0] == "ok"
    assert out[2] == "ok"
    assert isinstance(out[1], tuple)
    assert out[1][0] == "__error__"
    assert isinstance(out[1][1], RuntimeError)
    assert str(out[1][1]) == "nope"


# ----------------------------------------------- _run_host_tasks -----


def test_run_host_tasks_empty_hosts_returns_zero():
    log_event = AsyncMock()
    result = asyncio.run(
        so._run_host_tasks(
            scan_id="scan-id",
            hosts=[],
            strict_tls=False,
            scan_type="full",
            advanced_tools=False,
            log_event=log_event,
        )
    )
    assert result == {"assets_total": 0, "findings_total": 0, "errors": []}


def test_run_host_tasks_aggregates_per_host_results():
    """Patch `scan_host` to return canned results, verify aggregation."""
    fake_results = [
        {"host": "h1", "assets": 3, "findings": 2, "logs": [], "error": None},
        {"host": "h2", "assets": 5, "findings": 4, "logs": [], "error": None},
    ]
    call_count = {"n": 0}

    async def fake_scan_host(**kwargs):
        n = call_count["n"]
        call_count["n"] += 1
        return fake_results[n]

    log_event = AsyncMock()
    with patch.object(so, "scan_host", side_effect=fake_scan_host, create=True):
        # scan_host is imported inside the function, so we patch the module
        with patch("app.services.scan_host.scan_host", side_effect=fake_scan_host):
            result = asyncio.run(
                so._run_host_tasks(
                    scan_id="scan-id",
                    hosts=["h1", "h2"],
                    strict_tls=False,
                    scan_type="full",
                    advanced_tools=False,
                    log_event=log_event,
                )
            )
    assert result["assets_total"] == 8
    assert result["findings_total"] == 6
    assert result["errors"] == []


def test_run_host_tasks_collects_per_host_errors():
    fake_results = [
        {
            "host": "h1",
            "assets": 1,
            "findings": 0,
            "logs": [],
            "error": "scan timed out",
        },
        {"host": "h2", "assets": 0, "findings": 0, "logs": [], "error": None},
    ]
    call_count = {"n": 0}

    async def fake_scan_host(**kwargs):
        n = call_count["n"]
        call_count["n"] += 1
        return fake_results[n]

    log_event = AsyncMock()
    with patch("app.services.scan_host.scan_host", side_effect=fake_scan_host):
        result = asyncio.run(
            so._run_host_tasks(
                scan_id="scan-id",
                hosts=["h1", "h2"],
                strict_tls=False,
                scan_type="full",
                advanced_tools=False,
                log_event=log_event,
            )
        )
    assert result["assets_total"] == 1
    assert result["findings_total"] == 0
    assert "scan timed out" in result["errors"][0]


def test_run_host_tasks_handles_executor_exception():
    """A host that raises (not a per-host `error` field) is captured as an error tuple."""

    async def raise_one(**kwargs):
        raise ConnectionError("boom")

    log_event = AsyncMock()
    with patch("app.services.scan_host.scan_host", side_effect=raise_one):
        result = asyncio.run(
            so._run_host_tasks(
                scan_id="scan-id",
                hosts=["bad-host"],
                strict_tls=False,
                scan_type="full",
                advanced_tools=False,
                log_event=log_event,
            )
        )
    assert result["assets_total"] == 0
    assert result["findings_total"] == 0
    assert "boom" in result["errors"][0]


def test_max_concurrent_hosts_default_is_8():
    """The default MAX_CONCURRENT_HOSTS is 8."""
    assert MAX_CONCURRENT_HOSTS == 8
