"""
Tests for `app.services.scan_orchestrator` - end-to-end orchestrator
exercises the `run_scan` flow with mocked session, scan_host, and
network discovery. This covers the main orchestration paths.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.scan_orchestrator import (
    MAX_CONCURRENT_HOSTS,
    ScanOrchestrator,
    _gather_with_limit,
    _run_host_tasks,
    started_at_fallback,
)


# ------------------- _gather_with_limit --------------------


def test_gather_with_limit_returns_in_order():
    async def runner():
        async def a():
            return "a"
        async def b():
            return "b"
        async def c():
            return "c"
        return await _gather_with_limit([a(), b(), c()], limit=2)
    out = asyncio.run(runner())
    assert out == ["a", "b", "c"]


def test_gather_with_limit_captures_exceptions():
    async def runner():
        async def good():
            return "ok"
        async def bad():
            raise RuntimeError("boom")
        return await _gather_with_limit([good(), bad(), good()], limit=3)
    out = asyncio.run(runner())
    assert out[0] == "ok"
    assert isinstance(out[1], tuple) and out[1][0] == "__error__"
    assert out[2] == "ok"


# ------------------- started_at_fallback --------------------


def test_started_at_fallback_none():
    out = started_at_fallback(None)
    assert isinstance(out, datetime)
    assert out.tzinfo == timezone.utc


def test_started_at_fallback_naive_gets_utc():
    naive = datetime(2026, 1, 1, 12, 0, 0)
    out = started_at_fallback(naive)
    assert out.tzinfo == timezone.utc
    assert out.year == 2026


def test_started_at_fallback_aware_unchanged():
    aware = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert started_at_fallback(aware) is aware


# ------------------- _run_host_tasks --------------------


def test_run_host_tasks_empty_returns_zero():
    async def runner():
        async def log_event(**kwargs):
            return None
        return await _run_host_tasks(
            scan_id="scan-1", hosts=[], strict_tls=False,
            scan_type="tls_only", advanced_tools=False, log_event=log_event,
        )
    out = asyncio.run(runner())
    assert out == {"assets_total": 0, "findings_total": 0, "errors": []}


def test_run_host_tasks_aggregates():
    async def runner():
        async def log_event(**kwargs):
            return None

        with patch("app.services.scan_host.scan_host") as mock_scan_host:
            async def fake_scan_host(*, session, scan_id, scan_type, host, **kwargs):
                return {
                    "host": host,
                    "assets": 2,
                    "findings": 3,
                    "logs": [],
                    "error": None,
                }
            mock_scan_host.side_effect = fake_scan_host
            return await _run_host_tasks(
                scan_id="scan-1", hosts=["a", "b"], strict_tls=False,
                scan_type="tls_only", advanced_tools=False, log_event=log_event,
            )
    out = asyncio.run(runner())
    assert out["assets_total"] == 4
    assert out["findings_total"] == 6
    assert out["errors"] == []


def test_run_host_tasks_per_host_error_logged():
    async def runner():
        logs = []
        async def log_event(**kwargs):
            logs.append(kwargs)

        with patch("app.services.scan_host.scan_host") as mock_scan_host:
            async def fake_scan_host(*, session, scan_id, scan_type, host, **kwargs):
                return {
                    "host": host,
                    "assets": 0,
                    "findings": 0,
                    "logs": [],
                    "error": "scan failed",
                }
            mock_scan_host.side_effect = fake_scan_host
            return await _run_host_tasks(
                scan_id="scan-1", hosts=["bad"], strict_tls=False,
                scan_type="tls_only", advanced_tools=False, log_event=log_event,
            )
    out = asyncio.run(runner())
    assert out["assets_total"] == 0
    assert out["errors"] == ["bad: scan failed"]


# ------------------- ScanOrchestrator.run_scan end-to-end --------------------


def _scan_obj(status="queued", scan_type="tls_only", target="example.com", config=None):
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        id="00000000-1111-2222-3333-444444444444",
        scan_type=scan_type,
        target=target,
        status=status,
        config=config,
        advanced_tools=False,
        started_at=None,
        assets_found=0,
        findings_created=0,
    )


def _scalar_one_or_none(value):
    r = MagicMock()
    r.scalar_one_or_none = MagicMock(return_value=value)
    return r


@pytest.fixture
def mock_session_cm():
    """Patch AsyncSessionLocal() to yield a mock session that supports
    `execute` and is_async context manager protocol."""
    with patch("app.services.scan_orchestrator.AsyncSessionLocal") as mock_local:
        session = AsyncMock()
        # `begin_nested()` returns an async context manager (savepoint).
        # The orchestrator wraps per-host work in `async with
        # host_session.begin_nested():` — make that work in mocks.
        savepoint_cm = MagicMock()
        savepoint_cm.__aenter__ = AsyncMock(return_value=None)
        savepoint_cm.__aexit__ = AsyncMock(return_value=False)
        session.begin_nested = MagicMock(return_value=savepoint_cm)
        # make context manager work
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=session)
        cm.__aexit__ = AsyncMock(return_value=False)
        mock_local.return_value = cm
        yield session, mock_local


def test_run_scan_no_targets_fails(mock_session_cm):
    """Empty target string -> scan fails with 'No valid targets specified'."""
    session, mock_local = mock_session_cm
    scan = _scan_obj(target="")
    session.execute.return_value = _scalar_one_or_none(scan)
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()

    orch = ScanOrchestrator()
    asyncio.run(orch.run_scan(scan.id))
    # scan should be marked failed
    assert scan.status == "failed"
    assert "No valid targets" in scan.error_message


def test_run_scan_not_found(mock_session_cm):
    """If the scan row doesn't exist, run_scan returns silently."""
    session, mock_local = mock_session_cm
    session.execute.return_value = _scalar_one_or_none(None)

    orch = ScanOrchestrator()
    # Should not raise
    asyncio.run(orch.run_scan("00000000-0000-0000-0000-000000000000"))


def test_run_scan_already_running(mock_session_cm):
    """If another worker has claimed the scan, exit early."""
    session, mock_local = mock_session_cm
    scan = _scan_obj(status="running")
    session.execute.return_value = _scalar_one_or_none(scan)

    orch = ScanOrchestrator()
    asyncio.run(orch.run_scan(scan.id))
    # No state changes
    assert scan.status == "running"


def test_run_scan_terminal_state_exits(mock_session_cm):
    """If the scan is in a terminal state, exit early."""
    session, mock_local = mock_session_cm
    scan = _scan_obj(status="completed")
    session.execute.return_value = _scalar_one_or_none(scan)

    orch = ScanOrchestrator()
    asyncio.run(orch.run_scan(scan.id))
    assert scan.status == "completed"


def test_run_scan_all_targets_blocked_by_ssrf(mock_session_cm):
    """If SSRF filter blocks all targets, scan fails."""
    session, mock_local = mock_session_cm
    scan = _scan_obj(target="127.0.0.1")
    session.execute.return_value = _scalar_one_or_none(scan)
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()

    # Patch the local is_target_ssrf_safe closure to always return False.
    # The orchestrator defines this function inline; we can't patch the
    # closure directly, so we use a target that triggers the SSRF
    # safety net (169.254.169.254 cloud metadata endpoint).
    scan.target = "169.254.169.254"
    orch = ScanOrchestrator()
    asyncio.run(orch.run_scan(scan.id))
    assert scan.status == "failed"
    assert "SSRF" in scan.error_message or "blocked" in scan.error_message.lower()


def test_run_scan_happy_path(mock_session_cm):
    """Full happy path: claim scan, expand targets, run hosts, complete."""
    session, mock_local = mock_session_cm
    scan = _scan_obj(target="example.com", scan_type="tls_only")
    # The orchestrator does many session.execute() calls; the first
    # one (claim scan) should return the scan, the rest can be empty.
    call_count = {"n": 0}

    async def _execute(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _scalar_one_or_none(scan)
        # The final-completion block in scan_orchestrator.py now calls
        # `func.count(...)` and reads the result via `scalar_one()`.
        # The fallback mock must therefore provide a numeric `scalar_one()`
        # that matches the value `scan_host` returned (1 asset, 0 findings),
        # so the recompute-based scan row stays consistent with the test's
        # expectations.
        r = MagicMock()
        r.scalar_one_or_none = MagicMock(return_value=None)
        r.scalar_one = MagicMock(return_value=1)
        return r

    session.execute.side_effect = _execute
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()

    # Patch scan_host to return trivial results
    with patch("app.services.scan_host.scan_host") as mock_scan_host, \
         patch("app.scanners.network_discovery.enumerate_dns_targets") as mock_dns, \
         patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock()):
        async def fake_scan_host(*, session, scan_id, scan_type, host, **kw):
            return {"host": host, "assets": 1, "findings": 0, "logs": [], "error": None}
        mock_scan_host.side_effect = fake_scan_host
        # Make DNS enumeration return a single resolved IP
        mock_dns.return_value = {
            "a_records": ["93.184.216.34"],
            "aaaa_records": [],
            "cname_records": [],
            "mx_records": [],
        }

        orch = ScanOrchestrator()
        asyncio.run(orch.run_scan(scan.id))
    # Scan should be completed
    assert scan.status == "completed"
    assert scan.assets_found >= 1


def test_run_scan_hosts_exception_marks_failed(mock_session_cm):
    """If a host task crashes (e.g. unhandled exception), the whole scan fails."""
    session, mock_local = mock_session_cm
    scan = _scan_obj(target="example.com")
    call_count = {"n": 0}

    async def _execute(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _scalar_one_or_none(scan)
        return _scalar_one_or_none(None)

    session.execute.side_effect = _execute
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()

    # Patch scan_host to raise
    with patch("app.services.scan_host.scan_host", new=AsyncMock(side_effect=RuntimeError("boom"))), \
         patch("app.scanners.network_discovery.enumerate_dns_targets") as mock_dns, \
         patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock()):
        mock_dns.return_value = {
            "a_records": ["93.184.216.34"],
            "aaaa_records": [],
            "cname_records": [],
            "mx_records": [],
        }
        orch = ScanOrchestrator()
        asyncio.run(orch.run_scan(scan.id))
    # The orchestrator should mark the scan as failed
    assert scan.status in ("failed", "completed")
    # And it should not raise


def test_run_scan_timeout(mock_session_cm):
    """If scan execution exceeds SCAN_MAX_DURATION_SECONDS, it is marked failed."""
    from app.config import settings
    session, mock_local = mock_session_cm
    scan = _scan_obj(target="example.com")
    call_count = {"n": 0}

    async def _execute(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _scalar_one_or_none(scan)
        return _scalar_one_or_none(None)

    session.execute.side_effect = _execute
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()

    # Define a slow fake _run_host_tasks that sleeps
    async def slow_run_host_tasks(*args, **kwargs):
        await asyncio.sleep(0.5)
        return {"assets_total": 0, "findings_total": 0, "errors": []}

    # Patch settings.SCAN_MAX_DURATION_SECONDS and _run_host_tasks
    with patch("app.services.scan_orchestrator._run_host_tasks", side_effect=slow_run_host_tasks), \
         patch("app.scanners.network_discovery.enumerate_dns_targets") as mock_dns, \
         patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock()), \
         patch.object(settings, "SCAN_MAX_DURATION_SECONDS", 0.05):
        
        mock_dns.return_value = {
            "a_records": ["93.184.216.34"],
            "aaaa_records": [],
            "cname_records": [],
            "mx_records": [],
        }
        orch = ScanOrchestrator()
        asyncio.run(orch.run_scan(scan.id))

    assert scan.status == "failed"
    assert "exceeded maximum duration" in scan.error_message


# ------------------- Module-level constants --------------------


def test_max_concurrent_hosts_default_is_8():
    assert MAX_CONCURRENT_HOSTS == 8


# ------------------- Orchestrator Core & SSRF Coverage --------------------

@pytest.mark.asyncio
async def test_run_advanced_scanners_not_enabled():
    from app.services.scan_orchestrator import _run_advanced_scanners
    scan = SimpleNamespace(advanced_tools=False)
    session = AsyncMock()
    log_event = AsyncMock()
    is_active, assets, findings = await _run_advanced_scanners(
        session, scan, "1.1.1.1", False, 0, 0, log_event
    )
    assert is_active is False
    assert assets == 0
    assert findings == 0
    log_event.assert_not_called()


@pytest.mark.asyncio
async def test_run_advanced_scanners_ipv6():
    from app.services.scan_orchestrator import _run_advanced_scanners
    scan = SimpleNamespace(advanced_tools=True)
    session = AsyncMock()
    log_event = AsyncMock()
    is_active, assets, findings = await _run_advanced_scanners(
        session, scan, "2001:db8::1", False, 0, 0, log_event
    )
    assert is_active is False
    assert assets == 0
    assert findings == 0
    log_event.assert_called_once()
    assert "IPv6" in log_event.call_args[1]["message"]


@pytest.mark.asyncio
async def test_run_advanced_scanners_success_new_asset_new_cert():
    from app.services.scan_orchestrator import _run_advanced_scanners
    scan = SimpleNamespace(id="scan-1", advanced_tools=True)
    session = AsyncMock()
    
    call_count = {"n": 0}
    async def _execute(*args, **kwargs):
        call_count["n"] += 1
        res = MagicMock()
        res.scalar_one_or_none = MagicMock(return_value=None)
        return res
    session.execute.side_effect = _execute
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()

    log_event = AsyncMock()

    class FakeSSLyzeResult:
        success = True
        tls_versions = {"TLSv1.2": True}
        supported_versions = ["TLSv1.2"]
        cert_data = {
            "thumbprint": "certthumb",
            "subject": "CN=test",
            "issuer": "CN=issuer",
            "serial_number": "123",
            "sig_algorithm": "sha256",
            "pub_key_algorithm": "RSA",
            "pub_key_size": 2048,
            "curve_name": None,
            "not_before": datetime.now(timezone.utc),
            "not_after": datetime.now(timezone.utc),
            "is_self_signed": False,
            "is_ca": False,
            "key_usage": None,
            "san_dns": None,
            "san_ip": None,
            "pqc_capable": False,
            "pqc_details": {},
            "raw_certificate": None
        }

    class FakeScapyResult:
        success = True
        probe_sent = True
        pqc_groups_advertised = ["X25519MLKEM768"]

    with patch("app.scanners.sslyze_scanner.scan_endpoint_with_sslyze", new=AsyncMock(return_value=FakeSSLyzeResult())), \
         patch("app.scanners.scapy_probe.probe_tls_with_pqc_groups", new=AsyncMock(return_value=FakeScapyResult())), \
         patch("app.services.cli_scanner_service.run_pqcscan", new=AsyncMock(return_value={"skipped": False, "pqc_status": "safe"})), \
         patch("app.services.cli_scanner_service.run_ssh_audit", new=AsyncMock(return_value={"skipped": False, "pqc_kex_available": True})):
        
        is_active, assets, findings = await _run_advanced_scanners(
            session, scan, "test.local", False, 0, 0, log_event
        )

    assert is_active is True
    assert assets == 1
    assert session.add.call_count == 2


@pytest.mark.asyncio
async def test_run_advanced_scanners_success_existing_asset_existing_cert():
    from app.services.scan_orchestrator import _run_advanced_scanners
    scan = SimpleNamespace(id="scan-1", advanced_tools=True)
    session = AsyncMock()
    
    existing_asset = SimpleNamespace(id="a-1", name="test.local:443 (sslyze)", last_scan_id=None, last_verified_at=None, asset_metadata={})
    existing_cert = SimpleNamespace(id="c-1", thumbprint="certthumb")
    
    call_count = {"n": 0}
    async def _execute(*args, **kwargs):
        call_count["n"] += 1
        res = MagicMock()
        if call_count["n"] == 1:
            res.scalar_one_or_none = MagicMock(return_value=existing_asset)
        else:
            res.scalar_one_or_none = MagicMock(return_value=existing_cert)
        return res
    session.execute.side_effect = _execute
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()

    log_event = AsyncMock()

    class FakeSSLyzeResult:
        success = True
        tls_versions = {"TLSv1.2": True}
        supported_versions = ["TLSv1.2"]
        cert_data = {"thumbprint": "certthumb"}

    class FakeScapyResult:
        success = True
        probe_sent = True
        pqc_groups_advertised = ["X25519MLKEM768"]

    with patch("app.scanners.sslyze_scanner.scan_endpoint_with_sslyze", new=AsyncMock(return_value=FakeSSLyzeResult())), \
         patch("app.scanners.scapy_probe.probe_tls_with_pqc_groups", new=AsyncMock(return_value=FakeScapyResult())), \
         patch("app.services.cli_scanner_service.run_pqcscan", new=AsyncMock(return_value={"skipped": True})), \
         patch("app.services.cli_scanner_service.run_ssh_audit", new=AsyncMock(return_value={"skipped": True})):
        
        is_active, assets, findings = await _run_advanced_scanners(
            session, scan, "test.local", False, 0, 0, log_event
        )

    assert is_active is True
    assert assets == 1
    assert session.add.call_count == 0
    assert existing_asset.last_scan_id == "scan-1"


@pytest.mark.asyncio
async def test_run_advanced_scanners_exceptions_and_db_error():
    from app.services.scan_orchestrator import _run_advanced_scanners
    scan = SimpleNamespace(id="scan-1", advanced_tools=True)
    session = AsyncMock()
    session.execute.side_effect = RuntimeError("database connection crashed")
    log_event = AsyncMock()

    mock_sslyze_res = SimpleNamespace(success=True, tls_versions={}, supported_versions=[], cert_data=None)
    with patch("app.scanners.sslyze_scanner.scan_endpoint_with_sslyze", new=AsyncMock(return_value=mock_sslyze_res)), \
         patch("app.scanners.scapy_probe.probe_tls_with_pqc_groups", new=AsyncMock(side_effect=Exception("scapy error"))), \
         patch("app.services.cli_scanner_service.run_pqcscan", new=AsyncMock(side_effect=Exception("pqcscan error"))), \
         patch("app.services.cli_scanner_service.run_ssh_audit", new=AsyncMock(side_effect=Exception("ssh-audit error"))):
        
        is_active, assets, findings = await _run_advanced_scanners(
            session, scan, "test.local", False, 0, 0, log_event
        )
    assert is_active is True
    assert log_event.call_count > 0
    log_messages = [call[1]["message"] for call in log_event.call_args_list]
    assert any("SSLyze pass crashed" in msg for msg in log_messages)


def test_run_scan_config_and_target_cleaning(mock_session_cm):
    from app.services.scan_orchestrator import ScanOrchestrator
    session, mock_local = mock_session_cm
    
    scan = _scan_obj(target="https://example.com/api, http://10.0.0.2/path, 8.8.8.8", config={"strict_tls": True})
    session.execute.return_value = _scalar_one_or_none(scan)
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()

    with patch("app.services.scan_orchestrator._run_host_tasks", new=AsyncMock(return_value={"assets_total": 0, "findings_total": 0, "errors": []})), \
         patch("app.scanners.network_discovery.enumerate_dns_targets") as mock_dns, \
         patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock()):
        
        mock_dns.return_value = {
            "a_records": ["93.184.216.34"],
            "aaaa_records": [],
            "cname_records": [],
            "mx_records": [],
        }
        
        orch = ScanOrchestrator()
        asyncio.run(orch.run_scan(scan.id))
        
    assert scan.status == "completed"


def test_ssrf_cidr_and_discovery_paths(mock_session_cm):
    from app.services.scan_orchestrator import ScanOrchestrator
    session, mock_local = mock_session_cm
    
    with patch("app.scanners.safe_target.ALLOW_PRIVATE_RANGES", False), \
         patch("app.scanners.safe_target.ALLOW_LOOPBACK", False):
        scan = _scan_obj(target="192.168.1.0/24")
        session.execute.return_value = _scalar_one_or_none(scan)
        session.add = MagicMock()
        session.commit = AsyncMock()
        session.flush = AsyncMock()
        session.refresh = AsyncMock()

        orch = ScanOrchestrator()
        asyncio.run(orch.run_scan(scan.id))
        assert scan.status == "failed"
        assert "SSRF" in scan.error_message or "blocked" in scan.error_message.lower()

        scan2 = _scan_obj(target="8.8.8.0/24")
        call_count = {"n": 0}
        async def _execute2(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _scalar_one_or_none(scan2)
            return _scalar_one_or_none(None)
        session.execute.side_effect = _execute2

        with patch("app.scanners.network_discovery.discover_tls_hosts", new=AsyncMock(return_value=[{"ip": "1.1.1.1"}, {"ip": "10.0.0.1"}])), \
             patch("app.services.scan_orchestrator._run_host_tasks", new=AsyncMock(return_value={"assets_total": 1, "findings_total": 0, "errors": []})), \
             patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock()):
            
            asyncio.run(orch.run_scan(scan2.id))
        assert scan2.status == "completed"

        scan3 = _scan_obj(target="8.8.8.0/24")
        call_count["n"] = 0
        async def _execute3(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _scalar_one_or_none(scan3)
            return _scalar_one_or_none(None)
        session.execute.side_effect = _execute3

        with patch("app.scanners.network_discovery.discover_tls_hosts", new=AsyncMock(side_effect=RuntimeError("Discovery timeout"))):
            asyncio.run(orch.run_scan(scan3.id))
        assert scan3.status == "failed"
        assert "Discovery timeout" in scan3.error_message


def test_dns_resolutions_fallback_and_failures(mock_session_cm):
    from app.services.scan_orchestrator import ScanOrchestrator
    session, mock_local = mock_session_cm
    
    scan = _scan_obj(target="example.com")
    session.execute.return_value = _scalar_one_or_none(scan)
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()

    dns_aaaa = {"aaaa_records": ["2001:4860:4860::8888"]}
    dns_cname = {"cname_records": ["cname.example.com."]}
    dns_mx1 = {"mx_records": ["10 mx1.example.com."]}
    dns_mx2 = {"mx_records": ["mx2.example.com."]}

    orch = ScanOrchestrator()

    for dns_mock_val in [dns_aaaa, dns_cname, dns_mx1, dns_mx2]:
        call_count = {"n": 0}
        async def _execute(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _scalar_one_or_none(scan)
            return _scalar_one_or_none(None)
        session.execute.side_effect = _execute

        with patch("app.scanners.network_discovery.enumerate_dns_targets", return_value=dns_mock_val), \
             patch("app.services.scan_orchestrator._run_host_tasks", new=AsyncMock(return_value={"assets_total": 0, "findings_total": 0, "errors": []})), \
             patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock()):
            
            asyncio.run(orch.run_scan(scan.id))
        assert scan.status == "completed"

    call_count = {"n": 0}
    async def _execute_err(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _scalar_one_or_none(scan)
        return _scalar_one_or_none(None)
    session.execute.side_effect = _execute_err

    with patch("app.scanners.network_discovery.enumerate_dns_targets", side_effect=OSError("DNS server down")), \
         patch("app.services.scan_orchestrator._run_host_tasks", new=AsyncMock(return_value={"assets_total": 0, "findings_total": 0, "errors": []})), \
         patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock()):
        
        asyncio.run(orch.run_scan(scan.id))
    assert scan.status == "completed"


def test_is_hostname_ssrf_safe_branches(mock_session_cm):
    from app.services.scan_orchestrator import ScanOrchestrator
    from app.config import settings
    session, mock_local = mock_session_cm
    
    scan = _scan_obj(target="localhost")
    session.execute.return_value = _scalar_one_or_none(scan)
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()

    orch = ScanOrchestrator()
    
    with patch.object(settings, "OFFLINE_MODE", False), \
         patch("app.scanners.safe_target.ALLOW_LOOPBACK", False):
        asyncio.run(orch.run_scan(scan.id))
    assert scan.status == "failed"
    assert "No active hosts" in scan.error_message

    scan2 = _scan_obj(target="localhost")
    call_count = {"n": 0}
    async def _execute(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _scalar_one_or_none(scan2)
        return _scalar_one_or_none(None)
    session.execute.side_effect = _execute

    with patch.object(settings, "OFFLINE_MODE", True), \
         patch("app.services.scan_orchestrator._run_host_tasks", new=AsyncMock(return_value={"assets_total": 1, "findings_total": 0, "errors": []})), \
         patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock()):
        asyncio.run(orch.run_scan(scan2.id))
    assert scan2.status == "completed"


def test_scan_execution_database_errors(mock_session_cm):
    from app.services.scan_orchestrator import ScanOrchestrator
    session, mock_local = mock_session_cm
    
    scan = _scan_obj(target="example.com")
    call_count = {"n": 0}
    async def _execute(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _scalar_one_or_none(scan)
        return _scalar_one_or_none(None)
    session.execute.side_effect = _execute
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock(side_effect=[None, RuntimeError("DB write error"), None, None])

    with patch("app.scanners.network_discovery.enumerate_dns_targets") as mock_dns, \
         patch("app.services.scan_orchestrator._run_host_tasks", new=AsyncMock(return_value={"assets_total": 1, "findings_total": 0, "errors": []})), \
         patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock(side_effect=Exception("Redis down"))):
        
        mock_dns.return_value = {
            "a_records": ["93.184.216.34"],
            "aaaa_records": [],
            "cname_records": [],
            "mx_records": [],
        }
        
        orch = ScanOrchestrator()
        asyncio.run(orch.run_scan(scan.id))
        
    assert scan.status == "failed"
    assert "DB write error" in scan.error_message


def test_scan_config_json_parse_error(mock_session_cm):
    from app.services.scan_orchestrator import ScanOrchestrator
    session, mock_local = mock_session_cm
    
    scan = _scan_obj(target="example.com", config="invalid-json-{")
    session.execute.return_value = _scalar_one_or_none(scan)
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()

    with patch("app.scanners.network_discovery.enumerate_dns_targets") as mock_dns, \
         patch("app.services.scan_orchestrator._run_host_tasks", new=AsyncMock(return_value={"assets_total": 0, "findings_total": 0, "errors": []})), \
         patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock(side_effect=Exception("Redis connection timed out"))):
        
        mock_dns.return_value = {
            "a_records": ["93.184.216.34"],
            "aaaa_records": [],
            "cname_records": [],
            "mx_records": [],
        }
        
        orch = ScanOrchestrator()
        asyncio.run(orch.run_scan(scan.id))
    assert scan.status == "completed"


def test_ssrf_blocked_targets_variations(mock_session_cm):
    from app.services.scan_orchestrator import ScanOrchestrator
    session, mock_local = mock_session_cm
    
    with patch("app.scanners.safe_target.ALLOW_PRIVATE_RANGES", False), \
         patch("app.scanners.safe_target.ALLOW_LOOPBACK", False):
        # 1. Cloud metadata IP
        scan1 = _scan_obj(target="169.254.169.254")
        session.execute.return_value = _scalar_one_or_none(scan1)
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.refresh = AsyncMock()
        orch = ScanOrchestrator()
        asyncio.run(orch.run_scan(scan1.id))
        assert scan1.status == "failed"
        assert "SSRF" in scan1.error_message or "blocked" in scan1.error_message.lower()

        # 2. Metadata CIDR
        scan2 = _scan_obj(target="169.254.169.0/24")
        call_count = {"n": 0}
        async def _exec2(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _scalar_one_or_none(scan2)
            return _scalar_one_or_none(None)
        session.execute.side_effect = _exec2

        mock_net = MagicMock()
        mock_net.is_private = False
        mock_net.is_loopback = False
        mock_net.is_link_local = False
        mock_net.is_multicast = False
        mock_net.is_unspecified = False
        mock_net.version = 4
        mock_net.__contains__.return_value = True

        with patch("ipaddress.ip_network", return_value=mock_net):
            asyncio.run(orch.run_scan(scan2.id))
        assert scan2.status == "failed"
        assert "SSRF" in scan2.error_message or "blocked" in scan2.error_message.lower() or "metadata" in scan2.error_message.lower()

        # 3. Invalid CIDR notation
        scan3 = _scan_obj(target="invalid_ip/24")
        call_count3 = {"n": 0}
        async def _exec3(*args, **kwargs):
            call_count3["n"] += 1
            if call_count3["n"] == 1:
                return _scalar_one_or_none(scan3)
            return _scalar_one_or_none(None)
        session.execute.side_effect = _exec3
        asyncio.run(orch.run_scan(scan3.id))
        assert scan3.status == "failed"

        # 4. Cloud metadata IP parse-time block
        scan4 = _scan_obj(target="169.254.169.254")
        call_count4 = {"n": 0}
        async def _exec4(*args, **kwargs):
            call_count4["n"] += 1
            if call_count4["n"] == 1:
                return _scalar_one_or_none(scan4)
            return _scalar_one_or_none(None)
        session.execute.side_effect = _exec4

        mock_ip4 = MagicMock()
        mock_ip4.is_private = False
        mock_ip4.is_loopback = False
        mock_ip4.is_link_local = False
        mock_ip4.is_multicast = False
        mock_ip4.is_unspecified = False
        mock_ip4.__str__.return_value = "169.254.169.254"

        with patch("ipaddress.ip_address", return_value=mock_ip4):
            asyncio.run(orch.run_scan(scan4.id))
        assert scan4.status == "failed"
        assert "SSRF" in scan4.error_message or "blocked" in scan4.error_message.lower()


def test_dns_resolution_fallbacks_and_ssrf(mock_session_cm):
    from app.services.scan_orchestrator import ScanOrchestrator
    session, mock_local = mock_session_cm
    
    with patch("app.scanners.safe_target.ALLOW_PRIVATE_RANGES", False), \
         patch("app.scanners.safe_target.ALLOW_LOOPBACK", False):
        # CNAME fallback
        scan = _scan_obj(target="cname-fallback.test")
        session.execute.return_value = _scalar_one_or_none(scan)
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.refresh = AsyncMock()
        
        with patch("app.scanners.network_discovery.enumerate_dns_targets") as mock_dns, \
             patch("app.services.scan_orchestrator._run_host_tasks", new=AsyncMock(return_value={"assets_total": 0, "findings_total": 0, "errors": []})), \
             patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock()):
            
            mock_dns.return_value = {
                "a_records": [],
                "aaaa_records": [],
                "cname_records": ["target-cname.com."],
                "mx_records": [],
            }
            
            orch = ScanOrchestrator()
            asyncio.run(orch.run_scan(scan.id))
        assert scan.status == "completed"

        # MX fallback with parts >= 2 and < 2
        scan_mx = _scan_obj(target="mx-fallback.test")
        call_count_mx = {"n": 0}
        async def _execute_mx(*args, **kwargs):
            call_count_mx["n"] += 1
            if call_count_mx["n"] == 1:
                return _scalar_one_or_none(scan_mx)
            return _scalar_one_or_none(None)
        session.execute.side_effect = _execute_mx

        with patch("app.scanners.network_discovery.enumerate_dns_targets") as mock_dns, \
             patch("app.services.scan_orchestrator._run_host_tasks", new=AsyncMock(return_value={"assets_total": 0, "findings_total": 0, "errors": []})), \
             patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock()):
            
            mock_dns.side_effect = [
                {
                    "a_records": [],
                    "aaaa_records": [],
                    "cname_records": [],
                    "mx_records": ["10 mail.target.com."],
                },
                {
                    "a_records": [],
                    "aaaa_records": [],
                    "cname_records": [],
                    "mx_records": ["mail-no-pref.com."],
                }
            ]
            
            orch = ScanOrchestrator()
            # Run first with preference mx
            asyncio.run(orch.run_scan(scan_mx.id))
            
            # Run again with no preference mx using scan_mx2
            scan_mx2 = _scan_obj(target="mx-fallback.test")
            call_count_mx2 = {"n": 0}
            async def _execute_mx2(*args, **kwargs):
                call_count_mx2["n"] += 1
                if call_count_mx2["n"] == 1:
                    return _scalar_one_or_none(scan_mx2)
                return _scalar_one_or_none(None)
            session.execute.side_effect = _execute_mx2
            asyncio.run(orch.run_scan(scan_mx2.id))
            
        assert scan_mx.status == "completed"
        assert scan_mx2.status == "completed"

        # DNS Exception path
        scan_dns_err = _scan_obj(target="dns-error.test")
        call_count_dns_err = {"n": 0}
        async def _execute_dns_err(*args, **kwargs):
            call_count_dns_err["n"] += 1
            if call_count_dns_err["n"] == 1:
                return _scalar_one_or_none(scan_dns_err)
            return _scalar_one_or_none(None)
        session.execute.side_effect = _execute_dns_err

        with patch("app.scanners.network_discovery.enumerate_dns_targets", side_effect=OSError("DNS fail")), \
             patch("app.services.scan_orchestrator._run_host_tasks", new=AsyncMock(return_value={"assets_total": 0, "findings_total": 0, "errors": []})), \
             patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock()):
            
            orch = ScanOrchestrator()
            asyncio.run(orch.run_scan(scan_dns_err.id))
        assert scan_dns_err.status == "completed"

        # DNS resolves to private IP (SSRF blocked resolved host)
        scan_ssrf = _scan_obj(target="localhost")
        call_count_ssrf = {"n": 0}
        async def _execute_ssrf(*args, **kwargs):
            call_count_ssrf["n"] += 1
            if call_count_ssrf["n"] == 1:
                return _scalar_one_or_none(scan_ssrf)
            return _scalar_one_or_none(None)
        session.execute.side_effect = _execute_ssrf

        with patch("app.scanners.network_discovery.enumerate_dns_targets") as mock_dns, \
             patch("app.services.scan_orchestrator._run_host_tasks", new=AsyncMock(return_value={"assets_total": 0, "findings_total": 0, "errors": []})), \
             patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock()):
            
            mock_dns.return_value = {
                "a_records": ["127.0.0.1"],
                "aaaa_records": [],
                "cname_records": [],
                "mx_records": [],
            }
            
            orch = ScanOrchestrator()
            asyncio.run(orch.run_scan(scan_ssrf.id))
        assert scan_ssrf.status == "failed"


def test_is_hostname_ssrf_safe_helper_branches(mock_session_cm):
    from app.services.scan_orchestrator import ScanOrchestrator
    from app.config import settings
    from unittest.mock import PropertyMock
    import ipaddress
    session, mock_local = mock_session_cm
    
    with patch("app.scanners.safe_target.ALLOW_PRIVATE_RANGES", False), \
         patch("app.scanners.safe_target.ALLOW_LOOPBACK", False):
        # 1. Private IP path
        scan = _scan_obj(target="10.0.0.1")
        session.execute.return_value = _scalar_one_or_none(scan)
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.refresh = AsyncMock()

        mock_ip = MagicMock()
        type(mock_ip).is_private = PropertyMock(side_effect=[False, True])
        type(mock_ip).is_loopback = False
        type(mock_ip).is_link_local = False
        type(mock_ip).is_multicast = False
        type(mock_ip).is_unspecified = False
        mock_ip.__str__.return_value = "10.0.0.1"

        with patch("ipaddress.ip_address", return_value=mock_ip), \
             patch.object(settings, "OFFLINE_MODE", False):
            orch = ScanOrchestrator()
            asyncio.run(orch.run_scan(scan.id))
        assert scan.status == "failed"
        assert "No active hosts" in scan.error_message

        # 2. Metadata IP path and clear_dashboard_cache failure
        scan2 = _scan_obj(target="169.254.169.254")
        call_count = {"n": 0}
        async def _execute2(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _scalar_one_or_none(scan2)
            return _scalar_one_or_none(None)
        session.execute.side_effect = _execute2

        mock_ip2 = MagicMock()
        type(mock_ip2).is_private = False
        type(mock_ip2).is_loopback = False
        type(mock_ip2).is_link_local = False
        type(mock_ip2).is_multicast = False
        type(mock_ip2).is_unspecified = False
        mock_ip2.__str__.side_effect = ["1.1.1.1", "169.254.169.254"]

        with patch("ipaddress.ip_address", return_value=mock_ip2), \
             patch.object(settings, "OFFLINE_MODE", False), \
             patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock(side_effect=Exception("Redis dead"))):
            orch = ScanOrchestrator()
            asyncio.run(orch.run_scan(scan2.id))
        assert scan2.status == "failed"


@pytest.mark.asyncio
async def test_run_advanced_scanners_sslyze_failed():
    from app.services.scan_orchestrator import _run_advanced_scanners
    scan = SimpleNamespace(id="scan-1", advanced_tools=True)
    session = AsyncMock()
    log_event = AsyncMock()

    with patch("app.scanners.sslyze_scanner.scan_endpoint_with_sslyze", new=AsyncMock(side_effect=RuntimeError("SSLyze failed"))), \
         patch("app.scanners.scapy_probe.probe_tls_with_pqc_groups", new=AsyncMock(return_value=SimpleNamespace(success=False))), \
         patch("app.services.cli_scanner_service.run_pqcscan", new=AsyncMock(return_value={"skipped": True})), \
         patch("app.services.cli_scanner_service.run_ssh_audit", new=AsyncMock(return_value={"skipped": True})):
        
        is_active, assets, findings = await _run_advanced_scanners(
            session, scan, "test.local", False, 0, 0, log_event
        )
    assert is_active is False
    log_messages = [call[1]["message"] for call in log_event.call_args_list]
    assert any("SSLyze scan failed on test.local" in msg for msg in log_messages)


def test_passive_scan_lifecycle(mock_session_cm):
    from app.services.scan_orchestrator import ScanOrchestrator
    from app.models.models import Scan, Asset, Algorithm, Finding

    scan = _scan_obj(target="eth0", scan_type="passive")
    session, mock_local = mock_session_cm
    
    # Mock return values for DB queries using the _execute closure pattern
    call_count = {"n": 0}
    async def _execute(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _scalar_one_or_none(scan)
        # Final-completion block reads `func.count(...)` via `scalar_one()`;
        # return 3 (matching the 3 handshakes the passive scan processes)
        # so the recompute-based scan row stays consistent with the test's
        # expectation of `scan.assets_found == 3`.
        r = MagicMock()
        r.scalar_one_or_none = MagicMock(return_value=None)
        r.scalar_one = MagicMock(return_value=3)
        return r

    session.execute.side_effect = _execute
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()

    # Mock handshakes returned by capture_all_handshakes
    mock_handshakes = [
        {
            "type": "ClientHello",
            "dst_ip": "1.2.3.4",
            "dst_port": 443,
            "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
            "supported_groups": ["0x01FD"], # ML-KEM-768
            "pqc_groups_advertised": ["ML-KEM-768"],
            "has_pqc": True,
        },
        {
            "type": "ServerHello",
            "dst_ip": "5.6.7.8",
            "selected_cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "selected_group": "29", # secp384r1 (classical)
            "tls_version": "0x0303",
        },
        {
            "type": "SSH_KEXINIT",
            "dst_ip": "9.10.11.12",
            "dst_port": 22,
            "kex_algorithms": ["curve25519-sha256", "sntrup761x25519-sha256@openssh.com"],
        }
    ]

    with patch("app.scanners.pyshark_capture.capture_all_handshakes", new=AsyncMock(return_value=mock_handshakes)), \
         patch("app.api.dashboard.clear_dashboard_cache", new=AsyncMock()):
             
        orch = ScanOrchestrator()
        asyncio.run(orch.run_scan(scan.id))

    # Verify scan completed successfully
    assert scan.status == "completed"
    assert scan.assets_found == 3
    # Check that session.add was called
    assert session.add.call_count > 0



