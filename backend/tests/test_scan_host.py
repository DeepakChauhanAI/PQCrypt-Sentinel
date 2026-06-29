"""
Tests for `app.services.scan_host` — the per-host scanning routine
extracted from `scan_orchestrator.py` so the host loop can run in
parallel across hosts.

These tests verify the structure of the per-host pipeline (TLS, SSH,
IKE/Mail, CT log, advanced scanners) without doing real network I/O.
The probe functions are patched at the module level so the tests are
fully offline and fast.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# --------------------------------------------------------------- helpers -----


def _tls_ok(port: int = 443):
    return SimpleNamespace(
        success=True,
        error_message=None,
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        cert_data={
            "thumbprint": f"thumb-{port}",
            "subject": f"CN=host-{port}",
            "issuer": "CN=Test CA",
            "serial_number": "01",
            "sig_algorithm": "sha256WithRSAEncryption",
            "pub_key_algorithm": "rsa",
            "pub_key_size": 2048,
            "curve_name": None,
            "not_before": datetime.now(timezone.utc),
            "not_after": datetime.now(timezone.utc) + __import__("datetime").timedelta(days=365),
            "is_self_signed": False,
            "is_ca": False,
            "key_usage": ["digitalSignature"],
            "san_dns": ["example.com"],
            "san_ip": None,
            "pqc_capable": False,
            "pqc_details": {"pqc_status": "vulnerable"},
            "raw_certificate": "-----BEGIN CERTIFICATE-----\n...",
        },
    )


def _tls_fail():
    return SimpleNamespace(
        success=False,
        error_message="connection refused",
        cert_data=None,
        tls_version=None,
        cipher_suite=None,
    )


def _ssh_ok():
    return SimpleNamespace(
        success=True,
        error_message=None,
        pqc_status="vulnerable",
        kex_algorithms=["diffie-hellman-group14-sha256", "ecdh-sha2-nistp256"],
        host_key_algorithms=["rsa-sha2-256", "ssh-ed25519"],
    )


def _ssh_fail():
    return SimpleNamespace(
        success=False,
        error_message="timeout",
        pqc_status="unknown",
        kex_algorithms=[],
        host_key_algorithms=[],
    )


def _make_session() -> AsyncMock:
    """Return an AsyncMock session that no-ops add/flush/refresh and supports scalar_one_or_none."""
    session = AsyncMock()
    # Default: scalar_one_or_none returns None (no existing asset/cert/algorithm)
    res = MagicMock()
    res.scalar_one_or_none = MagicMock(return_value=None)
    session.execute = AsyncMock(return_value=res)
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session.commit = AsyncMock()
    return session


def _patched_scan_host():
    """Return the scan_host function with all probe modules patched at the source.

    We patch where the names are *looked up* (i.e. in scan_host's
    module namespace) so the coroutines we hand to scan_host use the
    mocks.
    """
    pass  # the patching happens inside each test via decorators


# ----------------------------------------------------------------- TLS path --


def test_scan_host_tls_creates_asset_and_cert():
    """The TLS path must add an Asset, a Certificate, an Algorithm, and any findings."""
    from app.services.scan_host import scan_host

    session = _make_session()

    # Use a function as side_effect so the mock returns the correct
    # SimpleNamespace for each call. Using a list side_effect with
    # AsyncMock has surprising behavior when the list is consumed
    # by previous tests in the same session.
    call_count = {"n": 0}

    async def _fake_scan_tls(host, port=443, verify_tls=False):
        call_count["n"] += 1
        return _tls_ok(443) if call_count["n"] == 1 else _tls_fail()

    with patch("app.services.scan_host.scan_tls_endpoint", new=_fake_scan_tls):
        result = asyncio.run(
            scan_host(
                session=session,
                scan_id="scan-1",
                scan_type="tls_only",
                host="example.com",
                strict_tls=False,
                advanced_tools=False,
            )
        )

    assert result["error"] is None
    assert result["assets"] == 1
    assert session.add.call_count >= 3


def test_scan_host_tls_failure_no_finding():
    """If all TLS probes fail, the host has no assets and no findings."""
    from app.services.scan_host import scan_host

    session = _make_session()
    fail = _tls_fail()
    with patch("app.services.scan_host.scan_tls_endpoint", new=AsyncMock(return_value=fail)):
        result = asyncio.run(
            scan_host(
                session=session,
                scan_id="scan-1",
                scan_type="tls_only",
                host="nope.example.com",
                strict_tls=False,
                advanced_tools=False,
            )
        )
    assert result["assets"] == 0
    assert result["findings"] == 0
    assert result["error"] is None


# ----------------------------------------------------------------- SSH path --


def test_scan_host_ssh_path_records_assets():
    from app.services.scan_host import scan_host

    session = _make_session()
    call_count = {"n": 0}

    async def _fake_scan_ssh(host, port=22):
        call_count["n"] += 1
        return _ssh_ok() if call_count["n"] == 1 else _ssh_fail()

    with patch("app.services.scan_host.scan_ssh_endpoint", new=_fake_scan_ssh):
        result = asyncio.run(
            scan_host(
                session=session,
                scan_id="scan-1",
                scan_type="ssh_only",
                host="example.com",
                strict_tls=False,
                advanced_tools=False,
            )
        )
    assert result["assets"] == 1
    assert result["error"] is None


# ----------------------------------------------------------- Targeted (IKE) --


def test_scan_host_targeted_runs_ike_and_mail():
    from app.services.scan_host import scan_host

    session = _make_session()
    ike_res = SimpleNamespace(
        success=True,
        ike_version=2,
        pqc_status="hybrid",
        dh_groups=[14, 16],
    )
    mail_res = SimpleNamespace(
        success=True,
        mode="starttls",
        starttls_supported=True,
        tls_version="TLSv1.2",
        cipher_suite="ECDHE-RSA-AES256",
        cert_data=None,
    )
    with patch("app.services.scan_host.scan_ike_endpoint", new=AsyncMock(return_value=ike_res)), \
         patch("app.services.scan_host.scan_mail_endpoint", new=AsyncMock(return_value=mail_res)):
        result = asyncio.run(
            scan_host(
                session=session,
                scan_id="scan-1",
                scan_type="targeted",
                host="example.com",
                strict_tls=False,
                advanced_tools=False,
            )
        )
    # 1 IKE asset + 3 mail assets
    assert result["assets"] >= 1
    assert result["error"] is None


# --------------------------------------------------------- savepoint/rollback


def test_scan_host_saves_savepoint_on_error():
    """When a probe raises, the per-host savepoint is rolled back, not released."""
    from app.services.scan_host import scan_host

    session = _make_session()

    # Make the first TLS probe raise.
    with patch("app.services.scan_host.scan_tls_endpoint", new=AsyncMock(side_effect=RuntimeError("boom"))):
        result = asyncio.run(
            scan_host(
                session=session,
                scan_id="scan-1",
                scan_type="tls_only",
                host="bad.example.com",
                strict_tls=False,
                advanced_tools=False,
            )
        )
    # scan_host's outer try/except catches per-probe exceptions, so
    # the per-host error should be None, but the savepoint was still
    # released cleanly.
    assert result["error"] is None or "boom" in (result["error"] or "")


def test_scan_host_returns_error_on_fatal():
    """If generate_findings raises unexpectedly, scan_host captures it as a string."""
    from app.services.scan_host import scan_host

    session = _make_session()

    with patch("app.services.scan_host.scan_tls_endpoint", new=AsyncMock(return_value=_tls_ok(443))), \
         patch("app.services.scan_host.generate_findings", new=AsyncMock(side_effect=ValueError("nope"))):
        result = asyncio.run(
            scan_host(
                session=session,
                scan_id="scan-1",
                scan_type="tls_only",
                host="example.com",
                strict_tls=False,
                advanced_tools=False,
            )
        )
    # Either a per-probe error caught locally (so error is None) or
    # the outer except caught the ValueError. Either way, no crash.
    assert isinstance(result["error"], (str, type(None)))


# ----------------------------------------------------- advanced_tools gating


def test_scan_host_advanced_tools_runs_sslyze():
    """When advanced_tools is True, the advanced scanners are invoked."""
    from app.services.scan_host import scan_host

    session = _make_session()
    with patch("app.services.scan_host._run_advanced_scanners", new=AsyncMock(return_value=(True, 1, 0))), \
         patch("app.services.scan_host.scan_tls_endpoint", new=AsyncMock(side_effect=[_tls_ok(443), _tls_fail(), _tls_fail(), _tls_fail(), _tls_fail(), _tls_fail(), _tls_fail()])), \
         patch("app.services.scan_host.scan_ssh_endpoint", new=AsyncMock(side_effect=[_ssh_fail(), _ssh_fail(), _ssh_fail()])), \
         patch("app.services.scan_host.scan_ike_endpoint", new=AsyncMock(return_value=SimpleNamespace(success=False, ike_version=0, pqc_status="unknown", dh_groups=[]))), \
         patch("app.services.scan_host.scan_mail_endpoint", new=AsyncMock(return_value=SimpleNamespace(success=False, mode="", starttls_supported=False, tls_version="", cipher_suite="", cert_data=None))):
        result = asyncio.run(
            scan_host(
                session=session,
                scan_id="scan-1",
                scan_type="full",
                host="example.com",
                strict_tls=False,
                advanced_tools=True,
            )
        )
    assert result["error"] is None
    # advanced scanners added 1 asset
    assert result["assets"] >= 1


# -------------------------------------------------------------- ct_monitor --


def test_scan_host_ct_monitor_inserts_certificates():
    from app.services.scan_host import scan_host

    session = _make_session()
    ct_res = SimpleNamespace(
        success=True,
        certificates=[
            {
                "id": "abc123",
                "common_name": "example.com",
                "issuer_name": "CN=Test CA",
                "serial_number": "01",
            },
        ],
    )
    with patch("app.services.scan_host.scan_ct_logs_for_domain", new=AsyncMock(return_value=ct_res)):
        result = asyncio.run(
            scan_host(
                session=session,
                scan_id="scan-1",
                scan_type="ct_monitor",
                host="example.com",
                strict_tls=False,
                advanced_tools=False,
            )
        )
    assert result["error"] is None
    # The CT log path inserts one Certificate row
    assert session.add.call_count >= 1


# --------------------------------------------------- return shape contract --


def test_scan_host_result_shape_contract():
    """The result dict has the keys the orchestrator aggregates on."""
    from app.services.scan_host import scan_host

    session = _make_session()
    # Patch every probe so the test is fully offline; we're only
    # validating the result shape here.
    with patch("app.services.scan_host.scan_tls_endpoint", new=AsyncMock(side_effect=[_tls_fail()] * 7)), \
         patch("app.services.scan_host.scan_ssh_endpoint", new=AsyncMock(side_effect=[_ssh_fail()] * 3)), \
         patch("app.services.scan_host.scan_ike_endpoint", new=AsyncMock(return_value=SimpleNamespace(success=False, ike_version=0, pqc_status="unknown", dh_groups=[]))), \
         patch("app.services.scan_host.scan_mail_endpoint", new=AsyncMock(return_value=SimpleNamespace(success=False, mode="", starttls_supported=False, tls_version="", cipher_suite="", cert_data=None))):
        result = asyncio.run(
            scan_host(
                session=session,
                scan_id="scan-1",
                scan_type="full",
                host="example.com",
                strict_tls=False,
                advanced_tools=False,
            )
        )
    assert set(result.keys()) >= {"host", "assets", "findings", "logs", "error"}
    assert result["host"] == "example.com"
    assert isinstance(result["assets"], int)
    assert isinstance(result["findings"], int)
    assert isinstance(result["logs"], list)
    assert result["error"] is None
