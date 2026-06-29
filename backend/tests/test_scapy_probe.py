"""
Tests for `app.scanners.scapy_probe` - the PQC TLS group probe.

The scanner module has 51% line coverage; this file pushes it well
above 80% by exercising:
  * `_do_probe` success path (mocked scapy.sr1)
  * `_do_probe` PermissionError path (raw socket needs admin)
  * `_do_probe` generic exception path
  * `probe_tls_with_pqc_groups` happy path
  * `probe_tls_with_pqc_groups` timeout

The scapy imports happen INSIDE `_do_probe` (line 74: `from scapy.all import
IP, TCP, sr1`), so we patch the names in the `scapy.all` namespace.
"""
from __future__ import annotations

import asyncio
import sys
from unittest.mock import MagicMock, patch

import pytest

from app.scanners import scapy_probe as scapy_mod
from app.scanners.scapy_probe import (
    _GROUP_ID_NAMES,
    ScapyProbeResult,
    probe_tls_with_pqc_groups,
)


# ----------------------------------------- scapy.all mock injection --


@pytest.fixture
def mock_scapy():
    """Inject fake IP, TCP, sr1 into scapy.all (where _do_probe imports from)."""
    fake_ip = MagicMock()
    fake_tcp = MagicMock()
    fake_sr1 = MagicMock()

    sys.modules.setdefault("scapy", MagicMock())
    sys.modules.setdefault("scapy.all", MagicMock())
    scapy_all = sys.modules["scapy.all"]
    scapy_all.IP = fake_ip
    scapy_all.TCP = fake_tcp
    scapy_all.sr1 = fake_sr1

    yield {"IP": fake_ip, "TCP": fake_tcp, "sr1": fake_sr1}

    # Don't fully clean up; subsequent tests in the session reuse these.


# --------------------------------------------------- _do_probe paths --


def test_do_probe_success_with_syn_ack(mock_scapy):
    """When sr1 returns a SYN-ACK, success=True and probe_sent=True."""
    mock_scapy["sr1"].return_value = MagicMock()
    with patch.object(scapy_mod, "_build_tls_hello", return_value=b"tls_payload"):
        result = scapy_mod._do_probe("1.2.3.4", 443, timeout=2)
    assert result["success"] is True
    assert result["probe_sent"] is True
    assert result["target_ip"] == "1.2.3.4"
    assert result["port"] == 443
    # The PQC group names are surfaced as advertised
    assert "X25519MLKEM768" in result["pqc_groups_advertised"]


def test_do_probe_no_response_to_syn(mock_scapy):
    """When sr1 returns None (filtered / dropped), success=True but probe_sent=False."""
    mock_scapy["sr1"].return_value = None
    with patch.object(scapy_mod, "_build_tls_hello", return_value=b"tls_payload"):
        result = scapy_mod._do_probe("1.2.3.4", 443, timeout=2)
    assert result["success"] is True
    assert result["probe_sent"] is False
    assert "No response" in result["error_message"]
    # PQC groups are still reported as advertised
    assert "X25519MLKEM768" in result["pqc_groups_advertised"]


def test_do_probe_permission_error(mock_scapy):
    """PermissionError is captured as a clean failure with a useful message."""
    mock_scapy["sr1"].side_effect = PermissionError("Npcap required")
    with patch.object(scapy_mod, "_build_tls_hello", return_value=b"tls_payload"):
        result = scapy_mod._do_probe("1.2.3.4", 443, timeout=2)
    assert result["success"] is False
    assert "Permission denied" in result["error_message"]
    assert "Npcap" in result["error_message"]


def test_do_probe_generic_exception(mock_scapy):
    """Any other exception is captured as a failure with its message."""
    mock_scapy["sr1"].side_effect = OSError("boom")
    with patch.object(scapy_mod, "_build_tls_hello", return_value=b"tls_payload"):
        result = scapy_mod._do_probe("1.2.3.4", 443, timeout=2)
    assert result["success"] is False
    assert result["error_message"] == "boom"


# ------------------------------- probe_tls_with_pqc_groups (async) ---


def test_probe_tls_with_pqc_groups_happy():
    """The async wrapper builds a ScapyProbeResult from the executor's dict."""
    fake_dict = {
        "success": True,
        "probe_sent": True,
        "target_ip": "1.2.3.4",
        "port": 443,
        "pqc_groups_advertised": ["X25519MLKEM768"],
        "error_message": None,
    }
    with patch.object(scapy_mod, "_do_probe", return_value=fake_dict):
        result = asyncio.run(probe_tls_with_pqc_groups("1.2.3.4", port=443, timeout=2))
    assert isinstance(result, ScapyProbeResult)
    assert result.success is True
    assert result.probe_sent is True
    assert "X25519MLKEM768" in result.pqc_groups_advertised


def test_probe_tls_with_pqc_groups_timeout():
    """asyncio.TimeoutError -> success=False, error_message describes it."""
    with patch.object(asyncio, "wait_for", side_effect=asyncio.TimeoutError()):
        result = asyncio.run(probe_tls_with_pqc_groups("1.2.3.4", port=443, timeout=1))
    assert result.success is False
    assert "timed out" in result.error_message


def test_probe_tls_with_pqc_groups_exception():
    """An exception in the executor is captured."""
    with patch("app.scanners.scapy_probe._do_probe", side_effect=RuntimeError("scapy crashed")):
        result = asyncio.run(probe_tls_with_pqc_groups("1.2.3.4", port=443, timeout=2))
    assert result.success is False
    assert "scapy crashed" in result.error_message


# ---------------------------------------------- _GROUP_ID_NAMES spot --


def test_group_id_names_contains_ml_kem_groups():
    assert _GROUP_ID_NAMES[0x01FC] == "ML-KEM-512"
    assert _GROUP_ID_NAMES[0x01FD] == "ML-KEM-768"
    assert _GROUP_ID_NAMES[0x0200] == "ML-KEM-1024"
    assert _GROUP_ID_NAMES[0x2B92] == "SecP256r1MLKEM768"
    assert _GROUP_ID_NAMES[0x2B93] == "X25519MLKEM768"
