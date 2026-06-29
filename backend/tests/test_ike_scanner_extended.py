import pytest
import socket
from unittest.mock import patch, MagicMock
from app.scanners.ike_scanner import (
    _do_socket_ike_probe,
    _do_ike_probe,
    _parse_ikev2_response,
    IKEScanResult,
    scan_ike_endpoint,
)
import asyncio


class TestDoSocketIKEProbe:
    def test_timeout(self):
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.recvfrom.side_effect = socket.timeout("timed out")
            mock_sock_cls.return_value = mock_sock
            result = _do_socket_ike_probe("10.0.0.1", 500, 5)
        assert result["success"] is False
        assert "timeout" in result["error_message"].lower()

    def test_generic_exception(self):
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.recvfrom.side_effect = OSError("network unreachable")
            mock_sock_cls.return_value = mock_sock
            result = _do_socket_ike_probe("10.0.0.1", 500, 5)
        assert result["success"] is False
        assert "network unreachable" in result["error_message"]

    def test_short_response(self):
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.recvfrom.return_value = (b"\x00" * 10, ("10.0.0.1", 500))
            mock_sock_cls.return_value = mock_sock
            result = _do_socket_ike_probe("10.0.0.1", 500, 5)
        assert result["success"] is False
        assert "too short" in result["error_message"].lower()

    def test_valid_response(self):
        # Build a valid IKEv2 SA response with DH group 19
        sa_body = (
            b"\x00\x00\x00\x08\x04\x00\x00\x13"  # DH group 19
        )
        payload = (
            b"\x00\x00"          # next_payload=0, critical=0
            + (4 + len(sa_body)).to_bytes(2, "big")  # length
            + sa_body
        )
        total_len = 28 + len(payload)
        data = (
            b"\x3f\x5a\x2b\x1c\x0d\x9e\x8f\x7a"  # ISPI
            + b"\x00" * 8                            # RSPI
            + bytes([33, 0x20, 34, 0x08])           # next=SA, version, exch, flags
            + b"\x00\x00\x00\x00"                   # msg_id
            + total_len.to_bytes(4, "big")
            + payload
        )

        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.recvfrom.return_value = (data, ("10.0.0.1", 500))
            mock_sock_cls.return_value = mock_sock
            result = _do_socket_ike_probe("10.0.0.1", 500, 5)
        assert result["success"] is True
        assert result["ike_version"] == "IKEv2"
        assert len(result["dh_groups"]) > 0


class TestDoIKEProbe:
    def test_socket_probe_succeeds(self):
        fake = {"success": True, "ike_version": "IKEv2", "dh_groups": ["ML-KEM-768"], "pqc_status": "pqc_ready"}
        with patch("app.scanners.ike_scanner._do_socket_ike_probe", return_value=fake):
            result = _do_ike_probe("10.0.0.1", 500, 5)
        assert result["success"] is True

    def test_socket_fails_ike_scan_not_found(self):
        fake = {"success": False, "error_message": "timeout"}
        with patch("app.scanners.ike_scanner._do_socket_ike_probe", return_value=fake), \
             patch("shutil.which", return_value=None):
            result = _do_ike_probe("10.0.0.1", 500, 5)
        assert result["success"] is False
        assert "timeout" in result["error_message"]

    def test_ike_scan_binary_timeout(self):
        import subprocess
        fake = {"success": False, "error_message": "timeout"}
        with patch("app.scanners.ike_scanner._do_socket_ike_probe", return_value=fake), \
             patch("shutil.which", return_value="/usr/bin/ike-scan"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ike-scan", 5)):
            result = _do_ike_probe("10.0.0.1", 500, 5)
        assert result["success"] is False
        assert "timeout" in result["error_message"].lower()

    def test_ike_scan_binary_os_error(self):
        fake = {"success": False, "error_message": "timeout"}
        with patch("app.scanners.ike_scanner._do_socket_ike_probe", return_value=fake), \
             patch("shutil.which", return_value="/usr/bin/ike-scan"), \
             patch("subprocess.run", side_effect=OSError("permission denied")):
            result = _do_ike_probe("10.0.0.1", 500, 5)
        assert result["success"] is False

    def test_ike_scan_binary_nonzero_exit(self):
        fake = {"success": False, "error_message": "timeout"}
        completed = MagicMock()
        completed.returncode = 1
        completed.stdout = b""
        completed.stderr = b"error output"
        with patch("app.scanners.ike_scanner._do_socket_ike_probe", return_value=fake), \
             patch("shutil.which", return_value="/usr/bin/ike-scan"), \
             patch("subprocess.run", return_value=completed):
            result = _do_ike_probe("10.0.0.1", 500, 5)
        assert result["success"] is False
        assert "ike-scan failed" in result["error_message"]

    def test_ike_scan_binary_success_with_groups(self):
        fake = {"success": False, "error_message": "timeout"}
        completed = MagicMock()
        completed.returncode = 0
        completed.stdout = b"Encryption algorithm: AES-CBC-256\nHash algorithm: SHA-256\nOakley group 14 [14]\n"
        completed.stderr = b""
        with patch("app.scanners.ike_scanner._do_socket_ike_probe", return_value=fake), \
             patch("shutil.which", return_value="/usr/bin/ike-scan"), \
             patch("subprocess.run", return_value=completed):
            result = _do_ike_probe("10.0.0.1", 500, 5)
        assert result["success"] is True
        assert "AES-CBC-256" in result["encryption_algorithms"]
        assert "SHA-256" in result["integrity_algorithms"]
        assert len(result["dh_groups"]) > 0

    def test_ike_scan_binary_with_pqc_group(self):
        fake = {"success": False, "error_message": "timeout"}
        completed = MagicMock()
        completed.returncode = 0
        completed.stdout = b"Oakley group 38 [38]\n"
        completed.stderr = b""
        with patch("app.scanners.ike_scanner._do_socket_ike_probe", return_value=fake), \
             patch("shutil.which", return_value="/usr/bin/ike-scan"), \
             patch("subprocess.run", return_value=completed):
            result = _do_ike_probe("10.0.0.1", 500, 5)
        assert result["success"] is True
        assert result["pqc_status"] == "pqc_ready"

    def test_ike_scan_binary_no_groups(self):
        fake = {"success": False, "error_message": "timeout"}
        completed = MagicMock()
        completed.returncode = 0
        completed.stdout = b"Starting ike-scan\n"
        completed.stderr = b""
        with patch("app.scanners.ike_scanner._do_socket_ike_probe", return_value=fake), \
             patch("shutil.which", return_value="/usr/bin/ike-scan"), \
             patch("subprocess.run", return_value=completed):
            result = _do_ike_probe("10.0.0.1", 500, 5)
        assert result["success"] is True
        assert result["pqc_status"] == "unknown"

    def test_import_subprocess_error(self):
        fake = {"success": False, "error_message": "timeout"}
        with patch("app.scanners.ike_scanner._do_socket_ike_probe", return_value=fake), \
             patch("shutil.which", return_value="/usr/bin/ike-scan"), \
             patch("builtins.__import__", side_effect=ImportError("no subprocess")):
            result = _do_ike_probe("10.0.0.1", 500, 5)
        assert result["success"] is False
        assert result.get("skipped") is True


class TestScanIKEEndpointExtended:
    def test_skipped_result(self):
        fake = {"success": True, "skipped": True, "ike_version": "IKEv2", "pqc_status": "unknown"}
        with patch("app.scanners.ike_scanner._do_ike_probe", return_value=fake):
            result = asyncio.run(scan_ike_endpoint("10.0.0.1", port=500, timeout=2))
        assert result.success is True
        assert result.pqc_status == "unknown"

    def test_response_too_short(self):
        fake = {"success": True, "response_len": 5}
        with patch("app.scanners.ike_scanner._do_ike_probe", return_value=fake):
            result = asyncio.run(scan_ike_endpoint("10.0.0.1"))
        assert result.success is False
