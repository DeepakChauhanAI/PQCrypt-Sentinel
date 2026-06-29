"""Tests for SSH scanner PQC KEX detection and MAC algorithm capture."""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from paramiko.message import Message

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.scanners.ssh_scanner import (
    PQC_KEX_ALGORITHMS,
    SSHScanResult,
    scan_ssh_endpoint,
    _build_kexinit_payload,
    _wrap_ssh_packet,
)


def _build_server_kexinit_payload(
    kex_algorithms=None,
    host_key_algorithms=None,
    encryption_algorithms=None,
    mac_algorithms=None,
):
    m = Message()
    m.add_byte(b"\x14")  # SSH_MSG_KEXINIT
    m.add_bytes(b"\x00" * 16)
    m.add_list(kex_algorithms or [])
    m.add_list(host_key_algorithms or [])
    m.add_list(encryption_algorithms or [])
    m.add_list(encryption_algorithms or [])
    m.add_list(mac_algorithms or [])
    m.add_list(mac_algorithms or [])
    m.add_list([])
    m.add_list([])
    m.add_list([])
    m.add_list([])
    m.add_boolean(False)
    m.add_int(0)
    return m.asbytes()


def test_pqc_kex_constants_includes_mlkem_and_sntrup():
    """The PQC KEX list must include both ML-KEM and sntrup761 hybrid algorithms."""
    joined = " ".join(PQC_KEX_ALGORITHMS).lower()
    assert "mlkem" in joined
    assert "sntrup" in joined
    assert "kyber" in joined


def test_ssh_result_includes_mac_algorithms():
    """SSHScanResult must surface captured MAC algorithms (Phase 1.10)."""
    r = SSHScanResult(
        host="example.com",
        port=22,
        success=True,
        mac_algorithms=["hmac-sha2-512", "hmac-sha2-256"],
    )
    assert r.mac_algorithms == ["hmac-sha2-512", "hmac-sha2-256"]


class _FakeSocket:
    """In-memory socket that replays a preloaded server transcript."""

    def __init__(self, transcript: bytes):
        self._buf = transcript
        self.sent = bytearray()

    def recv(self, n):
        if not self._buf:
            return b""
        chunk = self._buf[:n]
        self._buf = self._buf[n:]
        return bytes(chunk)

    def sendall(self, data):
        self.sent += data

    def settimeout(self, _t):
        pass

    def close(self):
        pass


def test_do_ssh_connect_detects_pqc_kex_from_server_kexinit():
    """Scanner must read the server's KEXINIT and flag PQC algorithms."""
    from app.scanners import ssh_scanner

    server_payload = _build_server_kexinit_payload(
        kex_algorithms=[
            "mlkem768x25519-sha512@openssh.com",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
        ],
        host_key_algorithms=["ssh-ed25519", "rsa-sha2-512"],
        encryption_algorithms=["aes256-gcm@openssh.com", "aes128-ctr"],
        mac_algorithms=["hmac-sha2-512", "hmac-sha2-256"],
    )
    server_packet = _wrap_ssh_packet(server_payload)
    transcript = b"SSH-2.0-OpenSSH_9.0\r\n" + server_packet

    fake = _FakeSocket(transcript)
    fake_sock_pair = MagicMock()
    fake_sock_pair.__enter__ = MagicMock(return_value=fake)
    fake_sock_pair.__exit__ = MagicMock(return_value=False)

    with patch.object(ssh_scanner.socket, "create_connection", return_value=fake):
        result = ssh_scanner._do_ssh_connect("example.com", 22, 5)

    assert result["success"] is True
    assert result["pqc_kex_available"] is True
    assert "mlkem768x25519-sha512@openssh.com" in result["pqc_kex_algorithms"]
    assert result["pqc_status"] == "pqc_ready"
    assert result["kex_algorithms"] == [
        "mlkem768x25519-sha512@openssh.com",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
    ]
    assert "ssh-ed25519" in result["host_key_algorithms"]
    assert "aes256-gcm@openssh.com" in result["encryption_algorithms"]
    assert "hmac-sha2-512" in result["mac_algorithms"]

    # We should have sent our own banner and a framed KEXINIT packet.
    sent = bytes(fake.sent)
    assert sent.startswith(b"SSH-2.0-PQCScanner\r\n")
    assert sent[len(b"SSH-2.0-PQCScanner\r\n") + 5 :]  # 5-byte packet header follows


def test_do_ssh_connect_reports_vulnerable_when_no_pqc_in_server_kexinit():
    from app.scanners import ssh_scanner

    server_payload = _build_server_kexinit_payload(
        kex_algorithms=["curve25519-sha256@libssh.org", "ecdh-sha2-nistp256"],
        host_key_algorithms=["ssh-ed25519"],
        encryption_algorithms=["aes256-gcm@openssh.com"],
        mac_algorithms=["hmac-sha2-512"],
    )
    transcript = b"SSH-2.0-OpenSSH_8.0\r\n" + _wrap_ssh_packet(server_payload)
    fake = _FakeSocket(transcript)

    with patch.object(ssh_scanner.socket, "create_connection", return_value=fake):
        result = ssh_scanner._do_ssh_connect("scanme.nmap.org", 22, 5)

    assert result["success"] is True
    assert result["pqc_kex_available"] is False
    assert result["pqc_kex_algorithms"] == []
    assert result["pqc_status"] == "vulnerable"


def test_do_ssh_connect_returns_failure_on_error():
    """On exception, the result dict must be a failure with error_message."""
    from app.scanners import ssh_scanner

    with patch.object(
        ssh_scanner.socket, "create_connection", side_effect=OSError("refused")
    ):
        result = ssh_scanner._do_ssh_connect("nope.example.com", 22, 2)

    assert result["success"] is False
    assert "refused" in result["error_message"]


def test_build_kexinit_payload_starts_with_msg_20():
    payload = _build_kexinit_payload()
    assert payload[0] == 20
    # First 1 + 16 bytes = msg type + cookie; rest is the algorithm lists.
    assert len(payload) > 17
