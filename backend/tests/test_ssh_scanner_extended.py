import pytest
import socket
import struct
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio

from app.scanners.ssh_scanner import (
    _recv_exact,
    _read_ssh_banner,
    _build_kexinit_payload,
    _wrap_ssh_packet,
    _read_ssh_packet_payload,
    _parse_server_kexinit,
    _do_ssh_connect,
    SSHScanResult,
)


class TestRecvExact:
    def test_recv_exact_success(self):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [b"hel", b"lo!"]
        result = _recv_exact(mock_sock, 6)
        assert result == b"hello!"

    def test_recv_exact_connection_closed(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        with pytest.raises(ConnectionError, match="closed"):
            _recv_exact(mock_sock, 10)


class TestReadSSHBanner:
    def test_read_banner_success(self):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [b"S", b"S", b"H", b"-", b"2", b".", b"0", b"\n"]
        banner = _read_ssh_banner(mock_sock)
        assert banner == b"SSH-2.0"

    def test_read_banner_with_preface(self):
        mock_sock = MagicMock()
        # First line: "Welcome\n", second line: "SSH-2.0-OpenSSH\n"
        mock_sock.recv.side_effect = [
            b"W", b"e", b"l", b"c", b"o", b"m", b"e", b"\n",
            b"S", b"S", b"H", b"-", b"2", b".", b"0", b"\n",
        ]
        banner = _read_ssh_banner(mock_sock)
        assert banner == b"SSH-2.0"

    def test_read_banner_connection_closed(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        with pytest.raises(ConnectionError, match="banner"):
            _read_ssh_banner(mock_sock)


class TestBuildKexinitPayload:
    def test_payload_starts_with_kexinit_type(self):
        payload = _build_kexinit_payload()
        assert payload[0] == 20

    def test_payload_contains_algorithms(self):
        payload = _build_kexinit_payload()
        assert len(payload) > 16 + 1


class TestWrapSSHPacket:
    def test_packet_structure(self):
        payload = b"\x14" + b"\x00" * 16
        packet = _wrap_ssh_packet(payload)
        length = struct.unpack(">I", packet[:4])[0]
        padding_length = packet[4]
        assert length == 1 + len(payload) + padding_length
        assert padding_length >= 4

    def test_minimum_padding(self):
        payload = b"\x14" + b"\x00" * 16
        packet = _wrap_ssh_packet(payload)
        padding_length = packet[4]
        assert padding_length >= 4


class TestParseServerKexinit:
    def test_parse_valid_kexinit(self):
        m = MagicMock()
        payload = _build_server_kexinit_for_test(
            kex=["curve25519-sha256", "mlkem768x25519-sha512@openssh.com"],
            host_keys=["ssh-ed25519"],
            enc=["aes256-gcm@openssh.com"],
            mac=["hmac-sha2-256"],
        )
        result = _parse_server_kexinit(payload)
        assert "mlkem768x25519-sha512@openssh.com" in result["kex_algorithms"]
        assert "ssh-ed25519" in result["host_key_algorithms"]

    def test_parse_malformed_returns_empty(self):
        result = _parse_server_kexinit(b"\x00" * 5)
        assert result["kex_algorithms"] == []

    def test_parse_empty_payload(self):
        result = _parse_server_kexinit(b"")
        assert result["kex_algorithms"] == []


class TestDoSSHConnect:
    def test_connection_failure(self):
        with patch("socket.create_connection", side_effect=ConnectionError("refused")):
            result = _do_ssh_connect("10.0.0.1", 22, 5)
        assert result["success"] is False
        assert "refused" in result["error_message"]

    def test_timeout(self):
        with patch("socket.create_connection", side_effect=socket.timeout("timed out")):
            result = _do_ssh_connect("10.0.0.1", 22, 5)
        assert result["success"] is False
        assert "timed out" in result["error_message"]

    def test_banner_read_failure(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        with patch("socket.create_connection", return_value=mock_sock):
            result = _do_ssh_connect("10.0.0.1", 22, 5)
        assert result["success"] is False
        assert result["error_message"] is not None


class TestSSHScanResult:
    def test_defaults(self):
        r = SSHScanResult(host="h", port=22, success=False, error_message="err")
        assert r.kex_algorithms == []
        assert r.pqc_kex_available is False
        assert r.pqc_status == "vulnerable"

    def test_pqc_ready(self):
        r = SSHScanResult(
            host="h", port=22, success=True,
            pqc_kex_available=True,
            pqc_status="pqc_ready",
            pqc_kex_algorithms=["mlkem768x25519-sha512@openssh.com"],
        )
        assert r.pqc_status == "pqc_ready"
        assert r.pqc_kex_available is True


def _build_server_kexinit_for_test(kex=None, host_keys=None, enc=None, mac=None):
    from paramiko.message import Message
    m = Message()
    m.add_byte(b"\x14")
    m.add_bytes(b"\x00" * 16)
    m.add_list(kex or [])
    m.add_list(host_keys or [])
    m.add_list(enc or [])
    m.add_list(enc or [])
    m.add_list(mac or [])
    m.add_list(mac or [])
    m.add_list(["none"])
    m.add_list(["none"])
    m.add_list([])
    m.add_list([])
    m.add_boolean(False)
    m.add_int(0)
    return m.asbytes()


def _wrap_ssh_packet_for_test(payload):
    block_size = 8
    pre_pad = 5 + len(payload)
    padding_length = block_size - (pre_pad % block_size)
    if padding_length < 4:
        padding_length += block_size
    packet_length = 1 + len(payload) + padding_length
    return (
        struct.pack(">I", packet_length)
        + bytes([padding_length])
        + payload
        + b"\x00" * padding_length
    )


def _banner_bytes(banner):
    return list(banner)
