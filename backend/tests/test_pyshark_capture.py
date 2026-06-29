import pytest
import sys
import datetime
from unittest.mock import MagicMock, patch, AsyncMock
from app.scanners import pyshark_capture as pyshark_mod
from app.scanners.pyshark_capture import (
    capture_tls_handshakes,
    capture_ssh_handshakes,
    capture_all_handshakes,
    analyze_pcap_file,
    _extract_cipher_suites,
    _extract_supported_groups,
)

@pytest.fixture(autouse=True)
def mock_tshark_path():
    """Ensure tshark path is treated as found so tests do not raise RuntimeError."""
    with patch("app.scanners.pyshark_capture._get_tshark_path", return_value="/usr/bin/tshark"):
        yield

@pytest.mark.asyncio
async def test_capture_tls_handshakes_success():
    # Mock pyshark
    mock_pyshark = MagicMock()
    sys.modules["pyshark"] = mock_pyshark
    
    # Create fake packets
    packet1 = MagicMock()
    packet1.sniff_time = datetime.datetime(2026, 6, 6, 12, 0, 0)
    packet1.ip.src = "10.0.0.1"
    packet1.ip.dst = "10.0.0.2"
    packet1.tcp.dstport = 443
    packet1.tls = MagicMock()
    packet1.tls.handshake_type = "1"
    packet1.tls.handshake_version = "0x0303"
    packet1.tls.field_names = ["handshake.ciphersuite", "handshake.extensions.supported_group"]
    
    # Set the attributes directly on the mock
    setattr(packet1.tls, "handshake.ciphersuite", "0x1302")
    setattr(packet1.tls, "handshake.extensions.supported_group", "0x01FD")
    
    mock_cap = MagicMock()
    mock_cap.sniff_continuously.return_value = [packet1]
    mock_pyshark.LiveCapture.return_value = mock_cap
    
    res = await capture_tls_handshakes("eth0", duration_seconds=5)
    assert len(res) == 1
    assert res[0]["type"] == "ClientHello"
    assert res[0]["pqc_groups_advertised"] == ["ML-KEM-768"]
    assert res[0]["has_pqc"] is True

    # Packet 2: Server Hello
    packet2 = MagicMock()
    packet2.sniff_time = datetime.datetime(2026, 6, 6, 12, 0, 1)
    packet2.ip.src = "10.0.0.2"
    packet2.ip.dst = "10.0.0.1"
    packet2.tls = MagicMock()
    packet2.tls.handshake_type = "2"
    packet2.tls.handshake_ciphersuite = "0x1302"
    packet2.tls.handshake_extensions_key_share_group = "0x01FD"
    packet2.tls.handshake_version = "0x0303"
    
    mock_cap2 = MagicMock()
    mock_cap2.sniff_continuously.return_value = [packet2]
    mock_pyshark.LiveCapture.return_value = mock_cap2
    
    res2 = await capture_tls_handshakes("eth0", duration_seconds=5)
    assert len(res2) == 1
    assert res2[0]["type"] == "ServerHello"
    assert res2[0]["selected_group"] == "0x01FD"

@pytest.mark.asyncio
async def test_capture_tls_handshakes_ignores_non_tls():
    mock_pyshark = MagicMock()
    sys.modules["pyshark"] = mock_pyshark

    # packet with no tls layer attributes
    packet_no_tls = MagicMock(spec=[])

    mock_cap = MagicMock()
    mock_cap.sniff_continuously.return_value = [packet_no_tls]
    mock_pyshark.LiveCapture.return_value = mock_cap

    res = await capture_tls_handshakes("eth0", duration_seconds=5)
    assert len(res) == 0

@pytest.mark.asyncio
async def test_capture_tls_handshakes_import_error():
    with patch("builtins.__import__", side_effect=ImportError("No module named pyshark")):
        with pytest.raises(RuntimeError, match="pyshark is not installed"):
            await capture_tls_handshakes("eth0")

@pytest.mark.asyncio
async def test_require_tshark_failure():
    with patch("app.scanners.pyshark_capture._get_tshark_path", return_value=None):
        with pytest.raises(RuntimeError, match="tshark not found"):
            await capture_tls_handshakes("eth0")

@pytest.mark.asyncio
async def test_capture_ssh_handshakes_success():
    mock_pyshark = MagicMock()
    sys.modules["pyshark"] = mock_pyshark
    
    packet = MagicMock()
    packet.sniff_time = datetime.datetime(2026, 6, 6, 12, 0, 0)
    packet.ip.src = "10.0.0.1"
    packet.ip.dst = "10.0.0.2"
    packet.tcp.dstport = 22
    packet.ssh = MagicMock()
    packet.ssh.field_names = [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_algorithms",
        "mac_algorithms"
    ]
    setattr(packet.ssh, "kex_algorithms", "sntrup761x25519-sha256@openssh.com,curve25519-sha256")
    setattr(packet.ssh, "server_host_key_algorithms", "ssh-rsa")
    setattr(packet.ssh, "encryption_algorithms", "aes256-gcm@openssh.com")
    setattr(packet.ssh, "mac_algorithms", "hmac-sha2-256")
    
    mock_cap = MagicMock()
    mock_cap.sniff_continuously.return_value = [packet]
    mock_pyshark.LiveCapture.return_value = mock_cap
    
    res = await capture_ssh_handshakes("eth0", duration_seconds=5)
    assert len(res) == 1
    assert res[0]["type"] == "SSH_KEXINIT"
    assert "sntrup761x25519-sha256@openssh.com" in res[0]["kex_algorithms"]
    assert res[0]["has_pqc"] is True

@pytest.mark.asyncio
async def test_analyze_pcap_file_success():
    mock_pyshark = MagicMock()
    sys.modules["pyshark"] = mock_pyshark

    # Packet 1: Server Hello with PQC group ID
    packet1 = MagicMock()
    packet1.sniff_time = datetime.datetime(2026, 6, 6, 12, 0, 0)
    packet1.ip.dst = "10.0.0.2"
    packet1.tls = MagicMock()
    packet1.tls.handshake_type = "2"
    packet1.tls.handshake_ciphersuite = "TLS_AES_256_GCM_SHA384"
    packet1.tls.handshake_extensions_key_share_group = str(0x01FD)  # ML-KEM-768 group ID

    # Packet 2: Server Hello with vulnerable group ID
    packet2 = MagicMock()
    packet2.sniff_time = datetime.datetime(2026, 6, 6, 12, 0, 1)
    packet2.ip.dst = "10.0.0.2"
    packet2.tls = MagicMock()
    packet2.tls.handshake_type = "2"
    packet2.tls.handshake_ciphersuite = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    packet2.tls.handshake_extensions_key_share_group = "29"  # secp384r1

    # Packet 3: Certificate info
    packet3 = MagicMock()
    packet3.sniff_time = datetime.datetime(2026, 6, 6, 12, 0, 2)
    packet3.ip.dst = "10.0.0.2"
    packet3.tls = MagicMock()
    packet3.tls.handshake_type = "11"
    packet3.tls.handshake_certificate = "00a0f0..."

    mock_cap = MagicMock()
    mock_cap.__iter__.return_value = [packet1, packet2, packet3]
    mock_pyshark.FileCapture.return_value = mock_cap

    res = await analyze_pcap_file("test.pcap")
    assert res["total_tls_handshakes"] == 2
    assert len(res["pqc_kex_negotiated"]) == 1
    assert res["pqc_kex_negotiated"][0]["group_id"] == 509
    assert len(res["vulnerable_kex"]) == 1
    assert res["vulnerable_kex"][0]["group_id"] == 29
    assert len(res["certificates"]) == 1
    assert res["certificates"][0]["raw_cert_hex"] == "00a0f0..."

@pytest.mark.asyncio
async def test_capture_all_handshakes():
    with patch("app.scanners.pyshark_capture.capture_tls_handshakes", new_callable=AsyncMock) as mock_tls, \
         patch("app.scanners.pyshark_capture.capture_ssh_handshakes", new_callable=AsyncMock) as mock_ssh:
             
             mock_tls.return_value = [{"type": "ClientHello"}]
             mock_ssh.return_value = [{"type": "SSH_KEXINIT"}]
             
             res = await capture_all_handshakes("eth0")
             assert len(res) == 2
             assert res[0]["type"] == "ClientHello"
             assert res[1]["type"] == "SSH_KEXINIT"
