import socket
from unittest.mock import MagicMock, patch
import pytest

from app.scanners.tls_scanner import scan_tls_endpoint, TLSScanResult


def test_tls_scan_result_init():
    """Verify TLSScanResult initializes attributes correctly."""
    res = TLSScanResult(
        host="test.example.com",
        port=443,
        success=True,
        error_message=None,
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        cert_data={"subject": "CN=test"},
        supported_versions=["TLSv1.3"],
    )
    assert res.host == "test.example.com"
    assert res.port == 443
    assert res.success is True
    assert res.error_message is None
    assert res.tls_version == "TLSv1.3"
    assert res.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert res.cert_data == {"subject": "CN=test"}
    assert res.supported_versions == ["TLSv1.3"]


@pytest.mark.asyncio
async def test_scan_tls_endpoint_success():
    """Verify scan_tls_endpoint returns successful scan result when handshake succeeds."""
    mock_response = {
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cert_data": {"subject": "CN=test"},
        "supported_versions": ["TLSv1.3"],
    }

    with patch(
        "app.scanners.tls_scanner._do_tls_connect", return_value=mock_response
    ) as mock_connect:
        res = await scan_tls_endpoint(
            "test.example.com", port=443, timeout=5, verify_tls=True
        )

    assert res.success is True
    assert res.tls_version == "TLSv1.3"
    assert res.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert res.cert_data == {"subject": "CN=test"}
    assert res.supported_versions == ["TLSv1.3"]
    mock_connect.assert_called_once_with("test.example.com", 443, 5, True)


@pytest.mark.asyncio
async def test_scan_tls_endpoint_exception():
    """Verify scan_tls_endpoint handles socket or SSL exceptions gracefully."""
    with patch(
        "app.scanners.tls_scanner._do_tls_connect",
        side_effect=socket.timeout("Connection timed out"),
    ):
        res = await scan_tls_endpoint(
            "test.example.com", port=443, timeout=2, verify_tls=True
        )

    assert res.success is False
    assert "Connection timed out" in res.error_message


def test_do_tls_connect_no_verify():
    """Verify _do_tls_connect with verify_tls=False disables context validation."""
    from app.scanners.tls_scanner import _do_tls_connect
    from app.scanners import tls_scanner

    with patch.object(tls_scanner.ssl, "create_default_context") as cdc, patch.object(
        tls_scanner, "parse_certificate", return_value={}
    ):
        ctx = MagicMock()
        cdc.return_value = ctx
        with patch.object(tls_scanner.socket, "create_connection") as ccc:
            sock = MagicMock()
            sock.__enter__ = lambda self: sock
            sock.__exit__ = lambda self, *a: False
            sock.settimeout = MagicMock()
            ccc.return_value = sock
            fake = MagicMock()
            fake.__enter__ = lambda self: fake
            fake.__exit__ = lambda self, *a: False
            fake.getpeercert.return_value = b"X"
            fake.version.return_value = "TLSv1.3"
            fake.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            ctx.wrap_socket.return_value = fake
            with patch.object(
                tls_scanner.ssl, "DER_cert_to_PEM_cert", return_value="PEM"
            ):
                _do_tls_connect("example.com", 443, 5, verify_tls=False)

    assert ctx.check_hostname is False
    assert ctx.verify_mode == tls_scanner.ssl.CERT_NONE
