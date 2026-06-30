"""Tests for the TSA scanner skeleton."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.scanners.tsa_scanner import scan_tsa_authority, scan_tsa_authority_dict


def _self_signed_cert() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


@pytest.fixture
def tsa_cert():
    return _self_signed_cert()


@pytest.mark.asyncio
async def test_scan_tsa_authority_success(tsa_cert):
    from unittest.mock import MagicMock

    mock_resp = AsyncMock()
    mock_resp.text = tsa_cert
    mock_resp.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch(
        "app.scanners.tsa_scanner.httpx.AsyncClient", return_value=mock_client
    ), patch(
        "app.scanners.tsa_scanner.resolve_safely",
        new=AsyncMock(return_value=["1.2.3.4"]),
    ):
        result = await scan_tsa_authority("https://tsa.example.com")

    assert result.success is True
    assert len(result.certificates) == 1
    assert result.certificates[0]["subject"] == "CN=Test TSA"
    assert "sha256WithRSAEncryption" in result.certificates[0]["sig_algorithm"]


@pytest.mark.asyncio
async def test_scan_tsa_authority_dict_success(tsa_cert):
    from unittest.mock import MagicMock

    mock_resp = AsyncMock()
    mock_resp.text = tsa_cert
    mock_resp.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch(
        "app.scanners.tsa_scanner.httpx.AsyncClient", return_value=mock_client
    ), patch(
        "app.scanners.tsa_scanner.resolve_safely",
        new=AsyncMock(return_value=["1.2.3.4"]),
    ):
        data = await scan_tsa_authority_dict("https://tsa.example.com")

    assert data["status"] == "success"
    assert data["pqc_status"] == "vulnerable"
    assert "RSA" in data["algorithms"] or any("RSA" in a for a in data["algorithms"])


@pytest.mark.asyncio
async def test_scan_tsa_authority_no_certs():
    from unittest.mock import MagicMock

    mock_resp = AsyncMock()
    mock_resp.text = "no certificates here"
    mock_resp.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch(
        "app.scanners.tsa_scanner.httpx.AsyncClient", return_value=mock_client
    ), patch(
        "app.scanners.tsa_scanner.resolve_safely",
        new=AsyncMock(return_value=["1.2.3.4"]),
    ):
        result = await scan_tsa_authority("https://tsa.example.com")

    assert result.success is False
    assert "No parseable X.509 certificates" in result.error_message


@pytest.mark.asyncio
async def test_scan_tsa_authority_invalid_url():
    result = await scan_tsa_authority("not-a-url")
    assert result.success is False
    assert "hostname" in result.error_message.lower()


@pytest.mark.asyncio
async def test_scan_tsa_authority_network_error():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(side_effect=Exception("connection refused"))

    with patch(
        "app.scanners.tsa_scanner.httpx.AsyncClient", return_value=mock_client
    ), patch(
        "app.scanners.tsa_scanner.resolve_safely",
        new=AsyncMock(return_value=["1.2.3.4"]),
    ):
        result = await scan_tsa_authority("https://tsa.example.com")

    assert result.success is False
    assert "connection refused" in result.error_message
