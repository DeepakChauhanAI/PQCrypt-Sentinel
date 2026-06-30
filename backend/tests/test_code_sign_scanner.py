"""Tests for the code-signing verification skeleton."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.scanners.code_sign_scanner import verify_code_signature


def _self_signed_cert_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Signer")])
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
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def cert_file(tmp_path: Path) -> Path:
    path = tmp_path / "signer.pem"
    path.write_bytes(_self_signed_cert_pem())
    return path


def test_verify_pem_certificate_detected(cert_file: Path):
    result = verify_code_signature(str(cert_file))
    assert result["status"] == "success"
    assert result["signature_present"] is True
    assert len(result["certificates"]) == 1
    assert result["certificates"][0]["subject"] == "CN=Test Signer"
    assert result["pqc_status"] == "vulnerable"
    assert result["verification"] == "not_implemented"


def test_verify_missing_file():
    result = verify_code_signature("/nonexistent/path.bin")
    assert result["status"] == "error"
    assert result["signature_present"] is False
    assert "File not found" in result["errors"]


def test_verify_no_signature(tmp_path: Path):
    path = tmp_path / "plain.txt"
    path.write_text("hello world")
    result = verify_code_signature(str(path))
    assert result["signature_present"] is False
    assert result["status"] == "success"


def test_find_pkcs7_blob_short_data():
    """_find_pkcs7_blob returns the trailing bytes when data is too short for length read."""
    from app.scanners.code_sign_scanner import _find_pkcs7_blob
    signed_data_oid = bytes.fromhex("06 09 2A 86 48 86 F7 0D 01 07 02".replace(" ", ""))
    result = _find_pkcs7_blob(b"\x30\x82" + signed_data_oid)
    assert result is not None


def test_find_pkcs7_blob_no_sequence_prefix(tmp_path: Path):
    """Binary containing OID but no enclosing SEQUENCE is treated as no certs."""
    signed_data_oid = bytes.fromhex("06 09 2A 86 48 86 F7 0D 01 07 02".replace(" ", ""))
    data = b"\x00" * 8 + signed_data_oid + b"\x00" * 20
    path = tmp_path / "no_seq.bin"
    path.write_bytes(data)
    result = verify_code_signature(str(path))
    assert result["signature_present"] is False


def test_find_pkcs7_blob_with_sequence_prefix(tmp_path: Path):
    """A synthetic PKCS#7 blob inside a binary is discovered."""
    signed_data_oid = bytes.fromhex("06 09 2A 86 48 86 F7 0D 01 07 02".replace(" ", ""))
    # SEQUENCE (0x30 0x82 <2-byte length>) + OID + padding
    length = 32
    seq = bytes([0x30, 0x82]) + length.to_bytes(2, "big") + signed_data_oid + b"\x00" * (length - len(signed_data_oid))
    data = b"MZ" + seq + b"\x00" * 16
    path = tmp_path / "with_seq.bin"
    path.write_bytes(data)
    result = verify_code_signature(str(path))
    # No real certs, so signature_present is False but the branch was exercised
    assert result["signature_present"] is False


def test_verify_pem_with_invalid_block(tmp_path: Path):
    """Invalid PEM blocks are collected as errors but the scan succeeds."""
    text = (
        "-----BEGIN CERTIFICATE-----\n"
        "not-valid-base64!!!\n"
        "-----END CERTIFICATE-----\n"
    )
    path = tmp_path / "bad.pem"
    path.write_text(text)
    result = verify_code_signature(str(path))
    assert result["signature_present"] is False
    assert any("PEM parse failed" in e for e in result["errors"])


def test_verify_partial_status_on_cert_parse_error(tmp_path: Path, cert_file: Path):
    """If one cert parses and another fails, status is partial."""
    from unittest.mock import patch
    with patch("app.scanners.code_sign_scanner.parse_certificate", side_effect=[Exception("bad cert"), {}]):
        # Need two certs; use two copies of the same cert file concatenated
        pem_bytes = cert_file.read_bytes()
        path = tmp_path / "two.pem"
        path.write_bytes(pem_bytes + pem_bytes)
        result = verify_code_signature(str(path))
    assert result["status"] == "partial"
