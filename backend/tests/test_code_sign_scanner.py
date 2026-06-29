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
