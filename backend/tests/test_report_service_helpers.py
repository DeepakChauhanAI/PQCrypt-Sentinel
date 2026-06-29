"""
Tests for `app.services.report_service` - the post-processing helpers
and the small utilities that are easy to exercise in isolation.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.report_service import (
    _CRYPTO_PROPERTIES_ORDER,
    _reorder_crypto_properties,
    post_process_cbom,
)


def _make_cert(
    sig_algorithm: str = "sha256WithRSAEncryption",
    pub_key_algorithm: str = "rsa",
    pub_key_size: int = 2048,
    curve_name: str | None = None,
    pqc_capable: bool = False,
    is_self_signed: bool = False,
    is_ca: bool = False,
) -> SimpleNamespace:
    """A full Certificate-shaped SimpleNamespace that satisfies
    every attribute `post_process_cbom` reads."""
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        thumbprint="a" * 64,
        subject="CN=test.example.com",
        issuer="CN=Test CA",
        serial_number="01",
        not_before=now,
        not_after=now,
        is_self_signed=is_self_signed,
        is_ca=is_ca,
        key_usage=None,
        pqc_capable=pqc_capable,
        sig_algorithm=sig_algorithm,
        pub_key_algorithm=pub_key_algorithm,
        pub_key_size=pub_key_size,
        curve_name=curve_name,
    )


# ----------------------------------------------- _reorder_crypto_properties --


def test_reorder_crypto_properties_no_components():
    """Empty components list -> no error, data unchanged."""
    data = {"components": []}
    _reorder_crypto_properties(data)
    assert data == {"components": []}


def test_reorder_crypto_properties_no_crypto_properties():
    data = {"components": [{"bom-ref": "x"}]}
    _reorder_crypto_properties(data)
    assert data["components"][0] == {"bom-ref": "x"}


def test_reorder_crypto_properties_reorders_standard_keys():
    """Standard keys appear in the ECMA-424 mandated order."""
    data = {
        "components": [
            {
                "bom-ref": "cert-1",
                "cryptoProperties": {
                    "pqc:status": "vulnerable",
                    "oid": "1.2.3.4",
                    "assetType": "certificate",
                    "algorithmProperties": {"primitive": "signature"},
                },
            }
        ]
    }
    _reorder_crypto_properties(data)
    cp = data["components"][0]["cryptoProperties"]
    keys = list(cp.keys())
    # First keys must be in the standard order, custom keys (pqc:*) follow
    standard_subset = [k for k in keys if k in _CRYPTO_PROPERTIES_ORDER]
    custom_subset = [k for k in keys if k not in _CRYPTO_PROPERTIES_ORDER]
    # Standard subset must follow _CRYPTO_PROPERTIES_ORDER
    expected = [k for k in _CRYPTO_PROPERTIES_ORDER if k in standard_subset]
    assert standard_subset == expected
    # Custom subset is sorted alphabetically
    assert custom_subset == sorted(custom_subset)


def test_reorder_crypto_properties_only_custom_keys():
    data = {
        "components": [
            {
                "bom-ref": "x",
                "cryptoProperties": {"z_custom": 1, "a_custom": 2, "m_custom": 3},
            }
        ]
    }
    _reorder_crypto_properties(data)
    keys = list(data["components"][0]["cryptoProperties"].keys())
    assert keys == ["a_custom", "m_custom", "z_custom"]


# ----------------------------------------------- post_process_cbom ------


def test_post_process_cbom_invalid_json_returns_unchanged():
    out = post_process_cbom("not json", {})
    assert out == "not json"


def test_post_process_cbom_sets_spec_version():
    cbom = json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.0",
        "components": [],
    })
    out = post_process_cbom(cbom, assets_map={})
    parsed = json.loads(out)
    assert parsed["specVersion"] == "1.7"


def test_post_process_cbom_certificate_rsa_pqc_vulnerable():
    """An RSA cert with no PQC support -> pqcSafe=False, pqc_status=vulnerable."""
    cbom = json.dumps({
        "components": [
            {
                "bom-ref": "cert-abc123",
                "type": "certificate",
            }
        ]
    })
    cert_obj = _make_cert()
    assets_map = {"cert-abc123": cert_obj}
    out = post_process_cbom(cbom, assets_map)
    parsed = json.loads(out)
    comp = parsed["components"][0]
    cp = comp["cryptoProperties"]
    assert cp["assetType"] == "certificate"
    assert cp["pqcSafe"] is False
    assert cp["algorithmProperties"]["primitive"] == "signature"
    assert "RSA" in cp["algorithmProperties"]["variant"]


def test_post_process_cbom_certificate_ed25519_pqc_safe():
    """An Ed25519 cert is pqcSafe=True, variant=Ed25519."""
    cbom = json.dumps({
        "components": [
            {"bom-ref": "cert-ed", "type": "certificate"},
        ]
    })
    cert_obj = _make_cert(
        sig_algorithm="ed25519",
        pub_key_algorithm="ed25519",
        pub_key_size=256,
        curve_name="curve25519",
    )
    out = post_process_cbom(cbom, {"cert-ed": cert_obj})
    cp = json.loads(out)["components"][0]["cryptoProperties"]
    assert cp["pqcSafe"] is False
    assert cp["algorithmProperties"]["variant"] == "Ed25519"


def test_post_process_cbom_certificate_pqc_capable():
    """A pqc_capable cert gets pqcSafe=True and nistQuantumSecurityLevel=3."""
    cbom = json.dumps({
        "components": [
            {"bom-ref": "cert-pqc", "type": "certificate"},
        ]
    })
    cert_obj = _make_cert(pqc_capable=True, sig_algorithm="mldsa", pub_key_algorithm="mldsa")
    out = post_process_cbom(cbom, {"cert-pqc": cert_obj})
    cp = json.loads(out)["components"][0]["cryptoProperties"]
    assert cp["pqcSafe"] is True
    assert cp["algorithmProperties"]["nistQuantumSecurityLevel"] == 3


def test_post_process_cbom_certificate_ecdsa_p256():
    """An ECDSA P-256 cert -> variant=ECDSA-P256, classical sec level 128."""
    cbom = json.dumps({
        "components": [
            {"bom-ref": "cert-ec", "type": "certificate"},
        ]
    })
    cert_obj = _make_cert(
        sig_algorithm="ecdsa-with-SHA256",
        pub_key_algorithm="ec",
        pub_key_size=256,
        curve_name="secp256r1",
    )
    out = post_process_cbom(cbom, {"cert-ec": cert_obj})
    cp = json.loads(out)["components"][0]["cryptoProperties"]
    assert cp["algorithmProperties"]["variant"] == "ECDSA-P256"
    assert cp["algorithmProperties"]["classicalSecurityLevel"] == 128


def test_post_process_cbom_certificate_rsa_4096_classical_128():
    """An RSA 4096 cert -> classicalSecurityLevel=128."""
    cbom = json.dumps({
        "components": [
            {"bom-ref": "cert-rsa4k", "type": "certificate"},
        ]
    })
    cert_obj = _make_cert(pub_key_size=4096)
    out = post_process_cbom(cbom, {"cert-rsa4k": cert_obj})
    cp = json.loads(out)["components"][0]["cryptoProperties"]
    assert cp["algorithmProperties"]["classicalSecurityLevel"] == 128


def test_post_process_cbom_certificate_rsa_1024_classical_80():
    """RSA 1024 -> classical sec level 80."""
    cbom = json.dumps({
        "components": [
            {"bom-ref": "cert-rsa1k", "type": "certificate"},
        ]
    })
    cert_obj = _make_cert(pub_key_size=1024)
    out = post_process_cbom(cbom, {"cert-rsa1k": cert_obj})
    cp = json.loads(out)["components"][0]["cryptoProperties"]
    assert cp["algorithmProperties"]["classicalSecurityLevel"] == 80


def test_post_process_cbom_algorithm_component_passthrough():
    """Algorithm components without an assets_map entry are passed through unchanged."""
    cbom = json.dumps({
        "components": [
            {
                "bom-ref": "algo-rsa2048",
                "type": "algorithm",
                "name": "RSA-2048",
            }
        ]
    })
    out = post_process_cbom(cbom, {})
    comp = json.loads(out)["components"][0]
    # The function doesn't decorate algo components; the component is preserved
    assert comp["bom-ref"] == "algo-rsa2048"
    assert comp["type"] == "algorithm"


def test_post_process_cbom_preserves_existing_crypto_properties():
    """If the component already has cryptoProperties, they are kept + augmented."""
    cbom = json.dumps({
        "components": [
            {
                "bom-ref": "cert-existing",
                "cryptoProperties": {"oid": "1.2.3", "pqcSafe": True},
            }
        ]
    })
    cert_obj = _make_cert()
    out = post_process_cbom(cbom, {"cert-existing": cert_obj})
    cp = json.loads(out)["components"][0]["cryptoProperties"]
    assert cp["oid"] == "1.2.3"
    # Was overridden (from existing True) to False because the cert is vulnerable
    assert cp["pqcSafe"] is False
