"""
Tests for the L4 JWT and L7 Windows Cert Store connectors.
"""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------- JWT -----
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_jwt(header: Dict[str, Any], payload: Dict[str, Any], sig: bytes = b"") -> str:
    return ".".join(
        [
            _b64url(json.dumps(header).encode("utf-8")),
            _b64url(json.dumps(payload).encode("utf-8")),
            _b64url(sig),
        ]
    )


def test_jwt_connector_decodes_offline_token():
    """Offline tokens are decoded, classified, and an Asset is persisted."""
    from app.connectors.jwt_connector import JWTConnector

    token = _make_jwt(
        {"alg": "RS256", "typ": "JWT", "kid": "k1"},
        {
            "iss": "https://issuer",
            "sub": "user-1",
            "exp": 9999999999,
            "scope": "read write",
        },
    )

    session = AsyncMock()
    session.execute = AsyncMock()
    session.execute.return_value.scalar_one_or_none = MagicMock(return_value=None)
    session.commit = AsyncMock()
    session.add = MagicMock()

    c = JWTConnector(tokens=[token])
    result = asyncio.run(c.sync(session))

    assert result["status"] == "success"
    assert result["imported"] == 1
    assert result["updated"] == 0
    # Asset.add called once
    assert session.add.call_count == 1
    asset = session.add.call_args[0][0]
    assert asset.asset_type == "jwt"
    assert asset.discovery_source == "jwt_audit"
    assert asset.asset_metadata["alg"] == "RS256"
    assert asset.asset_metadata["iss"] == "https://issuer"
    assert asset.asset_metadata["layer"] == "L4"


def test_jwt_connector_updates_existing_token():
    """Re-importing the same token updates the existing Asset."""
    from app.connectors.jwt_connector import JWTConnector

    token = _make_jwt({"alg": "ES256"}, {"sub": "abc"})

    existing = MagicMock()
    existing.asset_metadata = {}
    res = MagicMock()
    res.scalar_one_or_none = MagicMock(return_value=existing)
    session = AsyncMock()
    session.execute = AsyncMock(return_value=res)
    session.commit = AsyncMock()

    c = JWTConnector(tokens=[token])
    result = asyncio.run(c.sync(session))

    assert result["imported"] == 0
    assert result["updated"] == 1
    assert existing.asset_type == "jwt"
    assert existing.asset_metadata["alg"] == "ES256"


def test_jwt_connector_skips_malformed_token():
    """A malformed token is reported as an error and skipped."""
    from app.connectors.jwt_connector import JWTConnector

    session = AsyncMock()
    session.execute = AsyncMock()
    session.execute.return_value.scalar_one_or_none = MagicMock(return_value=None)
    session.commit = AsyncMock()
    session.add = MagicMock()

    c = JWTConnector(tokens=["not.a.valid.jwt", "alsogarbage"])
    result = asyncio.run(c.sync(session))

    assert result["imported"] == 0
    assert len(result["errors"]) == 2


def test_jwt_connector_handles_empty_input():
    """No tokens → graceful success with zero counts."""
    from app.connectors.jwt_connector import JWTConnector

    session = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()

    c = JWTConnector(tokens=[])
    result = asyncio.run(c.sync(session))

    assert result["status"] == "success"
    assert result["imported"] == 0
    assert "no tokens" in result["message"]


def test_jwt_connector_classifies_pqc_status():
    """Status mapping: HS256 with short key -> vulnerable, RS256 -> safe, none -> disallowed_now."""
    from app.connectors.jwt_connector import JWTConnector

    weak = _make_jwt({"alg": "HS256"}, {"sub": "x"})
    none_alg = _make_jwt({"alg": "none"}, {"sub": "x"})
    ed = _make_jwt({"alg": "EdDSA"}, {"sub": "x"})

    session = AsyncMock()
    session.execute = AsyncMock()
    session.execute.return_value.scalar_one_or_none = MagicMock(return_value=None)
    session.commit = AsyncMock()
    session.add = MagicMock()

    c = JWTConnector(tokens=[weak, none_alg, ed])
    result = asyncio.run(c.sync(session))

    assert result["imported"] == 3
    algs_to_status = {}
    for call in session.add.call_args_list:
        asset = call.args[0]
        algs_to_status[asset.asset_metadata["alg"]] = asset.asset_metadata["pqc_status"]
    assert algs_to_status["HS256"] == "vulnerable"
    assert algs_to_status["none"] == "disallowed_now"
    assert algs_to_status["EdDSA"] == "vulnerable"


def test_jwt_connector_derive_key_size_rsa():
    """An RSA JWK in the header exposes its modulus bit-length."""
    from app.connectors.jwt_connector import JWTConnector

    # 2048-bit modulus: 256 bytes starting with 0x01
    modulus = b"\x01" + b"\x00" * 255
    jwk = {"kty": "RSA", "n": _b64url(modulus)}
    token = _make_jwt({"alg": "RS256", "jwk": jwk}, {"sub": "x"})

    session = AsyncMock()
    session.execute = AsyncMock()
    session.execute.return_value.scalar_one_or_none = MagicMock(return_value=None)
    session.commit = AsyncMock()
    session.add = MagicMock()

    c = JWTConnector(tokens=[token])
    asyncio.run(c.sync(session))

    asset = session.add.call_args[0][0]
    assert asset.asset_metadata["key_size_bits"] >= 2040  # allow for leading-bit calc


def test_jwt_connector_derive_key_size_ecc():
    """An EC JWK in the header exposes the curve bit-length."""
    from app.connectors.jwt_connector import JWTConnector

    token = _make_jwt(
        {"alg": "ES384", "jwk": {"kty": "EC", "crv": "P-384"}}, {"sub": "x"}
    )

    session = AsyncMock()
    session.execute = AsyncMock()
    session.execute.return_value.scalar_one_or_none = MagicMock(return_value=None)
    session.commit = AsyncMock()
    session.add = MagicMock()

    c = JWTConnector(tokens=[token])
    asyncio.run(c.sync(session))

    asset = session.add.call_args[0][0]
    assert asset.asset_metadata["key_size_bits"] == 384


def test_jwt_connector_strips_raw_token_from_metadata():
    """The raw token must never be persisted in asset metadata."""
    from app.connectors.jwt_connector import JWTConnector

    token = _make_jwt({"alg": "RS256"}, {"sub": "x"})

    session = AsyncMock()
    session.execute = AsyncMock()
    session.execute.return_value.scalar_one_or_none = MagicMock(return_value=None)
    session.commit = AsyncMock()
    session.add = MagicMock()

    c = JWTConnector(tokens=[token])
    asyncio.run(c.sync(session))

    asset = session.add.call_args[0][0]
    meta_json = json.dumps(asset.asset_metadata)
    assert token not in meta_json, "raw token leaked into asset_metadata"


# ----------------------------------------------------- Windows Store -----
CERTUTIL_DUMP = """
================ Certificate 0 ================
Serial Number: 112233445566
Issuer: CN=Test CA, O=Example
Subject: CN=host.example.com
NotBefore: 1/1/2024 12:00 AM
NotAfter:  1/1/2025 12:00 AM
Cert Hash(sha1): aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd
================ Certificate 1 ================
Serial Number: 9988776655
Issuer: CN=Test CA, O=Example
Subject: CN=other.example.com
NotBefore: 6/15/2024 9:00 AM
NotAfter:  6/15/2025 9:00 AM
Cert Hash(sha1): 11 22 33 44 55 66 77 88 99 00 aa bb cc dd ee ff 00 11 22 33
"""


def test_windows_cert_store_parses_certutil_dump():
    """A multi-cert certutil dump is split into per-cert assets."""
    from app.connectors.winstore_connector import WindowsCertStoreConnector

    session = AsyncMock()
    session.execute = AsyncMock()
    session.execute.return_value.scalar_one_or_none = MagicMock(return_value=None)
    session.commit = AsyncMock()
    session.add = MagicMock()

    c = WindowsCertStoreConnector(store_name="My", store_kind="user")
    result = asyncio.run(c.sync(session, dump_text=CERTUTIL_DUMP))

    assert result["status"] == "success"
    assert result["imported"] == 2
    assert session.add.call_count == 2
    subjects = sorted(
        call.args[0].asset_metadata["subject"] for call in session.add.call_args_list
    )
    assert subjects == ["CN=host.example.com", "CN=other.example.com"]


def test_windows_cert_store_layer_is_L7():
    """Each cert-store asset is tagged with the L7 (Endpoint) layer."""
    from app.connectors.winstore_connector import WindowsCertStoreConnector

    session = AsyncMock()
    session.execute = AsyncMock()
    session.execute.return_value.scalar_one_or_none = MagicMock(return_value=None)
    session.commit = AsyncMock()
    session.add = MagicMock()

    c = WindowsCertStoreConnector(store_name="Root", store_kind="enterprise")
    asyncio.run(c.sync(session, dump_text=CERTUTIL_DUMP))

    layers = [
        call.args[0].asset_metadata["layer"] for call in session.add.call_args_list
    ]
    assert all(layer == "L7" for layer in layers)


def test_windows_cert_store_rejects_invalid_store_kind():
    """The constructor must reject store_kind values other than user/enterprise."""
    from app.connectors.winstore_connector import WindowsCertStoreConnector

    with pytest.raises(ValueError):
        WindowsCertStoreConnector(store_name="My", store_kind="bogus")


def test_windows_cert_store_requires_dump():
    """sync() returns an error if neither dump_path nor dump_text is given."""
    from app.connectors.winstore_connector import WindowsCertStoreConnector

    session = AsyncMock()
    c = WindowsCertStoreConnector()
    result = asyncio.run(c.sync(session))
    assert result["status"] == "error"
    assert "dump_path" in result["error"]


def test_windows_cert_store_missing_subject_is_skipped():
    """A cert block with no subject is skipped (not crashed)."""
    from app.connectors.winstore_connector import WindowsCertStoreConnector

    dump = """
================ Certificate 0 ================
Serial Number: 12
================ Certificate 1 ================
Serial Number: 34
Subject: CN=ok.example.com
"""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.execute.return_value.scalar_one_or_none = MagicMock(return_value=None)
    session.commit = AsyncMock()
    session.add = MagicMock()

    c = WindowsCertStoreConnector()
    result = asyncio.run(c.sync(session, dump_text=dump))

    assert result["imported"] == 1
    assert len(result["errors"]) == 1
    assert "no subject" in result["errors"][0]


def test_jwt_connector_endpoint_failure_does_not_block_offline():
    """If the endpoint fetch raises, offline tokens still produce a result."""
    from app.connectors.jwt_connector import JWTConnector

    token = _make_jwt({"alg": "RS256"}, {"sub": "x"})

    session = AsyncMock()
    session.execute = AsyncMock()
    session.execute.return_value.scalar_one_or_none = MagicMock(return_value=None)
    session.commit = AsyncMock()
    session.add = MagicMock()

    # Endpoint that will fail — overridden to raise.
    async def _boom():
        raise RuntimeError("network down")

    c = JWTConnector(tokens=[token], endpoint="https://example.invalid/tokens")
    c._fetch_tokens = _boom  # type: ignore[assignment]

    result = asyncio.run(c.sync(session))

    assert result["status"] == "success"
    assert result["imported"] == 1
    assert any("network down" in e for e in result["errors"])


def test_jwt_connector_uses_dict_credentials_ref():
    """Dict-shaped credentials_ref must work as a vault reference."""
    from app.connectors.jwt_connector import JWTConnector

    async def _fake_vault(path, version):
        assert path == "secret/pqc/jwt"
        return {"token": "bearer-abc"}

    import app.connectors.jwt_connector as jc

    jc.get_vault_secret = _fake_vault  # type: ignore[assignment]

    c = JWTConnector(credentials_ref={"vault_path": "secret/pqc/jwt", "version": None})
    creds = asyncio.run(c._get_credentials())
    assert creds == {"token": "bearer-abc"}


def test_jwt_connector_uses_object_credentials_ref():
    """Object-shaped credentials_ref (with vault_path attribute) must work."""
    from app.connectors.jwt_connector import JWTConnector
    from types import SimpleNamespace

    async def _fake_vault(path, version):
        return {"token": "bearer-xyz"}

    import app.connectors.jwt_connector as jc

    jc.get_vault_secret = _fake_vault  # type: ignore[assignment]

    c = JWTConnector(
        credentials_ref=SimpleNamespace(vault_path="secret/pqc/jwt2", version=1)
    )
    creds = asyncio.run(c._get_credentials())
    assert creds == {"token": "bearer-xyz"}


def test_jwt_connector_derives_layer_from_asset_type():
    """The asset metadata must record the L4 layer for JWT assets."""
    from app.connectors.jwt_connector import JWTConnector

    token = _make_jwt({"alg": "RS256"}, {"sub": "x"})

    session = AsyncMock()
    session.execute = AsyncMock()
    session.execute.return_value.scalar_one_or_none = MagicMock(return_value=None)
    session.commit = AsyncMock()
    session.add = MagicMock()

    c = JWTConnector(tokens=[token])
    asyncio.run(c.sync(session))

    asset = session.add.call_args.args[0]
    assert asset.asset_metadata["layer"] == "L4"
