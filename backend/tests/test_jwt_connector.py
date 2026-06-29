import pytest
import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch
from app.connectors.jwt_connector import JWTConnector, JWTDecodeError, _FakeAsset


def _make_jwt(header=None, payload=None):
    header = header or {"alg": "RS256", "typ": "JWT"}
    payload = payload or {"sub": "1234", "iss": "https://idp.example.com"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.fake-sig"


class TestJWTDecodeUnverified:
    def test_valid_rs256(self):
        token = _make_jwt({"alg": "RS256"}, {"sub": "user1", "iss": "idp"})
        header, payload = JWTConnector._decode_unverified(token)
        assert header["alg"] == "RS256"
        assert payload["sub"] == "user1"

    def test_valid_es256(self):
        token = _make_jwt({"alg": "ES256", "kid": "key-1"}, {"aud": "api"})
        header, payload = JWTConnector._decode_unverified(token)
        assert header["alg"] == "ES256"
        assert header["kid"] == "key-1"

    def test_empty_token_raises(self):
        with pytest.raises(JWTDecodeError, match="empty"):
            JWTConnector._decode_unverified("")

    def test_none_token_raises(self):
        with pytest.raises(JWTDecodeError, match="empty"):
            JWTConnector._decode_unverified(None)

    def test_two_segments_raises(self):
        with pytest.raises(JWTDecodeError, match="3 segments"):
            JWTConnector._decode_unverified("abc.def")

    def test_bad_base64_raises(self):
        # Single segment triggers the "expected 3 segments" error
        with pytest.raises(JWTDecodeError, match="3 segments"):
            JWTConnector._decode_unverified("x")

    def test_non_json_raises(self):
        h = base64.urlsafe_b64encode(b"not-json").rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(b"{}").rstrip(b"=").decode()
        with pytest.raises(JWTDecodeError, match="json"):
            JWTConnector._decode_unverified(f"{h}.{p}.sig")

    def test_non_dict_payload_raises(self):
        h = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(["array"]).encode()).rstrip(b"=").decode()
        with pytest.raises(JWTDecodeError, match="JSON objects"):
            JWTConnector._decode_unverified(f"{h}.{p}.sig")


class TestJWTClassify:
    def test_none_alg_disallowed(self):
        assert JWTConnector._classify("none", None) == "disallowed_now"

    def test_hs1_disallowed(self):
        assert JWTConnector._classify("HS1", None) == "disallowed_now"

    def test_empty_alg_unknown(self):
        assert JWTConnector._classify("", None) == "unknown"

    def test_rs256_small_key_vulnerable(self):
        assert JWTConnector._classify("RS256", 1024) == "vulnerable"

    def test_rs256_medium_key_safe_until_2030(self):
        assert JWTConnector._classify("RS256", 2048) == "safe_until_2030"

    def test_rs256_large_key_safe(self):
        assert JWTConnector._classify("RS256", 4096) == "safe"

    def test_rs256_no_key_safe(self):
        assert JWTConnector._classify("RS256", None) == "safe"

    def test_es256_vulnerable(self):
        assert JWTConnector._classify("ES256", 256) == "vulnerable"

    def test_eddsa_vulnerable(self):
        assert JWTConnector._classify("EdDSA", 256) == "vulnerable"

    def test_hs256_small_key_vulnerable(self):
        assert JWTConnector._classify("HS256", 128) == "vulnerable"

    def test_hs384_small_key_vulnerable(self):
        assert JWTConnector._classify("HS384", 256) == "vulnerable"

    def test_unknown_alg(self):
        assert JWTConnector._classify("UNKNOWN", None) == "unknown"


class TestDeriveKeySizeBits:
    def test_rsa_key_with_n(self):
        n_bytes = b"\x01" + b"\x00" * 255
        n_b64 = base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode()
        jwk = {"n": n_b64, "e": "AQAB"}
        size = JWTConnector._derive_key_size_bits(jwk)
        assert size is not None
        assert size > 0

    def test_ec_p256(self):
        jwk = {"crv": "P-256", "x": "abc", "y": "def"}
        assert JWTConnector._derive_key_size_bits(jwk) == 256

    def test_ec_p384(self):
        jwk = {"crv": "P-384", "x": "abc"}
        assert JWTConnector._derive_key_size_bits(jwk) == 384

    def test_ec_ed25519(self):
        jwk = {"crv": "Ed25519", "x": "abc"}
        assert JWTConnector._derive_key_size_bits(jwk) == 256

    def test_ec_ed448(self):
        jwk = {"crv": "Ed448", "x": "abc"}
        assert JWTConnector._derive_key_size_bits(jwk) == 448

    def test_unknown_curve(self):
        jwk = {"crv": "unknown", "x": "abc"}
        assert JWTConnector._derive_key_size_bits(jwk) is None

    def test_empty_jwk(self):
        assert JWTConnector._derive_key_size_bits({}) is None

    def test_bad_n_value_returns_none(self):
        # Some strings decode without error even if nonsensical, so just verify it returns an int or None
        jwk = {"n": ""}
        assert JWTConnector._derive_key_size_bits(jwk) is None


class TestBuildMetadata:
    def test_rs256_metadata(self):
        connector = JWTConnector()
        header = {"alg": "RS256", "kid": "key-1", "typ": "JWT"}
        payload = {"iss": "idp", "aud": "api", "sub": "user1", "exp": 9999999999}
        metadata = connector._build_metadata(header, payload, _make_jwt(header, payload))
        assert metadata["alg"] == "RS256"
        assert metadata["kid"] == "key-1"
        assert metadata["iss"] == "idp"
        assert metadata["aud"] == "api"
        assert metadata["sub"] == "user1"
        assert metadata["exp"] == 9999999999
        assert "token_sha256_prefix" in metadata

    def test_es256_with_jwk(self):
        connector = JWTConnector()
        header = {"alg": "ES256", "jwk": {"kty": "EC", "crv": "P-256", "x": "abc"}}
        payload = {"iss": "idp"}
        metadata = connector._build_metadata(header, payload, _make_jwt(header, payload))
        assert metadata["kty"] == "EC"
        assert metadata["key_size_bits"] == 256


class TestSync:
    @pytest.mark.asyncio
    async def test_no_tokens(self):
        connector = JWTConnector()
        session = AsyncMock()
        result = await connector.sync(session)
        assert result["status"] == "success"
        assert result["imported"] == 0

    @pytest.mark.asyncio
    async def test_valid_token_imported(self):
        token = _make_jwt({"alg": "RS256"}, {"sub": "user1"})
        connector = JWTConnector(tokens=[token])
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result
        result = await connector.sync(session)
        assert result["status"] == "success"
        assert result["imported"] == 1
        session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_valid_token_updated(self):
        token = _make_jwt({"alg": "RS256"}, {"sub": "user1"})
        connector = JWTConnector(tokens=[token])
        session = AsyncMock()
        existing = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing
        session.execute.return_value = mock_result
        result = await connector.sync(session)
        assert result["status"] == "success"
        assert result["updated"] == 1

    @pytest.mark.asyncio
    async def test_invalid_token_skipped(self):
        connector = JWTConnector(tokens=["not-a-jwt"])
        session = AsyncMock()
        result = await connector.sync(session)
        assert result["status"] == "success"
        assert result["skipped"] == 1
        assert len(result["errors"]) == 1

    @pytest.mark.asyncio
    async def test_mixed_valid_and_invalid(self):
        valid = _make_jwt({"alg": "ES256"}, {"sub": "user"})
        connector = JWTConnector(tokens=[valid, "bad", valid])
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result
        result = await connector.sync(session)
        assert result["imported"] == 2
        assert result["skipped"] == 1

    @pytest.mark.asyncio
    async def test_flush_failure(self):
        token = _make_jwt({"alg": "RS256"}, {"sub": "user1"})
        connector = JWTConnector(tokens=[token])
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result
        session.flush = AsyncMock(side_effect=Exception("DB error"))
        result = await connector.sync(session)
        assert result["status"] == "error"
        assert "flush failed" in result["error"]


class TestFakeAsset:
    def test_init(self):
        fa = _FakeAsset("jwt")
        assert fa.asset_type == "jwt"
        assert fa.discovery_source == "jwt"
        assert fa.asset_metadata == {}
