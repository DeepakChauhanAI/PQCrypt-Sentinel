"""
JWT (L4 Application layer) connector.

Accepts a list of JSON Web Tokens (offline mode) or fetches them from a
configured JWKS / token endpoint (online mode), decodes the header and
payload *without* verifying the signature, and surfaces the following
information for each token:

  * signing algorithm (alg)
  * key type / family (kty)
  * key modulus or curve for asymmetric algos
  * public-key size in bits (when derivable from the JWK)
  * issuer / audience / expiry metadata
  * pqc_status, derived from the algorithm using `risk_service`

Each token is persisted as an Asset with `asset_type=jwt`,
`discovery_source=jwt_audit`, and `asset_metadata` carrying the decoded
material. The connector does not store raw token bytes (only the digest)
so it is safe to use in logs and CBOM outputs.

The connector is intentionally library-light (stdlib + `cryptography`)
so it can be used in restricted environments.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.base import BaseConnector
from app.connectors.vault_helper import get_vault_secret
from app.models.models import Asset
from app.services.layer_service import layer_for_asset

logger = logging.getLogger(__name__)


# Algorithms considered safe or PQC-ready today.
_SAFE_ALGS = {
    "ES256", "ES384", "ES512",
    "EdDSA",
    "PS256", "PS384", "PS512",
    "RS256", "RS384", "RS512",  # not safe per se, but tracked separately
}
_PQC_ALGS: set[str] = set()  # none standardised yet
_DISALLOWED_NOW = {"none", "HS1", "RS1"}


class JWTConnector(BaseConnector):
    """
    Offline + online JWT auditor for the L4 Application layer.

    Parameters
    ----------
    tokens:
        Optional iterable of raw JWT strings to analyse in offline mode.
    endpoint:
        Optional HTTPS URL that returns a list of tokens (JSON array of
        strings or a `{"tokens": [...]}` payload). Requires `credentials_ref`.
    credentials_ref:
        Vault reference (dict or object) for bearer-token / mTLS auth.
    """

    def __init__(
        self,
        tokens: Optional[Iterable[str]] = None,
        endpoint: Optional[str] = None,
        credentials_ref: Optional[Any] = None,
    ):
        super().__init__("JWT Connector")
        self.tokens: List[str] = list(tokens or [])
        self.endpoint = endpoint
        self.credentials_ref = credentials_ref

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------
    async def sync(self, session: AsyncSession, **kwargs: Any) -> Dict[str, Any]:
        """
        Decode each token, persist or update the corresponding Asset row,
        and return a summary dict.
        """
        imported = 0
        updated = 0
        errors: List[str] = []
        token_list: List[str] = list(self.tokens)

        if self.endpoint:
            try:
                token_list.extend(await self._fetch_tokens())
            except Exception as exc:  # network / auth errors
                logger.warning("JWTConnector: endpoint fetch failed: %s", exc)
                errors.append(f"endpoint_fetch: {exc}")

        if not token_list:
            return {
                "status": "success",
                "imported": 0,
                "updated": 0,
                "skipped": 0,
                "errors": errors,
                "message": "no tokens supplied or fetched",
            }

        for idx, raw in enumerate(token_list):
            try:
                header, payload = self._decode_unverified(raw)
            except JWTDecodeError as exc:
                errors.append(f"token[{idx}]: decode error: {exc}")
                continue

            # Use SHA-256 of the token as a stable identifier — never store
            # the raw token.
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
            asset_name = f"jwt:{digest}"
            metadata = self._build_metadata(header, payload, raw)

            stmt = select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
            res = await session.execute(stmt)
            existing = res.scalar_one_or_none()
            if existing:
                existing.asset_metadata = metadata
                existing.asset_type = "jwt"
                existing.discovery_source = "jwt_audit"
                updated += 1
            else:
                asset = Asset(
                    name=asset_name,
                    asset_type="jwt",
                    environment="unknown",
                    discovery_source="jwt_audit",
                    asset_metadata=metadata,
                )
                session.add(asset)
                imported += 1

        try:
            await session.flush()
        except Exception as exc:
            await session.rollback()
            return {
                "status": "error",
                "error": f"flush failed: {exc}",
                "imported": 0,
                "updated": 0,
                "skipped": len(errors),
                "errors": errors,
            }

        return {
            "status": "success",
            "imported": imported,
            "updated": updated,
            "skipped": len(errors),
            "errors": errors,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _get_credentials(self) -> Dict[str, Any]:
        if not self.credentials_ref:
            return {}
        # Direct credentials dictionary fallback/override
        if isinstance(self.credentials_ref, dict) and "token" in self.credentials_ref:
            return self.credentials_ref

        if isinstance(self.credentials_ref, dict):
            return await get_vault_secret(
                self.credentials_ref.get("vault_path", ""),
                self.credentials_ref.get("version"),
            )
        vault_path = getattr(self.credentials_ref, "vault_path", "")
        version = getattr(self.credentials_ref, "version", None)
        return await get_vault_secret(vault_path, version)

    async def _fetch_tokens(self) -> List[str]:
        """Fetch a list of tokens from a remote endpoint using httpx if available."""
        try:
            import httpx  # type: ignore
        except ImportError:
            raise RuntimeError("httpx is required to fetch JWTs from an endpoint")

        if self.endpoint:
            from urllib.parse import urlparse
            from app.scanners.safe_target import resolve_safely
            parsed = urlparse(self.endpoint)
            if not parsed.hostname:
                raise ValueError("JWT endpoint URL must have a hostname")
            await resolve_safely(parsed.hostname)

        creds = await self._get_credentials()
        headers = {}
        if token := creds.get("token"):
            headers["Authorization"] = f"Bearer {token}"

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(self.endpoint, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        if isinstance(data, list):
            return [str(t) for t in data]
        if isinstance(data, dict) and isinstance(data.get("tokens"), list):
            return [str(t) for t in data["tokens"]]
        raise RuntimeError("unexpected token-list payload shape")

    @staticmethod
    def _decode_unverified(token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Decode a JWT header and payload without verifying the signature."""
        if not token or not isinstance(token, str):
            raise JWTDecodeError("token is empty or not a string")
        parts = token.split(".")
        if len(parts) != 3:
            raise JWTDecodeError(f"expected 3 segments, got {len(parts)}")

        def _b64decode(seg: str) -> bytes:
            padded = seg + "=" * (-len(seg) % 4)
            try:
                return base64.urlsafe_b64decode(padded.encode("ascii"))
            except Exception as exc:
                raise JWTDecodeError(f"base64 decode failed: {exc}") from exc

        try:
            header = json.loads(_b64decode(parts[0]) or b"{}")
            payload = json.loads(_b64decode(parts[1]) or b"{}")
        except json.JSONDecodeError as exc:
            raise JWTDecodeError(f"json decode failed: {exc}") from exc

        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise JWTDecodeError("header / payload must be JSON objects")
        return header, payload

    @staticmethod
    def _derive_key_size_bits(jwk: Dict[str, Any]) -> Optional[int]:
        """Return the bit-size of the public key, or None if not derivable."""
        if "n" in jwk and isinstance(jwk["n"], str):
            try:
                raw = base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4))
                # Strip leading 0x00 byte that some libraries prepend.
                if raw and raw[0] == 0:
                    raw = raw[1:]
                return max(0, len(raw) * 8 - raw[0].bit_length() + 1) if raw else None
            except Exception:
                return None
        if "e" in jwk and isinstance(jwk["e"], str):
            # RSA without n is unusual; return None
            return None
        if "crv" in jwk or "x" in jwk:
            crv = (jwk.get("crv") or "").lower()
            return {
                "p-256": 256, "p-384": 384, "p-521": 521,
                "secp256k1": 256, "ed25519": 256, "ed448": 448,
                "x25519": 256, "x448": 448,
            }.get(crv)
        return None

    def _build_metadata(
        self,
        header: Dict[str, Any],
        payload: Dict[str, Any],
        raw: str,
    ) -> Dict[str, Any]:
        alg = (header.get("alg") or "").strip()
        kid = header.get("kid")
        jwk = header.get("jwk") or {}
        kty = jwk.get("kty") or header.get("kty")
        key_bits = self._derive_key_size_bits(jwk) if isinstance(jwk, dict) else None
        pqc_status = self._classify(alg, key_bits)
        layer = layer_for_asset(_FakeAsset("jwt"))
        return {
            "provider": "jwt",
            "layer": layer,
            "alg": alg or None,
            "kid": kid,
            "kty": kty,
            "key_size_bits": key_bits,
            "pqc_status": pqc_status,
            "iss": payload.get("iss"),
            "aud": payload.get("aud"),
            "sub": payload.get("sub"),
            "exp": payload.get("exp"),
            "iat": payload.get("iat"),
            "nbf": payload.get("nbf"),
            "jti": payload.get("jti"),
            "scopes": payload.get("scope") or payload.get("scp"),
            "header_typ": header.get("typ"),
            "token_sha256_prefix": hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16],
        }

    @staticmethod
    def _classify(alg: str, key_bits: Optional[int]) -> str:
        if not alg:
            return "unknown"
        if alg.lower() in {"none", "hs1", "rs1"}:
            return "disallowed_now"
        if alg in _PQC_ALGS:
            return "pqc_ready"
        if alg == "HS256" and (key_bits or 0) < 256:
            return "vulnerable"
        if alg in {"HS256", "HS384", "HS512"} and (key_bits or 0) < (256 if alg == "HS256" else 384):
            return "vulnerable"
        if alg.startswith("RS") or alg.startswith("PS"):
            if key_bits is not None and key_bits < 2048:
                return "vulnerable"
            if key_bits is not None and key_bits < 3072:
                return "safe_until_2030"
            return "safe"
        if alg in {"ES256", "ES384", "ES512", "EdDSA"}:
            return "vulnerable"
        if alg.startswith("RS") or alg.startswith("PS"):
            return "safe"
        return "unknown"


class JWTDecodeError(ValueError):
    """Raised when a JWT cannot be base64-decoded or parsed."""


class _FakeAsset:
    """Minimal stand-in used for layer derivation without instantiating Asset."""

    def __init__(self, asset_type: str):
        self.asset_type = asset_type
        self.discovery_source = asset_type
        self.asset_metadata: Dict[str, Any] = {}


__all__ = ["JWTConnector", "JWTDecodeError"]
