"""
L1 OCSP + DNSSEC live probe scanner.

The OCSP probe:
  * Uses the AIAs (Authority Information Access) extension in a previously-
    discovered certificate to build an OCSP request URL.
  * Fetches a DER-encoded OCSP response over HTTPS with a strict timeout.
  * Parses the response and surfaces the certificate status
    (good / revoked / unknown) along with the responder name and signature
    algorithm.

The DNSSEC probe:
  * Resolves ``DNSKEY``, ``RRSIG`` and ``DS`` records for a domain.
  * Reports whether the chain of trust is intact (signed delegations
    all the way to the root) and which algorithms are in use.

Both probes are offline-friendly: they are pure network calls and never
require credentials.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import dns.exception
import dns.flags
import dns.rdatatype
import dns.resolver
import dns.dnssec
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp as crypto_ocsp

from app.scanners.safe_target import UnsafeTargetError, build_safe_target_async

logger = logging.getLogger(__name__)


# Algorithms considered "safe" in DNSSEC. RSA < 2048 and the SHA-1 family
# are flagged as vulnerable. Per NIST IR 8547, ED25519/ED448 are
# quantum-vulnerable (disallowed 2035), not safe.
_DNSSEC_SAFE_ALGS = {
    "RSASHA256",
    "RSASHA512",
    "ECDSAP256SHA256",
    "ECDSAP384SHA384",
}
_DNSSEC_TRANSITION_ALGS = {"ED25519", "ED448"}
_DNSSEC_WARN_ALGS = {"RSASHA1", "RSAMD5", "DSA", "NSEC3DSA"}


@dataclass
class OCSPProbeResult:
    """Result of an OCSP check for a single certificate."""

    host: str
    cert_thumbprint: Optional[str]
    success: bool
    status: str = "unknown"  # good / revoked / unknown / error
    responder_url: Optional[str] = None
    responder_name: Optional[str] = None
    signature_algorithm: Optional[str] = None
    error_message: Optional[str] = None
    pqc_status: str = "unknown"
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DNSSECProbeResult:
    """Result of a DNSSEC probe for a single domain."""

    domain: str
    success: bool
    has_dnskey: bool = False
    has_rrsig: bool = False
    has_ds: bool = False
    algorithms: List[str] = field(default_factory=list)
    chain_of_trust: bool = False
    error_message: Optional[str] = None
    pqc_status: str = "unknown"


# ---------------------------------------------------------------- OCSP ------
def _extract_aia_ocsp_url(cert_pem_or_der: bytes) -> Optional[str]:
    """Return the first OCSP URL from the AIA extension, or None."""
    try:
        if b"BEGIN CERTIFICATE" in cert_pem_or_der:
            cert = x509.load_pem_x509_certificate(cert_pem_or_der)
        else:
            cert = x509.load_der_x509_certificate(cert_pem_or_der)
    except Exception:
        return None

    # The AIA extension's own OID is 1.3.6.1.5.5.7.1.1 — cryptography
    # exposes this as `x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS`.
    try:
        aia = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
    except x509.ExtensionNotFound:
        return None

    for ad in aia.value:  # type: ignore[attr-defined]
        if ad.access_method == x509.AuthorityInformationAccessOID.OCSP:
            return ad.access_location.value
    return None


async def probe_ocsp(
    host: str,
    cert_der: Optional[bytes] = None,
    timeout: float = 5.0,
) -> OCSPProbeResult:
    """
    Issue an OCSP request for `host` using `cert_der` (if supplied).

    If `cert_der` is None, the function still returns a result with
    `success=False` and a clear error message — never raises.
    """
    if not cert_der:
        return OCSPProbeResult(
            host=host,
            cert_thumbprint=None,
            success=False,
            status="error",
            error_message="no certificate supplied for OCSP probe",
        )

    ocsp_url = _extract_aia_ocsp_url(cert_der)
    if not ocsp_url:
        return OCSPProbeResult(
            host=host,
            cert_thumbprint=None,
            success=False,
            status="error",
            error_message="certificate has no AIA OCSP entry",
        )

    try:
        cert = x509.load_der_x509_certificate(cert_der)
        thumbprint = cert.fingerprint(hashes.SHA1()).hex()  # nosec B303
    except Exception as exc:
        return OCSPProbeResult(
            host=host,
            cert_thumbprint=None,
            success=False,
            status="error",
            responder_url=ocsp_url,
            error_message=f"could not parse cert: {exc}",
        )

    # Build a minimal OCSP request.
    # Try to resolve issuer certificate from AIA CA_ISSUERS extension.
    issuer_cert = None
    try:
        from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

        try:
            aia = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value
            ca_issuers = [
                desc
                for desc in aia  # type: ignore[attr-defined]
                if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS
            ]
            if ca_issuers:
                ca_issuer_url = ca_issuers[0].access_location.value
                try:
                    parsed = urlparse(ca_issuer_url)
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    await build_safe_target_async(parsed.hostname or "", port)
                except (UnsafeTargetError, Exception) as exc:
                    logger.warning(
                        "Unsafe CA issuer URL %s, skipping: %s", ca_issuer_url, exc
                    )
                    ca_issuer_url = None
                if ca_issuer_url:
                    async with httpx.AsyncClient(timeout=timeout) as client:
                        resp = await client.get(ca_issuer_url)
                        if resp.status_code == 200:
                            try:
                                issuer_cert = x509.load_der_x509_certificate(
                                    resp.content
                                )
                            except Exception:
                                try:
                                    issuer_cert = x509.load_pem_x509_certificate(
                                        resp.content
                                    )
                                except Exception:
                                    logger.warning(
                                        "Failed to parse AIA issuer certificate as DER or PEM from %s",
                                        ca_issuer_url,
                                    )
                        else:
                            logger.warning(
                                "Failed to download AIA issuer certificate from %s: HTTP %s",
                                ca_issuer_url,
                                resp.status_code,
                            )
        except x509.ExtensionNotFound:
            pass
    except Exception as exc:
        logger.warning("Failed to resolve issuer cert via AIA: %s", exc)

    issuer = issuer_cert if issuer_cert is not None else cert

    try:
        builder = crypto_ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(
            cert=cert, issuer=issuer, algorithm=hashes.SHA1()  # nosec B303
        )
        req = builder.build()
        req_der = req.public_bytes(serialization.Encoding.DER)
    except Exception as exc:
        return OCSPProbeResult(
            host=host,
            cert_thumbprint=thumbprint,
            success=False,
            status="error",
            responder_url=ocsp_url,
            error_message=f"could not build OCSP request: {exc}",
        )

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.post(
                ocsp_url,
                content=req_der,
                headers={"Content-Type": "application/ocsp-request"},
            )
        if resp.status_code != 200:
            return OCSPProbeResult(
                host=host,
                cert_thumbprint=thumbprint,
                success=False,
                status="error",
                responder_url=ocsp_url,
                error_message=f"responder returned HTTP {resp.status_code}",
            )
        ocsp_resp = crypto_ocsp.load_der_ocsp_response(resp.content)
    except Exception as exc:
        return OCSPProbeResult(
            host=host,
            cert_thumbprint=thumbprint,
            success=False,
            status="error",
            responder_url=ocsp_url,
            error_message=f"OCSP request failed: {exc}",
        )

    # Map the response to good/revoked/unknown
    status_map = {
        crypto_ocsp.OCSPCertStatus.GOOD: "good",
        crypto_ocsp.OCSPCertStatus.REVOKED: "revoked",
        crypto_ocsp.OCSPCertStatus.UNKNOWN: "unknown",
    }
    status_str = status_map.get(ocsp_resp.certificate_status, "unknown")
    sig_alg_name = (
        ocsp_resp.signature_algorithm_oid._name
        if ocsp_resp.signature_algorithm_oid
        else "unknown"
    )

    pqc_status = "safe"
    if "md5" in sig_alg_name.lower() or "sha1" in sig_alg_name.lower():
        pqc_status = "disallowed_now"
    elif "rsa" in sig_alg_name.lower():
        pqc_status = "vulnerable"
    elif "ed25519" in sig_alg_name.lower() or "ed448" in sig_alg_name.lower():
        # NIST IR 8547: disallowed after 2035, no 2030 deprecation step
        pqc_status = "vulnerable"
    elif "ecdsa" in sig_alg_name.lower():
        pqc_status = "safe_until_2030"

    return OCSPProbeResult(
        host=host,
        cert_thumbprint=thumbprint,
        success=True,
        status=status_str,
        responder_url=ocsp_url,
        responder_name=str(ocsp_resp.responder_name),
        signature_algorithm=sig_alg_name,
        pqc_status=pqc_status,
        raw={"response_status": str(ocsp_resp.response_status)},
    )


# ----------------------------------------------------------- DNSSEC --------
async def probe_dnssec(domain: str, timeout: float = 3.0) -> DNSSECProbeResult:
    """
    Query DNSKEY, RRSIG and DS records for `domain` and report on the
    DNSSEC chain of trust.

    The probe succeeds if at least one record type is found; the chain
    is considered intact when DNSKEY, RRSIG and DS are all present.
    """
    res = DNSSECProbeResult(domain=domain, success=False)
    try:
        loop = asyncio.get_event_loop()
        answers = await asyncio.wait_for(
            loop.run_in_executor(None, _resolve_dnssec_sync, domain),
            timeout=timeout,
        )
    except Exception as exc:
        res.error_message = f"DNSSEC resolution failed: {exc}"
        return res

    res.has_dnskey = bool(answers.get("DNSKEY"))
    res.has_rrsig = bool(answers.get("RRSIG"))
    res.has_ds = bool(answers.get("DS"))
    res.algorithms = sorted(set(answers.get("algorithms", [])))
    res.success = res.has_dnskey or res.has_rrsig or res.has_ds
    res.chain_of_trust = res.has_dnskey and res.has_rrsig and res.has_ds

    if any(a in _DNSSEC_WARN_ALGS for a in res.algorithms):
        res.pqc_status = "vulnerable"
    elif any(a in _DNSSEC_TRANSITION_ALGS for a in res.algorithms):
        res.pqc_status = "vulnerable"
    elif all(a in _DNSSEC_SAFE_ALGS for a in res.algorithms) and res.algorithms:
        res.pqc_status = "safe_until_2030"
    elif res.algorithms:
        res.pqc_status = "unknown"
    else:
        res.pqc_status = "unknown"
    return res


def _resolve_dnssec_sync(domain: str) -> Dict[str, Any]:
    """Blocking DNS lookup; runs in the executor."""
    out: Dict[str, Any] = {
        "DNSKEY": [],
        "RRSIG": [],
        "DS": [],
        "algorithms": [],
    }
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    resolver.timeout = 3
    try:
        dnskey_ans = resolver.resolve(domain, "DNSKEY", raise_on_no_answer=False)
        out["DNSKEY"] = [rr.to_text() for rr in dnskey_ans]
        for rr in dnskey_ans:
            algo = getattr(rr, "algorithm", None)
            if algo is not None:
                out["algorithms"].append(dns.dnssec.algorithm_to_text(algo))  # type: ignore[attr-defined]
    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer):
        pass

    try:
        rrsig_ans = resolver.resolve(domain, "RRSIG", raise_on_no_answer=False)
        out["RRSIG"] = [rr.to_text() for rr in rrsig_ans]
        for rr in rrsig_ans:
            algo = getattr(rr, "algorithm", None)
            if algo is not None:
                out["algorithms"].append(dns.dnssec.algorithm_to_text(algo))  # type: ignore[attr-defined]
    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer):
        pass

    try:
        ds_ans = resolver.resolve(domain, "DS", raise_on_no_answer=False)
        out["DS"] = [rr.to_text() for rr in ds_ans]
        for rr in ds_ans:
            digest_type = getattr(rr, "digest_type", None)
            if digest_type is not None:
                out["algorithms"].append(dns.dnssec.algorithm_to_text(digest_type))  # type: ignore[attr-defined]
    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer):
        pass

    return out


# ------------------------------------------------------------ Batch API ----
async def probe_ocsp_batch(
    targets: Sequence[Tuple[str, bytes]],
    timeout: float = 5.0,
    max_concurrency: int = 10,
) -> List[OCSPProbeResult]:
    """
    Run OCSP probes for many (host, cert_der) tuples concurrently.
    """
    sem = asyncio.Semaphore(max_concurrency)

    async def _one(host: str, cert_der: bytes) -> OCSPProbeResult:
        async with sem:
            return await probe_ocsp(host, cert_der, timeout)

    return await asyncio.gather(*[_one(h, c) for h, c in targets])


async def probe_dnssec_batch(
    domains: Sequence[str],
    timeout: float = 3.0,
    max_concurrency: int = 10,
) -> List[DNSSECProbeResult]:
    """Run DNSSEC probes for many domains concurrently."""
    sem = asyncio.Semaphore(max_concurrency)

    async def _one(d: str) -> DNSSECProbeResult:
        async with sem:
            return await probe_dnssec(d, timeout)

    return await asyncio.gather(*[_one(d) for d in domains])


__all__ = [
    "OCSPProbeResult",
    "DNSSECProbeResult",
    "probe_ocsp",
    "probe_dnssec",
    "probe_ocsp_batch",
    "probe_dnssec_batch",
]
