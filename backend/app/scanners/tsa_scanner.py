"""Time-Stamp Authority (TSA) scanner skeleton.

Validates RFC 3161 / CMS time-stamping authorities by fetching their
signing certificate, parsing the chain, and classifying the signature
algorithms for quantum vulnerability.

This is intentionally a skeleton: it performs network discovery and
certificate parsing but does not yet send a full TimeStampReq or verify
an actual timestamp token signature.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from app.scanners.cert_parser import parse_certificate
from app.scanners.safe_target import resolve_safely

logger = logging.getLogger(__name__)

_TSA_USER_AGENT = "PQCryptSentinel/1.0 TSA-Scanner"


class TSAResult:
    """Container for TSA scan results."""

    def __init__(
        self,
        url: str,
        success: bool,
        error_message: Optional[str] = None,
        certificates: Optional[List[Dict[str, Any]]] = None,
    ):
        self.url = url
        self.success = success
        self.error_message = error_message
        self.certificates = certificates or []

    def to_dict(self) -> Dict[str, Any]:
        algorithms: List[str] = []
        statuses: List[str] = []
        for cert in self.certificates:
            algo = cert.get("sig_algorithm") or "unknown"
            if algo not in algorithms:
                algorithms.append(algo)
            status = cert.get("pqc_details", {}).get("pqc_status", "unknown")
            if status not in statuses:
                statuses.append(status)

        worst = "unknown"
        for candidate in ("disallowed_now", "vulnerable", "hybrid", "pqc_ready", "safe"):
            if candidate in statuses:
                worst = candidate
                break

        return {
            "status": "success" if self.success else "error",
            "url": self.url,
            "error": self.error_message,
            "certificates": self.certificates,
            "algorithms": algorithms,
            "pqc_status": worst,
        }


def _extract_pem_blocks(text: str) -> List[str]:
    """Extract PEM certificate blocks from arbitrary text."""
    pattern = re.compile(
        r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
        re.DOTALL,
    )
    blocks: List[str] = []
    for match in pattern.finditer(text):
        body = match.group(1).replace(" ", "").replace("\r", "").replace("\n", "")
        blocks.append(
            "-----BEGIN CERTIFICATE-----\n"
            + "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
            + "\n-----END CERTIFICATE-----"
        )
    return blocks


async def scan_tsa_authority(
    url: str,
    cert_url: Optional[str] = None,
    timeout: int = 15,
) -> TSAResult:
    """Fetch and classify certificates exposed by a TSA endpoint.

    Parameters
    ----------
    url: Base TSA endpoint (e.g. ``http://timestamp.digicert.com``).
    cert_url: Optional direct URL to the TSA signing certificate. When
        omitted, ``url`` itself is fetched and inspected for PEM data.
    timeout: Request timeout in seconds.
    """
    parsed = urlparse(cert_url or url)
    if not parsed.hostname:
        return TSAResult(url=url, success=False, error_message="URL must include a hostname")

    try:
        await resolve_safely(parsed.hostname)
    except Exception as exc:
        return TSAResult(url=url, success=False, error_message=f"SSRF check failed: {exc}")

    target = cert_url or url
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": _TSA_USER_AGENT, "Accept": "*/*"},
        ) as client:
            resp = await client.get(target)
            resp.raise_for_status()
            body = resp.text
    except Exception as exc:
        logger.warning(f"TSA fetch failed for {target}: {exc}")
        return TSAResult(
            url=url,
            success=False,
            error_message=f"Failed to fetch TSA certificate from {target}: {exc}",
        )

    # Look for PEM certificates first.
    pem_blocks = _extract_pem_blocks(body)
    certificates: List[Dict[str, Any]] = []
    errors: List[str] = []

    for pem in pem_blocks:
        try:
            cert_meta = parse_certificate(pem)
            certificates.append(cert_meta)
        except Exception as exc:
            errors.append(f"Certificate parse failed: {exc}")

    if not certificates:
        return TSAResult(
            url=url,
            success=False,
            error_message="No parseable X.509 certificates found in TSA response",
        )

    return TSAResult(
        url=url,
        success=True,
        certificates=certificates,
        error_message="; ".join(errors) if errors else None,
    )


async def scan_tsa_authority_dict(
    url: str,
    cert_url: Optional[str] = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    """Convenience wrapper returning a plain dictionary."""
    result = await scan_tsa_authority(url=url, cert_url=cert_url, timeout=timeout)
    return result.to_dict()
