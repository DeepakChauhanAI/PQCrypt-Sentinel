import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor

import httpx

from app.scanners.cert_parser import parse_certificate

_CT_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ct_log_scanner")

_CT_ENDPOINTS = [
    "https://crt.sh/?q={domain}&output=json",
    "https://ct.googleapis.com/logs/argon2026?ct=json",
]


class CTLogResult:
    def __init__(
        self,
        domain: str,
        success: bool,
        error_message: Optional[str] = None,
        certificates: Optional[List[Dict[str, Any]]] = None,
    ):
        self.domain = domain
        self.success = success
        self.error_message = error_message
        self.certificates = certificates or []


def _fetch_ct_json(url: str, timeout: int) -> List[Dict[str, Any]]:
    headers = {"User-Agent": "PQCryptSentinel/1.0"}
    with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.json()


async def scan_ct_logs_for_domain(domain: str, timeout: int = 15) -> CTLogResult:
    """Query crt.sh for certificates observed in public CT logs for a domain."""
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        loop = asyncio.get_event_loop()
        data = await asyncio.wait_for(
            loop.run_in_executor(_CT_EXECUTOR, _fetch_ct_json, url, timeout),
            timeout=timeout + 2,
        )
        if not isinstance(data, list):
            return CTLogResult(domain=domain, success=False, error_message="Unexpected CT log response format")
        return CTLogResult(domain=domain, success=True, certificates=data)
    except Exception as exc:
        return CTLogResult(domain=domain, success=False, error_message=str(exc))
