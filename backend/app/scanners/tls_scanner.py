# mypy: ignore-errors
import asyncio
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from app.scanners.cert_parser import parse_certificate
from app.utils.retry import async_retry

_SSL_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="tls_scanner")


class TLSScanResult:
    def __init__(
        self,
        host: str,
        port: int,
        success: bool,
        error_message: Optional[str] = None,
        tls_version: Optional[str] = None,
        cipher_suite: Optional[str] = None,
        cert_data: Optional[Dict[str, Any]] = None,
        supported_versions: Optional[List[str]] = None,
    ):
        self.host = host
        self.port = port
        self.success = success
        self.error_message = error_message
        self.tls_version = tls_version
        self.cipher_suite = cipher_suite
        self.cert_data = cert_data
        self.supported_versions = supported_versions or []


def _do_tls_connect(
    host: str, port: int, timeout: int, verify_tls: bool = True
) -> Dict[str, Any]:
    """Blocking TLS handshake — must run in a thread executor.

    `verify_tls=True` (default) performs full chain validation against the
    system trust store — the only safe posture for production scans. Pass
    `verify_tls=False` to explicitly opt out via Scan.config["strict_tls"]=False
    when scanning internal PKI / self-signed endpoints.
    """
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            negotiated_protocol = ssock.version()
            negotiated_cipher = ssock.cipher()

    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
    parsed_cert = parse_certificate(pem_cert)
    cipher_name = negotiated_cipher[0] if negotiated_cipher else None

    return {
        "tls_version": negotiated_protocol,
        "cipher_suite": cipher_name,
        "cert_data": parsed_cert,
        "supported_versions": [negotiated_protocol],
    }


@async_retry(
    attempts=2,
    initial_delay=0.5,
    retry_on=(asyncio.TimeoutError, ConnectionError, OSError),
)
async def scan_tls_endpoint(
    host: str,
    port: int = 443,
    timeout: int = 10,
    verify_tls: bool = True,
) -> TLSScanResult:
    """Scan a target host and port for TLS configuration and certificate."""
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(
                _SSL_EXECUTOR, _do_tls_connect, host, port, timeout, verify_tls
            ),
            timeout=timeout + 2,
        )
        return TLSScanResult(
            host=host,
            port=port,
            success=True,
            tls_version=result["tls_version"],
            cipher_suite=result["cipher_suite"],
            cert_data=result["cert_data"],
            supported_versions=result["supported_versions"],
        )
    except Exception as e:
        return TLSScanResult(
            host=host,
            port=port,
            success=False,
            error_message=str(e),
        )
