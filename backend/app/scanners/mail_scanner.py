import asyncio
import logging
import socket
import ssl
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor

from app.scanners.cert_parser import parse_certificate
from app.utils.retry import async_retry

_MAIL_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="mail_scanner")

_SMTP_PORTS = {
    25: "smtp-starttls",
    465: "smtps",
    587: "submission-starttls",
}

_EHLO_DOMAIN = "scanner.local"


class MailScanResult:
    def __init__(
        self,
        host: str,
        port: int,
        success: bool,
        error_message: Optional[str] = None,
        mode: Optional[str] = None,
        banner: Optional[str] = None,
        ehlo_response: Optional[str] = None,
        starttls_supported: bool = False,
        cert_data: Optional[Dict[str, Any]] = None,
        tls_version: Optional[str] = None,
        cipher_suite: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.success = success
        self.error_message = error_message
        self.mode = mode
        self.banner = banner
        self.ehlo_response = ehlo_response
        self.starttls_supported = starttls_supported
        self.cert_data = cert_data
        self.tls_version = tls_version
        self.cipher_suite = cipher_suite


def _recv_line(sock: socket.socket, timeout: int) -> str:
    sock.settimeout(timeout)
    data = b""
    while b"\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", errors="replace").strip()


def _do_mail_connect(host: str, port: int, timeout: int, verify_tls: bool = False) -> Dict[str, Any]:
    """Blocking mail probe — runs in a thread executor.

    `verify_tls=False` (default) preserves historical MITM-tolerant behaviour
    for posture discovery against internal mail relays. Pass `verify_tls=True`
    for full chain validation.
    """
    mode = _SMTP_PORTS.get(port, "unknown")
    try:
        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        if port == 465:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    banner = _recv_line(ssock, timeout)
                    tls_version = getattr(ssock, "version", lambda: None)()
                    cipher = ssock.cipher()
                    cipher_name = cipher[0] if cipher else None
                    der_cert = ssock.getpeercert(binary_form=True)
            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
            parsed_cert = parse_certificate(pem_cert)
            return {
                "success": True,
                "mode": mode,
                "banner": banner,
                "starttls_supported": False,
                "cert_data": parsed_cert,
                "tls_version": tls_version,
                "cipher_suite": cipher_name,
            }

        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = _recv_line(sock, timeout)
            if not banner.startswith(("220", "250")):
                return {
                    "success": True,
                    "mode": mode,
                    "banner": banner,
                    "starttls_supported": False,
                    "cert_data": None,
                    "tls_version": None,
                    "cipher_suite": None,
                    "error_message": f"Unexpected SMTP banner: {banner}",
                }
            ehlo = f"EHLO {_EHLO_DOMAIN}\r\n".encode("utf-8")
            sock.sendall(ehlo)
            ehlo_response = _recv_line(sock, timeout)
            starttls_supported = "STARTTLS" in ehlo_response.upper()
            if not starttls_supported:
                return {
                    "success": True,
                    "mode": mode,
                    "banner": banner,
                    "ehlo_response": ehlo_response,
                    "starttls_supported": False,
                    "cert_data": None,
                    "tls_version": None,
                    "cipher_suite": None,
                }
            sock.sendall(b"STARTTLS\r\n")
            resp = _recv_line(sock, timeout)
            if not resp.startswith("220"):
                return {
                    "success": True,
                    "mode": mode,
                    "banner": banner,
                    "ehlo_response": ehlo_response,
                    "starttls_supported": True,
                    "cert_data": None,
                    "tls_version": None,
                    "cipher_suite": None,
                    "error_message": f"STARTTLS rejected: {resp}",
                }
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                tls_version = getattr(ssock, "version", lambda: None)()
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else None
                der_cert = ssock.getpeercert(binary_form=True)
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        parsed_cert = parse_certificate(pem_cert)
        return {
            "success": True,
            "mode": mode,
            "banner": banner,
            "ehlo_response": ehlo_response,
            "starttls_supported": True,
            "cert_data": parsed_cert,
            "tls_version": tls_version,
            "cipher_suite": cipher_name,
        }
    except Exception as exc:
        return {"success": False, "error_message": str(exc)}


@async_retry(attempts=2, initial_delay=0.5, retry_on=(asyncio.TimeoutError, ConnectionError, OSError))
async def scan_mail_endpoint(
    host: str,
    port: int = 25,
    timeout: int = 10,
    verify_tls: bool = False,
) -> MailScanResult:
    """Probe a mail endpoint for STARTTLS / SMTPS and capture its TLS certificate."""
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(_MAIL_EXECUTOR, _do_mail_connect, host, port, timeout, verify_tls),
            timeout=timeout + 2,
        )
        if not result["success"]:
            return MailScanResult(host=host, port=port, success=False, error_message=result.get("error_message"))
        return MailScanResult(
            host=host,
            port=port,
            success=True,
            mode=result.get("mode"),
            banner=result.get("banner"),
            ehlo_response=result.get("ehlo_response"),
            starttls_supported=result.get("starttls_supported", False),
            cert_data=result.get("cert_data"),
            tls_version=result.get("tls_version"),
            cipher_suite=result.get("cipher_suite"),
        )
    except Exception as exc:
        return MailScanResult(host=host, port=port, success=False, error_message=str(exc))
