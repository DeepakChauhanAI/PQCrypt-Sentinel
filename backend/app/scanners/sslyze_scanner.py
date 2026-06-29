import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from app.scanners.cert_parser import parse_certificate

logger = logging.getLogger(__name__)

_SSLYZE_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="sslyze_scanner")


class SSLyzeScanResult:
    def __init__(
        self,
        host: str,
        port: int,
        success: bool,
        error_message: Optional[str] = None,
        tls_versions: Optional[Dict[str, Any]] = None,
        cert_data: Optional[Dict[str, Any]] = None,
        supported_versions: Optional[List[str]] = None,
    ):
        self.host = host
        self.port = port
        self.success = success
        self.error_message = error_message
        self.tls_versions = tls_versions or {}
        self.cert_data = cert_data
        self.supported_versions = supported_versions or []


def _run_sslyze_sync(host: str, port: int, timeout: int = 30) -> Dict[str, Any]:
    from sslyze import (
        ServerNetworkLocation,
        ServerScanRequest,
        ScanCommand,
        ServerNetworkConfiguration,
        Scanner,
    )
    from sslyze.server_connectivity import check_connectivity_to_server

    server_location = ServerNetworkLocation(hostname=host, port=port)
    try:
        network_config = ServerNetworkConfiguration(
            tls_server_name_indication=host,
            network_timeout=timeout,
        )
        connectivity = check_connectivity_to_server(
            server_location,
            network_configuration=network_config,
        )
    except Exception as exc:
        return {"success": False, "error": str(exc)}

    scan_requests = [
        ServerScanRequest(
            server_info=connectivity,  # type: ignore[call-arg]
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
            },
        ),
    ]

    scanner = Scanner()
    scan_results = list(scanner.get_results(scan_requests))  # type: ignore[call-arg]

    tls_versions: Dict[str, Any] = {}
    cert_info_raw: Optional[Any] = None

    for result in scan_results:
        cmd_results = result.scan_commands_results  # type: ignore[attr-defined]

        for tls_cmd in (
            ScanCommand.TLS_1_3_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
        ):
            if tls_cmd not in cmd_results:
                continue
            cipher_result = cmd_results[tls_cmd]
            tls_versions[tls_cmd.name] = {
                "accepted_ciphers": [
                    {"name": cs.name, "key_size": getattr(cs, "key_size", None)}
                    for cs in cipher_result.accepted_cipher_suites
                ],
                "rejected_count": len(cipher_result.rejected_cipher_suites),
            }

        if ScanCommand.CERTIFICATE_INFO in cmd_results:
            cert_info_raw = cmd_results[ScanCommand.CERTIFICATE_INFO]

    cert_data = None
    if cert_info_raw and getattr(cert_info_raw, "certificate_deployments", None):
        try:
            leaf = cert_info_raw.certificate_deployments[0]
            pem = leaf.received_certificate_chain[0].certificate.public_bytes_pem().decode("utf-8")
            cert_data = parse_certificate(pem)
        except Exception as exc:
            logger.warning("sslyze cert parse failed: %s", exc)

    supported = [v for v, info in tls_versions.items() if info.get("accepted_ciphers")]
    return {
        "success": True,
        "tls_versions": tls_versions,
        "cert_data": cert_data,
        "supported_versions": supported,
    }


async def scan_endpoint_with_sslyze(host: str, port: int = 443, timeout: int = 30) -> SSLyzeScanResult:
    try:
        loop = __import__("asyncio").get_event_loop()
        result = await __import__("asyncio").wait_for(
            loop.run_in_executor(_SSLYZE_EXECUTOR, _run_sslyze_sync, host, port, timeout),
            timeout=timeout + 10,
        )
        if not result.get("success"):
            return SSLyzeScanResult(
                host=host, port=port, success=False, error_message=result.get("error")
            )
        return SSLyzeScanResult(
            host=host,
            port=port,
            success=True,
            tls_versions=result.get("tls_versions", {}),
            cert_data=result.get("cert_data"),
            supported_versions=result.get("supported_versions", []),
        )
    except Exception as exc:
        return SSLyzeScanResult(host=host, port=port, success=False, error_message=str(exc))
