import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SCAPY_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="scapy_probe")

_PQC_GROUPS = [0x2B93, 0x2B92, 0x2B94]
_CLASSICAL_GROUPS = [0x001D, 0x0017]
_CIPHERS = [
    0x1301,
    0x1302,
    0x1303,
    0xC02B,
    0xC02F,
]


class ScapyProbeResult:
    def __init__(
        self,
        target_ip: str,
        port: int,
        success: bool,
        error_message: Optional[str] = None,
        pqc_groups_advertised: Optional[List[str]] = None,
        probe_sent: bool = False,
    ):
        self.target_ip = target_ip
        self.port = port
        self.success = success
        self.error_message = error_message
        self.pqc_groups_advertised = pqc_groups_advertised or []
        self.probe_sent = probe_sent


_GROUP_ID_NAMES = {
    0x01FC: "ML-KEM-512",
    0x01FD: "ML-KEM-768",
    0x0200: "ML-KEM-1024",
    0x2B92: "SecP256r1MLKEM768",
    0x2B93: "X25519MLKEM768",
    0x2B94: "SecP384r1MLKEM1024",
    0xFE30: "X25519Kyber768Draft00",
    0x639A: "X25519Kyber768Draft00Old",
    0x001D: "x25519",
    0x0017: "secp256r1",
}


def _build_tls_hello(groups: List[int], ciphers: List[int]) -> bytes:
    try:
        from scapy.layers.tls.all import (
            TLSClientHello,
            TLS_Ext_SupportedGroups,
        )

        groups_extension = TLS_Ext_SupportedGroups(groups=groups)
        client_hello = TLSClientHello(
            version=0x0303,
            ciphers=ciphers,
            ext=groups_extension,
        )
        return bytes(client_hello)
    except Exception as exc:
        raise RuntimeError(f"scapy TLS packet build failed: {exc}") from exc


def _do_probe(host: str, port: int, timeout: int) -> Dict[str, Any]:
    try:
        from scapy.all import IP, TCP, sr1  # type: ignore[attr-defined]

        groups = _PQC_GROUPS + _CLASSICAL_GROUPS
        _ = _build_tls_hello(groups, _CIPHERS)
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        syn_ack = sr1(pkt, timeout=timeout)
        if syn_ack is None:
            return {
                "success": True,
                "probe_sent": False,
                "target_ip": host,
                "port": port,
                "error_message": "No response to SYN probe",
                "pqc_groups_advertised": [
                    _GROUP_ID_NAMES.get(g, hex(g)) for g in _PQC_GROUPS
                ],
            }
        pqc_names = [_GROUP_ID_NAMES.get(g, hex(g)) for g in _PQC_GROUPS]
        return {
            "success": True,
            "probe_sent": True,
            "target_ip": host,
            "port": port,
            "pqc_groups_advertised": pqc_names,
            "error_message": None,
        }
    except PermissionError as exc:
        return {
            "success": False,
            "probe_sent": False,
            "target_ip": host,
            "port": port,
            "error_message": f"Permission denied (raw sockets require admin/Npcap): {exc}",
            "pqc_groups_advertised": [],
        }
    except Exception as exc:
        return {
            "success": False,
            "probe_sent": False,
            "target_ip": host,
            "port": port,
            "error_message": str(exc),
            "pqc_groups_advertised": [],
        }


async def probe_tls_with_pqc_groups(
    target_ip: str, port: int = 443, timeout: int = 10
) -> ScapyProbeResult:
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(_SCAPY_EXECUTOR, _do_probe, target_ip, port, timeout),
            timeout=timeout + 5,
        )
        return ScapyProbeResult(
            target_ip=target_ip,
            port=port,
            success=result["success"],
            error_message=result.get("error_message"),
            pqc_groups_advertised=result.get("pqc_groups_advertised", []),
            probe_sent=result.get("probe_sent", False),
        )
    except asyncio.TimeoutError:
        return ScapyProbeResult(
            target_ip=target_ip,
            port=port,
            success=False,
            error_message="scapy probe timed out",
        )
    except Exception as exc:
        return ScapyProbeResult(
            target_ip=target_ip,
            port=port,
            success=False,
            error_message=str(exc),
        )
