# mypy: ignore-errors
import asyncio
import logging
import os
import shutil
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


def _get_tshark_path() -> Optional[str]:
    candidates = [
        shutil.which("tshark"),
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    return next((p for p in candidates if p and os.path.exists(p)), None)


def _require_tshark() -> str:
    path = _get_tshark_path()
    if path is None:
        raise RuntimeError(
            "tshark not found — install Wireshark and ensure "
            "'tshark' is reachable from the command line"
        )
    return path


async def capture_tls_handshakes(
    interface: str, duration_seconds: int = 60
) -> List[Dict[str, Any]]:
    _require_tshark()
    try:
        import pyshark
    except ImportError as exc:
        raise RuntimeError("pyshark is not installed") from exc

    def _do_capture() -> List[Dict[str, Any]]:
        cap = pyshark.LiveCapture(
            interface=interface,
            display_filter="tls.handshake.type == 1 or tls.handshake.type == 2",
            decode_as={"tcp.port==443": "tls"},
        )
        results: List[Dict[str, Any]] = []
        collected = 0
        max_packets = 500

        try:
            for packet in cap.sniff_continuously(packet_count=max_packets):
                try:
                    if not hasattr(packet, "tls"):
                        continue
                    tls_layer = packet.tls
                    handshake_type = getattr(tls_layer, "handshake_type", None)
                    if handshake_type is None:
                        continue

                    entry: Dict[str, Any] = {
                        "timestamp": (
                            getattr(packet, "sniff_time", None).isoformat()
                            if hasattr(packet, "sniff_time") and packet.sniff_time
                            else None
                        ),
                    }

                    if handshake_type == "1":
                        entry.update(
                            {
                                "type": "ClientHello",
                                "src_ip": (
                                    getattr(packet, "ip", None).src
                                    if hasattr(packet, "ip")
                                    else None
                                ),
                                "dst_ip": (
                                    getattr(packet, "ip", None).dst
                                    if hasattr(packet, "ip")
                                    else None
                                ),
                                "dst_port": (
                                    getattr(packet, "tcp", None).dstport
                                    if hasattr(packet, "tcp")
                                    else None
                                ),
                                "tls_version": getattr(
                                    tls_layer, "handshake_version", None
                                ),
                                "cipher_suites": _extract_cipher_suites(tls_layer),
                                "supported_groups": _extract_supported_groups(
                                    tls_layer
                                ),
                            }
                        )
                    elif handshake_type == "2":
                        entry.update(
                            {
                                "type": "ServerHello",
                                "src_ip": (
                                    getattr(packet, "ip", None).dst
                                    if hasattr(packet, "ip")
                                    else None
                                ),
                                "dst_ip": (
                                    getattr(packet, "ip", None).src
                                    if hasattr(packet, "ip")
                                    else None
                                ),
                                "selected_cipher": getattr(
                                    tls_layer, "handshake_ciphersuite", None
                                ),
                                "selected_group": getattr(
                                    tls_layer,
                                    "handshake_extensions_key_share_group",
                                    None,
                                ),
                                "tls_version": getattr(
                                    tls_layer, "handshake_version", None
                                ),
                            }
                        )

                    pqc_groups = {
                        0x01FC: "ML-KEM-512",
                        0x01FD: "ML-KEM-768",
                        0x0200: "ML-KEM-1024",
                        0x2B92: "SecP256r1MLKEM768",
                        0x2B93: "X25519MLKEM768",
                        0x2B94: "SecP384r1MLKEM1024",
                        0xFE30: "X25519Kyber768Draft00",
                        0x639A: "X25519Kyber768Draft00Old",
                    }
                    groups = entry.get("supported_groups") or []
                    parsed_groups = []
                    for g in groups:
                        try:
                            if isinstance(g, str):
                                if g.lower().startswith("0x"):
                                    parsed_groups.append(int(g, 16))
                                else:
                                    parsed_groups.append(int(g))
                            else:
                                parsed_groups.append(int(g))
                        except (ValueError, TypeError):
                            parsed_groups.append(g)
                    entry["pqc_groups_advertised"] = [
                        pqc_groups.get(g, g) for g in parsed_groups if g in pqc_groups
                    ]
                    entry["has_pqc"] = len(entry["pqc_groups_advertised"]) > 0

                    results.append(entry)
                    collected += 1
                except (AttributeError, ValueError, TypeError):
                    continue
        except Exception as exc:
            logger.exception("pyshark capture failed: %s", exc)
        finally:
            try:
                cap.close()
            except Exception:
                pass

        return results

    return await asyncio.to_thread(_do_capture)


async def analyze_pcap_file(pcap_path: str) -> Dict[str, Any]:
    _require_tshark()
    try:
        import pyshark
    except ImportError as exc:
        raise RuntimeError("pyshark is not installed") from exc

    def _do_analyze() -> Dict[str, Any]:
        cap = pyshark.FileCapture(
            input_file=pcap_path,
            display_filter="tls",
            decode_as={"tcp.port==443": "tls"},
        )
        findings: Dict[str, Any] = {
            "total_tls_handshakes": 0,
            "pqc_kex_negotiated": [],
            "vulnerable_kex": [],
            "certificates": [],
            "cipher_suites_seen": set(),
        }
        pqc_group_ids = {0x01FC, 0x01FD, 0x0200, 0x2B92, 0x2B93, 0x2B94, 0xFE30, 0x639A}

        try:
            for packet in cap:
                try:
                    if not hasattr(packet, "tls"):
                        continue
                    tls = packet.tls
                    handshake_type = getattr(tls, "handshake_type", None)
                    if handshake_type is None:
                        continue

                    if handshake_type == "2":
                        findings["total_tls_handshakes"] += 1
                        cipher = getattr(tls, "handshake_ciphersuite", None)
                        if cipher:
                            findings["cipher_suites_seen"].add(cipher)
                        group_raw = getattr(
                            tls, "handshake_extensions_key_share_group", None
                        )
                        if group_raw is not None:
                            try:
                                group_id = int(group_raw)
                            except (TypeError, ValueError):
                                group_id = None
                            if group_id is not None:
                                entry = {
                                    "server": (
                                        getattr(packet, "ip", None).dst
                                        if hasattr(packet, "ip")
                                        else None
                                    ),
                                    "group_id": group_id,
                                    "timestamp": (
                                        getattr(packet, "sniff_time", None).isoformat()
                                        if hasattr(packet, "sniff_time")
                                        and packet.sniff_time
                                        else None
                                    ),
                                }
                                if group_id in pqc_group_ids:
                                    findings["pqc_kex_negotiated"].append(entry)
                                else:
                                    findings["vulnerable_kex"].append(entry)

                    if handshake_type == "11":
                        raw_cert = getattr(tls, "handshake_certificate", None)
                        if raw_cert:
                            findings["certificates"].append(
                                {
                                    "server": (
                                        getattr(packet, "ip", None).dst
                                        if hasattr(packet, "ip")
                                        else None
                                    ),
                                    "raw_cert_hex": str(raw_cert),
                                    "timestamp": (
                                        getattr(packet, "sniff_time", None).isoformat()
                                        if hasattr(packet, "sniff_time")
                                        and packet.sniff_time
                                        else None
                                    ),
                                }
                            )
                except (AttributeError, ValueError, TypeError):
                    continue
        except Exception as exc:
            logger.exception("PCAP analysis failed: %s", exc)
        finally:
            try:
                cap.close()
            except Exception:
                pass

        findings["cipher_suites_seen"] = list(findings["cipher_suites_seen"])
        return findings

    return await asyncio.to_thread(_do_analyze)


def _extract_cipher_suites(tls_layer: Any) -> List[str]:
    suites: List[str] = []
    try:
        for field_name in getattr(tls_layer, "field_names", []):
            if "handshake.ciphersuite" in field_name:
                val = getattr(tls_layer, field_name, None)
                if val:
                    suites.append(str(val))
    except Exception:
        pass
    return suites


def _extract_supported_groups(tls_layer: Any) -> List[str]:
    groups: List[str] = []
    try:
        for field_name in getattr(tls_layer, "field_names", []):
            if "handshake.extensions.supported_group" in field_name:
                val = getattr(tls_layer, field_name, None)
                if val:
                    groups.append(str(val))
    except Exception:
        pass
    return groups


async def capture_ssh_handshakes(
    interface: str, duration_seconds: int = 60
) -> List[Dict[str, Any]]:
    _require_tshark()
    try:
        import pyshark
    except ImportError as exc:
        raise RuntimeError("pyshark is not installed") from exc

    def _do_capture_ssh() -> List[Dict[str, Any]]:
        cap = pyshark.LiveCapture(
            interface=interface,
            display_filter="ssh.message_code == 20",
        )
        results: List[Dict[str, Any]] = []
        collected = 0
        max_packets = 500

        try:
            for packet in cap.sniff_continuously(packet_count=max_packets):
                try:
                    if not hasattr(packet, "ssh"):
                        continue
                    ssh_layer = packet.ssh

                    # Defensively extract SSH algorithms
                    kex_algs = []
                    host_key_algs = []
                    enc_algs = []
                    mac_algs = []

                    for field in getattr(ssh_layer, "field_names", []):
                        if "kex_algorithms" in field:
                            val = getattr(ssh_layer, field, None)
                            if val:
                                kex_algs.extend(str(val).split(","))
                        elif "server_host_key_algorithms" in field:
                            val = getattr(ssh_layer, field, None)
                            if val:
                                host_key_algs.extend(str(val).split(","))
                        elif "encryption_algorithms" in field:
                            val = getattr(ssh_layer, field, None)
                            if val:
                                enc_algs.extend(str(val).split(","))
                        elif "mac_algorithms" in field:
                            val = getattr(ssh_layer, field, None)
                            if val:
                                mac_algs.extend(str(val).split(","))

                    pqc_kex_patterns = ["sntrup761x25519", "mlkem768x25519", "mlkem"]
                    has_pqc = any(
                        any(pat in alg.lower() for pat in pqc_kex_patterns)
                        for alg in kex_algs
                    )

                    entry = {
                        "type": "SSH_KEXINIT",
                        "timestamp": (
                            getattr(packet, "sniff_time", None).isoformat()
                            if hasattr(packet, "sniff_time") and packet.sniff_time
                            else None
                        ),
                        "src_ip": (
                            getattr(packet, "ip", None).src
                            if hasattr(packet, "ip")
                            else None
                        ),
                        "dst_ip": (
                            getattr(packet, "ip", None).dst
                            if hasattr(packet, "ip")
                            else None
                        ),
                        "dst_port": (
                            getattr(packet, "tcp", None).dstport
                            if hasattr(packet, "tcp")
                            else None
                        ),
                        "kex_algorithms": list(set(kex_algs)),
                        "server_host_key_algorithms": list(set(host_key_algs)),
                        "encryption_algorithms": list(set(enc_algs)),
                        "mac_algorithms": list(set(mac_algs)),
                        "has_pqc": has_pqc,
                    }
                    results.append(entry)
                    collected += 1
                except Exception:
                    continue
        except Exception as exc:
            logger.exception("pyshark SSH capture failed: %s", exc)
        finally:
            try:
                cap.close()
            except Exception:
                pass
        return results

    return await asyncio.to_thread(_do_capture_ssh)


async def capture_all_handshakes(
    interface: str, duration_seconds: int = 60
) -> List[Dict[str, Any]]:
    tls_results: Union[List[Dict[str, Any]], Exception]
    ssh_results: Union[List[Dict[str, Any]], Exception]
    tls_results, ssh_results = await asyncio.gather(
        capture_tls_handshakes(interface, duration_seconds),
        capture_ssh_handshakes(interface, duration_seconds),
        return_exceptions=True,
    )
    results = []
    if isinstance(tls_results, list):
        results.extend(tls_results)
    if isinstance(ssh_results, list):
        results.extend(ssh_results)
    return results
