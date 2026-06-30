import asyncio
import logging
import shutil
import socket
from typing import Any, Dict, List, Optional, TypedDict
from concurrent.futures import ThreadPoolExecutor

from app.utils.retry import async_retry

logger = logging.getLogger(__name__)


class _IKEResultDict(TypedDict, total=False):
    """Typed shape of the dictionary returned by `_do_ike_probe`.

    Additional ad-hoc keys (raw_response, stdout, stderr) may appear
    when the function falls back to the ike-scan binary; the TypedDict
    lists only the fields that callers actually consume.
    """

    success: bool
    skipped: bool
    error_message: str
    ike_version: str
    dh_groups: List[str]
    encryption_algorithms: List[str]
    integrity_algorithms: List[str]
    pqc_dh_groups: List[str]
    pqc_status: str
    response_len: int
    raw_response: str
    stdout: str
    stderr: str


_IKE_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ike_scanner")

_IKEV2_HEADER_LEN = 28
_IKEV2_MIN_RESPONSE_LEN = _IKEV2_HEADER_LEN

_DH_GROUP_POLICY: Dict[str, Dict[str, str]] = {
    "1": {"name": "768-bit MODP", "pqc_status": "vulnerable"},
    "2": {"name": "1024-bit MODP", "pqc_status": "vulnerable"},
    "5": {"name": "1536-bit MODP", "pqc_status": "vulnerable"},
    "14": {"name": "2048-bit MODP", "pqc_status": "vulnerable"},
    "15": {"name": "3072-bit MODP", "pqc_status": "vulnerable"},
    "16": {"name": "4096-bit MODP", "pqc_status": "vulnerable"},
    "17": {"name": "6144-bit MODP", "pqc_status": "vulnerable"},
    "18": {"name": "8192-bit MODP", "pqc_status": "vulnerable"},
    "19": {"name": "256-bit random ECP (NIST P-256)", "pqc_status": "vulnerable"},
    "20": {"name": "384-bit random ECP (NIST P-384)", "pqc_status": "vulnerable"},
    "21": {"name": "521-bit random ECP (secp521r1)", "pqc_status": "vulnerable"},
    "22": {"name": "1024-bit MODP with 160-bit POS", "pqc_status": "vulnerable"},
    "23": {"name": "2048-bit MODP with 224-bit POS", "pqc_status": "vulnerable"},
    "24": {"name": "2048-bit MODP with 256-bit POS", "pqc_status": "vulnerable"},
    "25": {"name": "192-bit random ECP", "pqc_status": "vulnerable"},
    "26": {"name": "224-bit random ECP", "pqc_status": "vulnerable"},
    "27": {"name": "224-bit random ECP (secp224r1)", "pqc_status": "vulnerable"},
    "28": {"name": "256-bit random ECP (secp256r1)", "pqc_status": "vulnerable"},
    "29": {"name": "384-bit random ECP (secp384r1)", "pqc_status": "vulnerable"},
    "30": {"name": "521-bit random ECP (secp521r1)", "pqc_status": "vulnerable"},
    "31": {"name": "256-bit random ECP (brainpoolP256r1)", "pqc_status": "vulnerable"},
    "32": {"name": "384-bit random ECP (brainpoolP384r1)", "pqc_status": "vulnerable"},
    "33": {"name": "521-bit random ECP (brainpoolP512r1)", "pqc_status": "vulnerable"},
    "34": {"name": "256-bit random ECP (curve25519)", "pqc_status": "vulnerable"},
    "35": {"name": "448-bit random ECP (curve448)", "pqc_status": "vulnerable"},
    "36": {"name": "256-bit random ECP (curve25519, hybrid)", "pqc_status": "hybrid"},
    "37": {"name": "448-bit random ECP (curve448, hybrid)", "pqc_status": "hybrid"},
    "38": {"name": "ML-KEM-768", "pqc_status": "pqc_ready"},
    "39": {"name": "ML-KEM-1024", "pqc_status": "pqc_ready"},
    "40": {"name": "ML-KEM-512", "pqc_status": "pqc_ready"},
}


class IKEScanResult:
    def __init__(
        self,
        host: str,
        port: int,
        success: bool,
        error_message: Optional[str] = None,
        ike_version: Optional[str] = None,
        dh_groups: Optional[List[str]] = None,
        encryption_algorithms: Optional[List[str]] = None,
        integrity_algorithms: Optional[List[str]] = None,
        pqc_dh_groups: Optional[List[str]] = None,
        pqc_status: str = "unknown",
    ):
        self.host = host
        self.port = port
        self.success = success
        self.error_message = error_message
        self.ike_version = ike_version
        self.dh_groups = dh_groups or []
        self.encryption_algorithms = encryption_algorithms or []
        self.integrity_algorithms = integrity_algorithms or []
        self.pqc_dh_groups = pqc_dh_groups or []
        self.pqc_status = pqc_status


def _parse_ikev2_response(data: bytes) -> Dict[str, Any]:
    if len(data) < 28:
        return {"error": "Response too short"}

    next_payload = data[16]
    offset = 28

    dh_groups = []
    pqc_status = "vulnerable"
    encryption = []
    integrity = []

    while next_payload != 0 and offset < len(data):
        if offset + 4 > len(data):
            break

        payload_type = next_payload
        next_payload = data[offset]
        pay_len = int.from_bytes(data[offset + 2 : offset + 4], "big")

        if pay_len < 4 or offset + pay_len > len(data):
            break

        payload_body = data[offset + 4 : offset + pay_len]

        # Parse SA Payload (Type 33)
        if payload_type == 33:
            idx = 0
            while idx + 8 <= len(payload_body):
                t_type = payload_body[idx + 4]
                t_id = int.from_bytes(payload_body[idx + 6 : idx + 8], "big")
                t_len = int.from_bytes(payload_body[idx + 2 : idx + 4], "big")

                if t_type == 4:  # DH
                    dh_str = str(t_id)
                    if dh_str in _DH_GROUP_POLICY:
                        dh_groups.append(_DH_GROUP_POLICY[dh_str]["name"])
                        status = _DH_GROUP_POLICY[dh_str]["pqc_status"]
                        if status == "pqc_ready":
                            pqc_status = "pqc_ready"
                        elif status == "hybrid" and pqc_status != "pqc_ready":
                            pqc_status = "hybrid"
                    else:
                        dh_groups.append(f"DH Group {t_id}")
                elif t_type == 1:  # ENCR
                    encryption.append(f"ENCR_{t_id}")
                elif t_type == 3:  # INTEG
                    integrity.append(f"INTEG_{t_id}")

                if t_len >= 8:
                    idx += t_len
                else:
                    idx += 8

        # Parse Notify Payload (Type 41)
        elif payload_type == 41:
            if len(payload_body) >= 4:
                msg_type = int.from_bytes(payload_body[2:4], "big")
                # Type 17 is INVALID_KE_PAYLOAD
                if msg_type == 17:
                    spi_size = payload_body[1]
                    data_offset = 4 + spi_size
                    if len(payload_body) >= data_offset + 2:
                        pref_group = int.from_bytes(
                            payload_body[data_offset : data_offset + 2], "big"
                        )
                        dh_str = str(pref_group)
                        if dh_str in _DH_GROUP_POLICY:
                            dh_groups.append(_DH_GROUP_POLICY[dh_str]["name"])
                            pqc_status = _DH_GROUP_POLICY[dh_str]["pqc_status"]
                        else:
                            dh_groups.append(f"DH Group {pref_group}")
                            pqc_status = "vulnerable"

        offset += pay_len

    return {
        "dh_groups": list(set(dh_groups)),
        "pqc_status": pqc_status,
        "encryption_algorithms": list(set(encryption)),
        "integrity_algorithms": list(set(integrity)),
    }


def _do_socket_ike_probe(host: str, port: int, timeout: int) -> _IKEResultDict:
    try:
        ispi = b"\x3f\x5a\x2b\x1c\x0d\x9e\x8f\x7a"
        rspi = b"\x00" * 8
        next_payload = 33  # SA
        version = 0x20
        exch = 34  # IKE_SA_INIT
        flags = 0x08  # Initiator
        msg_id = b"\x00\x00\x00\x00"

        sa_bytes = (
            b"\x22\x00\x00\x30"  # Next payload: 34 (KE), length: 48
            b"\x00\x00\x00\x2c"  # Proposal #1, Protocol: IKE, SPI: 0, Transforms: 4
            b"\x03\x00\x00\x0c\x01\x00\x00\x0c\x80\x0e\x01\x00"  # ENCR AES_CBC 256
            b"\x03\x00\x00\x08\x02\x00\x00\x05"  # PRF HMAC_SHA2_256
            b"\x03\x00\x00\x08\x03\x00\x00\x0c"  # INTEG HMAC_SHA2_256_128
            b"\x00\x00\x00\x08\x04\x00\x00\x13"  # DH NIST P-256 (Group 19)
        )

        ke_bytes = (
            b"\x28\x00\x00\x28"  # Next payload: 40 (Nonce), length: 40
            b"\x00\x13\x00\x00" + b"\xaa" * 32  # DH Group 19
        )

        nonce_bytes = b"\x00\x00\x00\x14" + b"\xbb" * 16  # Next payload: 0, length: 20

        payloads = sa_bytes + ke_bytes + nonce_bytes
        length = 28 + len(payloads)
        header = (
            ispi
            + rspi
            + bytes([next_payload, version, exch, flags])
            + msg_id
            + length.to_bytes(4, "big")
        )
        packet = header + payloads

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (host, port))

        data, addr = sock.recvfrom(2048)
        sock.close()

        parsed = _parse_ikev2_response(data)
        if "error" in parsed:
            return {"success": False, "error_message": parsed["error"]}

        pqc_dh_groups = [
            g
            for g in parsed["dh_groups"]
            if any(
                p in g.lower()
                for p in ["ml-kem", "mlkem", "kyber", "sntrup", "ntrup", "hybrid"]
            )
        ]

        return {
            "success": True,
            "ike_version": "IKEv2",
            "dh_groups": parsed["dh_groups"],
            "encryption_algorithms": parsed["encryption_algorithms"],
            "integrity_algorithms": parsed["integrity_algorithms"],
            "pqc_dh_groups": pqc_dh_groups,
            "pqc_status": parsed["pqc_status"],
            "response_len": len(data),
        }
    except socket.timeout:
        return {"success": False, "error_message": "IKE probe timeout (no response)"}
    except Exception as e:
        return {"success": False, "error_message": f"IKE socket probe error: {e}"}


def _parse_ike_group_from_line(line: str) -> Optional[str]:
    lower = line.lower()
    if "group" not in lower or "[" not in line:
        return None
    try:
        num = line.split("[")[1].split("]")[0].strip()
    except (IndexError, ValueError):
        return None
    policy = _DH_GROUP_POLICY.get(num)
    return policy["name"] if policy else f"DH Group {num}"


def _do_ike_probe(host: str, port: int, timeout: int) -> _IKEResultDict:
    # Try the socket probe first, since it is direct and doesn't depend on external binaries
    res = _do_socket_ike_probe(host, port, timeout)
    if res.get("success"):
        return res

    ike_scan = shutil.which("ike-scan")
    if not ike_scan:
        return res

    try:
        import subprocess
    except ImportError as exc:
        return {"success": False, "error_message": str(exc), "skipped": True}

    cmd = ["ike-scan", "--ikev2", "-M", f"{host}:{port}"]
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error_message": "IKE probe timeout (no response)"}
    except OSError as exc:
        return {"success": False, "error_message": str(exc)}
    except Exception as exc:
        return {"success": False, "error_message": str(exc)}

    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")

    if completed.returncode != 0:
        return {
            "success": False,
            "error_message": f"ike-scan failed: {stderr.strip() or stdout.strip()}",
            "stdout": stdout,
            "stderr": stderr,
        }

    dh_groups: List[str] = []
    encryption: List[str] = []
    integrity: List[str] = []
    ike_version = "IKEv2"
    for line in stdout.splitlines():
        lower = line.lower()
        if "encryption algorithm" in lower or "enc =" in lower:
            parts = line.split(":", 1)
            if len(parts) == 2:
                encryption.append(parts[1].strip())
        if "hash algorithm" in lower or "hash =" in lower:
            parts = line.split(":", 1)
            if len(parts) == 2:
                integrity.append(parts[1].strip())
        group_name = _parse_ike_group_from_line(line)
        if group_name:
            dh_groups.append(group_name)

    pqc_dh_groups = [
        g
        for g in dh_groups
        if any(
            p in g.lower()
            for p in ["ml-kem", "mlkem", "kyber", "sntrup", "ntrup", "hybrid"]
        )
    ]
    pqc_status = (
        "pqc_ready" if pqc_dh_groups else "vulnerable" if dh_groups else "unknown"
    )

    return {
        "success": True,
        "ike_version": ike_version,
        "dh_groups": dh_groups,
        "encryption_algorithms": encryption,
        "integrity_algorithms": integrity,
        "pqc_dh_groups": pqc_dh_groups,
        "pqc_status": pqc_status,
        "raw_response": stdout,
        "response_len": len(stdout.encode("utf-8")),
    }


@async_retry(
    attempts=2,
    initial_delay=0.5,
    retry_on=(asyncio.TimeoutError, ConnectionError, OSError),
)
async def scan_ike_endpoint(
    host: str, port: int = 500, timeout: int = 5
) -> IKEScanResult:
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(_IKE_EXECUTOR, _do_ike_probe, host, port, timeout),
            timeout=timeout + 2,
        )
    except Exception as exc:
        return IKEScanResult(
            host=host, port=port, success=False, error_message=str(exc)
        )

    if not result.get("success"):
        return IKEScanResult(
            host=host,
            port=port,
            success=False,
            error_message=result.get("error_message", "IKE probe failed"),
        )

    if result.get("skipped"):
        return IKEScanResult(
            host=host,
            port=port,
            success=True,
            ike_version=result.get("ike_version"),
            dh_groups=result.get("dh_groups", []),
            encryption_algorithms=result.get("encryption_algorithms", []),
            integrity_algorithms=result.get("integrity_algorithms", []),
            pqc_dh_groups=result.get("pqc_dh_groups", []),
            pqc_status=result.get("pqc_status", "unknown"),
        )

    response_len = result.get("response_len", 0)
    if isinstance(response_len, int) and response_len < _IKEV2_MIN_RESPONSE_LEN:
        return IKEScanResult(
            host=host,
            port=port,
            success=False,
            error_message="IKE response too short",
        )

    return IKEScanResult(
        host=host,
        port=port,
        success=True,
        ike_version=result.get("ike_version", "IKEv2"),
        dh_groups=result.get("dh_groups", []),
        encryption_algorithms=result.get("encryption_algorithms", []),
        integrity_algorithms=result.get("integrity_algorithms", []),
        pqc_dh_groups=result.get("pqc_dh_groups", []),
        pqc_status=result.get("pqc_status", "unknown"),
    )
