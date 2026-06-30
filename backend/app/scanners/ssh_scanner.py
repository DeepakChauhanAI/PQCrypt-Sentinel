import asyncio
import os
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from paramiko.message import Message

from app.utils.retry import async_retry

_SSH_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="ssh_scanner")


# Client-side default algorithm lists used to send a valid KEXINIT.
# The server's KEXINIT is independent of what we offer — we only need
# the server's packet to be a well-formed SSH_MSG_KEXINIT so we can
# extract the algorithms it actually advertises.
_DEFAULT_KEX = [
    "sntrup761x25519-sha512@openssh.com",
    "mlkem768x25519-sha512@openssh.com",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group-exchange-sha256",
]
_DEFAULT_HOST_KEY = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
]
_DEFAULT_ENC = [
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
]
_DEFAULT_MAC = [
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
]
_DEFAULT_COMP = ["none"]


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("SSH peer closed connection unexpectedly")
        data += chunk
    return data


def _read_ssh_banner(sock: socket.socket) -> bytes:
    """Read the SSH identification string (terminated by \\n).

    Some servers print extra lines before the SSH- banner; keep reading
    until a line starts with b"SSH-".
    """
    buf = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("Server closed before sending SSH banner")
        buf += ch
        if ch == b"\n":
            line = buf.strip()
            buf = b""
            if line.startswith(b"SSH-"):
                return line


def _build_kexinit_payload() -> bytes:
    m = Message()
    m.add_byte(b"\x14")  # SSH_MSG_KEXINIT
    m.add_bytes(os.urandom(16))
    m.add_list(_DEFAULT_KEX)
    m.add_list(_DEFAULT_HOST_KEY)
    m.add_list(_DEFAULT_ENC)  # enc c->s
    m.add_list(_DEFAULT_ENC)  # enc s->c
    m.add_list(_DEFAULT_MAC)  # mac c->s
    m.add_list(_DEFAULT_MAC)  # mac s->c
    m.add_list(_DEFAULT_COMP)  # comp c->s
    m.add_list(_DEFAULT_COMP)  # comp s->c
    m.add_string(bytes())  # lang c->s
    m.add_string(bytes())  # lang s->c
    m.add_boolean(False)  # first_kex_packet_follows
    m.add_int(0)  # reserved
    return m.asbytes()


def _wrap_ssh_packet(payload: bytes) -> bytes:
    """Frame a payload as a (currently unencrypted) SSH binary packet."""
    block_size = 8
    # packet_length covers padding_length byte + payload + padding
    pre_pad = 5 + len(payload)  # 4 length + 1 padlen + payload
    padding_length = block_size - (pre_pad % block_size)
    if padding_length < 4:
        padding_length += block_size
    packet_length = 1 + len(payload) + padding_length
    return (
        struct.pack(">I", packet_length)
        + bytes([padding_length])
        + payload
        + os.urandom(padding_length)
    )


def _read_ssh_packet_payload(sock: socket.socket) -> bytes:
    """Read one SSH binary packet and return its payload (no MAC)."""
    header = _recv_exact(sock, 5)
    packet_length = struct.unpack(">I", header[:4])[0]
    padding_length = header[4]
    if packet_length < 1 + padding_length:
        raise ConnectionError("Malformed SSH packet length/padding")
    payload_len = packet_length - padding_length - 1
    payload = _recv_exact(sock, payload_len)
    # skip padding (and any pre-newkeys MAC, but spec says no MAC here)
    _recv_exact(sock, padding_length)
    return payload


def _parse_server_kexinit(payload: bytes) -> dict:
    """Parse a server SSH_MSG_KEXINIT payload and extract algorithm lists."""

    def _clean(values):
        return [v for v in (values or []) if v]

    try:
        m = Message(payload)
        m.get_byte()  # message type (20)
        m.get_bytes(16)  # cookie
        kex_algorithms = _clean(m.get_list())
        host_key_algorithms = _clean(m.get_list())
        _ = _clean(m.get_list())  # encryption_algorithms_client_to_server
        encryption_algorithms_server_to_client = _clean(m.get_list())
        _ = _clean(m.get_list())  # mac_algorithms_client_to_server
        mac_algorithms_server_to_client = _clean(m.get_list())
        # compression, languages, first_kex_packet_follows, reserved follow — ignore
        return {
            "kex_algorithms": kex_algorithms,
            "host_key_algorithms": host_key_algorithms,
            "encryption_algorithms": encryption_algorithms_server_to_client,
            "mac_algorithms": mac_algorithms_server_to_client,
        }
    except Exception:
        return {
            "kex_algorithms": [],
            "host_key_algorithms": [],
            "encryption_algorithms": [],
            "mac_algorithms": [],
        }


PQC_KEX_ALGORITHMS = [
    "sntrup761x25519-sha512@openssh.com",
    "mlkem768x25519-sha512@openssh.com",
    "mlkem1024x25519-sha512@openssh.com",
    "mlkem768nistp256-sha256",
    "mlkem1024nistp384-sha384",
    "kyber-768-sha512",
    "kyber-1024-sha512",
]

PQC_KEX_KEYWORDS = ["mlkem", "sntrup", "kyber", "ntrup", "pqc"]


class SSHScanResult:
    def __init__(
        self,
        host: str,
        port: int,
        success: bool,
        error_message: Optional[str] = None,
        kex_algorithms: Optional[List[str]] = None,
        host_key_algorithms: Optional[List[str]] = None,
        encryption_algorithms: Optional[List[str]] = None,
        mac_algorithms: Optional[List[str]] = None,
        pqc_kex_available: bool = False,
        pqc_kex_algorithms: Optional[List[str]] = None,
        pqc_status: str = "vulnerable",
    ):
        self.host = host
        self.port = port
        self.success = success
        self.error_message = error_message
        self.kex_algorithms = kex_algorithms or []
        self.host_key_algorithms = host_key_algorithms or []
        self.encryption_algorithms = encryption_algorithms or []
        self.mac_algorithms = mac_algorithms or []
        self.pqc_kex_available = pqc_kex_available
        self.pqc_kex_algorithms = pqc_kex_algorithms or []
        self.pqc_status = pqc_status


def _do_ssh_connect(host: str, port: int, timeout: int) -> dict:
    """Read the server's SSH KEXINIT and extract advertised algorithms.

    Performs a minimal SSH handshake: TCP connect → read server banner →
    send client banner → send our KEXINIT → read server KEXINIT → parse.
    We do not complete the key exchange; we only need the server's
    advertised algorithm lists to audit for PQC support.
    """
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)

        _read_ssh_banner(sock)
        sock.sendall(b"SSH-2.0-PQCScanner\r\n")
        sock.sendall(_wrap_ssh_packet(_build_kexinit_payload()))

        # Drain packets until we get the server's KEXINIT (msg 20).
        payload = b""
        for _ in range(8):  # safety bound; we expect it on the first packet
            payload = _read_ssh_packet_payload(sock)
            if payload and payload[0] == 20:
                break
        else:
            return {
                "success": False,
                "error_message": "Did not receive SSH_MSG_KEXINIT from server",
            }

        parsed = _parse_server_kexinit(payload)
        kex = parsed["kex_algorithms"]
        host_keys = parsed["host_key_algorithms"]
        ciphers = parsed["encryption_algorithms"]
        macs = parsed["mac_algorithms"]

        pqc_kex = [a for a in kex if any(kw in a.lower() for kw in PQC_KEX_KEYWORDS)]
        pqc_kex_available = len(pqc_kex) > 0
        pqc_status = "pqc_ready" if pqc_kex_available else "vulnerable"

        return {
            "success": True,
            "kex_algorithms": kex,
            "host_key_algorithms": host_keys,
            "encryption_algorithms": ciphers,
            "mac_algorithms": macs,
            "pqc_kex_available": pqc_kex_available,
            "pqc_kex_algorithms": pqc_kex,
            "pqc_status": pqc_status,
        }
    except Exception as exc:
        return {
            "success": False,
            "error_message": str(exc),
        }
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass


@async_retry(
    attempts=2,
    initial_delay=0.5,
    retry_on=(asyncio.TimeoutError, ConnectionError, OSError),
)
async def scan_ssh_endpoint(
    host: str, port: int = 22, timeout: int = 10
) -> SSHScanResult:
    """Audit SSH server for key exchange and cipher suite options."""
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(_SSH_EXECUTOR, _do_ssh_connect, host, port, timeout),
            timeout=timeout + 2,
        )
        if not result["success"]:
            return SSHScanResult(
                host=host,
                port=port,
                success=False,
                error_message=result.get("error_message", "Unknown SSH error"),
            )
        return SSHScanResult(
            host=host,
            port=port,
            success=True,
            kex_algorithms=result["kex_algorithms"],
            host_key_algorithms=result["host_key_algorithms"],
            encryption_algorithms=result["encryption_algorithms"],
            mac_algorithms=result.get("mac_algorithms", []),
            pqc_kex_available=result["pqc_kex_available"],
            pqc_kex_algorithms=result["pqc_kex_algorithms"],
            pqc_status=result["pqc_status"],
        )
    except Exception as e:
        return SSHScanResult(
            host=host,
            port=port,
            success=False,
            error_message=str(e),
        )
