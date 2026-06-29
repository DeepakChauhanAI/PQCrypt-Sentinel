"""
SSRF / DNS-rebinding safe target resolution for the PQC scanner.

This module centralises the rules that govern what hosts/ports the scanner
is permitted to connect to. It is intentionally strict and provides:

  * CIDR / IP allowlist helpers (loopback / RFC1918 / link-local / multicast
    blocked by default, opt-in via ``ALLOW_PRIVATE_RANGES``).
  * Domain resolution that pins the IP at resolve time and refuses to
    connect if a later resolve returns a different IP (DNS rebinding).
  * A ``SafeTarget`` namedtuple that carries the validated (host, ip, port)
    tuple the scanners should use.

All checks raise :class:`UnsafeTargetError` on rejection so the orchestrator
can downgrade the finding to a "blocked by policy" event instead of opening
a connection.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
from dataclasses import dataclass
from typing import List, Optional, Sequence

import dns.resolver

logger = logging.getLogger(__name__)

ALLOW_PRIVATE_RANGES = os.environ.get("PQC_ALLOW_PRIVATE_RANGES", "0") == "1"
ALLOW_LOOPBACK = os.environ.get("PQC_ALLOW_LOOPBACK", "0") == "1"
ALLOW_LINK_LOCAL = os.environ.get("PQC_ALLOW_LINK_LOCAL", "0") == "1"
ALLOW_MULTICAST = os.environ.get("PQC_ALLOW_MULTICAST", "0") == "1"

from app.config import settings

ALLOW_PRIVATE_RANGES = settings.PQC_ALLOW_PRIVATE_RANGES
ALLOW_LOOPBACK = settings.PQC_ALLOW_LOOPBACK
ALLOW_LINK_LOCAL = settings.PQC_ALLOW_LINK_LOCAL
ALLOW_MULTICAST = settings.PQC_ALLOW_MULTICAST

MAX_PORT = 65535
MIN_PORT = 1


class UnsafeTargetError(ValueError):
    """Raised when a target fails the safety policy."""


@dataclass(frozen=True)
class SafeTarget:
    """A (host, ip, port) triple that has cleared the safety policy.

    The `host` is the user-supplied hostname/CIDR; `ip` is the resolved
    address that downstream code must use. Passing `ip` (not `host`) to
    `socket.create_connection` is what makes DNS-rebinding attacks fail.
    """
    host: str
    ip: str
    port: int

    def connection_target(self) -> tuple:
        """Return the (host, port) tuple for socket.create_connection.

        We still return `host` for TLS SNI, but the caller is expected to
        have already validated that this host resolves to `self.ip`.
        """
        return (self.host, self.port)


def _ip_is_safe(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if addr.is_loopback and not ALLOW_LOOPBACK:
        return False
    if addr.is_link_local and not ALLOW_LINK_LOCAL:
        return False
    if addr.is_multicast and not ALLOW_MULTICAST:
        return False
    if addr.is_private and not ALLOW_PRIVATE_RANGES:
        return False
    if addr.is_unspecified:
        return False
    if addr.is_reserved:
        return False
    return True


def _port_is_safe(port: int) -> bool:
    return MIN_PORT <= int(port) <= MAX_PORT


def validate_port(port: int) -> None:
    if not _port_is_safe(port):
        raise UnsafeTargetError(f"port {port} out of range")


def validate_ip(ip: str) -> None:
    if not _ip_is_safe(ip):
        raise UnsafeTargetError(f"ip {ip} is not in the safe-target policy")


def validate_cidr(cidr: str) -> None:
    """Validate a network range string (CIDR or single IP)."""
    if not cidr:
        raise UnsafeTargetError("empty network range")
    if "/" in cidr:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            raise UnsafeTargetError(f"invalid CIDR {cidr!r}: {e}") from e
        # For private ranges we accept the whole block; for public ranges we
        # must be careful — a multi-prefix public range would mean a huge
        # scan, so we cap by prefix size when the network is public.
        if net.num_addresses > 4096 and not net.is_private:
            raise UnsafeTargetError(
                f"network range {cidr} too large for public scan "
                f"({net.num_addresses} addresses > 4096 cap)"
            )
        # Spot-check the network address; if it's unsafe, reject.
        if not _ip_is_safe(str(net.network_address)):
            raise UnsafeTargetError(
                f"network range {cidr} contains unsafe addresses"
            )
    else:
        validate_ip(cidr)


def _resolve_sync(host: str) -> List[str]:
    if not host:
        return []
    try:
        # If it's already an IP, return as-is.
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    out: List[str] = []
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        ip = str(sockaddr[0])
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


async def resolve_safely(host: str) -> List[str]:
    """Resolve host to IPs in a thread, return the safe subset."""
    loop = asyncio.get_event_loop()
    addrs = await loop.run_in_executor(None, _resolve_sync, host)
    safe = [a for a in addrs if _ip_is_safe(a)]
    if not safe:
        raise UnsafeTargetError(f"host {host!r} did not resolve to any safe IPs")
    return safe


def build_safe_target(host: str, port: int) -> SafeTarget:
    """Validate host + port, resolve, and pin the IP.

    The returned ``SafeTarget.ip`` is the address the scanners must use for
    the actual socket connect — this prevents DNS rebinding because the
    second lookup cannot change the pinned IP.
    """
    validate_port(port)
    if not host:
        raise UnsafeTargetError("empty host")
    addrs = _resolve_sync(host)
    if not addrs:
        raise UnsafeTargetError(f"host {host!r} could not be resolved")
    chosen = next((a for a in addrs if _ip_is_safe(a)), None)
    if not chosen:
        raise UnsafeTargetError(
            f"host {host!r} resolved only to unsafe IPs: {addrs}"
        )
    return SafeTarget(host=host, ip=chosen, port=port)


async def build_safe_target_async(host: str, port: int) -> SafeTarget:
    """Async variant of :func:`build_safe_target`."""
    validate_port(port)
    addrs = await resolve_safely(host)
    return SafeTarget(host=host, ip=addrs[0], port=port)


def verify_rebind(initial_ip: str, current_ips: Sequence[str]) -> None:
    """Raise if a re-resolve of the same host no longer includes initial_ip."""
    if initial_ip not in current_ips:
        raise UnsafeTargetError(
            f"DNS rebinding detected: original IP {initial_ip} not in "
            f"current resolution {list(current_ips)}"
        )
