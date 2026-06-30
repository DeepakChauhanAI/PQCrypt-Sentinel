import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
import dns.resolver

from app.scanners.safe_target import (
    UnsafeTargetError,
    validate_cidr,
    validate_ip,
    validate_port,
    _ip_is_safe,
    build_safe_target_async,
)

logger = logging.getLogger(__name__)


async def discover_tls_hosts_fallback(network_range: str) -> List[Dict[str, Any]]:
    """
    Python-native fallback scanner using concurrent asyncio TCP connections.
    First performs a fast parallel host discovery (ping scan), then probes only alive hosts.
    """
    import ipaddress

    net = ipaddress.ip_network(network_range, strict=False)

    if net.num_addresses > 4096:
        raise RuntimeError(
            "Native fallback scanner is limited to subnets with 4096 or fewer addresses (e.g. /20). "
            "Please narrow your target range or install nmap on the host system."
        )

    ports = [22, 443, 8443, 636, 993, 995, 8883, 1001, 4096, 9080, 6432, 27017]
    port_services = {
        22: "ssh",
        443: "https",
        8443: "https-alt",
        636: "ldaps",
        993: "imaps",
        995: "pop3s",
        8883: "secure-mqtt",
        1001: "ssl",
        4096: "ssl",
        9080: "ssl",
        6432: "ssl",
        27017: "ssl",
    }

    sem = asyncio.Semaphore(128)

    # Phase 1: Host Discovery (Ping scan)
    async def is_host_alive(ip: str) -> bool:
        ping_ports = [443, 80, 22, 135, 445]

        async def probe_port(port: int) -> bool:
            async with sem:
                try:
                    conn = asyncio.open_connection(ip, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=0.20)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return True
                except (ConnectionRefusedError, ConnectionResetError):
                    return True
                except Exception:
                    return False

        results = await asyncio.gather(*(probe_port(p) for p in ping_ports))
        return any(results)

    # Filter hosts
    hosts = list(net.hosts())
    if not hosts:
        hosts = [net.network_address]

    safe_hosts = [str(host) for host in hosts if _ip_is_safe(str(host))]

    # Run host discovery in parallel
    alive_flags = await asyncio.gather(*(is_host_alive(ip) for ip in safe_hosts))
    alive_hosts = [ip for ip, alive in zip(safe_hosts, alive_flags) if alive]

    # Phase 2: Port Scan on active hosts
    discovered = []

    async def probe(ip: str, port: int):
        async with sem:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=0.4)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                discovered.append(
                    {
                        "ip": ip,
                        "port": port,
                        "service": port_services.get(port, "ssl"),
                        "version": "",
                        "product": "",
                    }
                )
            except Exception:
                pass

    tasks = []
    for ip in alive_hosts:
        for port in ports:
            tasks.append(probe(ip, port))

    if tasks:
        await asyncio.gather(*tasks)

    return discovered


async def discover_tls_hosts(network_range: str) -> List[Dict[str, Any]]:
    """
    Discover hosts with TLS or SSH services on a network range.
    Runs nmap on the standard crypto ports plus known local listening ports.

    Raises :class:`UnsafeTargetError` if the network range fails the SSRF policy.
    """
    validate_cidr(network_range)
    ports = "22,443,8443,636,993,995,8883,1001,4096,9080,6432,27017"
    args = [
        network_range,
        "-p",
        ports,
        "-sV",
        "--script",
        "ssl-enum-ciphers",
        "-oX",
        "-",
    ]

    logger.info(f"Running nmap discovery on {network_range} for ports {ports}")

    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap",
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
    except FileNotFoundError:
        logger.info(
            "nmap binary not found on the host system. Falling back to native async port scanner."
        )
        return await discover_tls_hosts_fallback(network_range)
    except Exception as e:
        logger.exception(f"Unexpected error when starting nmap: {e}")
        raise RuntimeError(f"Failed to start nmap: {str(e)}")

    if proc.returncode != 0:
        err_msg = stderr.decode("utf-8", errors="ignore").strip()
        logger.error(f"nmap execution failed with code {proc.returncode}: {err_msg}")
        raise RuntimeError(f"nmap failed: {err_msg}")

    xml_content = stdout.decode("utf-8", errors="ignore")

    try:
        root = ET.fromstring(xml_content)  # nosec B314
    except Exception as e:
        logger.error(f"Failed to parse nmap XML output: {e}")
        return []

    discovered = []

    # Allowed service names/keywords
    allowed_services = {
        "ssh",
        "https",
        "ldaps",
        "imaps",
        "pop3s",
        "smtps",
        "mqtt",
        "ssl/https",
        "https-alt",
        "secure-mqtt",
        "ssl",
        "imaps?",
        "pop3s?",
    }

    for host_node in root.findall("host"):
        status_node = host_node.find("status")
        if status_node is not None and status_node.get("state") != "up":
            continue

        ip = None
        addresses = host_node.findall("address")
        for addr in addresses:
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break
        if not ip:
            for addr in addresses:
                ip = addr.get("addr")
                break
        if not ip:
            continue

        # SSRF post-filter: drop any host nmap discovered that falls outside
        # the safe-target policy. This protects against targets that get
        # nmap'd indirectly (e.g. a NAT'd address returned for a hostname).
        try:
            validate_ip(ip)
        except UnsafeTargetError:
            logger.warning(f"Dropping nmap result for unsafe ip {ip}")
            continue

        ports_node = host_node.find("ports")
        if ports_node is None:
            continue

        for port_node in ports_node.findall("port"):
            port_id = port_node.get("portid")
            if not port_id:
                continue
            port = int(port_id)
            try:
                validate_port(port)
            except UnsafeTargetError:
                continue

            state_node = port_node.find("state")
            if state_node is None or state_node.get("state") != "open":
                continue

            service_node = port_node.find("service")
            service_name = "unknown"
            product = ""
            version = ""
            if service_node is not None:
                service_name = service_node.get("name", "unknown").lower()
                product = service_node.get("product", "")
                version = service_node.get("version", "")

            is_valid_service = service_name in allowed_services or port in [
                22,
                443,
                8443,
                636,
                993,
                995,
                8883,
            ]

            if is_valid_service:
                discovered.append(
                    {
                        "ip": ip,
                        "port": port,
                        "service": service_name,
                        "version": version,
                        "product": product,
                    }
                )

    return discovered


def enumerate_dns_targets(domain: str) -> Dict[str, List[str]]:
    """Enumerate DNS records to discover TLS endpoints.

    All returned IPs are filtered through the safe-target policy so callers
    can never be tricked into scanning loopback / link-local hosts via DNS.
    """
    results: dict[str, list[str]] = {
        "a_records": [],
        "aaaa_records": [],
        "cname_records": [],
        "mx_records": [],
        "srv_records": [],
    }

    for rtype in ["A", "AAAA", "CNAME", "MX", "SRV"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                value = str(rdata)
                if rtype in ("A", "AAAA"):
                    if not _ip_is_safe(value):
                        logger.warning(
                            f"Dropping unsafe DNS {rtype} for {domain}: {value}"
                        )
                        continue
                results[f"{rtype.lower()}_records"].append(value)
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.exception.Timeout,
            Exception,
        ):
            pass

    return results


async def safe_resolve(host: str, port: int):
    """Resolve + validate a single host/port for downstream scanners."""
    return await build_safe_target_async(host, port)
