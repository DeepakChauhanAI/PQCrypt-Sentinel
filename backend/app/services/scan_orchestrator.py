import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError, DBAPIError

from app.db import AsyncSessionLocal
from app.models.models import Scan, ScanLog, Asset, Certificate, Algorithm, Finding
from app.config import settings


logger = logging.getLogger(__name__)


# Extra ports observed on this dev PC that should be probed during full scans
_LOCAL_TLS_PORTS = [
    443,
    8443,
    9080,
    8883,
    636,
    993,
    995,
    500,
    4500,
    25,
    465,
    587,
    1001,
    4096,
    6432,
    27017,
]
_LOCAL_SSH_PORTS = [22, 1001, 4096]


# Bounded concurrency for per-port probes within a single host. This
# controls how many TLS/SSH/IKE/Mail probes run concurrently for one
# host — DB writes remain serial to keep the AsyncSession contract.
MAX_CONCURRENT_PORT_PROBES = 4

# Bounded concurrency across hosts in a single scan. Each host gets
# its own AsyncSession and its own savepoint so they can run truly in
# parallel without contending for the SQLAlchemy session. 8 is a
# reasonable default that saturates a single Postgres worker without
# overwhelming the DB pool; tune via env if needed.
MAX_CONCURRENT_HOSTS = 8


async def _gather_with_limit(coros, limit: int = MAX_CONCURRENT_PORT_PROBES):
    """
    Run an iterable of coroutines with a hard concurrency limit.

    The orchestrator fires many network probes per host (one per port)
    but we don't want to open N concurrent sockets on small VMs. This
    helper applies a Semaphore-bounded gather that returns a list of
    results in the original order.

    Any individual exception is captured and returned as `(None, exc)`,
    so a single bad port never aborts the whole host.
    """
    sem = asyncio.Semaphore(limit)

    async def _wrap(coro):
        async with sem:
            try:
                return await coro
            except Exception as exc:  # pragma: no cover - safety net
                return ("__error__", exc)

    results = await asyncio.gather(*[_wrap(c) for c in coros])
    return results


# Local TLS-level ports probed during full / tls_only scans
_LOCAL_TLS_PORTS = [
    443,
    8443,
    9080,
    8883,
    636,
    993,
    995,
    500,
    4500,
    25,
    465,
    587,
    1001,
    4096,
    6432,
    27017,
]
# Locally found SSH-like ports
_LOCAL_SSH_PORTS = [22, 1001, 4096]


def started_at_fallback(dt: Optional[datetime]) -> datetime:
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def _run_host_tasks(
    scan_id: str,
    hosts: list,
    strict_tls: bool,
    scan_type: str,
    advanced_tools: bool,
    log_event,
) -> dict:
    """Fan out `scan_host` across `hosts` with bounded concurrency.

    Uses the module-level `_scan_host_fn` indirection so tests can
    patch it without fighting the lazy `from app.services.scan_host
    import scan_host` import.


    Each host gets its own `AsyncSessionLocal()` so the per-host
    savepoints are isolated and the SQLAlchemy AsyncSession contract
    (single-task) isn't violated. Bounded by `MAX_CONCURRENT_HOSTS`.

    Returns a dict with `assets_total`, `findings_total`, and `errors`
    (list of per-host error messages). The caller is responsible for
    writing aggregated `ScanLog` rows.
    """
    if not hosts:
        return {"assets_total": 0, "findings_total": 0, "errors": []}

    from app.services.scan_host import scan_host

    async def _run_host(host: str) -> dict:
        # Use a nested savepoint so per-host writes are isolated and
        # can roll back independently if the host scan errors out.
        async with AsyncSessionLocal() as host_session:
            try:
                async with host_session.begin_nested():
                    res = await scan_host(
                        session=host_session,
                        scan_id=scan_id,
                        scan_type=scan_type,
                        host=host,
                        strict_tls=strict_tls,
                        advanced_tools=advanced_tools,
                    )
                await host_session.commit()
                return res
            except Exception:
                # Savepoint auto-rolls back; we still want the exception
                # captured as a host error for the caller.
                raise

    host_results = await _gather_with_limit(
        [_run_host(h) for h in hosts],
        limit=MAX_CONCURRENT_HOSTS,
    )

    assets_total = 0
    findings_total = 0
    errors: list = []
    for host_res in host_results:
        if isinstance(host_res, tuple) and host_res and host_res[0] == "__error__":
            logger.error("Host task raised: %s", host_res[1])
            errors.append(f"host-task: {host_res[1]}")
            continue
        assets_total += int(host_res.get("assets", 0))
        findings_total += int(host_res.get("findings", 0))
        if host_res.get("error"):
            msg = f"{host_res.get('host')}: {host_res.get('error')}"
            errors.append(msg)
            await log_event(
                level="error",
                phase="analysis",
                message=f"Host scan failed: {msg}",
            )

    return {
        "assets_total": assets_total,
        "findings_total": findings_total,
        "errors": errors,
    }


async def _run_advanced_scanners(
    session,
    scan,
    host: str,
    is_host_active: bool,
    assets_found_count: int,
    findings_created_count: int,
    log_event,
):
    if not getattr(scan, "advanced_tools", False):
        return is_host_active, assets_found_count, findings_created_count
    if ":" in host:
        await log_event(
            level="info",
            phase="advanced",
            message=f"Skipping advanced scanners for IPv6 host {host}.",
        )
        return is_host_active, assets_found_count, findings_created_count

    try:
        await log_event(
            level="info",
            phase="advanced",
            message=f"Running SSLyze deep TLS scan on {host}:443",
        )
        from app.scanners.sslyze_scanner import scan_endpoint_with_sslyze

        try:
            sslyze_res = await scan_endpoint_with_sslyze(host, port=443)
        except Exception as exc:
            await log_event(
                level="warn",
                phase="advanced",
                message=f"SSLyze scan failed on {host}: {exc}",
            )
            sslyze_res = None

        if sslyze_res and sslyze_res.success:
            is_host_active = True
            assets_found_count += 1
            await log_event(
                level="info",
                phase="advanced",
                message=(
                    f"SSLyze scan complete on {host}: "
                    f"{len(sslyze_res.tls_versions)} TLS versions checked"
                ),
                details={"tls_versions": list(sslyze_res.tls_versions.keys())},
            )

            existing_asset = await session.execute(
                select(Asset).where(
                    Asset.name == f"{host}:443 (sslyze)", Asset.deleted_at.is_(None)
                )
            )
            asset = existing_asset.scalar_one_or_none()
            # Resolve ip/fqdn from the *host* we are scanning. Previously this
            # read `scan.target`, but scan_host calls this with a synthetic
            # object that has no `target` attribute, crashing with
            # AttributeError whenever the host was an IP. The host is the
            # resolved target here, so derive ip/fqdn from it directly.
            ip_addr = None
            fqdn_val = None
            try:
                import ipaddress

                ipaddress.ip_address(host)
                ip_addr = host
            except ValueError:
                fqdn_val = host

            if not asset:
                asset = Asset(
                    name=f"{host}:443 (sslyze)",
                    asset_type="server",
                    ip_address=ip_addr,
                    fqdn=fqdn_val,
                    port=443,
                    protocol="tcp",
                    environment=(
                        "development"
                        if ("test" in host or "local" in host)
                        else "production"
                    ),
                    discovery_source="sslyze",
                    first_scan_id=scan.id,
                    first_discovered_at=datetime.now(timezone.utc),
                )
                session.add(asset)
                await session.flush()
                await session.refresh(asset)
            else:
                asset.ip_address = ip_addr
                asset.fqdn = fqdn_val

            asset.last_scan_id = scan.id
            asset.last_verified_at = datetime.now(timezone.utc)
            asset.asset_metadata = {
                "tls_versions": sslyze_res.tls_versions,
                "supported_versions": sslyze_res.supported_versions,
            }

            if sslyze_res.cert_data:
                existing_cert = await session.execute(
                    select(Certificate).where(
                        Certificate.thumbprint == sslyze_res.cert_data["thumbprint"],
                        Certificate.deleted_at.is_(None),
                    )
                )
                certificate = existing_cert.scalar_one_or_none()
                if certificate is None:
                    certificate = Certificate(
                        asset_id=asset.id,
                        thumbprint=sslyze_res.cert_data["thumbprint"],
                        subject=sslyze_res.cert_data["subject"],
                        issuer=sslyze_res.cert_data["issuer"],
                        serial_number=sslyze_res.cert_data.get("serial_number"),
                        sig_algorithm=sslyze_res.cert_data["sig_algorithm"],
                        pub_key_algorithm=sslyze_res.cert_data["pub_key_algorithm"],
                        pub_key_size=sslyze_res.cert_data.get("pub_key_size"),
                        curve_name=sslyze_res.cert_data.get("curve_name"),
                        not_before=sslyze_res.cert_data["not_before"],
                        not_after=sslyze_res.cert_data["not_after"],
                        is_self_signed=sslyze_res.cert_data["is_self_signed"],
                        is_ca=sslyze_res.cert_data["is_ca"],
                        key_usage=sslyze_res.cert_data.get("key_usage"),
                        san_dns=sslyze_res.cert_data.get("san_dns"),
                        san_ip=sslyze_res.cert_data.get("san_ip"),
                        pqc_capable=sslyze_res.cert_data["pqc_capable"],
                        pqc_details=sslyze_res.cert_data["pqc_details"],
                        raw_certificate=sslyze_res.cert_data.get("raw_certificate"),
                    )
                    session.add(certificate)
                    await session.flush()
                elif certificate.asset_id != asset.id:
                    # Same cert served by a different asset — re-link
                    certificate.asset_id = asset.id
    except Exception as exc:
        await log_event(
            level="warn",
            phase="advanced",
            message=f"SSLyze pass crashed on {host}: {exc}",
        )

    try:
        await log_event(
            level="info",
            phase="advanced",
            message=f"Running scapy PQC group probe on {host}:443",
        )
        from app.scanners.scapy_probe import probe_tls_with_pqc_groups

        scapy_res = await probe_tls_with_pqc_groups(host, port=443)
        if scapy_res.success:
            await log_event(
                level="info",
                phase="advanced",
                message=(
                    f"Scapy probe on {host}: sent={scapy_res.probe_sent}, "
                    f"PQC groups={scapy_res.pqc_groups_advertised}"
                ),
            )
    except Exception as exc:
        await log_event(
            level="warn",
            phase="advanced",
            message=f"scapy probe failed on {host}: {exc}",
        )

    try:
        from app.services.cli_scanner_service import run_pqcscan, run_ssh_audit

        await log_event(
            level="info",
            phase="advanced",
            message=f"Running pqcscan against {host}:443",
        )
        pqcscan_res = await run_pqcscan(host, port=443)
        if not pqcscan_res.get("skipped"):
            await log_event(
                level="info",
                phase="advanced",
                message=f"pqcscan result on {host}: {pqcscan_res.get('pqc_status')}",
                details={"tool": "pqcscan", "result": pqcscan_res},
            )

        await log_event(
            level="info",
            phase="advanced",
            message=f"Running ssh-audit against {host}:22",
        )
        ssh_audit_res = await run_ssh_audit(host, port=22)
        if not ssh_audit_res.get("skipped"):
            await log_event(
                level="info",
                phase="advanced",
                message=(
                    f"ssh-audit result on {host}: "
                    f"pqc={ssh_audit_res.get('pqc_kex_available')}"
                ),
                details={"tool": "ssh-audit", "result": ssh_audit_res},
            )
    except Exception as exc:
        await log_event(
            level="warn",
            phase="advanced",
            message=f"CLI scanner pass crashed on {host}: {exc}",
        )

    return is_host_active, assets_found_count, findings_created_count


class ScanOrchestrator:
    async def run_scan(self, scan_id: str) -> None:
        """Orchestrate the active scan lifecycle for a given scan ID."""
        async with AsyncSessionLocal() as session:
            # ── 1. Claim the scan row with a pessimistic lock ────────────────────
            result = await session.execute(
                select(Scan).where(Scan.id == scan_id).with_for_update()
            )
            scan = result.scalar_one_or_none()
            if not scan:
                logger.error(f"Scan {scan_id} not found in database.")
                return

            # Guard: if another worker already claimed this scan, exit
            if scan.status == "running":
                logger.warning(f"Scan {scan_id} is already running. Exiting.")
                return
            if scan.status in {"completed", "failed", "cancelled"}:
                logger.info(
                    f"Scan {scan_id} already in terminal state {scan.status}. Exiting."
                )
                return

            now = datetime.now(timezone.utc)
            scan.status = "running"
            scan.started_at = now
            scan.updated_at = now
            await session.commit()  # <── LOCK HELD AND STATE PERSISTED BEFORE ANY IO

            # ── 2. Helper: log_event uses flush (no per-entry commit) ────────────
            async def log_event(
                level: str, phase: str, message: str, details: Optional[dict] = None
            ):
                session.add(
                    ScanLog(
                        scan_id=scan.id,
                        level=level,
                        phase=phase,
                        message=message,
                        details=details,
                    )
                )
                await session.flush()  # Assigns PK without committing transaction

            await log_event(
                level="info",
                phase="discovery",
                message=f"Starting scan task. Target: {scan.target}, Type: {scan.scan_type}",
            )

            # ── 2b. Parse scan config (strict TLS opt-in) ──────────────────────────
            strict_tls = False
            try:
                if scan.config:
                    cfg = (
                        json.loads(scan.config)
                        if isinstance(scan.config, str)
                        else scan.config
                    )
                    if isinstance(cfg, dict):
                        strict_tls = bool(cfg.get("strict_tls", False))
            except Exception:
                strict_tls = False
            if strict_tls:
                await log_event(
                    level="info",
                    phase="discovery",
                    message="Strict TLS verification enabled via Scan.config.strict_tls",
                )

            # ── 3. Parse targets ─────────────────────────────────────────────────
            target_str = scan.target or ""
            parsed_targets = [
                h.strip() for h in target_str.replace(";", ",").split(",") if h.strip()
            ]

            raw_targets: list[str] = []
            for t in parsed_targets:
                cleaned = t
                if cleaned.lower().startswith("https://"):
                    cleaned = cleaned[8:]
                elif cleaned.lower().startswith("http://"):
                    cleaned = cleaned[7:]

                if "/" in cleaned:
                    parts = cleaned.split("/")
                    is_cidr = False
                    if len(parts) == 2:
                        try:
                            mask = int(parts[1])
                            if 0 <= mask <= 128:
                                is_cidr = True
                        except ValueError:
                            pass
                    if not is_cidr:
                        cleaned = parts[0]

                if cleaned:
                    raw_targets.append(cleaned)

            if not raw_targets:
                scan.status = "failed"
                scan.error_message = "No valid targets specified."
                scan.completed_at = datetime.now(timezone.utc)
                scan.updated_at = scan.completed_at
                await session.commit()
                await log_event(
                    level="error",
                    phase="discovery",
                    message="Scan failed: No valid targets specified.",
                )
                return

            # ── 3b. SSRF Protection: Validate raw targets at parse time ────────────
            def is_target_ssrf_safe(target: str) -> tuple[bool, str]:
                """
                Validate a target (IP, hostname, or CIDR) for SSRF safety.
                Returns (is_safe, reason_if_unsafe).
                """
                import ipaddress
                from app.scanners.safe_target import (
                    ALLOW_PRIVATE_RANGES,
                    ALLOW_LOOPBACK,
                    ALLOW_LINK_LOCAL,
                    ALLOW_MULTICAST,
                )

                # Check if it's a CIDR range
                if "/" in target:
                    try:
                        network = ipaddress.ip_network(target, strict=False)
                        if network.is_loopback and not ALLOW_LOOPBACK:
                            return False, f"CIDR {target} contains loopback addresses"
                        if network.is_private and not ALLOW_PRIVATE_RANGES:
                            return (
                                False,
                                f"CIDR {target} resolves to restricted private network range",
                            )
                        if network.is_link_local and not ALLOW_LINK_LOCAL:
                            return (
                                False,
                                f"CIDR {target} resolves to restricted link-local network range",
                            )
                        if network.is_multicast and not ALLOW_MULTICAST:
                            return (
                                False,
                                f"CIDR {target} resolves to restricted multicast network range",
                            )
                        if network.is_unspecified:
                            return (
                                False,
                                f"CIDR {target} contains unspecified network range",
                            )
                        # Block metadata endpoint range (169.254.169.254/32)
                        if network.version == 4 and not ALLOW_PRIVATE_RANGES:
                            metadata_ip = ipaddress.IPv4Address("169.254.169.254")
                            if metadata_ip in network:
                                return (
                                    False,
                                    f"CIDR {target} includes metadata endpoint 169.254.169.254",
                                )
                    except ValueError:
                        return False, f"Invalid CIDR notation: {target}"
                    return True, ""

                # Try parsing as IP address
                try:
                    ip = ipaddress.ip_address(target)
                    if ip.is_loopback and not ALLOW_LOOPBACK:
                        return False, f"IP {target} is a loopback address"
                    if ip.is_private and not ALLOW_PRIVATE_RANGES:
                        return False, f"IP {target} is a restricted private address"
                    if ip.is_link_local and not ALLOW_LINK_LOCAL:
                        return False, f"IP {target} is a link-local address"
                    if ip.is_multicast and not ALLOW_MULTICAST:
                        return False, f"IP {target} is a multicast address"
                    if ip.is_unspecified:
                        return False, f"IP {target} is an unspecified address"
                    # Block AWS/Azure/GCP metadata endpoints
                    if str(ip) == "169.254.169.254" and not ALLOW_PRIVATE_RANGES:
                        return False, f"IP {target} is a cloud metadata endpoint"
                    return True, ""
                except ValueError:
                    # Not an IP, treat as hostname - will be validated after DNS resolution
                    pass

                return True, ""

            # Validate all raw targets
            safe_raw_targets: list[str] = []
            for target in raw_targets:
                is_safe, reason = is_target_ssrf_safe(target)
                if not is_safe:
                    await log_event(
                        level="warn",
                        phase="discovery",
                        message=f"SSRF Filter blocked unsafe scan target at parse time: {target} ({reason})",
                    )
                else:
                    safe_raw_targets.append(target)

            raw_targets = safe_raw_targets
            if not raw_targets:
                scan.status = "failed"
                scan.error_message = (
                    "All specified targets were blocked by SSRF protection."
                )
                scan.completed_at = datetime.now(timezone.utc)
                scan.updated_at = scan.completed_at
                await session.commit()
                await log_event(
                    level="error",
                    phase="discovery",
                    message="Scan failed: All targets blocked by SSRF protection.",
                )
                return

            # ── 4. Expand targets (DNS / network discovery) ──────────────────────
            expanded_hosts: list[str] = []
            for target in raw_targets:
                if "/" in target:
                    await log_event(
                        level="info",
                        phase="discovery",
                        message=f"Network range target detected: {target}. Starting network discovery...",
                    )
                    try:
                        from app.scanners.network_discovery import discover_tls_hosts

                        discovered = await discover_tls_hosts(target)

                        await log_event(
                            level="info",
                            phase="discovery",
                            message=f"Discovery on range {target} found {len(discovered)} active service(s).",
                            details={"discovered": discovered},
                        )

                        for d in discovered:
                            ip = d["ip"]
                            # Validate discovered IP for SSRF safety
                            is_safe, reason = is_target_ssrf_safe(ip)
                            if not is_safe:
                                await log_event(
                                    level="warn",
                                    phase="discovery",
                                    message=f"SSRF Filter blocked discovered IP: {ip} ({reason})",
                                )
                            elif ip not in expanded_hosts:
                                expanded_hosts.append(ip)
                    except (RuntimeError, OSError) as e:
                        error_msg = f"Network discovery failed: {str(e)}"
                        logger.exception(error_msg)
                        scan.status = "failed"
                        scan.error_message = error_msg
                        scan.completed_at = datetime.now(timezone.utc)
                        scan.updated_at = scan.completed_at
                        await session.commit()
                        await log_event(
                            level="error",
                            phase="discovery",
                            message=f"Scan failed: {error_msg}",
                        )
                        return

                elif (
                    any(c.isalpha() for c in target)
                    and not target.startswith("fe80")
                    and ":" not in target
                ):
                    # Domain/hostname target (exclude raw IPv6 here — handled above)
                    await log_event(
                        level="info",
                        phase="discovery",
                        message=f"Domain target detected: {target}. Querying DNS records...",
                    )
                    try:
                        from app.scanners.network_discovery import enumerate_dns_targets

                        dns_res = enumerate_dns_targets(target)

                        await log_event(
                            level="info",
                            phase="discovery",
                            message=f"DNS enumeration for {target} complete.",
                            details=dns_res,
                        )

                        resolved_hosts: list[str] = []
                        a_records = dns_res.get("a_records", [])
                        aaaa_records = dns_res.get("aaaa_records", [])

                        if a_records:
                            resolved_hosts.append(a_records[0])
                        elif aaaa_records:
                            resolved_hosts.append(aaaa_records[0])
                        else:
                            cnames = dns_res.get("cname_records", [])
                            if cnames:
                                resolved_hosts.append(cnames[0].strip("."))
                            else:
                                mxs = dns_res.get("mx_records", [])
                                if mxs:
                                    parts = mxs[0].split()
                                    if len(parts) >= 2:
                                        resolved_hosts.append(parts[1].strip("."))
                                    else:
                                        resolved_hosts.append(mxs[0].strip("."))

                        resolved_hosts = [h for h in resolved_hosts if h]

                        # Validate DNS-resolved hosts for SSRF safety
                        safe_resolved: list[str] = []
                        for h in resolved_hosts:
                            is_safe, reason = is_target_ssrf_safe(h)
                            if not is_safe:
                                await log_event(
                                    level="warn",
                                    phase="discovery",
                                    message=f"SSRF Filter blocked DNS-resolved host: {h} ({reason})",
                                )
                            else:
                                safe_resolved.append(h)

                        if safe_resolved:
                            for h in safe_resolved:
                                if h not in expanded_hosts:
                                    expanded_hosts.append(h)
                        else:
                            if target not in expanded_hosts:
                                expanded_hosts.append(target)
                    except (RuntimeError, OSError) as e:
                        logger.warning(
                            f"DNS enumeration failed for {target}: {e}. Scanning target directly."
                        )
                        if target not in expanded_hosts:
                            expanded_hosts.append(target)
                else:
                    if target not in expanded_hosts:
                        expanded_hosts.append(target)

            # Final SSRF safety net for any remaining hosts (e.g., hostnames not yet resolved)
            import ipaddress

            def is_hostname_ssrf_safe(host: str) -> bool:
                """Final safety check for hostnames that haven't been resolved yet."""
                if settings.OFFLINE_MODE:
                    return True
                from app.scanners.safe_target import (
                    ALLOW_PRIVATE_RANGES,
                    ALLOW_LOOPBACK,
                    ALLOW_LINK_LOCAL,
                    ALLOW_MULTICAST,
                )

                try:
                    ip = ipaddress.ip_address(host)
                    if ip.is_loopback and not ALLOW_LOOPBACK:
                        return False
                    if ip.is_private and not ALLOW_PRIVATE_RANGES:
                        return False
                    if ip.is_link_local and not ALLOW_LINK_LOCAL:
                        return False
                    if ip.is_multicast and not ALLOW_MULTICAST:
                        return False
                    if ip.is_unspecified:
                        return False
                    if str(ip) == "169.254.169.254" and not ALLOW_PRIVATE_RANGES:
                        return False
                    return True
                except ValueError:
                    # Hostname - will be resolved later, allow for now but log
                    if host.lower().strip() in ["localhost", "localhost.localdomain"]:
                        return ALLOW_LOOPBACK
                    return True

            safe_hosts = []
            for h in expanded_hosts:
                if is_hostname_ssrf_safe(h):
                    safe_hosts.append(h)
                else:
                    await log_event(
                        level="warn",
                        phase="discovery",
                        message=f"SSRF Filter blocked unsafe scan target: {h}",
                    )

            hosts = safe_hosts
            if not hosts:
                scan.status = "failed"
                scan.error_message = "No active hosts resolved or discovered."
                scan.completed_at = datetime.now(timezone.utc)
                scan.updated_at = scan.completed_at
                await session.commit()
                await log_event(
                    level="error",
                    phase="discovery",
                    message="Scan failed: No active hosts resolved or discovered.",
                )
                return

            assets_found_count = 0
            findings_created_count = 0

            try:
                # ── 5. Passive Sniffing Scan vs Active Scanning ────────────────
                if scan.scan_type == "passive":
                    interface = scan.target or ""
                    duration_seconds = 60
                    try:
                        if scan.config:
                            cfg = (
                                json.loads(scan.config)
                                if isinstance(scan.config, str)
                                else scan.config
                            )
                            if isinstance(cfg, dict):
                                duration_seconds = int(cfg.get("duration_seconds", 60))
                    except Exception:
                        duration_seconds = 60

                    await log_event(
                        level="info",
                        phase="discovery",
                        message=f"Initiating passive sniffing on interface '{interface}' for {duration_seconds} seconds.",
                    )

                    from app.scanners.pyshark_capture import capture_all_handshakes
                    from app.analysis.algo_classifier import classify_algorithm
                    from app.services.finding_service import generate_findings

                    try:
                        handshakes = await capture_all_handshakes(
                            interface=interface, duration_seconds=duration_seconds
                        )
                    except Exception as sniff_exc:
                        await log_event(
                            level="error",
                            phase="discovery",
                            message=f"Passive sniff failed to run: {sniff_exc}. Check permissions/tshark.",
                        )
                        raise

                    await log_event(
                        level="info",
                        phase="analysis",
                        message=f"Sniffing completed. Captured {len(handshakes)} handshake records.",
                    )

                    for entry in handshakes:
                        server_ip = None
                        port = None
                        proto = "tcp"
                        h_type = entry.get("type")

                        if h_type == "ClientHello":
                            server_ip = entry.get("dst_ip")
                            port = int(entry.get("dst_port") or 443)
                        elif h_type == "ServerHello":
                            server_ip = entry.get("dst_ip")
                            port = 443
                        elif h_type == "SSH_KEXINIT":
                            server_ip = entry.get("dst_ip")
                            port = int(entry.get("dst_port") or 22)

                        if not server_ip:
                            continue

                        # Create/Get Asset
                        asset_name = (
                            f"{server_ip}:{port}"
                            if h_type != "SSH_KEXINIT"
                            else f"{server_ip}:{port} (SSH)"
                        )
                        asset_res = await session.execute(
                            select(Asset).where(
                                Asset.name == asset_name, Asset.deleted_at.is_(None)
                            )
                        )
                        asset = asset_res.scalar_one_or_none()
                        if not asset:
                            asset = Asset(
                                name=asset_name,
                                asset_type="server",
                                ip_address=server_ip,
                                port=port,
                                protocol=proto,
                                environment=(
                                    "development"
                                    if (
                                        "test" in server_ip
                                        or "local" in server_ip
                                        or server_ip == "127.0.0.1"
                                    )
                                    else "production"
                                ),
                                discovery_source="passive_sniff",
                                first_scan_id=scan.id,
                                first_discovered_at=datetime.now(timezone.utc),
                            )
                            session.add(asset)
                            await session.flush()
                            await session.refresh(asset)

                        asset.last_scan_id = scan.id
                        asset.last_verified_at = datetime.now(timezone.utc)
                        assets_found_count += 1

                        # Save Algorithms and generate findings
                        if h_type in ("ClientHello", "ServerHello"):
                            # Save Cipher
                            ciphers: list[str] = []
                            if h_type == "ClientHello":
                                ciphers = entry.get("cipher_suites") or []
                            else:
                                selected_cipher = entry.get("selected_cipher")
                                if selected_cipher:
                                    ciphers = [selected_cipher]

                            for cipher in ciphers:
                                existing_algo = await session.execute(
                                    select(Algorithm).where(
                                        Algorithm.asset_id == asset.id,
                                        Algorithm.scan_id == scan.id,
                                        Algorithm.algorithm_name == cipher,
                                    )
                                )
                                if not existing_algo.scalar_one_or_none():
                                    cls_res = classify_algorithm(
                                        cipher, algorithm_type="symmetric"
                                    )
                                    algo = Algorithm(
                                        asset_id=asset.id,
                                        scan_id=scan.id,
                                        algorithm_name=cipher,
                                        algorithm_type="symmetric",
                                        pqc_status=cls_res["pqc_status"],
                                        is_quantum_vulnerable=cls_res[
                                            "is_quantum_vulnerable"
                                        ],
                                    )
                                    session.add(algo)

                            # Save Key Exchange Groups
                            groups: list[str] = []
                            if h_type == "ClientHello":
                                groups = entry.get("supported_groups") or []
                            else:
                                selected_group = entry.get("selected_group")
                                if selected_group:
                                    groups = [selected_group]

                            for group_val in groups:
                                group_id = None
                                group_name = str(group_val)
                                try:
                                    if isinstance(
                                        group_val, str
                                    ) and group_val.lower().startswith("0x"):
                                        group_id = int(group_val, 16)
                                    else:
                                        group_id = int(group_val)
                                except (ValueError, TypeError):
                                    pass

                                existing_algo = await session.execute(
                                    select(Algorithm).where(
                                        Algorithm.asset_id == asset.id,
                                        Algorithm.scan_id == scan.id,
                                        Algorithm.algorithm_name == group_name,
                                    )
                                )
                                if not existing_algo.scalar_one_or_none():
                                    cls_res = classify_algorithm(
                                        group_name,
                                        kex_group_id=group_id,
                                        algorithm_type="key_exchange",
                                    )
                                    algo = Algorithm(
                                        asset_id=asset.id,
                                        scan_id=scan.id,
                                        algorithm_name=group_name,
                                        algorithm_type="key_exchange",
                                        pqc_status=cls_res["pqc_status"],
                                        is_quantum_vulnerable=cls_res[
                                            "is_quantum_vulnerable"
                                        ],
                                    )
                                    session.add(algo)

                            pqc_group_ids = {
                                0x01FC,
                                0x01FD,
                                0x0200,
                                0x2B92,
                                0x2B93,
                                0x2B94,
                                0xFE30,
                                0x639A,
                            }
                            is_pqc = False
                            if h_type == "ClientHello":
                                is_pqc = entry.get("has_pqc", False)
                            else:
                                selected_group_raw = entry.get("selected_group")
                                if selected_group_raw:
                                    try:
                                        if isinstance(
                                            selected_group_raw, str
                                        ) and selected_group_raw.lower().startswith(
                                            "0x"
                                        ):
                                            sg_id = int(selected_group_raw, 16)
                                        else:
                                            sg_id = int(selected_group_raw)
                                        is_pqc = sg_id in pqc_group_ids
                                    except (ValueError, TypeError):
                                        pass

                            if not is_pqc:
                                existing_finding = await session.execute(
                                    select(Finding).where(
                                        Finding.asset_id == asset.id,
                                        Finding.scan_id == scan.id,
                                        Finding.finding_type == "pqc_not_supported",
                                    )
                                )
                                if not existing_finding.scalar_one_or_none():
                                    from app.services.layer_service import (
                                        layer_for_finding,
                                    )
                                    from app.services.risk_service import (
                                        calculate_risk_score,
                                    )

                                    risk_score = calculate_risk_score(
                                        hndl_exposure="high",
                                        system_exposure="internal",
                                        pqc_status="vulnerable",
                                        replaceability="medium",
                                        years_to_deadline=10,
                                    )

                                    desc = "The SSL/TLS client handshake does not advertise support for any post-quantum key exchange groups."
                                    if h_type == "ServerHello":
                                        desc = f"The SSL/TLS server completed handshake using a classical key exchange group ({entry.get('selected_group') or 'classical'}), which is vulnerable to decryption by future quantum computers."

                                    finding = Finding(
                                        asset_id=asset.id,
                                        scan_id=scan.id,
                                        finding_type="pqc_not_supported",
                                        severity="high",
                                        title=(
                                            "SSL/TLS Client Lacks Post-Quantum Support"
                                            if h_type == "ClientHello"
                                            else "SSL/TLS Negotiation Settled on Classical Key Exchange"
                                        ),
                                        description=desc,
                                        algorithm=entry.get("selected_group")
                                        or "classical",
                                        pqc_status="vulnerable",
                                        risk_score=risk_score,
                                        layer=layer_for_finding(
                                            finding_type="pqc_not_supported",
                                            asset=asset,
                                        ),
                                        hndl_exposure="high",
                                        evidence=entry,
                                        remediation="Configure the server/client to support hybrid post-quantum groups like X25519MLKEM768.",
                                        recommended_algorithm="X25519MLKEM768",
                                        status="open",
                                    )
                                    session.add(finding)
                                    findings_created_count += 1

                        elif h_type == "SSH_KEXINIT":
                            kex_algs = entry.get("kex_algorithms") or []
                            for algo_name in kex_algs[:10]:
                                existing_algo = await session.execute(
                                    select(Algorithm).where(
                                        Algorithm.asset_id == asset.id,
                                        Algorithm.scan_id == scan.id,
                                        Algorithm.algorithm_name == algo_name,
                                    )
                                )
                                if not existing_algo.scalar_one_or_none():
                                    cls_res = classify_algorithm(
                                        algo_name, algorithm_type="key_exchange"
                                    )
                                    algo = Algorithm(
                                        asset_id=asset.id,
                                        scan_id=scan.id,
                                        algorithm_name=algo_name,
                                        algorithm_type="key_exchange",
                                        pqc_status=cls_res["pqc_status"],
                                        is_quantum_vulnerable=cls_res[
                                            "is_quantum_vulnerable"
                                        ],
                                    )
                                    session.add(algo)

                            fc = await generate_findings(
                                session, scan.id, asset.id, kex_algos=kex_algs
                            )
                            findings_created_count += fc

                    await session.flush()
                else:
                    try:
                        host_agg = await asyncio.wait_for(
                            _run_host_tasks(
                                scan_id=scan.id,
                                hosts=hosts,
                                strict_tls=strict_tls,
                                scan_type=scan.scan_type,
                                advanced_tools=getattr(scan, "advanced_tools", False),
                                log_event=log_event,
                            ),
                            timeout=settings.SCAN_MAX_DURATION_SECONDS,
                        )
                    except asyncio.TimeoutError:
                        error_msg = f"Scan exceeded maximum duration of {settings.SCAN_MAX_DURATION_SECONDS} seconds."
                        logger.error(f"Scan {scan.id} failed: {error_msg}")
                        scan.status = "failed"
                        scan.error_message = error_msg
                        scan.completed_at = datetime.now(timezone.utc)
                        scan.updated_at = scan.completed_at
                        await session.commit()
                        await log_event(
                            level="error",
                            phase="discovery",
                            message=f"Scan failed: {error_msg}",
                        )
                        return
                    assets_found_count += host_agg["assets_total"]
                    findings_created_count += host_agg["findings_total"]

                # ── 6. Final scan completion ──────────────────────────────────────
                end_time = datetime.now(timezone.utc)
                duration = int(
                    (end_time - started_at_fallback(scan.started_at)).total_seconds()
                )

                # Recompute assets/findings counts from the database so the
                # scan row is always consistent with the actual persisted
                # rows. This guards against the case where a per-host
                # savepoint was rolled back (discarding the asset/finding
                # rows) but the in-memory `assets_found_count` /
                # `findings_created_count` accumulators were never
                # decremented, leaving the scan row in a "ghost" state.
                real_assets_res = await session.execute(
                    select(func.count(Asset.id)).where(
                        Asset.last_scan_id == scan.id,
                        Asset.deleted_at.is_(None),
                    )
                )
                real_findings_res = await session.execute(
                    select(func.count(Finding.id)).where(
                        Finding.scan_id == scan.id,
                        Finding.deleted_at.is_(None),
                    )
                )
                assets_found_count = real_assets_res.scalar_one() or 0
                findings_created_count = real_findings_res.scalar_one() or 0

                scan.status = "completed"
                scan.completed_at = end_time
                scan.duration_seconds = duration
                scan.assets_found = assets_found_count
                scan.findings_created = findings_created_count
                scan.updated_at = end_time
                await session.commit()

                # Clear dashboard cache
                try:
                    from app.api.dashboard import clear_dashboard_cache

                    await clear_dashboard_cache()
                except Exception as cache_err:
                    logger.warning(f"Failed to clear dashboard cache: {cache_err}")

                await log_event(
                    level="info",
                    phase="reporting",
                    message=(
                        f"Scan task finished successfully. "
                        f"Discovered {assets_found_count} assets, raised {findings_created_count} findings."
                    ),
                )

            except (RuntimeError, OSError, IntegrityError, DBAPIError) as e:
                logger.exception("Error during scan execution")
                scan.status = "failed"
                scan.error_message = str(e)
                scan.completed_at = datetime.now(timezone.utc)
                scan.updated_at = scan.completed_at
                await session.commit()

                try:
                    from app.api.dashboard import clear_dashboard_cache

                    await clear_dashboard_cache()
                except Exception as cache_err:
                    logger.warning(f"Failed to clear dashboard cache: {cache_err}")

                session.add(
                    ScanLog(
                        scan_id=scan.id,
                        level="error",
                        phase="reporting",
                        message=f"Scan execution crashed: {str(e)}",
                    )
                )
                await session.commit()
