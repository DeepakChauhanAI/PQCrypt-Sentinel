"""
Per-host scanning routine for the PQC orchestrator.

Extracted from `scan_orchestrator.py` so the host loop can run in
parallel across hosts — each host gets its own AsyncSession (via
`AsyncSessionLocal()`) and its own savepoint, isolating DB state
between hosts.

This module never raises. Per-host exceptions are captured and
returned as `(error_message)` so the orchestrator can log them
without aborting the rest of the scan.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import AsyncSessionLocal
from app.models.models import Asset, Certificate, Algorithm, ScanLog, Scan
from app.scanners.tls_scanner import scan_tls_endpoint
from app.scanners.ssh_scanner import scan_ssh_endpoint
from app.scanners.ike_scanner import scan_ike_endpoint
from app.scanners.mail_scanner import scan_mail_endpoint
from app.scanners.ct_log_scanner import scan_ct_logs_for_domain
from app.services.finding_service import generate_findings
from app.analysis.algo_classifier import classify_algorithm
from app.services.scan_orchestrator import (
    MAX_CONCURRENT_PORT_PROBES,
    _gather_with_limit,
    _run_advanced_scanners,
)

logger = logging.getLogger(__name__)


# Per-host ports (kept identical to scan_orchestrator's old hard-coded
# values so behavior is preserved across the refactor).
_TLS_PORTS = [443, 8443, 9080, 8883, 636, 993, 995]
_SSH_PORTS = [22, 1001, 4096]
_MAIL_PORTS = [25, 465, 587]


LogFn = Callable[..., Awaitable[None]]


async def _host_log(
    session: AsyncSession,
    scan_id: str,
    level: str,
    phase: str,
    message: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Add a ScanLog row using the host's own session (no commit)."""
    session.add(
        ScanLog(
            scan_id=scan_id,
            level=level,
            phase=phase,
            message=message,
            details=details,
        )
    )
    await session.flush()


async def _log_outside_savepoint(
    scan_id: str,
    level: str,
    phase: str,
    message: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Write a ScanLog row in a fresh session so it survives savepoint rollback.

    The per-host savepoint in `scan_host` is rolled back whenever the
    host scan raises an exception. Any `ScanLog` rows added to the
    host's session before the rollback are also discarded, which means
    the error is invisible to the user. This helper opens its own
    short-lived `AsyncSessionLocal()` connection, writes the log row,
    commits, and closes — guaranteeing the row persists regardless of
    the host-session transaction state.
    """
    try:
        async with AsyncSessionLocal() as session:
            session.add(
                ScanLog(
                    scan_id=scan_id,
                    level=level,
                    phase=phase,
                    message=message,
                    details=details,
                )
            )
            await session.commit()
    except Exception as exc:  # pragma: no cover - defensive
        # Never let the error-logging path itself crash the scan.
        logger.warning(
            "Failed to write out-of-savepoint log for scan %s: %s", scan_id, exc
        )


def _is_local_host(host: str) -> bool:
    return "test" in host or "local" in host


async def _get_host_ip_and_fqdn(session: AsyncSession, scan_id: str, host: str) -> Tuple[Optional[str], Optional[str]]:
    import ipaddress
    ip_addr = None
    fqdn_val = None
    try:
        ipaddress.ip_address(host)
        ip_addr = host
    except ValueError:
        fqdn_val = host

    if ip_addr:
        try:
            scan_res = await session.execute(
                select(Scan.target).where(Scan.id == scan_id)
            )
            scan_target = scan_res.scalar_one_or_none()
            if scan_target and "/" not in scan_target:
                try:
                    ipaddress.ip_address(scan_target)
                except ValueError:
                    fqdn_val = scan_target
        except Exception:
            pass
    return ip_addr, fqdn_val


async def _scan_host_tls(
    session: AsyncSession,
    scan_id: str,
    scan_type: str,
    host: str,
    strict_tls: bool,
    log: LogFn,
) -> Tuple[int, int, bool]:
    """Run the TLS probes for a host. Returns (assets_delta, findings_delta, is_active)."""
    assets_delta = 0
    findings_delta = 0
    is_active = False

    tls_probe_tasks = [
        scan_tls_endpoint(host, port=p, verify_tls=strict_tls) for p in _TLS_PORTS
    ]
    tls_results = await _gather_with_limit(
        tls_probe_tasks, limit=MAX_CONCURRENT_PORT_PROBES
    )
    for tls_port, tls_res in zip(_TLS_PORTS, tls_results):
        if isinstance(tls_res, tuple) and tls_res and tls_res[0] == "__error__":
            await log(
                "warn",
                "analysis",
                f"TLS probe raised exception on {host}:{tls_port}: {tls_res[1]}",
            )
            continue
        try:
            await log("info", "discovery", f"Initiating TLS probe on {host}:{tls_port}")
            if not (tls_res.success and tls_res.cert_data):
                await log(
                    "warn",
                    "analysis",
                    f"TLS probe failed on {host}:{tls_port}: {tls_res.error_message}",
                )
                continue

            is_active = True
            assets_delta += 1
            await log(
                "info",
                "analysis",
                (
                    f"TLS service detected on {host}:{tls_port}. "
                    f"Cipher: {tls_res.cipher_suite}, Protocol: {tls_res.tls_version}"
                ),
            )

            asset_name = f"{host}:{tls_port}"
            asset_result = await session.execute(
                select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
            )
            asset = asset_result.scalar_one_or_none()
            ip_addr, fqdn_val = await _get_host_ip_and_fqdn(session, scan_id, host)
            if not asset:
                asset = Asset(
                    name=asset_name,
                    asset_type="server",
                    ip_address=ip_addr,
                    fqdn=fqdn_val,
                    port=tls_port,
                    protocol="tcp",
                    environment="development" if _is_local_host(host) else "production",
                    discovery_source="tls_scan",
                    first_scan_id=scan_id,
                    first_discovered_at=datetime.now(timezone.utc),
                )
                session.add(asset)
                await session.flush()
                await session.refresh(asset)
            else:
                asset.ip_address = ip_addr
                asset.fqdn = fqdn_val

            asset.last_scan_id = scan_id
            asset.last_verified_at = datetime.now(timezone.utc)
            asset.asset_metadata = {
                "tls_version": tls_res.tls_version,
                "cipher_suite": tls_res.cipher_suite,
            }

            cert_vals = tls_res.cert_data
            thumbprint = cert_vals["thumbprint"]
            existing_cert = await session.execute(
                select(Certificate).where(
                    Certificate.thumbprint == thumbprint,
                    Certificate.deleted_at.is_(None),
                )
            )
            certificate = existing_cert.scalar_one_or_none()
            if certificate is None:
                certificate = Certificate(
                    asset_id=asset.id,
                    thumbprint=thumbprint,
                    subject=cert_vals["subject"],
                    issuer=cert_vals["issuer"],
                    serial_number=cert_vals.get("serial_number"),
                    sig_algorithm=cert_vals["sig_algorithm"],
                    pub_key_algorithm=cert_vals["pub_key_algorithm"],
                    pub_key_size=cert_vals.get("pub_key_size"),
                    curve_name=cert_vals.get("curve_name"),
                    not_before=cert_vals["not_before"],
                    not_after=cert_vals["not_after"],
                    is_self_signed=cert_vals["is_self_signed"],
                    is_ca=cert_vals["is_ca"],
                    key_usage=cert_vals.get("key_usage"),
                    san_dns=cert_vals.get("san_dns"),
                    san_ip=cert_vals.get("san_ip"),
                    pqc_capable=cert_vals["pqc_capable"],
                    pqc_details=cert_vals["pqc_details"],
                    raw_certificate=cert_vals.get("raw_certificate"),
                )
                session.add(certificate)
                await session.flush()
            elif certificate.asset_id != asset.id:
                # Same cert (thumbprint) served by a different asset — re-link
                # so the cert appears under both assets' Certificates tabs.
                certificate.asset_id = asset.id

            existing_algo = await session.execute(
                select(Algorithm).where(
                    Algorithm.asset_id == asset.id,
                    Algorithm.scan_id == scan_id,
                    Algorithm.algorithm_name == cert_vals["sig_algorithm"],
                )
            )
            if not existing_algo.scalar_one_or_none():
                algo = Algorithm(
                    asset_id=asset.id,
                    scan_id=scan_id,
                    algorithm_name=cert_vals["sig_algorithm"],
                    algorithm_type="signature",
                    pqc_status="pqc_ready" if cert_vals["pqc_capable"] else "vulnerable",
                    is_quantum_vulnerable=not cert_vals["pqc_capable"],
                )
                session.add(algo)

            fc = await generate_findings(session, scan_id, asset.id, cert_data=cert_vals)
            findings_delta += fc
        except Exception as tls_exc:  # pragma: no cover - safety net
            await _log_outside_savepoint(
                scan_id,
                "warn",
                "analysis",
                f"TLS probe raised exception on {host}:{tls_port}: {tls_exc}",
            )
    return assets_delta, findings_delta, is_active


async def _scan_host_ssh(
    session: AsyncSession,
    scan_id: str,
    scan_type: str,
    host: str,
    log: LogFn,
) -> Tuple[int, int, bool]:
    assets_delta = 0
    findings_delta = 0
    is_active = False

    ssh_probe_tasks = [scan_ssh_endpoint(host, port=p) for p in _SSH_PORTS]
    ssh_results = await _gather_with_limit(
        ssh_probe_tasks, limit=MAX_CONCURRENT_PORT_PROBES
    )
    for ssh_port, ssh_res in zip(_SSH_PORTS, ssh_results):
        if isinstance(ssh_res, tuple) and ssh_res and ssh_res[0] == "__error__":
            await log(
                "warn",
                "analysis",
                f"SSH probe raised exception on {host}:{ssh_port}: {ssh_res[1]}",
            )
            continue
        try:
            if not ssh_res.success:
                await log(
                    "warn",
                    "analysis",
                    f"SSH probe failed on {host}:{ssh_port}: {ssh_res.error_message}",
                )
                continue

            is_active = True
            assets_delta += 1
            await log(
                "info",
                "analysis",
                (
                    f"SSH service detected on {host}:{ssh_port}. "
                    f"KEX: {len(ssh_res.kex_algorithms)} algos, "
                    f"Host Key: {len(ssh_res.host_key_algorithms)} algos"
                ),
            )
            asset_name = f"{host}:{ssh_port} (SSH)"
            asset_result = await session.execute(
                select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
            )
            asset = asset_result.scalar_one_or_none()
            ip_addr, fqdn_val = await _get_host_ip_and_fqdn(session, scan_id, host)
            if not asset:
                asset = Asset(
                    name=asset_name,
                    asset_type="server",
                    ip_address=ip_addr,
                    fqdn=fqdn_val,
                    port=ssh_port,
                    protocol="tcp",
                    environment="development" if _is_local_host(host) else "production",
                    discovery_source="ssh_scan",
                    first_scan_id=scan_id,
                    first_discovered_at=datetime.now(timezone.utc),
                )
                session.add(asset)
                await session.flush()
                await session.refresh(asset)
            else:
                asset.ip_address = ip_addr
                asset.fqdn = fqdn_val

            asset.last_scan_id = scan_id
            asset.last_verified_at = datetime.now(timezone.utc)
            asset.asset_metadata = {
                "pqc_status": ssh_res.pqc_status,
                "kex_algorithms": ssh_res.kex_algorithms[:10],
            }
            for algo_name in ssh_res.kex_algorithms[:5]:
                existing_algo = await session.execute(
                    select(Algorithm).where(
                        Algorithm.asset_id == asset.id,
                        Algorithm.scan_id == scan_id,
                        Algorithm.algorithm_name == algo_name,
                    )
                )
                if not existing_algo.scalar_one_or_none():
                    cls_res = classify_algorithm(algo_name)
                    algo = Algorithm(
                        asset_id=asset.id,
                        scan_id=scan_id,
                        algorithm_name=algo_name,
                        algorithm_type="key_exchange",
                        pqc_status=cls_res["pqc_status"],
                        is_quantum_vulnerable=cls_res["is_quantum_vulnerable"],
                    )
                    session.add(algo)
            fc = await generate_findings(
                session, scan_id, asset.id, kex_algos=ssh_res.kex_algorithms
            )
            findings_delta += fc
        except Exception as ssh_exc:  # pragma: no cover - safety net
            await _log_outside_savepoint(
                scan_id,
                "warn",
                "analysis",
                f"SSH probe raised exception on {host}:{ssh_port}: {ssh_exc}",
            )
    return assets_delta, findings_delta, is_active


async def _scan_host_targeted(
    session: AsyncSession,
    scan_id: str,
    scan_type: str,
    host: str,
    strict_tls: bool,
    log: LogFn,
) -> Tuple[int, int, bool]:
    assets_delta = 0
    findings_delta = 0
    is_active = False

    if host.count(":") == 0:
        ike_res = await scan_ike_endpoint(host, port=500)
        if ike_res.success:
            is_active = True
            assets_delta += 1
            await log(
                "info",
                "analysis",
                f"IKE/IPsec responder detected on {host}:500",
            )
            asset_name = f"{host}:500 (IKE)"
            asset_result = await session.execute(
                select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
            )
            asset = asset_result.scalar_one_or_none()
            ip_addr, fqdn_val = await _get_host_ip_and_fqdn(session, scan_id, host)
            if not asset:
                asset = Asset(
                    name=asset_name,
                    asset_type="vpn_gateway",
                    ip_address=ip_addr,
                    fqdn=fqdn_val,
                    port=500,
                    protocol="udp",
                    environment="development" if _is_local_host(host) else "production",
                    discovery_source="ike_scan",
                    first_scan_id=scan_id,
                    first_discovered_at=datetime.now(timezone.utc),
                )
                session.add(asset)
                await session.flush()
                await session.refresh(asset)
            else:
                asset.ip_address = ip_addr
                asset.fqdn = fqdn_val
            asset.last_scan_id = scan_id
            asset.last_verified_at = datetime.now(timezone.utc)
            asset.asset_metadata = {
                "ike_version": ike_res.ike_version,
                "pqc_status": ike_res.pqc_status,
                "dh_groups": ike_res.dh_groups,
            }
            if ike_res.pqc_status in ("pqc_ready", "hybrid"):
                algo = Algorithm(
                    asset_id=asset.id,
                    scan_id=scan_id,
                    algorithm_name="IKE-SA",
                    algorithm_type="kem",
                    pqc_status=ike_res.pqc_status,
                    is_quantum_vulnerable=(ike_res.pqc_status == "vulnerable"),
                )
                session.add(algo)

    for mail_port in _MAIL_PORTS:
        mail_res = await scan_mail_endpoint(host, port=mail_port, verify_tls=strict_tls)
        if mail_res.success:
            is_active = True
            assets_delta += 1
            await log(
                "info",
                "analysis",
                f"Mail service detected on {host}:{mail_port} ({mail_res.mode})",
            )
            asset_name = f"{host}:{mail_port} (SMTP)"
            asset_result = await session.execute(
                select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
            )
            asset = asset_result.scalar_one_or_none()
            ip_addr, fqdn_val = await _get_host_ip_and_fqdn(session, scan_id, host)
            if not asset:
                asset = Asset(
                    name=asset_name,
                    asset_type="server",
                    ip_address=ip_addr,
                    fqdn=fqdn_val,
                    port=mail_port,
                    protocol="tcp",
                    environment="development" if _is_local_host(host) else "production",
                    discovery_source="mail_scan",
                    first_scan_id=scan_id,
                    first_discovered_at=datetime.now(timezone.utc),
                )
                session.add(asset)
                await session.flush()
                await session.refresh(asset)
            else:
                asset.ip_address = ip_addr
                asset.fqdn = fqdn_val
            asset.last_scan_id = scan_id
            asset.last_verified_at = datetime.now(timezone.utc)
            asset.asset_metadata = {
                "mail_mode": mail_res.mode,
                "starttls_supported": mail_res.starttls_supported,
                "tls_version": mail_res.tls_version,
                "cipher_suite": mail_res.cipher_suite,
            }
            if mail_res.cert_data:
                cert_data = mail_res.cert_data
                existing_cert = await session.execute(
                    select(Certificate).where(
                        Certificate.thumbprint == cert_data["thumbprint"],
                        Certificate.deleted_at.is_(None),
                    )
                )
                certificate = existing_cert.scalar_one_or_none()
                if certificate is None:
                    certificate = Certificate(
                        asset_id=asset.id,
                        thumbprint=cert_data["thumbprint"],
                        subject=cert_data["subject"],
                        issuer=cert_data["issuer"],
                        serial_number=cert_data.get("serial_number"),
                        sig_algorithm=cert_data["sig_algorithm"],
                        pub_key_algorithm=cert_data["pub_key_algorithm"],
                        pub_key_size=cert_data.get("pub_key_size"),
                        curve_name=cert_data.get("curve_name"),
                        not_before=cert_data["not_before"],
                        not_after=cert_data["not_after"],
                        is_self_signed=cert_data["is_self_signed"],
                        is_ca=cert_data["is_ca"],
                        key_usage=cert_data.get("key_usage"),
                        san_dns=cert_data.get("san_dns"),
                        san_ip=cert_data.get("san_ip"),
                        pqc_capable=cert_data["pqc_capable"],
                        pqc_details=cert_data["pqc_details"],
                        raw_certificate=cert_data.get("raw_certificate"),
                    )
                    session.add(certificate)
                elif certificate.asset_id != asset.id:
                    # Same cert served by a different asset — re-link
                    certificate.asset_id = asset.id
    return assets_delta, findings_delta, is_active


async def _scan_host_ct(
    session: AsyncSession,
    scan_id: str,
    host: str,
    log: LogFn,
) -> int:
    """CT log scan. Returns assets delta (0 or 1 — flagged via log only)."""
    ct_res = await scan_ct_logs_for_domain(host)
    if not ct_res.success:
        return 0
    await log(
        "info",
        "analysis",
        f"CT log scan for {host} returned {len(ct_res.certificates)} cert(s).",
    )
    for ct_cert in ct_res.certificates[:20]:
        thumbprint = ct_cert.get("id") or ct_cert.get("serial_number") or ""
        if not thumbprint:
            continue
        existing_cert = await session.execute(
            select(Certificate).where(
                Certificate.thumbprint == thumbprint,
                Certificate.deleted_at.is_(None),
            )
        )
        if not existing_cert.scalar_one_or_none():
            certificate = Certificate(
                asset_id=None,
                thumbprint=thumbprint,
                subject=ct_cert.get("common_name") or ct_cert.get("name_value") or "",
                issuer=ct_cert.get("issuer_name") or "",
                serial_number=ct_cert.get("serial_number"),
                sig_algorithm="unknown",
                pub_key_algorithm="unknown",
                not_before=datetime.now(timezone.utc),
                not_after=datetime.now(timezone.utc),
                is_self_signed=False,
                is_ca=False,
                pqc_capable=False,
            )
            session.add(certificate)
            await session.flush()
    return 0


async def scan_host(
    session: AsyncSession,
    scan_id: str,
    scan_type: str,
    host: str,
    strict_tls: bool,
    advanced_tools: bool,
) -> Dict[str, Any]:
    """Run the full per-host pipeline. Returns a result dict the orchestrator aggregates.

    Result shape::

        {
            "host": str,
            "assets": int,        # delta to add to scan.assets_found
            "findings": int,      # delta to add to scan.findings_created
            "logs": list[str],    # short log messages (caller flushes via own session)
            "error": str | None,  # exception message, if any
        }
    """
    log_messages: list[str] = []

    async def log(level: str, phase: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        log_messages.append(f"[{level}/{phase}] {message}")
        await _host_log(session, scan_id, level, phase, message, details)

    assets_delta = 0
    findings_delta = 0
    is_active = False
    error: Optional[str] = None

    savepoint_name = f"host_{host.replace('.', '_').replace(':', '_')}"
    await session.execute(text(f"SAVEPOINT {savepoint_name}"))

    try:
        await log("info", "discovery", f"Analyzing host: {host}")

        if scan_type in ("full", "tls_only"):
            a, f, is_active = await _scan_host_tls(
                session, scan_id, scan_type, host, strict_tls, log
            )
            assets_delta += a
            findings_delta += f

        if scan_type in ("full", "ssh_only"):
            a, f, is_active_now = await _scan_host_ssh(
                session, scan_id, scan_type, host, log
            )
            assets_delta += a
            findings_delta += f
            is_active = is_active or is_active_now

        if scan_type in ("full", "targeted"):
            a, f, is_active_now = await _scan_host_targeted(
                session, scan_id, scan_type, host, strict_tls, log
            )
            assets_delta += a
            findings_delta += f
            is_active = is_active or is_active_now

        if scan_type == "ct_monitor":
            await _scan_host_ct(session, scan_id, host, log)

        if not is_active and not advanced_tools:
            await log("warn", "discovery", f"No active services detected on {host}.")

        if advanced_tools:
            is_active, assets_delta, findings_delta = await _run_advanced_scanners(
                session,
                type("S", (), {"id": scan_id, "scan_type": scan_type, "advanced_tools": True})(),
                host,
                is_active,
                assets_delta,
                findings_delta,
                log,
            )

        await session.flush()
        await session.execute(text(f"RELEASE SAVEPOINT {savepoint_name}"))
    except Exception as host_err:  # pragma: no cover - safety net
        await session.execute(text(f"ROLLBACK TO SAVEPOINT {savepoint_name}"))
        logger.warning("Host %s failed: %s. Continuing with next host.", host, host_err)
        # Write the error log OUTSIDE the savepoint (in its own short
        # session) so it survives the rollback and is visible in the
        # scan's log console. Without this, every host-scan failure
        # would be invisible to the user.
        await _log_outside_savepoint(
            scan_id,
            "error",
            "analysis",
            f"Error scanning host {host}: {host_err}",
        )
        # The savepoint rollback discards any asset/finding rows that
        # `_scan_host_*` already added to the session, but the Python
        # accumulators were incremented optimistically before the
        # `session.flush()` / `session.add()` calls. Reset them so the
        # orchestrator doesn't persist ghost counters on the scan row.
        assets_delta = 0
        findings_delta = 0
        is_active = False
        error = str(host_err)

    return {
        "host": host,
        "assets": assets_delta,
        "findings": findings_delta,
        "logs": log_messages,
        "error": error,
    }


__all__ = ["scan_host"]
