# mypy: ignore-errors
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.config import settings
from app.db import get_session
from app.models.models import Scan, ScanGroup, User
from app.models.schemas import AssetOut, ScanCreate, ScanOut
from app.utils.target_classifier import (
    classify_target,
    suggest_group_name,
)

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_target_ports(target: str, scan_type: str) -> list[tuple[str, int]]:
    """Parse target string into list of (host, port) tuples."""
    if not target:
        return []

    # Default ports per scan type
    default_ports = {
        "tls_only": [443],
        "ssh_only": [22],
        "full": [443, 22],
        "targeted": [443, 22, 500, 25, 465, 587],
    }
    ports = default_ports.get(scan_type, [443])

    # Parse target - could be hostname, IP, or host:port
    hosts = [h.strip() for h in target.replace(";", ",").split(",") if h.strip()]
    result = []

    for host in hosts:
        # Remove protocol prefix
        if host.lower().startswith("https://"):
            host = host[8:]
        elif host.lower().startswith("http://"):
            host = host[7:]

        # Check for port specification
        if ":" in host and not host.startswith("["):  # IPv6 handling
            parts = host.rsplit(":", 1)
            try:
                port = int(parts[1])
                host = parts[0]
                result.append((host, port))
                continue
            except ValueError:
                pass

        # Use default ports for this host
        for port in ports:
            result.append((host, port))

    return result


def _targets_match(
    target1: str, target2: str, scan_type1: str, scan_type2: str
) -> bool:
    """Check if two scan targets overlap (same host+port combinations)."""
    ports1 = set(_parse_target_ports(target1, scan_type1))
    ports2 = set(_parse_target_ports(target2, scan_type2))
    return bool(ports1 & ports2)


@router.post("", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: ScanCreate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    # Deduplication: take a transaction-scoped advisory lock keyed on the
    # target+scan_type so that concurrent create_scan calls for the same
    # (target, scan_type) pair serialize through the database and cannot
    # both insert a fresh scan row inside the dedup window.
    if settings.SCAN_DEDUP_WINDOW_HOURS > 0:
        lock_key = f"{payload.scan_type}|{payload.target or ''}"
        try:
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:k))"),
                {"k": lock_key},
            )
        except Exception:
            pass

        window_start = _now() - timedelta(hours=settings.SCAN_DEDUP_WINDOW_HOURS)

        recent_scans = await session.execute(
            select(Scan).where(
                Scan.created_at >= window_start,
                Scan.status.in_(["queued", "running"]),
                Scan.scan_type == payload.scan_type,
            )
        )

        existing_scans = recent_scans.scalars().all()
        # Semantic match: same scan_type AND overlapping targets, same config/profile
        for existing in existing_scans:
            if (
                _targets_match(
                    existing.target or "",
                    payload.target or "",
                    existing.scan_type,
                    payload.scan_type,
                )
                and existing.config == payload.config
                and existing.credential_profile == payload.credential_profile
            ):
                # If the existing scan is queued, just return it — worker should pick it up.
                if existing.status == "queued":
                    return existing
                # If running but stale (>5 min since started_at with no progress), reset to queued and re-dispatch.
                if existing.status == "running" and existing.started_at:
                    if _now() - existing.started_at > timedelta(minutes=5):
                        existing.status = "queued"
                        existing.started_at = None
                        existing.error_message = (
                            "Previous worker appears stalled; re-queued."
                        )
                        await session.commit()
                        await session.refresh(existing)
                        from app.tasks import execute_scan

                        execute_scan.delay(str(existing.id))
                        return existing
                # If running and recent, return it (don't double-dispatch).
                if existing.status == "running":
                    return existing
                # Terminal state (shouldn't be in query but guard) — don't dedup.

    scan = Scan(
        scan_type=payload.scan_type,
        target=payload.target,
        status="queued",
        config=payload.config,
        credential_profile=payload.credential_profile,
        created_by=current_user.id,
    )

    # ── Server-side target classification ────────────────────────────────
    # The schema says target_kind/target_label "may be derived server-side
    # from the target string"; do that here so every scan row carries the
    # metadata the UI needs to render the Scan Groups tab and group
    # findings under their parent group. The classifier is purely
    # additive — it never raises, so a typo in a target can't block the
    # scan from being created.
    classification = classify_target(payload.target)
    # Honour client-supplied values when the client explicitly set them.
    scan.target_kind = payload.target_kind or classification.kind
    scan.target_label = payload.target_label or classification.label

    # ── Honour user-supplied scan_group_id (caller already placed the
    # scan inside an existing group, e.g. a child of a campaign). The
    # auto-wrap path below must never override an explicit assignment.
    if payload.scan_group_id:
        scan.scan_group_id = payload.scan_group_id

    # ── Auto-wrap groupable scans in a ScanGroup ─────────────────────────
    # A "groupable" target is one the orchestrator will fan out to
    # multiple assets (CIDR range, multi-host list, or a single domain
    # that DNS-enumerates to many hosts). We only run this on a *new*
    # scan (the dedup path above has already returned an existing scan,
    # so we never re-wrap the same target) and only when the caller has
    # not already supplied a scan_group_id.
    if classification.is_groupable and not scan.scan_group_id:
        group = ScanGroup(
            name=suggest_group_name(payload.target, payload.scan_type),
            description=(
                f"Auto-created group for {classification.kind} scan of "
                f"`{payload.target}` (created at {datetime.now(timezone.utc).isoformat()})."
            ),
            status="running",
            started_at=datetime.now(timezone.utc),
            created_by=current_user.id,
        )
        session.add(group)
        await session.flush()  # populate group.id
        scan.scan_group_id = group.id

    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    # Queue the background scan task
    from app.tasks import execute_scan

    execute_scan.delay(str(scan.id))

    return scan


@router.get("", response_model=List[ScanOut])
async def list_scans(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    result = await session.execute(select(Scan).order_by(Scan.created_at.desc()))
    scans = result.scalars().all()
    return scans


@router.get("/{scan_id}/findings", response_model=List)
async def list_scan_findings(
    scan_id: str,
    layer: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """List findings created by a specific scan (scan-scoped endpoint)."""
    from app.models.models import Finding
    from sqlalchemy.orm import selectinload

    scan_res = await session.execute(select(Scan).where(Scan.id == scan_id))
    if not scan_res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    stmt = (
        select(Finding)
        .options(selectinload(Finding.asset))
        .where(Finding.scan_id == scan_id, Finding.deleted_at.is_(None))
    )
    if layer:
        normalized = layer.strip().upper()
        if normalized not in {"L1", "L2", "L3", "L4", "L5", "L6", "L7"}:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid layer {layer!r}; must be one of L1..L7",
            )
        stmt = stmt.where(Finding.layer == normalized)
    if severity:
        stmt = stmt.where(Finding.severity == severity.lower())
    stmt = stmt.order_by(Finding.risk_score.desc()).limit(limit).offset(offset)
    result = await session.execute(stmt)
    findings = result.scalars().all()
    # Phase B — enrich with scan_type / scan_target / scan_group_name so the
    # scan-scoped view can show "Q2 Estate Audit › TLS_ONLY" inline.
    from app.api.findings import _enrich_with_scan_context

    await _enrich_with_scan_context(session, findings)
    return findings


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    result = await session.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )
    return scan


@router.get("/{scan_id}/assets", response_model=List[AssetOut])
async def list_scan_assets(
    scan_id: str,
    limit: int = 100,
    offset: int = 0,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """List assets touched (first or last) by a specific scan.

    An asset belongs to a scan if either ``first_scan_id`` or
    ``last_scan_id`` matches. This is the scan-scoped view the unified
    Scan-Run Detail page needs to render a per-target asset list.
    """
    from app.models.models import Asset

    scan_res = await session.execute(select(Scan).where(Scan.id == scan_id))
    if not scan_res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    stmt = (
        select(Asset)
        .where(
            Asset.deleted_at.is_(None),
            (Asset.first_scan_id == scan_id) | (Asset.last_scan_id == scan_id),
        )
        .order_by(Asset.last_verified_at.desc().nullslast(), Asset.name.asc())
        .limit(limit)
        .offset(offset)
    )
    result = await session.execute(stmt)
    return result.scalars().all()


@router.post("/{scan_id}/l1-probe", status_code=status.HTTP_200_OK)
async def run_l1_probe(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Run a one-off L1 (OCSP + DNSSEC) live probe against the host assets
    that this scan touched. Returns a per-host result summary; the probe
    never raises and is concurrency-bounded internally.
    """
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )

    # Confirm the scan exists and is readable.
    scan = (
        await session.execute(select(Scan).where(Scan.id == scan_id))
    ).scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )

    from sqlalchemy import select as _select
    from app.models.models import Asset, Certificate
    from app.scanners.ocsp_dnssec_scanner import (
        probe_dnssec_batch,
        probe_ocsp_batch,
    )
    from app.services.l1_finding_service import generate_l1_findings

    assets_res = await session.execute(
        _select(Asset).where(Asset.deleted_at.is_(None)).limit(200)
    )
    assets = assets_res.scalars().all()
    domains = sorted({a.fqdn for a in assets if a.fqdn})

    if not assets:
        return {
            "scan_id": scan_id,
            "l1_probe": {
                "domains_probed": 0,
                "certs_probed": 0,
                "dnssec_results": [],
                "ocsp_results": [],
            },
            "findings_created": {"ocsp_findings": 0, "dnssec_findings": 0},
        }

    # --- DNSSEC probes (one per unique FQDN) ----------------------------
    dnssec_results = await probe_dnssec_batch(domains, timeout=3.0)

    # Pair every DNSSEC result with the first asset that owns its domain,
    # so the Finding has a valid asset_id foreign key. If no asset claims
    # the domain, the pair is omitted (no orphan findings).
    fqdn_to_asset = {a.fqdn: a for a in assets if a.fqdn}
    dnssec_pairs = [
        (fqdn_to_asset[r.domain].id, r)
        for r in dnssec_results
        if r.domain in fqdn_to_asset
    ]

    # --- OCSP probes (one per cert-bearing asset) -----------------------
    # Pull the most recent non-deleted cert for each asset that has one.
    # OCSP needs the cert bytes; raw_certificate is stored as PEM text.
    # The probe scanner auto-detects PEM vs DER.
    certs_res = await session.execute(
        _select(Certificate)
        .where(Certificate.deleted_at.is_(None))
        .where(Certificate.raw_certificate.isnot(None))
        .order_by(Certificate.not_before.desc())
        .limit(200)
    )
    certs = certs_res.scalars().all()
    asset_by_id = {a.id: a for a in assets}

    ocsp_targets: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for cert in certs:
        if cert.asset_id in seen:
            continue
        asset = asset_by_id.get(cert.asset_id) if cert.asset_id else None
        if asset is None:
            continue
        host = asset.fqdn or asset.ip_address
        if not host:
            continue
        raw = cert.raw_certificate
        if isinstance(raw, str):
            raw_bytes = raw.encode("utf-8")
        elif isinstance(raw, (bytes, bytearray)):
            raw_bytes = bytes(raw)
        else:
            continue
        if not raw_bytes:
            continue
        ocsp_targets.append((host, raw_bytes))
        seen.add(cert.asset_id)

    ocsp_results = (
        await probe_ocsp_batch(ocsp_targets, timeout=5.0, max_concurrency=10)
        if ocsp_targets
        else []
    )

    # Pair every OCSP result with the first asset that owns its host.
    host_to_asset: dict[str, Asset] = {}
    for a in assets:
        h = a.fqdn or a.ip_address
        if h and h not in host_to_asset:
            host_to_asset[h] = a
    ocsp_pairs = [
        (host_to_asset[r.host].id, r) for r in ocsp_results if r.host in host_to_asset
    ]

    finding_counts = await generate_l1_findings(
        session,
        scan_id=scan_id,
        ocsp_results=ocsp_pairs,
        dnssec_results=dnssec_pairs,
    )

    return {
        "scan_id": scan_id,
        "l1_probe": {
            "domains_probed": len(domains),
            "certs_probed": len(ocsp_targets),
            "dnssec_results": [
                {
                    "domain": r.domain,
                    "success": r.success,
                    "chain_of_trust": r.chain_of_trust,
                    "has_dnskey": r.has_dnskey,
                    "has_rrsig": r.has_rrsig,
                    "has_ds": r.has_ds,
                    "algorithms": r.algorithms,
                    "pqc_status": r.pqc_status,
                    "error_message": r.error_message,
                }
                for r in dnssec_results
            ],
            "ocsp_results": [
                {
                    "host": r.host,
                    "cert_thumbprint": r.cert_thumbprint,
                    "success": r.success,
                    "status": r.status,
                    "responder_url": r.responder_url,
                    "responder_name": r.responder_name,
                    "signature_algorithm": r.signature_algorithm,
                    "pqc_status": r.pqc_status,
                    "error_message": r.error_message,
                }
                for r in ocsp_results
            ],
        },
        "findings_created": finding_counts,
    }


@router.delete("/{scan_id}", response_model=ScanOut)
async def cancel_scan(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    result = await session.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )
    if scan.status in {"completed", "failed", "cancelled"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Cannot cancel a terminal scan",
        )
    scan.status = "cancelled"
    scan.updated_at = _now()
    await session.commit()
    await session.refresh(scan)
    return scan
