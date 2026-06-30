# mypy: ignore-errors
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.db import get_session
from app.models.models import Finding, Scan, ScanGroup, User
from app.models.schemas import FindingOut, FindingUpdate
from app.utils.target_classifier import classify_target

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


def _strip_port(host: str) -> str:
    if host.startswith("["):
        return host.split("]")[0] + "]"
    if ":" in host and not host.count(":") > 1:
        return host.split(":")[0]
    return host


async def _enrich_with_scan_context(
    session: AsyncSession,
    findings: List[Finding],
) -> None:
    """Phase B — populate scan_type / scan_target / target_label / scan_group_id
    on every FindingOut so the UI can render "Q2 Estate Audit › TLS_ONLY"
    without an extra hop. Sets attributes directly on the ORM objects so
    Pydantic's from_attributes mode picks them up.

    This is a best-effort enrichment: any failure (missing scan, mock
    session, attribute mismatch in tests) is swallowed so it never breaks
    the primary findings response.
    """
    if not findings:
        return
    try:
        scan_ids = {f.scan_id for f in findings if getattr(f, "scan_id", None)}
        if not scan_ids:
            return
        stmt = select(Scan).where(Scan.id.in_(scan_ids))
        scans = (await session.execute(stmt)).scalars().all()
        scan_by_id = {s.id: s for s in scans}

        group_ids = {getattr(s, "scan_group_id", None) for s in scans}
        group_ids.discard(None)
        group_by_id = {}
        if group_ids:
            g_stmt = select(ScanGroup).where(ScanGroup.id.in_(group_ids))
            groups = (await session.execute(g_stmt)).scalars().all()
            group_by_id = {g.id: g for g in groups}

        for f in findings:
            scan = scan_by_id.get(f.scan_id)
            if not scan:
                continue
            f.scan_type = getattr(scan, "scan_type", None)
            f.scan_target = getattr(scan, "target", None)
            f.scan_target_label = getattr(scan, "target_label", None)
            sgid = getattr(scan, "scan_group_id", None)
            f.scan_group_id = str(sgid) if sgid else None
            if sgid and sgid in group_by_id:
                f.scan_group_name = group_by_id[sgid].name
    except Exception:
        # Enrichment is best-effort. If anything goes wrong (mock session
        # shape, partial data) the findings response still works.
        pass


@router.get("", response_model=List[FindingOut])
async def list_findings(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    asset_id: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
    scan_group_id: Optional[str] = Query(
        None, description="Phase B: filter by scan group"
    ),
    layer: Optional[str] = Query(None, description="Filter by layer id (L1..L7)"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    stmt = (
        select(Finding)
        .options(selectinload(Finding.asset))
        .where(Finding.deleted_at.is_(None))
    )

    if severity:
        stmt = stmt.where(Finding.severity == severity.lower())
    if status:
        stmt = stmt.where(Finding.status == status.lower())
    if finding_type:
        stmt = stmt.where(Finding.finding_type == finding_type)
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if scan_group_id:
        # Filter by joining to Scan. Requires the scan_group_id to be set on Scan.
        from sqlalchemy import select as _select

        sub = _select(Scan.id).where(Scan.scan_group_id == scan_group_id)
        stmt = stmt.where(Finding.scan_id.in_(sub))
    if layer:
        # Accept L1..L7 (case-insensitive). Reject other values early.
        normalized = layer.strip().upper()
        if normalized not in {"L1", "L2", "L3", "L4", "L5", "L6", "L7"}:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid layer {layer!r}; must be one of L1..L7",
            )
        stmt = stmt.where(Finding.layer == normalized)

    stmt = stmt.order_by(Finding.risk_score.desc()).limit(limit).offset(offset)
    result = await session.execute(stmt)
    findings = result.scalars().all()
    await _enrich_with_scan_context(session, findings)
    return findings


@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(
    finding_id: str,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    stmt = (
        select(Finding)
        .options(selectinload(Finding.asset))
        .where(Finding.id == finding_id, Finding.deleted_at.is_(None))
    )
    result = await session.execute(stmt)
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )
    await _enrich_with_scan_context(session, [finding])
    return finding


@router.patch("/{finding_id}", response_model=FindingOut)
async def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    stmt = (
        select(Finding)
        .options(selectinload(Finding.asset))
        .where(Finding.id == finding_id, Finding.deleted_at.is_(None))
    )
    result = await session.execute(stmt)
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )

    if payload.status is not None:
        if current_user.role not in ["analyst", "admin"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only analysts and admins can change finding status",
            )
        finding.status = payload.status.lower()
        if payload.status in ["resolved", "accepted", "false_positive"]:
            finding.resolved_at = datetime.now(timezone.utc)
            if payload.reason:
                if not finding.evidence:
                    finding.evidence = {}
                finding.evidence["status_change_reason"] = payload.reason

    finding.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(finding)
    return finding


@router.post("/{finding_id}/rescan", status_code=status.HTTP_202_ACCEPTED)
async def rescan_finding_asset(
    finding_id: str,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    stmt = (
        select(Finding)
        .options(selectinload(Finding.asset))
        .where(Finding.id == finding_id, Finding.deleted_at.is_(None))
    )
    result = await session.execute(stmt)
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )

    asset = finding.asset
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found for finding"
        )

    target = _strip_port(asset.ip_address or asset.fqdn or asset.name)
    scan_type = (
        "tls_only"
        if asset.port == 443
        else ("ssh_only" if asset.port == 22 else "full")
    )

    # Derive target_kind / target_label server-side so this rescan
    # surfaces under a Scan Group when the target is groupable (e.g. an
    # FQDN that DNS-enumerates to many hosts). Single-IP targets stay as
    # `host` and are not wrapped in a group.
    classification = classify_target(target)
    scan = Scan(
        scan_type=scan_type,
        target=target,
        status="queued",
        target_kind=classification.kind,
        target_label=classification.label,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    from app.tasks import execute_scan

    execute_scan.delay(str(scan.id))

    return {"status": "queued", "scan_id": str(scan.id)}
