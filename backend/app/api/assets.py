from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, or_, and_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.db import get_session
from app.models.models import Asset, Finding, Algorithm, Scan, ScanGroup
from app.models.schemas import AssetOut
from app.models.models import User

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


async def _enrich_assets_with_scan_groups(
    session: AsyncSession,
    assets: List[Asset],
) -> None:
    """Phase B — populate ``last_scan_group_id`` / ``last_scan_group_name``
    (and the matching ``first_scan_*`` pair) on each Asset so the UI can
    render "Last Scan Group" badges without a second round-trip per row.

    Best-effort: any failure (no scans, mock session, etc.) is swallowed
    so it never breaks the primary assets response.
    """
    if not assets:
        return
    try:
        scan_ids: set = set()
        for a in assets:
            if getattr(a, "last_scan_id", None):
                scan_ids.add(a.last_scan_id)
            if getattr(a, "first_scan_id", None):
                scan_ids.add(a.first_scan_id)
        scan_ids.discard(None)
        if not scan_ids:
            return

        scan_res = await session.execute(
            select(Scan).where(Scan.id.in_(scan_ids))
        )
        scans = scan_res.scalars().all()
        scan_by_id = {s.id: s for s in scans}

        group_ids: set = {
            getattr(s, "scan_group_id", None) for s in scans
        }
        group_ids.discard(None)
        group_by_id: dict = {}
        if group_ids:
            grp_res = await session.execute(
                select(ScanGroup).where(ScanGroup.id.in_(group_ids))
            )
            group_by_id = {g.id: g for g in grp_res.scalars().all()}

        def _resolve(scan_id):
            scan = scan_by_id.get(scan_id)
            if not scan:
                return None, None
            gid = getattr(scan, "scan_group_id", None)
            gname = group_by_id[gid].name if gid and gid in group_by_id else None
            return (str(gid) if gid else None), gname

        for a in assets:
            last_gid, last_gname = _resolve(getattr(a, "last_scan_id", None))
            first_gid, first_gname = _resolve(getattr(a, "first_scan_id", None))
            setattr(a, "last_scan_group_id", last_gid)
            setattr(a, "last_scan_group_name", last_gname)
            setattr(a, "first_scan_group_id", first_gid)
            setattr(a, "first_scan_group_name", first_gname)
    except Exception:
        # Enrichment is best-effort; never let it break the asset list.
        pass


@router.get("", response_model=List[AssetOut])
async def list_assets(
    asset_type: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    business_service: Optional[str] = Query(None),
    owner_id: Optional[str] = Query(None),
    pqc_status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    sort_by: str = Query("risk_score"),
    sort_order: str = Query("desc"),
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Asset).where(Asset.deleted_at.is_(None))

    # Apply filters
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if environment:
        stmt = stmt.where(Asset.environment == environment)
    if business_service:
        stmt = stmt.where(Asset.business_service == business_service)
    if owner_id:
        stmt = stmt.where(Asset.owner_id == owner_id)
    if search:
        stmt = stmt.where(
            or_(
                Asset.name.ilike(f"%{search}%"),
                Asset.ip_address.ilike(f"%{search}%"),
                Asset.fqdn.ilike(f"%{search}%")
            )
        )

    # Preload findings and algorithms to calculate risk score and status in Python
    stmt = stmt.options(
        selectinload(Asset.findings),
        selectinload(Asset.algorithms),
        selectinload(Asset.certificates),
    )

    result = await session.execute(stmt)
    assets = result.scalars().all()

    # Calculate virtual properties and apply pqc_status filter in Python *before* pagination
    filtered_assets = []
    for asset in assets:
        open_findings = [f for f in asset.findings if f.status == "open" and f.deleted_at is None]
        # SQLAlchemy allows attribute assignment on a non-mapped column;
        # mypy doesn't see that, so we use setattr/getattr to keep types honest.
        computed_risk = max([f.risk_score or 0 for f in open_findings]) if open_findings else 0
        setattr(asset, "risk_score", computed_risk)

        # Derive PQC status from algorithms; fall back to open findings for
        # connectors that only persist findings (e.g. SAST). If neither exists,
        # mark the asset as unknown rather than falsely vulnerable.
        if asset.algorithms:
            statuses = [a.pqc_status for a in asset.algorithms]
        else:
            statuses = [f.pqc_status for f in open_findings if f.pqc_status]

        if statuses:
            if "vulnerable" in statuses:
                derived_status = "vulnerable"
            elif "hybrid" in statuses:
                derived_status = "hybrid"
            elif "pqc_ready" in statuses:
                derived_status = "pqc_ready"
            elif "safe" in statuses:
                derived_status = "safe"
            else:
                derived_status = "vulnerable"
        else:
            derived_status = "unknown"
        setattr(asset, "pqc_status", derived_status)

        if pqc_status is None or getattr(asset, "pqc_status") == pqc_status.lower():
            filtered_assets.append(asset)

    # Sort (now operates on the filtered set)
    reverse = (sort_order.lower() == "desc")
    if sort_by == "risk_score":
        filtered_assets.sort(key=lambda a: getattr(a, "risk_score", 0), reverse=reverse)
    elif sort_by == "name":
        filtered_assets.sort(key=lambda a: a.name, reverse=reverse)
    elif sort_by == "last_scanned":
        filtered_assets.sort(
            key=lambda a: a.last_verified_at or datetime.min.replace(tzinfo=timezone.utc),
            reverse=reverse,
        )
    else:
        filtered_assets.sort(key=lambda a: a.name, reverse=reverse)

    paginated_assets = filtered_assets[offset : offset + limit]
    await _enrich_assets_with_scan_groups(session, paginated_assets)
    return paginated_assets

@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(
    asset_id: str,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Asset).options(
        selectinload(Asset.certificates),
        selectinload(Asset.algorithms),
        selectinload(Asset.findings)
    ).where(Asset.id == asset_id, Asset.deleted_at.is_(None))

    result = await session.execute(stmt)
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    # Calculate virtual properties
    open_findings = [f for f in asset.findings if f.status == "open" and f.deleted_at is None]
    setattr(asset, "risk_score", max([f.risk_score or 0 for f in open_findings]) if open_findings else 0)

    # Derive PQC status from algorithms; fall back to open findings for
    # connectors that only persist findings (e.g. SAST). If neither exists,
    # mark the asset as unknown rather than falsely vulnerable.
    if asset.algorithms:
        statuses = [a.pqc_status for a in asset.algorithms]
    else:
        statuses = [f.pqc_status for f in open_findings if f.pqc_status]

    if statuses:
        if "vulnerable" in statuses:
            derived_status = "vulnerable"
        elif "hybrid" in statuses:
            derived_status = "hybrid"
        elif "pqc_ready" in statuses:
            derived_status = "pqc_ready"
        elif "safe" in statuses:
            derived_status = "safe"
        else:
            derived_status = "vulnerable"
    else:
        derived_status = "unknown"
    setattr(asset, "pqc_status", derived_status)

    await _enrich_assets_with_scan_groups(session, [asset])
    return asset
