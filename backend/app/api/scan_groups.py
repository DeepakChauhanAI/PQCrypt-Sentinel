"""Scan-group correlation API (Phase B).

Endpoints:
  POST   /api/v1/scan-groups         - create a group + fan out member scans
  GET    /api/v1/scan-groups         - list groups (with roll-ups)
  GET    /api/v1/scan-groups/{id}    - group detail with member list
  DELETE /api/v1/scan-groups/{id}    - cancel a group and all running members
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.db import get_session
from app.models.models import Scan, ScanGroup, User
from app.models.schemas import (
    ScanGroupCreate,
    ScanGroupDetailOut,
    ScanGroupOut,
    ScanOut,
)
from app.tasks import execute_scan


router = APIRouter(prefix="/api/v1/scan-groups", tags=["scan-groups"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _compute_group_rollups(session: AsyncSession, group_id: str) -> dict:
    """Aggregate member counts and asset/finding totals for a group."""
    member_count = await session.execute(
        select(func.count(Scan.id)).where(Scan.scan_group_id == group_id)
    )
    assets = await session.execute(
        select(func.coalesce(func.sum(Scan.assets_found), 0)).where(
            Scan.scan_group_id == group_id
        )
    )
    findings = await session.execute(
        select(func.coalesce(func.sum(Scan.findings_created), 0)).where(
            Scan.scan_group_id == group_id
        )
    )
    return {
        "member_count": int(member_count.scalar_one() or 0),
        "assets_found": int(assets.scalar_one() or 0),
        "findings_created": int(findings.scalar_one() or 0),
    }


@router.post("", response_model=ScanGroupDetailOut, status_code=status.HTTP_201_CREATED)
async def create_scan_group(
    payload: ScanGroupCreate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Create a logical scan group and fan out to N member scans."""
    if not payload.members:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan group must have at least one member",
        )

    group = ScanGroup(
        name=payload.name,
        description=payload.description,
        status="running",
        started_at=_now(),
        created_by=current_user.id,
    )
    session.add(group)
    await session.commit()
    await session.refresh(group)

    member_scans: List[Scan] = []
    for spec in payload.members:
        scan = Scan(
            scan_type=spec.scan_type,
            target=spec.target,
            status="queued",
            config=spec.config,
            credential_profile=spec.credential_profile,
            advanced_tools=(
                payload.advanced_tools if spec.advanced_tools is None else spec.advanced_tools
            ),
            target_label=spec.target_label,
            target_kind=spec.target_kind,
            scan_group_id=group.id,
            created_by=current_user.id,
            assets_found=0,
            findings_created=0,
        )
        session.add(scan)
        member_scans.append(scan)
    await session.commit()
    for scan in member_scans:
        await session.refresh(scan)

    for scan in member_scans:
        execute_scan.delay(str(scan.id))

    rollups = await _compute_group_rollups(session, group.id)
    return ScanGroupDetailOut(
        id=str(group.id),
        name=group.name,
        description=group.description,
        status=group.status,
        started_at=group.started_at,
        completed_at=group.completed_at,
        created_at=group.created_at,
        updated_at=group.updated_at,
        members=[ScanOut.model_validate(s) for s in member_scans],
        **rollups,
    )


@router.get("", response_model=List[ScanGroupOut])
async def list_scan_groups(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    result = await session.execute(
        select(ScanGroup)
        .where(ScanGroup.deleted_at.is_(None))
        .order_by(ScanGroup.created_at.desc())
    )
    groups = result.scalars().all()
    out: List[ScanGroupOut] = []
    for g in groups:
        rollups = await _compute_group_rollups(session, g.id)
        out.append(ScanGroupOut(
            id=str(g.id),
            name=g.name,
            description=g.description,
            status=g.status,
            started_at=g.started_at,
            completed_at=g.completed_at,
            created_at=g.created_at,
            updated_at=g.updated_at,
            **rollups,
        ))
    return out


@router.get("/{group_id}", response_model=ScanGroupDetailOut)
async def get_scan_group(
    group_id: str,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    result = await session.execute(
        select(ScanGroup).where(
            ScanGroup.id == group_id, ScanGroup.deleted_at.is_(None)
        )
    )
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan group not found"
        )

    members_res = await session.execute(
        select(Scan)
        .where(Scan.scan_group_id == group_id)
        .order_by(Scan.created_at.asc())
    )
    members = members_res.scalars().all()

    rollups = await _compute_group_rollups(session, group_id)
    return ScanGroupDetailOut(
        id=str(group.id),
        name=group.name,
        description=group.description,
        status=group.status,
        started_at=group.started_at,
        completed_at=group.completed_at,
        created_at=group.created_at,
        updated_at=group.updated_at,
        members=[ScanOut.model_validate(m) for m in members],
        **rollups,
    )


@router.delete("/{group_id}", response_model=ScanGroupOut)
async def cancel_scan_group(
    group_id: str,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Cancel a group and all its non-terminal member scans."""
    result = await session.execute(
        select(ScanGroup).where(
            ScanGroup.id == group_id, ScanGroup.deleted_at.is_(None)
        )
    )
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan group not found"
        )

    members_res = await session.execute(
        select(Scan).where(
            Scan.scan_group_id == group_id,
            Scan.status.in_(["queued", "running"]),
        )
    )
    for scan in members_res.scalars().all():
        scan.status = "cancelled"
        scan.updated_at = _now()

    group.status = "cancelled"
    group.completed_at = _now()
    group.updated_at = _now()
    await session.commit()

    rollups = await _compute_group_rollups(session, group_id)
    return ScanGroupOut(
        id=str(group.id),
        name=group.name,
        description=group.description,
        status=group.status,
        started_at=group.started_at,
        completed_at=group.completed_at,
        created_at=group.created_at,
        updated_at=group.updated_at,
        **rollups,
    )
