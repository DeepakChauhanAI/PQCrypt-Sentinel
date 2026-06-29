from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.db import get_session
from app.models.models import Scan, ScanLog
from app.models.schemas import ScanLogCreate, ScanLogOut

router = APIRouter(prefix="/api/v1/scans/{scan_id}/logs", tags=["scan_logs"])


@router.post("", response_model=ScanLogOut, status_code=status.HTTP_201_CREATED)
async def create_scan_log(
    scan_id: str,
    payload: ScanLogCreate,
    session: AsyncSession = Depends(get_session),
    current_user=Depends(get_current_user),
):
    result = await session.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )

    scan_log = ScanLog(
        scan_id=scan.id,
        level=payload.level,
        phase=payload.phase,
        message=payload.message,
        details=payload.details,
    )
    session.add(scan_log)
    await session.commit()
    await session.refresh(scan_log)
    return scan_log


@router.get("", response_model=List[ScanLogOut])
async def list_scan_logs(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
    current_user=Depends(get_current_user),
):
    result = await session.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )

    logs_result = await session.execute(
        select(ScanLog)
        .where(ScanLog.scan_id == scan_id)
        .order_by(ScanLog.timestamp.asc())
    )
    logs = logs_result.scalars().all()
    return logs
