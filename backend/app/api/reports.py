import os
import logging
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.db import get_session
from app.models.models import Report, User
from app.models.schemas import ReportOut

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


# Allowed (report_type, format) combinations enforced at the API boundary.
ALLOWED_REPORT_COMBOS = {
    ("cbom", "json"),
    ("findings", "csv"),
    ("executive", "pdf"),
    ("sast", "sarif"),
}


class ReportCreate(BaseModel):
    report_type: str
    format: str
    scope_filters: Optional[dict] = Field(default_factory=dict)
    scan_ids: Optional[List[str]] = Field(default_factory=list)


@router.post("", response_model=ReportOut, status_code=status.HTTP_202_ACCEPTED)
async def create_report(
    payload: ReportCreate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    rt = payload.report_type.lower()
    fmt = payload.format.lower()

    if (rt, fmt) not in ALLOWED_REPORT_COMBOS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported report_type/format combination: {rt}/{fmt}. "
                f"Allowed: {sorted(ALLOWED_REPORT_COMBOS)}"
            ),
        )

    report = Report(
        report_type=rt,
        format=fmt,
        scope_filters=payload.scope_filters or {},
        status="pending",
        created_by=current_user.id,
    )
    session.add(report)
    await session.commit()
    await session.refresh(report)

    # Queue background task — pass scan_ids via JSON in scope_filters for SARIF.
    from app.tasks import execute_report
    scan_ids = payload.scan_ids or []
    execute_report.delay(str(report.id), scan_ids)

    return report


@router.get("", response_model=List[ReportOut])
async def list_reports(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Report).where(Report.deleted_at.is_(None)).order_by(Report.created_at.desc())
    result = await session.execute(stmt)
    return result.scalars().all()


@router.get("/{report_id}", response_model=ReportOut)
async def get_report(
    report_id: str,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Report).where(Report.id == report_id, Report.deleted_at.is_(None))
    result = await session.execute(stmt)
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Report).where(Report.id == report_id, Report.deleted_at.is_(None))
    result = await session.execute(stmt)
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    if report.status != "ready" or not report.file_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Report is not ready (status: {report.status})",
        )

    if not os.path.exists(report.file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file was not found on server disk",
        )

    filename = os.path.basename(report.file_path)

    # Pick media type by report type / format
    media_type_map = {
        "json": "application/json",
        "csv": "text/csv",
        "pdf": "application/pdf",
        "sarif": "application/sarif+json",
        "html": "text/html",
    }
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else report.format
    media_type = media_type_map.get(ext, "application/octet-stream")

    return FileResponse(
        path=report.file_path,
        filename=filename,
        media_type=media_type,
    )


@router.delete("/{report_id}", response_model=ReportOut)
async def delete_report(
    report_id: str,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Report).where(Report.id == report_id, Report.deleted_at.is_(None))
    result = await session.execute(stmt)
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    report.deleted_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(report)

    if report.file_path and os.path.exists(report.file_path):
        try:
            os.remove(report.file_path)
        except Exception as e:
            logger.warning("Could not delete file %s: %s", report.file_path, e)

    return report
