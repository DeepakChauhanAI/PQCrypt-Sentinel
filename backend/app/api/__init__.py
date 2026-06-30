from fastapi import FastAPI

from app.api.auth import router as auth_router
from app.api.scans import router as scans_router
from app.api.scan_logs import router as scan_logs_router
from app.api.scan_groups import router as scan_groups_router
from app.api.findings import router as findings_router
from app.api.assets import router as assets_router
from app.api.dashboard import router as dashboard_router
from app.api.reports import router as reports_router
from app.api.connectors import router as connectors_router


def register_routes(application: FastAPI) -> None:
    application.include_router(auth_router)
    application.include_router(scans_router)
    application.include_router(scan_logs_router)
    application.include_router(scan_groups_router)
    application.include_router(findings_router)
    application.include_router(assets_router)
    application.include_router(dashboard_router)
    application.include_router(reports_router)
    application.include_router(connectors_router)
