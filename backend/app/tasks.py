import asyncio
import logging
from app.celery_app import celery_app
from app.services.scan_orchestrator import ScanOrchestrator
from app.utils.target_classifier import classify_target

logger = logging.getLogger(__name__)


def _run_async(coro):
    """Run an async coroutine from a Celery worker safely.

    With ``-P solo`` the worker is single-threaded and sequential.
    ``asyncio.run()`` is NOT safe here because it closes the event loop
    after each coroutine, but the ``asyncpg`` connection pool (created at
    import time) is bound to the first loop. Reusing the same loop across
    tasks prevents stale-connection errors like:

        \"'NoneType' object has no attribute 'send'\"
        \"InterfaceError: another operation is in progress\"

    If the cached loop is ever closed (e.g. by Celery shutdown), a new one
    is created on the next task.
    """
    try:
        loop = _worker_loop
        if loop is None or loop.is_closed():
            loop = asyncio.new_event_loop()
            _set_worker_loop(loop)
        return loop.run_until_complete(coro)
    except RuntimeError as exc:
        if "Event loop is closed" in str(exc):
            loop = asyncio.new_event_loop()
            _set_worker_loop(loop)
            return loop.run_until_complete(coro)
        raise


_worker_loop: asyncio.AbstractEventLoop | None = None


def _set_worker_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Cache the loop globally and set it as the current thread's loop."""
    global _worker_loop
    _worker_loop = loop
    asyncio.set_event_loop(loop)


@celery_app.task(name="app.tasks.execute_scan", bind=True, max_retries=3)
def execute_scan(self, scan_id: str):
    """Celery background task to execute a scan."""
    logger.info(f"Received celery task execute_scan for scan_id: {scan_id}")
    try:
        orchestrator = ScanOrchestrator()
        return _run_async(orchestrator.run_scan(scan_id))
    except Exception as exc:
        logger.warning(
            f"Scan {scan_id} failed (attempt {self.request.retries + 1}/{self.max_retries + 1}): {exc}"
        )
        raise self.retry(exc=exc, countdown=2 ** self.request.retries * 10)  # 10s, 20s, 40s


@celery_app.task(name="app.tasks.execute_report", bind=True)
def execute_report(self, report_id: str, scan_ids=None):
    """Celery background task to execute report generation."""
    logger.info(f"Received celery task execute_report for report_id: {report_id}, scan_ids={scan_ids}")
    from app.db import AsyncSessionLocal
    from app.models.models import Report
    from app.services.report_service import generate_report
    from sqlalchemy import select

    if scan_ids is None:
        scan_ids = []

    async def run():
        async with AsyncSessionLocal() as session:
            stmt = select(Report).where(Report.id == report_id)
            result = await session.execute(stmt)
            report = result.scalar_one_or_none()
            if not report:
                logger.error(f"Report {report_id} not found")
                return
            await generate_report(
                session=session,
                report_id=str(report.id),
                report_type=report.report_type,
                fmt=report.format,
                scope_filters=report.scope_filters or {},
                scan_ids=scan_ids,
            )

    return _run_async(run())


@celery_app.task(name="app.tasks.execute_scheduled_scan", bind=True)
def execute_scheduled_scan(self):
    """Celery Beat task to trigger periodic scans."""
    logger.info("Executing scheduled periodic scans")
    from app.db import AsyncSessionLocal
    from app.models.models import Asset, Scan
    from sqlalchemy import select
    import os

    async def run():
        # Get targets from environment if configured
        env_targets = os.getenv("PQC_PERIODIC_SCAN_TARGETS", "")
        targets = [t.strip() for t in env_targets.split(",") if t.strip()]

        async with AsyncSessionLocal() as session:
            # If no targets in environment, query all active assets from database
            if not targets:
                stmt = select(Asset).where(Asset.deleted_at.is_(None))
                res = await session.execute(stmt)
                assets = res.scalars().all()
                unique_targets = set()
                for asset in assets:
                    if asset.ip_address:
                        unique_targets.add(asset.ip_address)
                    elif asset.name and not asset.name.startswith(("aws:", "azure:", "gcp:", "pkcs11:", "kmip:")):
                        unique_targets.add(asset.name)
                targets = list(unique_targets)

            # Fallback if still no targets
            if not targets:
                targets = ["localhost"]

            # Dispatch an execute_scan task for each target
            for target in targets:
                # Server-side classification so periodic scans also get a
                # target_kind / target_label on the Scan row. A scheduled
                # CIDR range will still need its group created explicitly
                # (the orchestrator worker doesn't run the auto-wrap path
                # that create_scan does); operators that want grouping
                # for scheduled scans can wrap the dispatch in a
                # ScanGroup at a higher level.
                classification = classify_target(target)
                scan = Scan(
                    scan_type="full",
                    target=target,
                    target_kind=classification.kind,
                    target_label=classification.label,
                    status="queued",
                    config="scheduled",
                )
                session.add(scan)
                await session.commit()
                await session.refresh(scan)
                logger.info(f"Dispatched scheduled scan {scan.id} for target {target}")

                # Import execute_scan locally to avoid circular import
                from app.tasks import execute_scan
                execute_scan.delay(str(scan.id))

    return _run_async(run())

