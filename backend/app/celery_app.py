from celery import Celery
from app.config import settings

celery_app = Celery(
    "pqcrypt_sentinel",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

# Configure Celery Beat schedule based on Settings.SCAN_SCHEDULE_CRON
from celery.schedules import crontab
cron_expr = settings.SCAN_SCHEDULE_CRON or "0 2 * * *"
parts = cron_expr.split()
if len(parts) == 5:
    beat_schedule = crontab(
        minute=parts[0],
        hour=parts[1],
        day_of_month=parts[2],
        month_of_year=parts[3],
        day_of_week=parts[4],
    )
else:
    beat_schedule = crontab(hour=2, minute=0)

celery_app.conf.beat_schedule = {
    "scheduled-full-scan": {
        "task": "app.tasks.execute_scheduled_scan",
        "schedule": beat_schedule,
    },
}

