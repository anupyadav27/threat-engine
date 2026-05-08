"""
Celery app for the onboarding engine.

Workers pick up periodic tasks (e.g. weekly credential health-checks).
Broker / result backend configured via environment variables:
  CELERY_BROKER_URL   — default: redis://redis:6379/0
  CELERY_RESULT_URL   — default: redis://redis:6379/1
"""
import os
from celery import Celery
from celery.schedules import crontab

BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
RESULT_URL  = os.getenv("CELERY_RESULT_URL",  "redis://redis:6379/1")

app = Celery(
    "engine_onboarding",
    broker=BROKER_URL,
    backend=RESULT_URL,
    include=["engine_onboarding.tasks.credential_health_check"],
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Beat schedule — weekly credential health-check every Monday at 03:00 UTC
    beat_schedule={
        "credential-health-check-weekly": {
            "task": "engine_onboarding.tasks.credential_health_check.run_credential_health_check",
            "schedule": crontab(hour=3, minute=0, day_of_week=1),
        },
    },
)
