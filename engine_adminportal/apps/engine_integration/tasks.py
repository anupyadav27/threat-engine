"""
Celery tasks for engine integration.
"""
from celery import shared_task
import logging
from .health_checker import health_checker

logger = logging.getLogger(__name__)


@shared_task
def health_check_engines():
    """Periodic task to check health of all engines."""
    try:
        results = health_checker.check_all_engines()
        logger.info(f"Health check completed: {len(results)} engines checked")
        return results
    except Exception as e:
        logger.error(f"Health check task failed: {str(e)}")
        raise
