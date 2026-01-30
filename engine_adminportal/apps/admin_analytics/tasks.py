"""
Celery tasks for admin analytics.
"""
from celery import shared_task
import logging
from .calculators import analytics_calculator

logger = logging.getLogger(__name__)


@shared_task
def calculate_analytics():
    """Periodic task to calculate analytics."""
    try:
        # Calculate all analytics
        overview = analytics_calculator.calculate_overview()
        compliance = analytics_calculator.calculate_compliance_analytics()
        scans = analytics_calculator.calculate_scan_analytics()
        
        logger.info("Analytics calculation completed")
        return {
            'overview': overview,
            'compliance': compliance,
            'scans': scans
        }
    except Exception as e:
        logger.error(f"Calculate analytics task failed: {str(e)}")
        raise
