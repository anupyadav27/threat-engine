"""
Celery tasks for admin monitoring.
"""
from celery import shared_task
import logging
from django.db import connection
from django.core.cache import cache
from .models import AdminMetric
from apps.engine_integration.aggregators import metrics_aggregator

logger = logging.getLogger(__name__)


@shared_task
def aggregate_tenant_metrics():
    """Periodic task to aggregate tenant metrics."""
    try:
        # Get all tenants
        with connection.cursor() as cursor:
            cursor.execute("SELECT tenant_id FROM tenants WHERE status = 'active'")
            tenant_ids = [row[0] for row in cursor.fetchall()]
        
        # Aggregate metrics for each tenant
        for tenant_id in tenant_ids:
            try:
                metrics = metrics_aggregator.aggregate_tenant_metrics(tenant_id)
                
                # Store metrics in database
                for metric_type, metric_value in metrics.items():
                    if metric_type != 'tenant_id' and isinstance(metric_value, (int, float)):
                        AdminMetric.objects.create(
                            tenant_id=tenant_id,
                            metric_type=metric_type,
                            metric_value=float(metric_value),
                            metadata={'source': 'aggregation_task'}
                        )
            except Exception as e:
                logger.error(f"Failed to aggregate metrics for tenant {tenant_id}: {str(e)}")
        
        logger.info(f"Aggregated metrics for {len(tenant_ids)} tenants")
        return {'tenants_processed': len(tenant_ids)}
    except Exception as e:
        logger.error(f"Aggregate tenant metrics task failed: {str(e)}")
        raise


@shared_task
def cleanup_old_metrics():
    """Periodic task to cleanup old metrics."""
    try:
        from django.utils import timezone
        from datetime import timedelta
        
        # Delete metrics older than 30 days
        cutoff_date = timezone.now() - timedelta(days=30)
        deleted_count = AdminMetric.objects.filter(timestamp__lt=cutoff_date).delete()[0]
        
        logger.info(f"Cleaned up {deleted_count} old metric records")
        return {'deleted_count': deleted_count}
    except Exception as e:
        logger.error(f"Cleanup old metrics task failed: {str(e)}")
        raise
