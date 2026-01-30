"""
Models for admin management app.
Note: This app uses existing tables from the main backend.
Additional admin-specific models can be added here if needed.
"""
from django.db import models
from django.utils import timezone


class TenantQuota(models.Model):
    """Usage quotas per tenant."""
    tenant_id = models.CharField(max_length=255, unique=True, db_index=True)
    max_scans_per_day = models.IntegerField(default=100)
    max_users = models.IntegerField(default=10)
    max_resources = models.IntegerField(default=10000)
    current_scans_today = models.IntegerField(default=0)
    last_reset_date = models.DateField(default=timezone.now)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'admin_tenant_quotas'
    
    def __str__(self):
        return f"Quota for {self.tenant_id}"
