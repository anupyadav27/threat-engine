"""
Models for admin analytics app.
"""
from django.db import models
from django.contrib.postgres.fields import JSONField
from django.utils import timezone


class AdminDashboard(models.Model):
    """Saved dashboard configurations for admin users."""
    admin_user_id = models.CharField(max_length=255, db_index=True)
    dashboard_name = models.CharField(max_length=255)
    widgets = models.JSONField(default=list)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'admin_dashboards'
        unique_together = [['admin_user_id', 'dashboard_name']]
    
    def __str__(self):
        return f"{self.dashboard_name} - {self.admin_user_id}"
