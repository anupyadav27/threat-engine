"""
Celery configuration for admin portal.
"""
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'admin_portal.settings')

app = Celery('admin_portal')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
