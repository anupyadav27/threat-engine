import uuid
from django.db import models
from django.conf import settings
from user_auth.models import Roles


class Tenants(models.Model):

    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=50, blank=True, null=True)
    plan = models.CharField(max_length=100, blank=True, null=True)
    contact_email = models.EmailField(blank=True, null=True)
    region = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'tenants'
        verbose_name = 'Tenant'
        verbose_name_plural = 'Tenants'

    def __str__(self):
        return self.name


class TenantUsers(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenants, on_delete=models.CASCADE, related_name='tenant_users')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='tenant_users')
    role = models.ForeignKey(Roles, on_delete=models.CASCADE, related_name='tenant_users_role')
    status = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'tenant_users'
        verbose_name = 'Tenant User'
        verbose_name_plural = 'Tenant Users'
        unique_together = ('tenant', 'user')

    def __str__(self):
        return f"{self.user.email} in {self.tenant.name}"

