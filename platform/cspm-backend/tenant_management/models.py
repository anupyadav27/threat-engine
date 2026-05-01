import uuid
from django.db import models
from django.conf import settings
from user_auth.models import Roles


IDP_TYPE_CHOICES = [
    ('google_oauth', 'Google OAuth'),
    ('oidc', 'Generic OIDC'),
    ('saml', 'SAML 2.0'),
]


class Tenants(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)

    # engine_tenant_id: the tenant_id used in CSPM engine databases.
    # Defaults to the UUID id; override for legacy tenants seeded with a text slug.
    engine_tenant_id = models.CharField(max_length=255, blank=True, default='')

    status = models.CharField(max_length=50, default="active")
    plan = models.CharField(max_length=100, blank=True, null=True)

    contact_email = models.EmailField(blank=True, null=True)
    region = models.CharField(max_length=100, blank=True, null=True)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="tenants_created"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'tenants'
        indexes = [
            models.Index(fields=['name']),
        ]

    def __str__(self):
        return self.name


class TenantUsers(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)

    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name='members'
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='tenants'
    )

    role = models.ForeignKey(
        Roles,
        on_delete=models.PROTECT
    )

    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'tenant_users'
        unique_together = ('tenant', 'user')
        indexes = [
            models.Index(fields=['tenant']),
            models.Index(fields=['user']),
        ]

    def __str__(self):
        return f"{self.user.email} → {self.tenant.name}"


class TenantIDPConfig(models.Model):
    """Per-tenant identity provider configuration.

    config JSONB schemas:
      google_oauth: {client_id, client_secret_ref, allowed_hd: [...]}
      oidc:         {issuer, client_id, client_secret_ref, scopes: [...],
                     claims_mapping: {email, first_name, last_name}, pkce: bool}
      saml:         {entity_id, metadata_url, metadata_xml, attribute_mapping,
                     sp_entity_id, acs_url}
    client_secret_ref points to AWS Secrets Manager path — never stored in plaintext.
    """

    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name='idp_configs',
    )
    idp_type = models.CharField(max_length=20, choices=IDP_TYPE_CHOICES)
    idp_name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=False)
    config = models.JSONField()
    allowed_domains = models.JSONField(default=list)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='idp_configs_created',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'tenant_idp_configs'
        unique_together = ('tenant', 'idp_type', 'idp_name')
        indexes = [
            models.Index(fields=['tenant', 'idp_type', 'is_active']),
        ]

    def __str__(self):
        return f"{self.tenant.name} / {self.idp_type} / {self.idp_name}"

