import uuid
from django.db import models
from django.conf import settings
from user_auth.models import Roles


IDP_TYPE_CHOICES = [
    ('google_oauth', 'Google OAuth'),
    ('oidc', 'Generic OIDC'),
    ('saml', 'SAML 2.0'),
]

TENANT_TYPE_CHOICES = [
    ('cloud', 'Cloud'),
    ('vulnerability', 'Vulnerability'),
    ('secops', 'SecOps'),
]


class Tenants(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)

    # engine_tenant_id: the tenant_id used in CSPM engine databases.
    # Defaults to the UUID id; override for legacy tenants seeded with a text slug.
    engine_tenant_id = models.CharField(max_length=255, blank=True, default='')

    status = models.CharField(max_length=50, default="active")
    tenant_type = models.CharField(
        max_length=50,
        choices=TENANT_TYPE_CHOICES,
        default='cloud',
    )
    customer_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
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


class UserAccountAccess(models.Model):
    """
    Explicit account-level access grant for a user within a tenant.

    When rows exist for a user, AuthContext.account_ids is populated with only
    those account_ids, restricting engine queries to those accounts.
    When no rows exist, account_ids = None (unrestricted within the tenant).

    account_id: cloud provider account ID (AWS account number, Azure subscription
                UUID, GCP project ID, etc.).
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='account_access',
    )
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name='account_access',
    )
    account_id = models.CharField(max_length=512)
    role = models.ForeignKey(
        Roles,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='account_access_grants',
    )
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='account_grants_given',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_account_access'
        unique_together = ('user', 'tenant', 'account_id')
        indexes = [
            models.Index(fields=['user', 'tenant']),
        ]

    def __str__(self):
        return f"{self.user.email} → {self.tenant.name} → {self.account_id}"


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


class CsmGroups(models.Model):
    """User group scoped to an org (customer_id). Groups can be granted access to tenants/accounts."""
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    customer_id = models.CharField(max_length=255, db_index=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='groups_created',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'csm_groups'
        unique_together = ('customer_id', 'name')
        indexes = [models.Index(fields=['customer_id'])]

    def __str__(self):
        return f"{self.customer_id}/{self.name}"


class GroupMembers(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    group = models.ForeignKey(CsmGroups, on_delete=models.CASCADE, related_name='members')
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='group_memberships',
    )
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'group_members'
        unique_together = ('group', 'user')


class TenantGroupAccess(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    group = models.ForeignKey(CsmGroups, on_delete=models.CASCADE, related_name='tenant_access')
    tenant = models.ForeignKey(Tenants, on_delete=models.CASCADE, related_name='group_access')
    role = models.ForeignKey(Roles, on_delete=models.PROTECT, related_name='tenant_group_grants')
    granted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'tenant_group_access'
        unique_together = ('group', 'tenant')


class AccountGroupAccess(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    group = models.ForeignKey(CsmGroups, on_delete=models.CASCADE, related_name='account_access')
    tenant = models.ForeignKey(Tenants, on_delete=models.CASCADE, related_name='account_group_access')
    account_id = models.CharField(max_length=512)
    role = models.ForeignKey(Roles, on_delete=models.PROTECT, related_name='account_group_grants')
    granted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'account_group_access'
        unique_together = ('group', 'tenant', 'account_id')

