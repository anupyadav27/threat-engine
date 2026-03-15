from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin, Group, Permission
from django.db import models
import uuid
from django.contrib.auth.hashers import make_password, check_password
from django.conf import settings

class UsersManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra_fields)


class Users(AbstractBaseUser, PermissionsMixin):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.TextField(unique=True)
    password = models.TextField(blank=True, null=True)
    sso_provider = models.TextField(blank=True, null=True)
    sso_id = models.TextField(blank=True, null=True)
    first_name = models.TextField(blank=True, null=True)
    last_name = models.TextField(blank=True, null=True)
    status = models.TextField(blank=True, null=True)
    last_login = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # PermissionsMixin fields
    groups = models.ManyToManyField(Group, related_name="custom_users_groups", blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name="custom_users_permissions", blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UsersManager()

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def __str__(self):
        return self.email

    class Meta:
        managed = True
        db_table = 'users'
        indexes = [models.Index(fields=['email'])]


class UserSessions(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('Users', models.DO_NOTHING)
    token = models.TextField(unique=True)
    refresh_token = models.TextField(blank=True, null=True)
    ip_address = models.TextField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    login_method = models.TextField(blank=True, null=True)
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)
    location_country = models.TextField(blank=True, null=True)
    location_city = models.TextField(blank=True, null=True)
    location_region = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    session_index = models.TextField(blank=True, null=True)

    class Meta:
        managed = True
        db_table = 'user_sessions'

class Permissions(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.CharField(max_length=100)
    feature = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    tenant_scoped = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True, null=True,
        related_name='permissions_created'
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True, null=True,
        related_name='permissions_updated'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'permissions'
        ordering = ['feature', 'action']

    def __str__(self):
        return f"{self.feature}:{self.action}"




class Roles(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)
    tenant_scoped = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True, null=True,
        related_name='roles_created'
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True, null=True,
        related_name='roles_updated'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    permissions = models.ManyToManyField(
        Permissions,
        through='RolePermissions',
        related_name='roles'
    )

    class Meta:
        db_table = 'roles'
        ordering = ['name']

    def __str__(self):
        return self.name

class UserRoles(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        'Users',
        on_delete=models.CASCADE,
        db_column='user_id'
    )
    role = models.ForeignKey(
        'Roles',
        on_delete=models.CASCADE,
        db_column='role_id'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_roles'
        unique_together = (('user', 'role'),)

class RolePermissions(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.ForeignKey(Roles, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permissions, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'role_permissions'
        unique_together = ('role', 'permission')

    def __str__(self):
        return f"{self.role.name} -> {self.permission.feature}:{self.permission.action}"


