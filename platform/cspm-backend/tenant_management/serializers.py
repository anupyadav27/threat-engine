from rest_framework import serializers
from .models import Tenants, TenantIDPConfig, CsmGroups, GroupMembers, TenantGroupAccess, AccountGroupAccess

VALID_TENANT_TYPES = ["cloud", "vulnerability", "secops"]


class OrgProfilePatch(serializers.Serializer):
    """Writable schema for PATCH /api/org/profile/ — only org_name and contact_email are patchable.

    customer_id, plan, and billing_org_id are intentionally absent (read-only — AC3).
    """

    org_name = serializers.CharField(max_length=255, required=False, allow_blank=False)
    contact_email = serializers.EmailField(required=False, allow_blank=False)


class TenantTypePatch(serializers.Serializer):
    """Writable schema for PATCH /api/tenants/{id}/type/ — tenant_type only."""

    tenant_type = serializers.ChoiceField(choices=VALID_TENANT_TYPES)


class TenantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenants
        fields = [
            "id", "name", "description", "status", "plan",
            "contact_email", "region", "tenant_type", "customer_id",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "customer_id", "created_at", "updated_at"]


class GroupSerializer(serializers.ModelSerializer):
    member_count = serializers.SerializerMethodField()

    class Meta:
        model = CsmGroups
        fields = ["id", "customer_id", "name", "description", "member_count", "created_at", "updated_at"]
        read_only_fields = ["id", "customer_id", "created_at", "updated_at"]

    def get_member_count(self, obj):
        return obj.members.count()


class GroupMemberSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source="user.email", read_only=True)
    user_id = serializers.CharField(write_only=True)

    class Meta:
        model = GroupMembers
        fields = ["id", "user_id", "user_email", "added_at"]
        read_only_fields = ["id", "user_email", "added_at"]


class TenantGroupAccessSerializer(serializers.ModelSerializer):
    group_name = serializers.CharField(source="group.name", read_only=True)
    role_name  = serializers.CharField(source="role.name", read_only=True)

    class Meta:
        model = TenantGroupAccess
        fields = ["id", "group", "group_name", "tenant", "role", "role_name", "granted_at"]
        read_only_fields = ["id", "group_name", "role_name", "granted_at"]


class AccountGroupAccessSerializer(serializers.ModelSerializer):
    group_name = serializers.CharField(source="group.name", read_only=True)
    role_name  = serializers.CharField(source="role.name", read_only=True)

    class Meta:
        model = AccountGroupAccess
        fields = ["id", "group", "group_name", "tenant", "account_id", "role", "role_name", "granted_at"]
        read_only_fields = ["id", "group_name", "role_name", "granted_at"]


class TenantAssignSerializer(serializers.Serializer):
    """Request body for POST /api/groups/{group_id}/tenants/ (onboarding-D3)."""

    tenant_id = serializers.CharField(max_length=255)
    role = serializers.CharField(max_length=50, default="viewer")


class AccountAssignSerializer(serializers.Serializer):
    """Request body for POST /api/groups/{group_id}/accounts/ (onboarding-D3)."""

    account_id = serializers.CharField(max_length=512)
    tenant_id = serializers.CharField(max_length=255)
    role = serializers.CharField(max_length=50, default="viewer")


class TenantIDPConfigSerializer(serializers.ModelSerializer):
    """Serializer for TenantIDPConfig.

    client_secret_ref inside config is write-only — stripped from GET responses
    to prevent leaking Secrets Manager paths.
    """

    config = serializers.SerializerMethodField(read_only=False)

    class Meta:
        model = TenantIDPConfig
        fields = [
            "id", "tenant", "idp_type", "idp_name", "is_active",
            "config", "allowed_domains", "created_by", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_by", "created_at", "updated_at"]

    def get_config(self, obj: TenantIDPConfig) -> dict:
        """Return config with client_secret_ref replaced by sentinel — never expose the path."""
        cfg = dict(obj.config or {})
        if "client_secret_ref" in cfg:
            cfg["client_secret_ref"] = "[stored]"
        return cfg

    def to_internal_value(self, data: dict) -> dict:
        """Preserve client_secret_ref on write."""
        return super().to_internal_value(data)

    def validate(self, attrs: dict) -> dict:
        idp_type = attrs.get("idp_type")
        config = attrs.get("config", {})
        required: dict[str, list[str]] = {
            "google_oauth": ["client_id"],
            "oidc": ["issuer", "client_id"],
            "saml": ["entity_id"],
        }
        missing = [k for k in required.get(idp_type, []) if k not in config]
        if missing:
            raise serializers.ValidationError(
                {"config": f"Missing required keys for {idp_type}: {missing}"}
            )
        return attrs