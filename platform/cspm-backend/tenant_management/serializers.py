from rest_framework import serializers
from .models import Tenants, TenantIDPConfig


class TenantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenants
        fields = [
            "id", "name", "description", "status", "plan",
            "contact_email", "region", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


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