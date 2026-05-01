import uuid
from django.db import models


class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "user_auth.Users",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_logs",
    )
    event = models.CharField(max_length=100)
    tenant_id = models.TextField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, default="")
    extra = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "audit_logs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "created_at"], name="audit_user_ts_idx"),
            models.Index(fields=["tenant_id", "created_at"], name="audit_tenant_ts_idx"),
            models.Index(fields=["event", "created_at"], name="audit_event_ts_idx"),
        ]
