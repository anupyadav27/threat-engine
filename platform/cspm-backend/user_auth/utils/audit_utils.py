"""Audit logging helper (AUTH-13). Never raises — failures are swallowed and logged."""
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def log_auth_event(
    event: str,
    request=None,
    user=None,
    tenant_id: Optional[str] = None,
    extra: Optional[dict] = None,
) -> None:
    """Write one row to audit_logs. Safe to call from any view — never raises."""
    try:
        from audit_logs.models import AuditLog

        ip: Optional[str] = None
        ua: str = ""
        if request is not None:
            raw_ip = request.META.get("REMOTE_ADDR") or None
            ip = raw_ip if raw_ip else None
            ua = request.META.get("HTTP_USER_AGENT", "")

        AuditLog.objects.create(
            user=user,
            event=event,
            tenant_id=str(tenant_id) if tenant_id else None,
            ip_address=ip,
            user_agent=ua,
            extra=extra or {},
        )
    except Exception as exc:
        logger.error("audit_utils: failed to write event=%s: %s", event, exc)
