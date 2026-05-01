---
story_id: AUTH-13
title: Audit log enrichment — auth events + IDP config changes
status: ready
sprint: auth-redesign-2
depends_on: [AUTH-02, AUTH-04, AUTH-05]
blocks: []
sme: Django/Python backend engineer
estimate: 1 day
---

# Story: Audit Log Enrichment for Auth Events

## Context

The platform has an `audit_logs` Django app but it is not wired to auth events.
Compliance frameworks (SOC 2, ISO 27001) require audit trails for:
- User login (method, IDP, success/failure, IP, user agent)
- User logout
- IDP configuration changes (create, update, activate, delete)
- Invite creation and acceptance
- Failed auth attempts

This story wires audit log writes to all auth events.

## Files to Create/Modify

- `platform/cspm-backend/audit_logs/models.py` — review and extend if needed
- `platform/cspm-backend/user_auth/views/oidc_auth.py` — add audit log calls
- `platform/cspm-backend/user_auth/views/saml_auth.py` — add audit log calls
- `platform/cspm-backend/user_auth/views/local_auth.py` — add audit log calls
- `platform/cspm-backend/tenant_management/views.py` — audit IDP config changes

## Implementation Notes

### Audit log helper

Create `platform/cspm-backend/user_auth/utils/audit_utils.py`:

```python
from audit_logs.models import AuditLog  # check actual model name
import logging

logger = logging.getLogger(__name__)

def log_auth_event(
    event_type: str,
    user=None,
    tenant_id: str = None,
    metadata: dict = None,
    request=None,
) -> None:
    """Write an audit log entry for an auth event. Never raises."""
    try:
        AuditLog.objects.create(
            event_type=event_type,
            user=user,
            tenant_id=tenant_id,
            ip_address=request.META.get('REMOTE_ADDR', '') if request else '',
            user_agent=request.META.get('HTTP_USER_AGENT', '') if request else '',
            metadata=metadata or {},
        )
    except Exception as e:
        logger.error(f"Failed to write audit log for {event_type}: {e}")
```

### Events to log

| Event type | Where | Metadata |
|-----------|-------|----------|
| `auth.login.success` | All login callbacks | `method`, `idp_name`, `user_id` |
| `auth.login.failure` | Local login, SAML ACS errors | `reason`, `email_attempted` |
| `auth.logout` | LogoutView | `session_id` |
| `auth.invite.created` | CreateInviteView | `invited_email`, `tenant_id`, `role` |
| `auth.invite.accepted` | AcceptInviteView | `accepted_by`, `tenant_id` |
| `idp.config.created` | TenantIDPConfigListCreateView | `idp_type`, `idp_name`, `tenant_id` |
| `idp.config.updated` | TenantIDPConfigDetailView PATCH | `idp_type`, `tenant_id` |
| `idp.config.activated` | TenantIDPConfigActivateView | `idp_name`, `tenant_id` |
| `idp.config.deleted` | TenantIDPConfigDetailView DELETE | `idp_name`, `tenant_id` |

### Check AuditLog model

Read `platform/cspm-backend/audit_logs/models.py` and verify it has:
- `event_type` field
- `user` FK (nullable)
- `tenant_id` field
- `ip_address`, `user_agent`
- `metadata` JSONB
- `created_at`

Add fields if missing via migration.

## Acceptance Criteria

- [ ] AC1: Successful Google/OIDC/SAML login creates an `AuditLog` row with `event_type='auth.login.success'` and correct `method`
- [ ] AC2: Failed SAML assertion creates `event_type='auth.login.failure'` row
- [ ] AC3: `TenantIDPConfig` create/update/activate writes corresponding `idp.config.*` audit log
- [ ] AC4: Audit log write failure does NOT break the auth flow (non-fatal)
- [ ] AC5: `GET /api/v1/audit-logs/` (existing endpoint if it exists, or new) returns login events filtered by tenant

## Definition of Done

- [ ] Code follows Python standards
- [ ] Tests verify audit log creation for each event type
- [ ] Story accepted by SM before merge
