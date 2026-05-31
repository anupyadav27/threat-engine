"""
Tenant provisioning utilities.

provision_tenant_for_new_user() — canonical function in services.provisioning.
  Imported here for convenience; all call sites should use this module as the
  import source so internal refactors remain transparent to callers.

accept_invite_membership() — wires TenantUsers + UserRoles for an invite acceptor.
  Wrapped in transaction.atomic() with SELECT FOR UPDATE to prevent the race condition
  where two concurrent requests both read used=False and both create membership rows
  (BILL-S01 / BLOCKER-01).
"""
import logging
import uuid

from django.db import transaction

from services.provisioning import provision_tenant_for_new_user  # noqa: F401 — re-export
from user_auth.utils.audit_utils import log_auth_event

logger = logging.getLogger(__name__)


def _get_viewer_role():
    from user_auth.models import Roles
    try:
        return Roles.objects.get(name="viewer")
    except Roles.DoesNotExist:
        raise RuntimeError("Role 'viewer' not found — run migration user_auth.0009 first.")


def accept_invite_membership(user, invite) -> None:
    """Create TenantUsers + UserRoles for an accepted invite and mark it used.

    Wrapped in transaction.atomic() with SELECT FOR UPDATE on the InviteTokens
    row so that two concurrent requests for the same token are serialised at the
    DB level. The second concurrent request will raise InviteTokens.DoesNotExist
    (used=False filter no longer matches after the first transaction commits) —
    callers must catch that exception and return HTTP 409.

    Cross-org invites (invite.tenant.customer_id != user.customer_id) are
    accepted but capped to the viewer role to prevent privilege escalation
    across org boundaries.

    Idempotent — safe to call even if membership already exists.
    """
    from tenant_management.models import TenantUsers
    from user_auth.models import UserRoles, InviteTokens

    with transaction.atomic():
        # SELECT FOR UPDATE acquires a row-level lock. The used=False filter
        # means the second concurrent request raises DoesNotExist once the
        # first transaction commits and flips used=True.
        locked_invite = InviteTokens.objects.select_for_update().get(
            token=invite.token, used=False
        )

        role = locked_invite.role or _get_viewer_role()

        # Cross-org invite: cap to viewer regardless of the assigned role
        user_customer_id = getattr(user, "customer_id", None) or str(user.id)
        tenant_customer_id = getattr(locked_invite.tenant, "customer_id", None)
        if tenant_customer_id and tenant_customer_id != user_customer_id:
            logger.info(
                "Cross-org invite accepted for %s — capping role to viewer "
                "(tenant customer_id=%s, user customer_id=%s)",
                user.email, tenant_customer_id, user_customer_id,
            )
            role = _get_viewer_role()

        TenantUsers.objects.get_or_create(
            user=user,
            tenant=locked_invite.tenant,
            defaults={"id": str(uuid.uuid4()), "role": role, "is_active": True},
        )

        UserRoles.objects.get_or_create(
            user=user,
            role=role,
            defaults={"id": str(uuid.uuid4())},
        )

        # Group membership — only if invite has a group assigned (BILL-S06).
        # Both GroupMembers and TenantGroupAccess are written inside this same
        # atomic block so partial membership is impossible (SEC-04).
        if locked_invite.group_id:
            from tenant_management.models import CsmGroups, GroupMembers, TenantGroupAccess

            # Re-validate group ownership at acceptance time (SEC-02 / BLOCKER-05).
            # A stale token may point to a group that was reassigned to a different
            # org after the invite was created — silently skip, do not block acceptance.
            try:
                group = CsmGroups.objects.get(
                    id=locked_invite.group_id,
                    customer_id=str(locked_invite.tenant.customer_id),
                )
            except CsmGroups.DoesNotExist:
                logger.warning(
                    "accept_invite: group %s no longer belongs to tenant customer %s "
                    "— skipping group membership",
                    locked_invite.group_id,
                    locked_invite.tenant.customer_id,
                )
                group = None

            if group:
                GroupMembers.objects.get_or_create(
                    group=group,
                    user=user,
                    defaults={"id": str(uuid.uuid4())},
                )
                TenantGroupAccess.objects.get_or_create(
                    group=group,
                    tenant=locked_invite.tenant,
                    defaults={"id": str(uuid.uuid4()), "role": role},
                )

                def _group_audit():
                    try:
                        log_auth_event(
                            "group_membership.granted",
                            extra={
                                "group_id": str(group.id),
                                "tenant_id": str(locked_invite.tenant_id),
                            },
                        )
                    except Exception as exc:
                        logger.warning("group membership audit log failed: %s", exc)

                transaction.on_commit(_group_audit)

        # LAST write inside atomic block — any error before this rolls back
        # the transaction and leaves used=False so the invite remains consumable.
        locked_invite.used = True
        locked_invite.save(update_fields=["used"])

        # Audit log fired only after the transaction successfully commits.
        # Defined inside the atomic block so it closes over locked_invite,
        # but deferred via on_commit so it never runs on rollback.
        def _audit():
            try:
                log_auth_event(
                    "invite.accept",
                    extra={
                        "token": invite.token[:8],
                        "tenant_id": str(locked_invite.tenant_id),
                    },
                )
            except Exception as exc:
                logger.warning("audit log failed post-invite-accept: %s", exc)

        transaction.on_commit(_audit)


