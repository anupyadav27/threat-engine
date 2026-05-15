"""
Invite send and accept endpoints for onboarding-D2.

POST /api/users/invite        — create invite (requires users:write)
POST /api/users/invite/accept — accept invite with token (public)

Design notes:
- customer_id is ALWAYS set server-side from the authenticated user's session.
  It is never read from the request body (STRIDE: spoofing mitigation).
- The raw invite token is never stored in the DB — only its SHA-256 hex digest
  is persisted in InviteTokens.token_hash.
- Tokens expire after 72 hours (AC6, AC10).
- Same-org duplicate invite returns HTTP 409 (AC3).
- Cross-org email returns HTTP 422 (AC4).
"""
import hashlib
import logging
import secrets
import uuid
from datetime import timedelta

from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView

from user_auth.drf_auth import CookieTokenAuthentication
from user_auth.drf_permissions import HasPermission
from user_auth.models import InviteTokens, Users

logger = logging.getLogger(__name__)

_TOKEN_TTL_HOURS = 72
_VALID_ROLES = {"org_admin", "tenant_admin", "analyst", "viewer"}


def _sha256(raw: str) -> str:
    """Return the SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class InviteUserView(APIView):
    """POST /api/users/invite — send an invite email to a new user.

    Required permission: users:write
    customer_id is always sourced from the authenticated user's session —
    it is never accepted from the request body.
    """

    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [HasPermission("users:write")]

    def post(self, request) -> Response:
        """Create a pending user record and send an SES invite email.

        Args:
            request: DRF request. Expected body fields:
                - email (str, required): target email address.
                - role (str, optional): one of org_admin/tenant_admin/analyst/viewer.
                  Defaults to "analyst".
                - group_id (str, optional): CsmGroups UUID to assign on acceptance.

        Returns:
            201 {"invited": email, "user_id": ..., "expires_at": ...} on success.
            400 on missing/invalid fields.
            409 if the email already exists in the same org (AC3).
            422 if the email belongs to a different org (AC4).
        """
        from user_auth.utils.email_utils import send_invite_email
        from user_auth.utils.audit_utils import log_auth_event

        email = (request.data.get("email") or "").strip().lower()
        role_name = (request.data.get("role") or "analyst").strip()
        group_id = request.data.get("group_id")

        if not email:
            return Response({"detail": "email is required"}, status=400)

        if role_name not in _VALID_ROLES:
            return Response(
                {"detail": f"Invalid role '{role_name}'. Valid roles: {sorted(_VALID_ROLES)}"},
                status=400,
            )

        # customer_id is ALWAYS server-side (never from request body)
        customer_id = getattr(request.user, "customer_id", None) or str(request.user.id)

        # ── Duplicate check ─────────────────────────────────────────────────
        existing = Users.objects.filter(email=email).first()
        if existing:
            if existing.customer_id == customer_id:
                return Response(
                    {"detail": "User already exists in this org"},
                    status=409,
                )
            else:
                return Response(
                    {
                        "detail": (
                            "Email is registered to a different org — "
                            "cross-org invite not supported"
                        )
                    },
                    status=422,
                )

        # ── Resolve role ─────────────────────────────────────────────────────
        from user_auth.models import Roles, UserRoles

        # Inviter role-cap: cannot grant a role with a lower level number
        # (lower level number = higher privilege in this system, e.g. l1 > l4)
        inviter_role_row = (
            UserRoles.objects.filter(user=request.user)
            .select_related("role")
            .order_by("role__level")
            .first()
        )
        inviter_level = inviter_role_row.role.level if inviter_role_row else 99

        target_role = Roles.objects.filter(name=role_name).first()
        if not target_role or target_role.level < inviter_level:
            # Silently cap to viewer
            target_role = Roles.objects.filter(name="viewer").first()

        # ── Optional group validation ────────────────────────────────────────
        group = None
        if group_id:
            from tenant_management.models import CsmGroups

            try:
                group = CsmGroups.objects.get(id=group_id, customer_id=customer_id)
            except CsmGroups.DoesNotExist:
                return Response(
                    {"detail": "Group not found or not in your organisation"},
                    status=404,
                )

        # ── Create pending user ──────────────────────────────────────────────
        # status="pending" marks the user as uninvited (not yet accepted).
        # The existing Users model uses the `status` text field rather than
        # a separate `is_active` boolean column.
        user = Users.objects.create_user(
            email=email,
            password=None,
            status="pending",
        )
        user.customer_id = customer_id
        user.save(update_fields=["customer_id"])

        # ── Generate invite token (raw never stored — only SHA-256 hash) ────
        raw_token = secrets.token_urlsafe(32)
        token_hash = _sha256(raw_token)
        expires_at = timezone.now() + timedelta(hours=_TOKEN_TTL_HOURS)

        invite = InviteTokens.objects.create(
            id=str(uuid.uuid4()),
            # `token` field (legacy plain-text field) stores the hash for
            # compatibility with the existing schema.  The token_hash column
            # is the authoritative storage for hashed lookup.
            token=token_hash,
            email=email,
            # `tenant` FK is nullable in older rows; new invite flow is
            # customer_id–scoped, so we set tenant to None and rely on
            # customer_id scoping via the Users row.
            tenant=None,
            role=target_role,
            invited_by=request.user,
            expires_at=expires_at,
            used=False,
            group=group,
        )

        # ── Send SES email (non-fatal) ───────────────────────────────────────
        try:
            send_invite_email(
                to_email=email,
                invite_token=raw_token,
                tenant_name="Onam Security",
                invited_by=request.user.email,
            )
        except Exception as exc:
            logger.warning("invite email send failed for %s: %s", email, exc)

        log_auth_event("invite.created", request=request, user=request.user)

        return Response(
            {
                "invited": email,
                "user_id": str(user.id),
                "expires_at": expires_at.isoformat(),
            },
            status=201,
        )


class InviteUserAcceptView(APIView):
    """POST /api/users/invite/accept — accept an invite using the raw token.

    This is a PUBLIC endpoint (no authentication required).  The caller
    supplies the raw token (from the accept URL query-string) and an optional
    password.  The view:
      1. Hashes the raw token and looks up the InviteTokens row.
      2. Validates expiry (72-hour TTL).
      3. Marks the pending user as active (status="active").
      4. Creates a session and sets auth cookies.
      5. Marks the invite as used.

    Request body:
        {
            "token": "<raw_token>",
            "password": "<password>",      # optional for SSO tenants
            "first_name": "Alice",         # optional
            "last_name":  "Smith"          # optional
        }

    Returns:
        200 {"status": "activated", "user": {...}} + auth cookies on success.
        400 on invalid token.
        409 on already-used token.
        410 on expired token (AC10).
    """

    authentication_classes = []
    permission_classes = []

    def post(self, request) -> Response:
        """Accept an invite token and activate the pending user.

        Args:
            request: DRF request with body fields: token, password, first_name, last_name.

        Returns:
            Response with status and user info, plus Set-Cookie headers on success.
        """
        from datetime import timedelta as _td

        from django.conf import settings as _settings

        from user_auth.models import UserSessions
        from user_auth.utils.auth_utils import (
            compute_auth_caches,
            generate_token,
            hash_token,
        )
        from user_auth.utils.cookie_utils import set_auth_cookies

        raw_token = request.data.get("token", "").strip()
        if not raw_token:
            return Response({"detail": "token is required"}, status=400)

        token_hash = _sha256(raw_token)

        # Lookup by token_hash (stored in the `token` field for this endpoint's
        # invites, created by InviteUserView above).
        try:
            invite = InviteTokens.objects.select_related("role").get(token=token_hash)
        except InviteTokens.DoesNotExist:
            return Response({"detail": "Invalid invite token"}, status=400)

        if invite.used:
            return Response({"detail": "This invite has already been used"}, status=409)

        if invite.expires_at < timezone.now():
            return Response({"detail": "Invite link expired"}, status=410)

        # ── Activate the user ─────────────────────────────────────────────
        try:
            user = Users.objects.get(email=invite.email)
        except Users.DoesNotExist:
            return Response({"detail": "Invited user record not found"}, status=404)

        first_name = (request.data.get("first_name") or "").strip()
        last_name = (request.data.get("last_name") or "").strip()
        password = request.data.get("password") or ""

        if first_name:
            user.first_name = first_name
        if last_name:
            user.last_name = last_name
        if password and len(password) >= 8:
            user.set_password(password)

        user.status = "active"
        user.save()

        # Mark invite consumed
        invite.used = True
        invite.save(update_fields=["used"])

        # ── Create session ────────────────────────────────────────────────
        UserSessions.objects.filter(user=user).delete()
        access_token = generate_token()
        refresh_token = generate_token()
        lifetime_days = getattr(_settings, "REFRESH_TOKEN_LIFETIME_DAYS", 7)
        session_expires = timezone.now() + _td(days=lifetime_days)
        permissions_cache, scope_cache = compute_auth_caches(user)

        UserSessions.objects.create(
            id=uuid.uuid4(),
            user=user,
            token=hash_token(access_token),
            refresh_token=hash_token(refresh_token),
            login_method="invite_accept",
            expires_at=session_expires,
            ip_address=request.META.get("REMOTE_ADDR", ""),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            token_hint=access_token[:8],
            permissions_cache=permissions_cache,
            scope_cache=scope_cache,
        )

        response = Response(
            {
                "status": "activated",
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "name": f"{user.first_name or ''} {user.last_name or ''}".strip(),
                },
            },
            status=200,
        )
        set_auth_cookies(response, access_token, refresh_token)
        response["Cache-Control"] = "no-store"
        return response
