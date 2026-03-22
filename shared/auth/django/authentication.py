"""
CookieTokenAuthentication — DRF authentication class.

Reads access_token from HTTPOnly cookie, validates via token_hint (indexed)
then full hash verification. Builds AuthContext from cached session data.

Performance: O(1) lookup via token_hint index instead of O(N) full table scan.
"""

from __future__ import annotations

import logging
from django.contrib.auth.hashers import check_password
from django.utils import timezone
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from engine_auth.core.models import AuthContext

logger = logging.getLogger(__name__)


class CookieTokenAuthentication(BaseAuthentication):
    """
    Authenticate via access_token cookie.

    Sets request.auth_context (AuthContext) on successful auth.
    Falls back to old-style auth if permissions_cache is not populated yet
    (backward compatible during migration rollout).
    """

    def authenticate(self, request):
        raw_token = request.COOKIES.get("access_token")
        if not raw_token:
            return None  # No cookie = anonymous

        from user_auth.models import UserSessions, UserRoles

        session = self._find_session(raw_token)
        if not session:
            raise AuthenticationFailed("Invalid or expired session.")

        user = session.user

        # Build AuthContext from cached data (fast path)
        if session.permissions_cache is not None and session.scope_cache is not None:
            # Get role info
            role_info = self._get_role_info(user)
            auth_ctx = AuthContext.from_session_cache(
                user_id=str(user.pk),
                email=user.email,
                role_name=role_info["name"],
                role_level=role_info["level"],
                role_scope_level=role_info["scope_level"],
                permissions_cache=session.permissions_cache,
                scope_cache=session.scope_cache,
            )
        else:
            # Slow path: resolve from DB (for old sessions without cache)
            auth_ctx = self._build_auth_context_from_db(user)

        # Attach auth context to request for permission classes to use
        request.auth_context = auth_ctx

        # Also set legacy attributes for backward compat
        request.tenant_id = None
        request.customer_id = None

        return (user, raw_token)

    def _find_session(self, raw_token: str):
        """Find session using token_hint (fast) or fallback to full scan."""
        from user_auth.models import UserSessions

        now = timezone.now()

        # Fast path: use token_hint index
        hint = raw_token[:8]
        candidates = UserSessions.objects.filter(
            token_hint=hint,
            revoked=False,
            expires_at__gt=now,
        ).select_related("user")

        for session in candidates:
            if check_password(raw_token, session.token):
                return session

        # Fallback: old sessions without token_hint
        # (during migration period — remove after Phase 6)
        candidates = UserSessions.objects.filter(
            token_hint__isnull=True,
            revoked=False,
            expires_at__gt=now,
        ).select_related("user")

        for session in candidates:
            if check_password(raw_token, session.token):
                # Backfill token_hint for next time
                session.token_hint = hint
                session.save(update_fields=["token_hint"])
                return session

        return None

    def _get_role_info(self, user) -> dict:
        """Get primary role info for user."""
        from user_auth.models import UserRoles

        ur = (
            UserRoles.objects.filter(user=user)
            .select_related("role")
            .order_by("role__level")
            .first()
        )
        if not ur:
            return {"name": "none", "level": 99, "scope_level": "account"}
        return {
            "name": ur.role.name,
            "level": ur.role.level,
            "scope_level": ur.role.scope_level,
        }

    def _build_auth_context_from_db(self, user) -> AuthContext:
        """Slow path: resolve permissions + scope from DB."""
        from engine_auth.core.scope_resolver import (
            resolve_permissions,
            resolve_scope,
            resolve_role_info,
        )

        role_info = resolve_role_info(user)
        perms = resolve_permissions(user)
        scope = resolve_scope(user)

        return AuthContext(
            user_id=str(user.pk),
            email=user.email,
            role=role_info["name"],
            level=role_info["level"],
            scope_level=role_info["scope_level"],
            permissions=perms,
            org_ids=scope.get("org_ids"),
            tenant_ids=scope.get("tenant_ids"),
            account_ids=scope.get("account_ids"),
        )
