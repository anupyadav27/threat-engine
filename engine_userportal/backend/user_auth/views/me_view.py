"""
GET /api/auth/me — current user, roles, allowed scope, capabilities.
Requires CookieTokenAuthentication.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from user_auth.auth import CookieTokenAuthentication
from user_auth.utils.scope_utils import get_allowed_scope


class MeView(APIView):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = []  # auth only; no extra permission

    def get(self, request):
        user = getattr(request, "user", None)
        if not user or not getattr(user, "pk", None):
            return Response(
                {"detail": "Authentication required"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        scope = get_allowed_scope(user)
        full_name = f"{getattr(user, 'name_first') or ''} {getattr(user, 'name_last') or ''}".strip()
        payload = {
            "user": {
                "id": str(user.id),
                "email": getattr(user, "email", ""),
                "name": full_name or getattr(user, "email", ""),
            },
            "roles": scope.get("roles") or [],
            "allowed_tenant_ids": scope.get("allowed_tenant_ids"),
            "allowed_customer_ids": scope.get("allowed_customer_ids"),
            "is_super_landlord": scope.get("is_super_landlord", False),
            "capabilities": scope.get("capabilities") or [],
        }
        return Response(payload)
