"""
Password reset flow:
  POST /api/auth/password-reset/request/   — send reset email (public)
  POST /api/auth/password-reset/confirm/   — set new password with token (public)
"""
import json
import secrets
import uuid
from datetime import timedelta

from django.http import JsonResponse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework.views import APIView

from user_auth.models import Users, PasswordResetTokens, UserSessions
from user_auth.utils.email_utils import send_password_reset_email


@method_decorator(ensure_csrf_cookie, name='dispatch')
class PasswordResetRequestView(APIView):
    """Accepts an email, sends a reset link if account exists. Always 200 to avoid email enumeration."""

    def post(self, request):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"message": "Invalid JSON"}, status=400)

        email = (data.get("email") or "").strip().lower()
        if not email:
            return JsonResponse({"message": "Email is required"}, status=400)

        # Always return 200 — don't reveal whether email exists
        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            return JsonResponse({"message": "If that email is registered, a reset link has been sent."})

        # Invalidate any existing unused tokens
        PasswordResetTokens.objects.filter(user=user, used=False).update(used=True)

        token = secrets.token_urlsafe(32)
        PasswordResetTokens.objects.create(
            id=str(uuid.uuid4()),
            token=token,
            user=user,
            expires_at=timezone.now() + timedelta(hours=1),
        )

        send_password_reset_email(email, token)

        return JsonResponse({"message": "If that email is registered, a reset link has been sent."})


@method_decorator(ensure_csrf_cookie, name='dispatch')
class PasswordResetConfirmView(APIView):
    """Validates token + sets new password."""

    def post(self, request):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"message": "Invalid JSON"}, status=400)

        token = (data.get("token") or "").strip()
        new_password = data.get("password") or data.get("new_password") or ""

        if not token or not new_password:
            return JsonResponse({"message": "Token and new password are required"}, status=400)

        if len(new_password) < 8:
            return JsonResponse({"message": "Password must be at least 8 characters"}, status=400)

        try:
            reset = PasswordResetTokens.objects.select_related('user').get(token=token)
        except PasswordResetTokens.DoesNotExist:
            return JsonResponse({"message": "Invalid or expired reset link"}, status=400)

        if reset.used:
            return JsonResponse({"message": "This reset link has already been used"}, status=410)

        if reset.expires_at < timezone.now():
            return JsonResponse({"message": "This reset link has expired"}, status=410)

        user = reset.user
        user.set_password(new_password)
        user.save(update_fields=["password"])

        reset.used = True
        reset.save(update_fields=["used"])

        # Revoke all sessions (security: force re-login everywhere)
        UserSessions.objects.filter(user=user).delete()

        return JsonResponse({"message": "Password updated. Please sign in with your new password."})
