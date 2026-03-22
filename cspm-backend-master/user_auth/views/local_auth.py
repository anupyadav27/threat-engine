import json
import uuid
from django.utils import timezone
from django.contrib.auth.hashers import check_password
from django.conf import settings
from datetime import timedelta

from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from user_auth.models import Users, UserSessions
from user_auth.utils.auth_utils import generate_token, hash_token, verify_token
from user_auth.utils.cookie_utils import set_auth_cookies, clear_auth_cookies
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_GET

@require_GET
@ensure_csrf_cookie
def csrf(request):
    return JsonResponse({"detail": "CSRF cookie set"})


@method_decorator(ensure_csrf_cookie, name='dispatch')
class LoginView(APIView):
    def post(self, request):
        # Parse JSON body
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"message": "Invalid JSON"}, status=400)

        email = data.get("email")
        password = data.get("password")
        remember_me = data.get("rememberMe", False)

        if not email or not password:
            return JsonResponse({"message": "Email and password are required."}, status=400)

        # Fetch user
        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            return JsonResponse({"message": "Invalid email or password."}, status=404)

        # Verify password
        if not user.password or not check_password(password, user.password):
            return JsonResponse({"message": "Invalid email or password."}, status=401)

        # Revoke all existing sessions for this user
        UserSessions.objects.filter(user=user).delete()

        # Generate raw tokens
        access_token = generate_token()
        refresh_token = generate_token() if remember_me else None

        # Hash tokens for secure storage
        hashed_access = hash_token(access_token)
        hashed_refresh = hash_token(refresh_token) if refresh_token else None

        # Calculate expiry
        expires_at = timezone.now() + (
            timedelta(days=getattr(settings, 'REFRESH_TOKEN_LIFETIME_DAYS', 1))
            if remember_me
            else timedelta(minutes=getattr(settings, 'ACCESS_TOKEN_LIFETIME_MINUTES', 60))
        )

        # Save session with hashed tokens
        UserSessions.objects.create(
            id=uuid.uuid4(),
            user=user,
            token=hashed_access,
            refresh_token=hashed_refresh,
            login_method="local",
            expires_at=expires_at,
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )

        # Update last login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        # Prepare response
        full_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
        response_data = {
            "message": "Login successful",
            "expiresIn": f"{getattr(settings, 'ACCESS_TOKEN_LIFETIME_MINUTES', 60)}m",
            "user": {
                "id": str(user.id),
                "email": user.email,
                "name": full_name,
                "roles": [],  # extend when role model exists
            },
        }

        response = JsonResponse(response_data)
        set_auth_cookies(response, access_token, refresh_token)
        response["Cache-Control"] = "no-store"
        return response

@method_decorator(ensure_csrf_cookie, name='dispatch')
class RefreshTokenView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")
        if not refresh_token:
            response = JsonResponse({"message": "No refresh token found"}, status=401)
            clear_auth_cookies(response)
            return response

        # Find session by hashed refresh token
        sessions = UserSessions.objects.filter(refresh_token__isnull=False)
        valid_session = None
        user = None

        for session in sessions:
            if verify_token(refresh_token, session.refresh_token):
                if session.expires_at < timezone.now():
                    session.delete()  # auto-cleanup expired
                    continue
                valid_session = session
                user = session.user
                break

        if not valid_session:
            response = JsonResponse({"message": "Invalid or expired refresh token"}, status=401)
            clear_auth_cookies(response)
            return response

        # Issue new access token
        new_access_token = generate_token()
        hashed_new_access = hash_token(new_access_token)

        valid_session.token = hashed_new_access
        valid_session.save(update_fields=["token"])

        response = JsonResponse({
            "message": "Access token refreshed successfully",
            "expiresIn": f"{getattr(settings, 'ACCESS_TOKEN_LIFETIME_MINUTES', 60)}m",
            "user": {
                "id": str(user.id),
                "email": user.email,
                "name": f"{user.first_name or ''} {user.last_name or ''}".strip(),
                "roles": [],
            },
        })
        set_auth_cookies(response, new_access_token)  # do NOT reissue refresh token
        return response

@method_decorator(ensure_csrf_cookie, name='dispatch')
class LogoutView(APIView):
    def post(self, request):
        access_token = request.COOKIES.get("access_token")
        refresh_token = request.COOKIES.get("refresh_token")

        user = None
        login_method = "local"
        deleted = False

        # Try to find session by access token
        if access_token:
            sessions = UserSessions.objects.filter(token__isnull=False)
            for session in sessions:
                if verify_token(access_token, session.token):
                    user = session.user
                    login_method = session.login_method
                    session.delete()
                    deleted = True
                    break

        # If not found, try refresh token
        if not deleted and refresh_token:
            sessions = UserSessions.objects.filter(refresh_token__isnull=False)
            for session in sessions:
                if verify_token(refresh_token, session.refresh_token):
                    user = session.user
                    login_method = session.login_method
                    session.delete()
                    deleted = True
                    break

        # TODO: Later, handle SAML SLO if login_method == "saml"

        response = JsonResponse({
            "message": "Logout successful",
            "sso": login_method == "saml"
        })

        clear_auth_cookies(response)
        return response