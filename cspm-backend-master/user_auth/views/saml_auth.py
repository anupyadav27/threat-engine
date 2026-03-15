import uuid
from django.conf import settings
from django.utils import timezone
from django.http import HttpResponseRedirect
from rest_framework.views import APIView
from user_auth.models import UserSessions
from user_auth.utils.auth_utils import generate_token, hash_token
from user_auth.utils.cookie_utils import set_auth_cookies


class SamlSuccessBridgeView(APIView):
    def get(self, request):
        if not request.user.is_authenticated:
            frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=saml_failed")

        user_obj = request.user

        if user_obj.sso_provider != 'okta':
            user_obj.sso_provider = 'okta'
            user_obj.status = 'active'

        user_obj.last_login = timezone.now()
        user_obj.save(update_fields=['sso_provider', 'status', 'last_login'])

        UserSessions.objects.filter(user=user_obj).delete()

        access_token = generate_token()
        refresh_token = generate_token()
        hashed_access = hash_token(access_token)
        hashed_refresh = hash_token(refresh_token)

        expires_at = timezone.now() + timezone.timedelta(
            minutes=getattr(settings, 'ACCESS_TOKEN_LIFETIME_MINUTES', 60)
        )

        UserSessions.objects.create(
            id=uuid.uuid4(),
            user=user_obj,
            token=hashed_access,
            refresh_token=hashed_refresh,
            login_method='saml',
            expires_at=expires_at,
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )

        request.session.flush()

        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')
        response = HttpResponseRedirect(f"{frontend_url}/dashboard")
        set_auth_cookies(response, access_token, refresh_token)

        return response