import uuid
from django.http import HttpResponseRedirect
from django.utils import timezone
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.utils.decorators import method_decorator
from djangosaml2.views import LogoutView
from djangosaml2.views import AssertionConsumerServiceView
from user_auth.models import Users, UserSessions
from user_auth.utils.auth_utils import generate_token, hash_token
from user_auth.utils.cookie_utils import set_auth_cookies,clear_auth_cookies
from django.shortcuts import redirect




@method_decorator(csrf_exempt, name='dispatch')
class SamlAcsView(AssertionConsumerServiceView):
    """
    Custom ACS view to handle SAML response and create our own session.
    """
    print("hii")
    def custom_create_user(self, email, sso_id, session_index):
        first_name = email.split('@')[0]
        last_name = ''
        return Users.objects.create(
            id=uuid.uuid4(),
            email=email,
            sso_provider='okta',
            sso_id=sso_id,
            name_first=first_name,
            name_last=last_name,
            status='active',
            created_at=timezone.now()
        )

    def post_login_hook(self, request, user, session_info):
        """Called after SAML validation"""
        saml_response = session_info.get('session_info', {})
        name_id = saml_response.get('name_id', {}).get('text', '').lower()
        session_index = saml_response.get('session_index')

        if not name_id:
            raise ValueError("Missing NameID in SAML response")

        email = name_id

        try:
            user_obj = Users.objects.get(email=email)
        except Users.DoesNotExist:
            user_obj = self.custom_create_user(email, sso_id=session_index, session_index=session_index)

        UserSessions.objects.filter(user=user_obj).delete()

        access_token = generate_token()
        refresh_token = generate_token()

        hashed_access = hash_token(access_token)
        hashed_refresh = hash_token(refresh_token)

        expires_at = timezone.now() + timezone.timedelta(hours=1)

        UserSessions.objects.create(
            id=uuid.uuid4(),
            user=user_obj,
            token=hashed_access,
            refresh_token=hashed_refresh,
            login_method='saml',
            session_index=session_index,
            expires_at=expires_at,
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )

        user_obj.last_login = timezone.now()
        user_obj.save(update_fields=['last_login'])

        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')
        response = HttpResponseRedirect(f"{frontend_url}/dashboard")
        set_auth_cookies(response, access_token, refresh_token)
        return response

    def post(self, request, *args, **kwargs):
        try:
            result = super().post(request, *args, **kwargs)
            if hasattr(request, 'session') and request.session.get('saml_session_info'):
                session_info = request.session['saml_session_info']
                user = None
                return self.post_login_hook(request, user, session_info)
            else:
                return HttpResponse("SAML validation failed", status=401)
        except Exception as e:
            print("SAML ACS Error:", str(e))
            return HttpResponse("SAML login failed", status=500)




@method_decorator(csrf_exempt, name='dispatch')
class SamlLogoutCallbackView(LogoutView):
    def get(self, request, *args, **kwargs):
        return self.post(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        name_id = request.POST.get('NameID') or request.GET.get('NameID')
        if name_id:
            try:
                user = Users.objects.get(email=name_id.lower())
                UserSessions.objects.filter(user=user).delete()
            except Users.DoesNotExist:
                pass

        frontend_url = getattr(settings, 'SAML_LOGOUT_REDIRECT_URL', settings.FRONTEND_URL)
        response = HttpResponse(f'<html><head><meta http-equiv="refresh" content="0;url={frontend_url}"></head></html>')
        clear_auth_cookies(response)
        return response