"""
Multi-tenant SAML 2.0 views using python3-saml (OneLogin library).

Routes are per-tenant: /api/auth/saml/{tenant_id}/login|acs|metadata|logout
IDP config is read from TenantIDPConfig (AUTH-01) at request time — no global SAML_CONFIG.
SP cert/key are stored per-tenant in AWS Secrets Manager.
"""
import logging
import uuid
from datetime import timedelta
from typing import Optional

from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.views import APIView

from tenant_management.models import TenantIDPConfig
from user_auth.models import Users, UserSessions
from user_auth.utils.audit_utils import log_auth_event
from user_auth.utils.auth_utils import compute_auth_caches, generate_token, hash_token
from user_auth.utils.cookie_utils import set_auth_cookies
from user_auth.utils.saml_utils import build_saml_settings, prepare_django_request
from user_auth.utils.secrets_utils import get_saml_sp_cert, get_saml_sp_key
from user_auth.utils.tenant_utils import provision_first_tenant

logger = logging.getLogger(__name__)


def _load_saml_idp(tenant_id: str) -> Optional[TenantIDPConfig]:
    """Return the active SAML TenantIDPConfig for a tenant."""
    return (
        TenantIDPConfig.objects.filter(
            tenant_id=tenant_id,
            idp_type="saml",
            is_active=True,
        )
        .select_related("tenant")
        .first()
    )


def _build_auth(request: HttpRequest, idp_config: TenantIDPConfig):
    """Instantiate OneLogin_Saml2_Auth from TenantIDPConfig and Secrets Manager certs."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    tenant_id = str(idp_config.tenant_id)
    sp_cert = get_saml_sp_cert(tenant_id) or ""
    sp_key = get_saml_sp_key(tenant_id) or ""

    saml_settings = build_saml_settings(idp_config.config, sp_cert, sp_key)
    req = prepare_django_request(request)
    return OneLogin_Saml2_Auth(req, saml_settings)


def _issue_session(
    request: HttpRequest, user: Users, idp_name: str
) -> tuple[str, str]:
    """Revoke existing sessions and create a new one. Returns (access_token, refresh_token)."""
    UserSessions.objects.filter(user=user).delete()
    access_token = generate_token()
    refresh_token = generate_token()
    expires_at = timezone.now() + timedelta(
        days=getattr(settings, "REFRESH_TOKEN_LIFETIME_DAYS", 7)
    )
    permissions_cache, scope_cache = compute_auth_caches(user)
    UserSessions.objects.create(
        id=uuid.uuid4(),
        user=user,
        token=hash_token(access_token),
        refresh_token=hash_token(refresh_token),
        login_method=f"saml:{idp_name}",
        expires_at=expires_at,
        ip_address=request.META.get("REMOTE_ADDR", ""),
        user_agent=request.META.get("HTTP_USER_AGENT", ""),
        token_hint=access_token[:8],
        permissions_cache=permissions_cache,
        scope_cache=scope_cache,
    )
    return access_token, refresh_token


class SAMLLoginView(APIView):
    """Redirect user to IDP SSO URL.

    GET /api/auth/saml/{tenant_id}/login/
    """

    def get(self, request: HttpRequest, tenant_id: str) -> HttpResponse:
        frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000")

        idp_config = _load_saml_idp(tenant_id)
        if not idp_config:
            return JsonResponse(
                {"message": f"No active SAML IDP for tenant {tenant_id}"},
                status=404,
            )

        try:
            auth = _build_auth(request, idp_config)
            return HttpResponseRedirect(auth.login())
        except Exception as exc:
            logger.error(f"SAML login failed for tenant {tenant_id}: {exc}")
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=saml_failed")


@method_decorator(csrf_exempt, name="dispatch")
class SAMLACSView(APIView):
    """Assertion Consumer Service — processes IDP POST response.

    POST /api/auth/saml/{tenant_id}/acs/
    """

    def post(self, request: HttpRequest, tenant_id: str) -> HttpResponse:
        frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000")

        idp_config = _load_saml_idp(tenant_id)
        if not idp_config:
            return JsonResponse(
                {"message": f"No active SAML IDP for tenant {tenant_id}"},
                status=404,
            )

        try:
            auth = _build_auth(request, idp_config)
            auth.process_response()
        except Exception as exc:
            logger.error(f"SAML ACS processing error for tenant {tenant_id}: {exc}")
            return JsonResponse({"message": "SAML processing error"}, status=400)

        errors = auth.get_errors()
        if errors:
            logger.warning(f"SAML assertion errors for tenant {tenant_id}: {errors}")
            return JsonResponse({"message": "Invalid SAML assertion", "errors": errors}, status=400)

        config = idp_config.config
        attr_mapping = config.get("attribute_mapping", {})

        # Get email from NameID or mapped attribute
        email_attr = attr_mapping.get("email", "")
        if email_attr:
            attrs = auth.get_attributes()
            email_vals = attrs.get(email_attr, [])
            email = (email_vals[0] if email_vals else "").lower()
        else:
            email = (auth.get_nameid() or "").lower()

        if not email:
            return JsonResponse({"message": "Could not extract email from SAML response"}, status=400)

        attrs = auth.get_attributes()

        def _attr(key: str) -> str:
            mapped = attr_mapping.get(key, key)
            vals = attrs.get(mapped, [])
            return vals[0] if vals else ""

        first_name = _attr("first_name")
        last_name = _attr("last_name")

        # Upsert user
        is_new_user = False
        try:
            user = Users.objects.get(email=email)
            if not user.sso_provider:
                user.sso_provider = "saml"
                user.sso_id = email
                user.save(update_fields=["sso_provider", "sso_id"])
        except Users.DoesNotExist:
            is_new_user = True
            user = Users.objects.create_user(
                email=email,
                first_name=first_name,
                last_name=last_name,
                status="active",
                sso_provider="saml",
                sso_id=email,
            )
            provision_first_tenant(user)

        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        # Consume pending invite token if SSO was triggered from an invite link
        pending_invite = request.session.pop("pending_invite_token", None)
        if pending_invite:
            try:
                from user_auth.models import InviteTokens
                from tenant_management.models import TenantUsers
                from user_auth.utils.tenant_utils import get_or_create_admin_role
                invite = InviteTokens.objects.select_related("tenant", "role").get(
                    token=pending_invite, used=False
                )
                if invite.expires_at >= timezone.now() and invite.email == email:
                    if not TenantUsers.objects.filter(user=user, tenant=invite.tenant).exists():
                        role = invite.role or get_or_create_admin_role()
                        TenantUsers.objects.create(
                            id=uuid.uuid4(),
                            tenant=invite.tenant,
                            user=user,
                            role=role,
                            is_active=True,
                        )
                    invite.used = True
                    invite.save(update_fields=["used"])
                    log_auth_event(
                        "invite.accept",
                        request=request,
                        user=user,
                        tenant_id=str(invite.tenant_id),
                        extra={"method": f"saml:{idp_config.idp_name}"},
                    )
            except Exception as exc:
                logger.warning("SAML ACS: failed to consume pending invite: %s", exc)

        log_auth_event(
            "login.saml",
            request=request,
            user=user,
            tenant_id=tenant_id,
            extra={"idp_name": idp_config.idp_name, "new_user": is_new_user},
        )

        access_token, refresh_token = _issue_session(request, user, idp_config.idp_name)
        response = HttpResponseRedirect(f"{frontend_url}/dashboard")
        set_auth_cookies(response, access_token, refresh_token)
        if is_new_user:
            response.set_cookie("onboarding_pending", "1", max_age=3600, httponly=True, samesite="Lax")  # WARN-04
        return response


class SAMLMetadataView(APIView):
    """Return SP metadata XML for this tenant.

    Tenant admin shares this URL with their IDP admin.
    GET /api/auth/saml/{tenant_id}/metadata/
    """

    def get(self, request: HttpRequest, tenant_id: str) -> HttpResponse:
        idp_config = _load_saml_idp(tenant_id)
        if not idp_config:
            return JsonResponse(
                {"message": f"No active SAML IDP for tenant {tenant_id}"},
                status=404,
            )

        try:
            from onelogin.saml2.settings import OneLogin_Saml2_Settings

            tenant_id_str = str(idp_config.tenant_id)
            sp_cert = get_saml_sp_cert(tenant_id_str) or ""
            sp_key = get_saml_sp_key(tenant_id_str) or ""
            saml_settings_dict = build_saml_settings(idp_config.config, sp_cert, sp_key)
            saml_settings = OneLogin_Saml2_Settings(settings=saml_settings_dict, sp_validation_only=True)
            metadata = saml_settings.get_sp_metadata()
            errors = saml_settings.validate_metadata(metadata)
            if errors:
                logger.warning(f"SP metadata validation errors for tenant {tenant_id}: {errors}")
        except Exception as exc:
            logger.error(f"SP metadata generation failed for tenant {tenant_id}: {exc}")
            return JsonResponse({"message": "Metadata generation failed"}, status=500)

        return HttpResponse(metadata, content_type="text/xml")


@method_decorator(csrf_exempt, name="dispatch")
class SAMLLogoutView(APIView):
    """Handle SAML Single Logout (SLO).

    GET /api/auth/saml/{tenant_id}/logout/
    """

    def get(self, request: HttpRequest, tenant_id: str) -> HttpResponse:
        frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000")

        access_token = request.COOKIES.get("access_token")
        if access_token:
            from user_auth.utils.auth_utils import verify_token
            sessions = UserSessions.objects.filter(revoked=False)
            for session in sessions:
                if verify_token(access_token, session.token):
                    session.delete()
                    break

        from user_auth.utils.cookie_utils import clear_auth_cookies
        response = HttpResponseRedirect(f"{frontend_url}/auth/login")
        clear_auth_cookies(response)
        return response
