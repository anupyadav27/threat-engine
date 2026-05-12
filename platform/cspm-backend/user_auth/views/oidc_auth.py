"""
Generic OIDC 1.0 login + callback views.

Supports any OIDC-compliant IDP: Google, Okta, Entra ID, Cognito, Auth0, Keycloak, etc.
IDP config is loaded per-tenant from TenantIDPConfig (AUTH-01).
ID tokens are validated via JWKS — no reliance on the userinfo endpoint.
"""
import base64
import hashlib
import logging
import os
import secrets
import time
import uuid
from datetime import timedelta
from typing import Optional
from urllib.parse import urlencode

import requests as http_requests
from authlib.jose import JsonWebKey, JsonWebToken
from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.utils import timezone
from rest_framework.views import APIView

from tenant_management.models import TenantIDPConfig
from user_auth.models import Users, UserSessions
from user_auth.throttles import IDPCallbackRateThrottle
from user_auth.utils.auth_utils import compute_auth_caches, generate_token, hash_token
from user_auth.utils.audit_utils import log_auth_event
from user_auth.utils.cookie_utils import set_auth_cookies
from user_auth.utils.secrets_utils import get_idp_client_secret
from user_auth.utils.tenant_utils import accept_invite_membership, provision_tenant_for_new_user

logger = logging.getLogger(__name__)

_OIDC_CALLBACK_URL = os.getenv(
    "OIDC_CALLBACK_URL",
    "http://localhost:8000/api/auth/oidc/callback/",
)

_jwt_validator = JsonWebToken(["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"])

# Module-level caches: { url: {"doc": ..., "ts": float} }
_discovery_cache: dict = {}
_jwks_cache: dict = {}


def _cache_ttl() -> int:
    return getattr(settings, "OIDC_DISCOVERY_CACHE_TTL", 300)


def _get_discovery_doc(issuer: str) -> dict:
    """Fetch OIDC discovery document with TTL cache.

    Args:
        issuer: OIDC issuer URL (without trailing slash).

    Returns:
        Parsed discovery document dict.
    """
    entry = _discovery_cache.get(issuer)
    if entry and (time.time() - entry["ts"]) < _cache_ttl():
        return entry["doc"]
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    resp = http_requests.get(url, timeout=10)
    resp.raise_for_status()
    doc = resp.json()
    _discovery_cache[issuer] = {"doc": doc, "ts": time.time()}
    return doc


def _get_jwks(jwks_uri: str) -> dict:
    """Fetch JWKS with TTL cache.

    Args:
        jwks_uri: JWKS endpoint URI from discovery document.

    Returns:
        Raw JWKS dict (keys list).
    """
    entry = _jwks_cache.get(jwks_uri)
    if entry and (time.time() - entry["ts"]) < _cache_ttl():
        return entry["keys"]
    resp = http_requests.get(jwks_uri, timeout=10)
    resp.raise_for_status()
    keys = resp.json()
    _jwks_cache[jwks_uri] = {"keys": keys, "ts": time.time()}
    return keys


def _load_active_oidc_idp(tenant_id: str) -> Optional[TenantIDPConfig]:
    """Return the active OIDC or google_oauth TenantIDPConfig for a tenant."""
    return (
        TenantIDPConfig.objects.filter(
            tenant_id=tenant_id,
            idp_type__in=("oidc", "google_oauth"),
            is_active=True,
        )
        .select_related("tenant")
        .first()
    )


def _pkce_pair() -> tuple[str, str]:
    """Generate PKCE (code_verifier, code_challenge) pair using S256 method."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


class OIDCLoginView(APIView):
    """Redirect browser to IDP authorization URL for the given tenant.

    GET /api/auth/oidc/login/?tenant={tenant_id}&redirect_after=/dashboard
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        tenant_id = request.GET.get("tenant", "").strip()
        redirect_after = request.GET.get("redirect_after", "/dashboard")

        if not tenant_id:
            return JsonResponse({"message": "tenant query param is required"}, status=400)

        idp_config = _load_active_oidc_idp(tenant_id)
        if not idp_config:
            return JsonResponse(
                {"message": f"No active OIDC IDP configured for tenant {tenant_id}"},
                status=404,
            )

        config = idp_config.config
        try:
            discovery = _get_discovery_doc(config["issuer"])
        except Exception as exc:
            logger.error(f"OIDC discovery fetch failed for tenant {tenant_id}: {exc}")
            return JsonResponse({"message": "IDP discovery failed — check issuer URL"}, status=502)

        nonce = secrets.token_urlsafe(32)
        state = secrets.token_urlsafe(32)

        request.session["oidc_state"] = {
            "state": state,
            "nonce": nonce,
            "tenant_id": tenant_id,
            "redirect_after": redirect_after,
            "idp_config_id": str(idp_config.id),
        }

        params: dict = {
            "client_id": config["client_id"],
            "redirect_uri": _OIDC_CALLBACK_URL,
            "response_type": "code",
            "scope": " ".join(config.get("scopes", ["openid", "email", "profile"])),
            "state": state,
            "nonce": nonce,
        }

        if config.get("pkce", False):
            verifier, challenge = _pkce_pair()
            request.session["oidc_pkce_verifier"] = verifier
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"

        return HttpResponseRedirect(f"{discovery['authorization_endpoint']}?{urlencode(params)}")


class OIDCCallbackView(APIView):
    """Handle IDP redirect: validate state, exchange code, validate ID token, issue session.

    GET /api/auth/oidc/callback/?code=...&state=...
    """

    throttle_classes = [IDPCallbackRateThrottle]

    def get(self, request: HttpRequest) -> HttpResponse:
        frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000")

        session_state = request.session.pop("oidc_state", None)
        if not session_state or request.GET.get("state") != session_state.get("state"):
            logger.warning("OIDC state mismatch — possible CSRF attempt")
            return JsonResponse({"message": "State mismatch — request rejected"}, status=400)

        error = request.GET.get("error")
        code = request.GET.get("code")
        if error or not code:
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=oidc_cancelled")

        redirect_after = session_state.get("redirect_after", "/dashboard")

        try:
            idp_config = TenantIDPConfig.objects.get(
                id=session_state["idp_config_id"], is_active=True
            )
        except TenantIDPConfig.DoesNotExist:
            return JsonResponse({"message": "IDP config no longer active"}, status=400)

        config = idp_config.config

        try:
            discovery = _get_discovery_doc(config["issuer"])
        except Exception as exc:
            logger.error(f"OIDC discovery fetch failed at callback: {exc}")
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=oidc_failed")

        # Exchange code for tokens
        token_params: dict = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": _OIDC_CALLBACK_URL,
            "client_id": config["client_id"],
            "client_secret": get_idp_client_secret(config["client_secret_ref"]),
        }
        pkce_verifier = request.session.pop("oidc_pkce_verifier", None)
        if pkce_verifier:
            token_params["code_verifier"] = pkce_verifier

        try:
            token_resp = http_requests.post(
                discovery["token_endpoint"], data=token_params, timeout=15
            )
            token_resp.raise_for_status()
            token_data = token_resp.json()
        except Exception as exc:
            logger.error(f"OIDC token exchange failed: {exc}")
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=oidc_failed")

        id_token = token_data.get("id_token")
        if not id_token:
            logger.error("OIDC token response missing id_token")
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=oidc_failed")

        # Validate ID token via JWKS
        try:
            jwks_data = _get_jwks(discovery["jwks_uri"])
            key_set = JsonWebKey.import_key_set(jwks_data)
            claims = _jwt_validator.decode(id_token, key_set)
            claims.validate()
        except Exception as exc:
            logger.error(f"OIDC ID token validation failed: {exc}")
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=oidc_invalid_token")

        mapping = config.get("claims_mapping", {
            "email": "email",
            "first_name": "given_name",
            "last_name": "family_name",
        })

        email = (claims.get(mapping.get("email", "email")) or "").lower()
        if not email:
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=oidc_no_email")

        sub = claims.get("sub", "")
        first_name = claims.get(mapping.get("first_name", "given_name"), "")
        last_name = claims.get(mapping.get("last_name", "family_name"), "")

        # Upsert user
        is_new_user = False
        try:
            user = Users.objects.get(email=email)
            if not user.sso_provider:
                user.sso_provider = "oidc"
                user.sso_id = sub
                user.save(update_fields=["sso_provider", "sso_id"])
        except Users.DoesNotExist:
            is_new_user = True
            user = Users.objects.create_user(
                email=email,
                first_name=first_name,
                last_name=last_name,
                status="active",
                sso_provider="oidc",
                sso_id=sub,
            )
            provision_tenant_for_new_user(user)

        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        # Consume pending invite token if SSO was triggered from an invite link
        pending_invite = request.session.pop("pending_invite_token", None)
        if pending_invite:
            try:
                from user_auth.models import InviteTokens
                invite = InviteTokens.objects.select_related("tenant", "role").get(
                    token=pending_invite, used=False
                )
                if invite.expires_at >= timezone.now() and invite.email == email:
                    accept_invite_membership(user, invite)
                    log_auth_event(
                        "invite.accept",
                        request=request,
                        user=user,
                        tenant_id=str(invite.tenant_id),
                        extra={"method": f"oidc:{idp_config.idp_name}"},
                    )
            except Exception as exc:
                logger.warning("OIDC: failed to consume pending invite: %s", exc)

        log_auth_event(
            "login.oidc",
            request=request,
            user=user,
            extra={"idp_name": idp_config.idp_name, "new_user": is_new_user},
        )

        # Issue session
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
            login_method=f"oidc:{idp_config.idp_name}",
            expires_at=expires_at,
            ip_address=request.META.get("REMOTE_ADDR", ""),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            token_hint=access_token[:8],
            permissions_cache=permissions_cache,
            scope_cache=scope_cache,
        )

        response = HttpResponseRedirect(f"{frontend_url}{redirect_after}")
        set_auth_cookies(response, access_token, refresh_token)
        if is_new_user:
            response.set_cookie("onboarding_pending", "1", max_age=3600, httponly=True, samesite="Lax")  # WARN-04
        return response
