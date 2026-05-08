from django.urls import path

from user_auth.views.local_auth import (
    LoginView, SignupView, MeView, RefreshTokenView, LogoutView,
    csrf, ChangePasswordView, UserListView,
)
from user_auth.views.google_auth import GoogleLoginView, GoogleCallbackView
from user_auth.views.microsoft_auth import MicrosoftLoginView, MicrosoftCallbackView
from user_auth.views.oidc_auth import OIDCLoginView, OIDCCallbackView
from user_auth.views.saml_auth import (
    SAMLLoginView, SAMLACSView, SAMLMetadataView, SAMLLogoutView,
)
from user_auth.views.invite import ValidateInviteView, AcceptInviteView, InviteSSORedirectView
from user_auth.views.password_reset import PasswordResetRequestView, PasswordResetConfirmView
from user_auth.views.account_access import UserAccountAccessView

urlpatterns = [
    # ── CSRF ────────────────────────────────────────────────────────────────
    path("csrf/", csrf, name="csrf"),

    # ── Local email+password auth (break-glass only in prod) ─────────────────
    path("login/", LoginView.as_view(), name="login"),
    path("signup/", SignupView.as_view(), name="signup"),
    path("me/", MeView.as_view(), name="me"),
    path("refresh/", RefreshTokenView.as_view(), name="refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),

    # ── Google OAuth ──────────────────────────────────────────────────────────
    # Supports ?hd=domain.com for workspace SSO routing
    path("google/login/", GoogleLoginView.as_view(), name="google_login"),
    path("google/callback/", GoogleCallbackView.as_view(), name="google_callback"),

    # ── Microsoft OIDC (Azure AD multi-tenant) ────────────────────────────────
    # One registration covers all Azure AD orgs + hybrid on-prem AD
    # Supports ?domain_hint=domain.com for SSO routing
    path("microsoft/login/", MicrosoftLoginView.as_view(), name="microsoft_login"),
    path("microsoft/callback/", MicrosoftCallbackView.as_view(), name="microsoft_callback"),

    # ── Generic OIDC (any IDP) ───────────────────────────────────────────────
    path("oidc/login/", OIDCLoginView.as_view(), name="oidc_login"),
    path("oidc/callback/", OIDCCallbackView.as_view(), name="oidc_callback"),

    # ── SAML 2.0 per-tenant ───────────────────────────────────────────────────
    path("saml/<str:tenant_id>/login/", SAMLLoginView.as_view(), name="saml_login"),
    path("saml/<str:tenant_id>/acs/", SAMLACSView.as_view(), name="saml_acs"),
    path("saml/<str:tenant_id>/metadata/", SAMLMetadataView.as_view(), name="saml_metadata"),
    path("saml/<str:tenant_id>/logout/", SAMLLogoutView.as_view(), name="saml_logout"),

    # ── Invite flow ───────────────────────────────────────────────────────────
    # POST invite/create/ removed — BILL-S07. Use /gateway/api/v1/invites/ instead.
    path("invite/<str:token>/", ValidateInviteView.as_view(), name="invite_validate"),
    path("invite/<str:token>/sso/", InviteSSORedirectView.as_view(), name="invite_sso"),
    path("invite/<str:token>/accept/", AcceptInviteView.as_view(), name="invite_accept"),

    # ── Password reset ────────────────────────────────────────────────────────
    path("password-reset/request/", PasswordResetRequestView.as_view(), name="password_reset_request"),
    path("password-reset/confirm/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),

    # ── Authenticated account management ──────────────────────────────────────
    path("change-password/", ChangePasswordView.as_view(), name="change_password"),
    path("users/", UserListView.as_view(), name="user_list"),
    path("users/<str:user_id>/accounts/", UserAccountAccessView.as_view(), name="user_account_access"),
]
