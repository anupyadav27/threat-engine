from django.urls import path
from djangosaml2 import views as saml2_views

from user_auth.views.local_auth import LoginView, SignupView, MeView, RefreshTokenView, LogoutView, csrf
from user_auth.views.saml_auth import SamlSuccessBridgeView
from user_auth.views.google_auth import GoogleLoginView, GoogleCallbackView
from user_auth.views.invite import CreateInviteView, ValidateInviteView, AcceptInviteView
from user_auth.views.password_reset import PasswordResetRequestView, PasswordResetConfirmView

urlpatterns = [
    # ── CSRF ────────────────────────────────────────────────────────────────
    path("csrf/", csrf, name="csrf"),

    # ── Local email+password auth ────────────────────────────────────────────
    path("login/", LoginView.as_view(), name="login"),
    path("signup/", SignupView.as_view(), name="signup"),
    path("me/", MeView.as_view(), name="me"),
    path("refresh/", RefreshTokenView.as_view(), name="refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),

    # ── Google OAuth ─────────────────────────────────────────────────────────
    path("google/login/", GoogleLoginView.as_view(), name="google_login"),
    path("google/callback/", GoogleCallbackView.as_view(), name="google_callback"),

    # ── SAML / Okta SSO ──────────────────────────────────────────────────────
    path("saml/login/", saml2_views.LoginView.as_view(), name="saml_login"),
    path("saml/acs/", saml2_views.AssertionConsumerServiceView.as_view(), name="saml_acs"),
    path("saml/acs/logout/", saml2_views.LogoutView.as_view(), name="saml_logout"),
    path("saml/metadata/", saml2_views.MetadataView.as_view(), name="saml_metadata"),
    path("saml/success/", SamlSuccessBridgeView.as_view(), name="saml_success"),

    # ── Invite flow ───────────────────────────────────────────────────────────
    path("invite/create/", CreateInviteView.as_view(), name="invite_create"),
    path("invite/<str:token>/", ValidateInviteView.as_view(), name="invite_validate"),
    path("invite/<str:token>/accept/", AcceptInviteView.as_view(), name="invite_accept"),

    # ── Password reset ────────────────────────────────────────────────────────
    path("password-reset/request/", PasswordResetRequestView.as_view(), name="password_reset_request"),
    path("password-reset/confirm/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
]
