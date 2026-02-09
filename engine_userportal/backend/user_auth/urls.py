from django.urls import path
from user_auth.views.local_auth import LoginView, RefreshTokenView, LogoutView, csrf
from user_auth.views.saml_auth import SamlAcsView, SamlLogoutCallbackView
from user_auth.views.me_view import MeView
from djangosaml2.views import LoginView as SamlLoginView

urlpatterns = [
    path("csrf/", csrf, name="csrf"),
    path("me/", MeView.as_view(), name="me"),
    path("login/", LoginView.as_view(), name="login"),
    path("refresh/", RefreshTokenView.as_view(), name="refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("saml/login/", SamlLoginView.as_view(), name="saml_login"),
    path("saml/acs/", SamlAcsView.as_view(), name="saml_acs"),
    path("saml/acs/logout/", SamlLogoutCallbackView.as_view(), name="saml_logout_callback"),
]
