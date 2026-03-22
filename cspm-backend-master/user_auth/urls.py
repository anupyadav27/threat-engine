from django.urls import path
from djangosaml2 import views as saml2_views

from user_auth.views.local_auth import LoginView, RefreshTokenView, LogoutView, csrf
from user_auth.views.saml_auth import SamlSuccessBridgeView

urlpatterns = [
    path("csrf/", csrf, name="csrf"),
    path('login/', LoginView.as_view(), name='login'),
    path('refresh/', RefreshTokenView.as_view(), name='refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),

    path('saml/login/', saml2_views.LoginView.as_view(), name='saml_login'),

    path('saml/acs/', saml2_views.AssertionConsumerServiceView.as_view(), name='saml_acs'),

    path('saml/acs/logout/', saml2_views.LogoutView.as_view(), name='saml_logout'),

    path('saml/metadata/', saml2_views.MetadataView.as_view(), name='saml_metadata'),

    path('saml/success/', SamlSuccessBridgeView.as_view(), name='saml_success'),
]