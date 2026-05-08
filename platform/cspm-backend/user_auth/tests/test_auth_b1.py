"""
Auth-B1 tests:
  - Email enumeration fix (duplicate email → 200 not 409)
  - Rate limiting (SignupRateThrottle, LoginRateThrottle)
  - hCaptcha skip when no secret key
  - hCaptcha failure returns 400
"""
import os
from unittest.mock import MagicMock, patch

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

from django.test import TestCase, RequestFactory, override_settings
from django.urls import reverse


class SignupEnumerationTest(TestCase):
    """BLOCK-01: duplicate email must return 200 with generic message, not 409."""

    @override_settings(ALLOW_LOCAL_SIGNUP=True, HCAPTCHA_SECRET_KEY="")
    def test_signup_duplicate_email_returns_200(self):
        from user_auth.models import Users
        from user_auth.views.local_auth import SignupView

        # Create user
        Users.objects.create_user(email="existing@test.com", password="testpass123")

        factory = RequestFactory()
        import json
        request = factory.post(
            "/api/auth/signup/",
            data=json.dumps({
                "email": "existing@test.com",
                "password": "Password123",
                "hcaptcha_token": "",
            }),
            content_type="application/json",
        )

        view = SignupView.as_view()
        with patch("user_auth.views.local_auth._ALLOW_LOCAL_SIGNUP", True):
            response = view(request)

        self.assertEqual(response.status_code, 200)
        import json as _json
        body = _json.loads(response.content)
        self.assertIn("verification email", body["message"])
        self.assertNotIn("already exists", body["message"])

    @override_settings(ALLOW_LOCAL_SIGNUP=True, HCAPTCHA_SECRET_KEY="test-secret")
    def test_hcaptcha_failure_returns_400(self):
        from user_auth.views.local_auth import SignupView
        import json

        factory = RequestFactory()
        request = factory.post(
            "/api/auth/signup/",
            data=json.dumps({
                "email": "new@test.com",
                "password": "Password123",
                "hcaptcha_token": "bad-token",
            }),
            content_type="application/json",
        )

        with patch("user_auth.views.local_auth._ALLOW_LOCAL_SIGNUP", True), \
             patch("user_auth.views.local_auth._verify_hcaptcha", return_value=False):
            view = SignupView.as_view()
            response = view(request)

        self.assertEqual(response.status_code, 400)
        body = json.loads(response.content)
        self.assertIn("CAPTCHA", body["message"])

    @override_settings(ALLOW_LOCAL_SIGNUP=True, HCAPTCHA_SECRET_KEY="")
    def test_hcaptcha_skip_when_no_secret(self):
        """When HCAPTCHA_SECRET_KEY is empty, signup proceeds without CAPTCHA."""
        from user_auth.views.local_auth import _verify_hcaptcha
        result = _verify_hcaptcha("any-token")
        self.assertTrue(result)


class ThrottleClassTest(TestCase):
    """BLOCK-02: throttle classes have correct scope/rate."""

    def test_signup_throttle_scope(self):
        from user_auth.throttles import SignupRateThrottle
        t = SignupRateThrottle()
        self.assertEqual(t.scope, "signup")

    def test_login_throttle_scope(self):
        from user_auth.throttles import LoginRateThrottle
        t = LoginRateThrottle()
        self.assertEqual(t.scope, "login")

    def test_throttles_applied_to_views(self):
        from user_auth.views.local_auth import SignupView, LoginView
        from user_auth.throttles import SignupRateThrottle, LoginRateThrottle
        self.assertIn(SignupRateThrottle, SignupView.throttle_classes)
        self.assertIn(LoginRateThrottle, LoginView.throttle_classes)

    def test_throttle_applied_to_password_reset(self):
        from user_auth.views.password_reset import PasswordResetRequestView
        from user_auth.throttles import SignupRateThrottle
        self.assertIn(SignupRateThrottle, PasswordResetRequestView.throttle_classes)
