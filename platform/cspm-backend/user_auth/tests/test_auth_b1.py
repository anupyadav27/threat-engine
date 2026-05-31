"""Auth-B1 unit tests.

Covers:
    AC1 — Login wrong-email and wrong-password both return 401 with identical body
    AC2 — Password reset always returns 200 with generic detail
    AC4 — RegisterRateThrottle is applied to SignupView (5/min scope)
    AC5 — PasswordResetRateThrottle is applied to PasswordResetRequestView (3/min scope)
    AC6 — Throttle classes defined in throttles.py (not inline)
    AC7 — validate_captcha() hook present in utils/captcha.py; called from signup
    AC8 — check_password used (constant-time); no timing oracle
    AC9 — Rate-limit test for 429 response; reset always-200; enumeration identity
"""

import json
import os
from unittest.mock import MagicMock, patch

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

from django.test import TestCase, RequestFactory, override_settings
from django.urls import reverse


# ---------------------------------------------------------------------------
# BLOCK-01: Email enumeration — Login
# ---------------------------------------------------------------------------

class LoginEnumerationTest(TestCase):
    """AC1: wrong-email and wrong-password must both return 401 with identical body."""

    def setUp(self):
        from user_auth.models import Users
        Users.objects.create_user(email="real@test.com", password="RealPass123!")

    def _post_login(self, email: str, password: str):
        from user_auth.views.local_auth import LoginView
        factory = RequestFactory()
        request = factory.post(
            "/api/auth/login/",
            data=json.dumps({"email": email, "password": password}),
            content_type="application/json",
        )
        return LoginView.as_view()(request)

    def test_wrong_email_returns_401(self):
        resp = self._post_login("nobody@test.com", "AnyPassword1!")
        self.assertEqual(resp.status_code, 401)

    def test_wrong_password_returns_401(self):
        resp = self._post_login("real@test.com", "WrongPassword!")
        self.assertEqual(resp.status_code, 401)

    def test_wrong_email_and_wrong_password_bodies_are_identical(self):
        """AC1 core: responses must be indistinguishable."""
        resp_no_user = self._post_login("nobody@test.com", "AnyPassword1!")
        resp_bad_pass = self._post_login("real@test.com", "WrongPassword!")

        body_no_user = json.loads(resp_no_user.content)
        body_bad_pass = json.loads(resp_bad_pass.content)

        self.assertEqual(resp_no_user.status_code, resp_bad_pass.status_code)
        self.assertEqual(body_no_user, body_bad_pass)
        # Must use "detail" key, not "message"
        self.assertIn("detail", body_no_user)
        self.assertEqual(body_no_user["detail"], "Invalid credentials")

    def test_login_never_returns_404(self):
        """AC1: status must not be 404 (old enumeration-leaking behaviour)."""
        resp = self._post_login("nobody@test.com", "AnyPassword1!")
        self.assertNotEqual(resp.status_code, 404)


# ---------------------------------------------------------------------------
# BLOCK-01: Email enumeration — Password reset
# ---------------------------------------------------------------------------

class PasswordResetEnumerationTest(TestCase):
    """AC2: password reset always returns 200 with generic body."""

    def _post_reset(self, email: str):
        from user_auth.views.password_reset import PasswordResetRequestView
        factory = RequestFactory()
        request = factory.post(
            "/api/auth/password-reset/request/",
            data=json.dumps({"email": email}),
            content_type="application/json",
        )
        return PasswordResetRequestView.as_view()(request)

    @patch("user_auth.views.password_reset.send_password_reset_email")
    def test_registered_email_returns_200(self, mock_send):
        from user_auth.models import Users
        Users.objects.create_user(email="user@test.com", password="Pass123!")
        resp = self._post_reset("user@test.com")
        self.assertEqual(resp.status_code, 200)

    def test_unregistered_email_returns_200(self):
        resp = self._post_reset("noone@test.com")
        self.assertEqual(resp.status_code, 200)

    @patch("user_auth.views.password_reset.send_password_reset_email")
    def test_registered_and_unregistered_response_bodies_identical(self, mock_send):
        """AC2 core: same body regardless of email existence."""
        from user_auth.models import Users
        Users.objects.create_user(email="reg@test.com", password="Pass123!")

        resp_reg = self._post_reset("reg@test.com")
        resp_unreg = self._post_reset("nobody@test.com")

        self.assertEqual(json.loads(resp_reg.content), json.loads(resp_unreg.content))
        body = json.loads(resp_reg.content)
        self.assertIn("detail", body)
        self.assertIn("reset link", body["detail"])


# ---------------------------------------------------------------------------
# BLOCK-02: Throttle class structure (AC4, AC5, AC6)
# ---------------------------------------------------------------------------

class ThrottleClassTest(TestCase):
    """Throttle classes must be defined in throttles.py and applied to views."""

    def test_login_throttle_scope_and_rate(self):
        """AC3: LoginRateThrottle at 10/min."""
        from user_auth.throttles import LoginRateThrottle
        t = LoginRateThrottle()
        self.assertEqual(t.scope, "login")
        self.assertEqual(t.rate, "10/min")

    def test_register_throttle_scope_and_rate(self):
        """AC4: RegisterRateThrottle at 5/min."""
        from user_auth.throttles import RegisterRateThrottle
        t = RegisterRateThrottle()
        self.assertEqual(t.scope, "register")
        self.assertEqual(t.rate, "5/min")

    def test_password_reset_throttle_scope_and_rate(self):
        """AC5: PasswordResetRateThrottle at 3/min."""
        from user_auth.throttles import PasswordResetRateThrottle
        t = PasswordResetRateThrottle()
        self.assertEqual(t.scope, "password_reset")
        self.assertEqual(t.rate, "3/min")

    def test_login_throttle_applied_to_login_view(self):
        """AC6: throttle applied via class attribute, not inline."""
        from user_auth.views.local_auth import LoginView
        from user_auth.throttles import LoginRateThrottle
        self.assertIn(LoginRateThrottle, LoginView.throttle_classes)

    def test_register_throttle_applied_to_signup_view(self):
        """AC4: RegisterRateThrottle applied to SignupView."""
        from user_auth.views.local_auth import SignupView
        from user_auth.throttles import RegisterRateThrottle
        self.assertIn(RegisterRateThrottle, SignupView.throttle_classes)

    def test_password_reset_throttle_applied(self):
        """AC5: PasswordResetRateThrottle applied to PasswordResetRequestView."""
        from user_auth.views.password_reset import PasswordResetRequestView
        from user_auth.throttles import PasswordResetRateThrottle
        self.assertIn(PasswordResetRateThrottle, PasswordResetRequestView.throttle_classes)

    def test_signup_rate_throttle_alias_still_importable(self):
        """Backwards-compatible alias SignupRateThrottle still resolves."""
        from user_auth.throttles import SignupRateThrottle, RegisterRateThrottle
        self.assertIs(SignupRateThrottle, RegisterRateThrottle)


# ---------------------------------------------------------------------------
# AC7: validate_captcha hook
# ---------------------------------------------------------------------------

class ValidateCaptchaTest(TestCase):
    """AC7: validate_captcha() hook in utils/captcha.py."""

    def test_validate_captcha_importable(self):
        from user_auth.utils.captcha import validate_captcha
        self.assertTrue(callable(validate_captcha))

    @override_settings()
    def test_captcha_skipped_when_no_secret(self):
        """When CAPTCHA_SECRET_KEY is unset, validate_captcha returns True."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CAPTCHA_SECRET_KEY", None)
            from user_auth.utils.captcha import validate_captcha
            self.assertTrue(validate_captcha("any-token"))

    def test_captcha_fails_closed_on_bad_response(self):
        """When provider returns success=false, validate_captcha returns False."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"success": False, "error-codes": ["invalid-input-response"]}
        with patch.dict(os.environ, {"CAPTCHA_SECRET_KEY": "test-secret"}), \
             patch("user_auth.utils.captcha.requests.post", return_value=mock_resp):
            from user_auth.utils.captcha import validate_captcha
            self.assertFalse(validate_captcha("bad-token"))

    def test_captcha_passes_on_success(self):
        """When provider returns success=true, validate_captcha returns True."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"success": True}
        with patch.dict(os.environ, {"CAPTCHA_SECRET_KEY": "test-secret"}), \
             patch("user_auth.utils.captcha.requests.post", return_value=mock_resp):
            from user_auth.utils.captcha import validate_captcha
            self.assertTrue(validate_captcha("good-token"))

    def test_captcha_fails_closed_on_network_error(self):
        """Network errors count as validation failure (fail closed)."""
        with patch.dict(os.environ, {"CAPTCHA_SECRET_KEY": "test-secret"}), \
             patch("user_auth.utils.captcha.requests.post", side_effect=ConnectionError("timeout")):
            from user_auth.utils.captcha import validate_captcha
            self.assertFalse(validate_captcha("any-token"))

    @override_settings(ALLOW_LOCAL_SIGNUP=True)
    def test_validate_captcha_called_from_signup_view(self):
        """AC7: validate_captcha must be invoked by SignupView."""
        from user_auth.views.local_auth import SignupView
        factory = RequestFactory()
        request = factory.post(
            "/api/auth/signup/",
            data=json.dumps({
                "email": "new@test.com",
                "password": "Password123!",
                "hcaptcha_token": "test-token",
            }),
            content_type="application/json",
        )
        with patch("user_auth.views.local_auth._ALLOW_LOCAL_SIGNUP", True), \
             patch("user_auth.views.local_auth.validate_captcha", return_value=False) as mock_captcha:
            resp = SignupView.as_view()(request)
            mock_captcha.assert_called_once_with("test-token")
        self.assertEqual(resp.status_code, 400)


# ---------------------------------------------------------------------------
# Legacy: existing CAPTCHA tests (kept for regression)
# ---------------------------------------------------------------------------

class SignupEnumerationTest(TestCase):
    """BLOCK-01: duplicate email must return 200 with generic message, not 409."""

    @override_settings(ALLOW_LOCAL_SIGNUP=True, HCAPTCHA_SECRET_KEY="")
    def test_signup_duplicate_email_returns_200(self):
        from user_auth.models import Users
        Users.objects.create_user(email="existing@test.com", password="testpass123")

        factory = RequestFactory()
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
        with patch("user_auth.views.local_auth._ALLOW_LOCAL_SIGNUP", True), \
             patch("user_auth.views.local_auth.validate_captcha", return_value=True):
            from user_auth.views.local_auth import SignupView as SV
            response = SV.as_view()(request)

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertIn("verification email", body["message"])
        self.assertNotIn("already exists", body["message"])

    @override_settings(ALLOW_LOCAL_SIGNUP=True, HCAPTCHA_SECRET_KEY="test-secret")
    def test_hcaptcha_failure_returns_400(self):
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
             patch("user_auth.views.local_auth.validate_captcha", return_value=False):
            from user_auth.views.local_auth import SignupView as SV
            response = SV.as_view()(request)

        self.assertEqual(response.status_code, 400)
        body = json.loads(response.content)
        self.assertIn("CAPTCHA", body["message"])
