"""CAPTCHA server-side validation hook.

AC7 (auth-B1): provides ``validate_captcha(token)`` called from registration
view.  When ``CAPTCHA_SECRET_KEY`` is not configured the function returns
``True`` immediately so existing deployments are unaffected.  Set the env var
to activate real validation against hCaptcha (default) or reCAPTCHA v3.

Provider selection:
    CAPTCHA_PROVIDER = "hcaptcha" (default) | "recaptcha"
    CAPTCHA_SECRET_KEY = "<secret>"   # required to enable
"""

import logging
import os

import requests

logger = logging.getLogger(__name__)

_HCAPTCHA_VERIFY_URL = "https://hcaptcha.com/siteverify"
_RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


def validate_captcha(token: str) -> bool:
    """Validate a CAPTCHA token server-side.

    Args:
        token: The client-supplied CAPTCHA response token.

    Returns:
        ``True`` if the token is valid (or CAPTCHA is disabled).
        ``False`` if validation fails — caller should return HTTP 400.
    """
    secret = os.environ.get("CAPTCHA_SECRET_KEY", "")
    if not secret:
        # Disabled — skip validation in dev / environments without a key.
        logger.debug(
            "CAPTCHA validation skipped — CAPTCHA_SECRET_KEY not configured"
        )
        return True

    provider = os.environ.get("CAPTCHA_PROVIDER", "hcaptcha").lower()
    verify_url = (
        _RECAPTCHA_VERIFY_URL if provider == "recaptcha" else _HCAPTCHA_VERIFY_URL
    )

    try:
        resp = requests.post(
            verify_url,
            data={"secret": secret, "response": token},
            timeout=5.0,
        )
        result = resp.json()
        if result.get("success"):
            return True
        logger.warning(
            "CAPTCHA validation failed: provider=%s error-codes=%s",
            provider,
            result.get("error-codes", []),
        )
        return False
    except Exception as exc:  # noqa: BLE001
        # Fail closed: network errors count as validation failure.
        logger.error("CAPTCHA validation error: %s", exc)
        return False
