from rest_framework.throttling import AnonRateThrottle


class LoginRateThrottle(AnonRateThrottle):
    """Maximum 10 login attempts per minute per IP (BLOCK-02)."""

    scope = "login"
    rate = "10/min"


class RegisterRateThrottle(AnonRateThrottle):
    """Maximum 5 registration attempts per minute per IP (BLOCK-02)."""

    scope = "register"
    rate = "5/min"


# Backwards-compatible alias — password_reset.py imports this name.
SignupRateThrottle = RegisterRateThrottle


class PasswordResetRateThrottle(AnonRateThrottle):
    """Maximum 3 password-reset requests per minute per IP (BLOCK-02).

    Keyed by email in the view; falls back to IP when email is unavailable.
    """

    scope = "password_reset"
    rate = "3/min"


class RefreshRateThrottle(AnonRateThrottle):
    scope = "refresh"
    rate = "60/hour"


class IDPByDomainRateThrottle(AnonRateThrottle):
    scope = "idp_domain"
    rate = "5/minute"


class IDPCallbackRateThrottle(AnonRateThrottle):
    """Maximum 20 IDP callback completions per minute per IP (BLOCK-10).

    Applied to Google, Microsoft, OIDC, and SAML ACS callback endpoints to
    mitigate token-stuffing and replay attacks on the OAuth/SAML code exchange.
    """

    scope = "idp_callback"
    rate = "20/min"
