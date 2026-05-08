from rest_framework.throttling import AnonRateThrottle


class SignupRateThrottle(AnonRateThrottle):
    scope = "signup"
    rate = "10/hour"


class LoginRateThrottle(AnonRateThrottle):
    scope = "login"
    rate = "20/hour"


class RefreshRateThrottle(AnonRateThrottle):
    scope = "refresh"
    rate = "60/hour"


class IDPByDomainRateThrottle(AnonRateThrottle):
    scope = "idp_domain"
    rate = "5/minute"
