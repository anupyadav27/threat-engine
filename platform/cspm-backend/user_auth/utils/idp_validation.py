"""IDP configuration validation helpers (AUTH-11)."""
import logging

import requests as http_requests

logger = logging.getLogger(__name__)


def validate_oidc_config(config: dict) -> str | None:
    """Return error string or None if OIDC discovery is reachable."""
    issuer = config.get("issuer", "").rstrip("/")
    if not issuer:
        return "issuer is required"
    try:
        url = f"{issuer}/.well-known/openid-configuration"
        resp = http_requests.get(url, timeout=10)
        resp.raise_for_status()
        doc = resp.json()
        if "authorization_endpoint" not in doc:
            return "discovery doc missing authorization_endpoint"
    except Exception as exc:
        return f"OIDC discovery unreachable: {exc}"
    return None


def validate_saml_config(config: dict) -> str | None:
    """Return error string or None. metadata_url is optional — skipped if absent."""
    metadata_url = config.get("metadata_url")
    if not metadata_url:
        return None
    try:
        resp = http_requests.get(metadata_url, timeout=10)
        resp.raise_for_status()
        if "EntityDescriptor" not in resp.text:
            return "metadata_url did not return valid SAML XML"
    except Exception as exc:
        return f"SAML metadata unreachable: {exc}"
    return None


def validate_google_oauth_config(config: dict) -> str | None:
    """Google OAuth — validate required fields only (endpoint is always reachable)."""
    if not config.get("client_id"):
        return "client_id is required"
    return None


_VALIDATORS = {
    "oidc": validate_oidc_config,
    "saml": validate_saml_config,
    "google_oauth": validate_google_oauth_config,
}


def validate_idp_config(idp_type: str, config: dict) -> str | None:
    """Dispatch to the correct validator. Returns error string or None on success."""
    fn = _VALIDATORS.get(idp_type)
    if fn is None:
        return f"Unknown idp_type: {idp_type}"
    return fn(config)
