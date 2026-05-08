"""
SAML 2.0 utilities for multi-tenant python3-saml integration.
Handles request preparation, settings construction, and SP keypair generation.
"""
import logging
from typing import Optional

from django.conf import settings
from django.http import HttpRequest

logger = logging.getLogger(__name__)


def prepare_django_request(request: HttpRequest) -> dict:
    """Convert Django HttpRequest to the dict python3-saml expects.

    Args:
        request: Django HTTP request object.

    Returns:
        Dict compatible with OneLogin_Saml2_Auth constructor.
    """
    return {
        "https": "on" if request.is_secure() else "off",
        "http_host": request.META.get("HTTP_HOST", "localhost"),
        "script_name": request.META.get("PATH_INFO", ""),
        "server_port": request.META.get(
            "SERVER_PORT", "443" if request.is_secure() else "80"
        ),
        "get_data": request.GET.copy(),
        "post_data": request.POST.copy(),
        "query_string": request.META.get("QUERY_STRING", ""),
    }


def _strip_pem(pem: str) -> str:
    """Remove PEM headers/footers and newlines for python3-saml."""
    lines = [
        line for line in pem.splitlines()
        if line and not line.startswith("-----")
    ]
    return "".join(lines)


def build_saml_settings(config: dict, sp_cert: str, sp_key: str) -> dict:
    """Build python3-saml settings dict from TenantIDPConfig.config and SP credentials.

    Args:
        config: TenantIDPConfig.config JSONB (saml type).
        sp_cert: SP X.509 certificate PEM string.
        sp_key: SP RSA private key PEM string.

    Returns:
        Settings dict accepted by OneLogin_Saml2_Auth.
    """
    return {
        "strict": True,
        "debug": settings.DEBUG,
        "sp": {
            "entityId": config["sp_entity_id"],
            "assertionConsumerService": {
                "url": config["acs_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": config.get("slo_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "x509cert": _strip_pem(sp_cert),
            "privateKey": _strip_pem(sp_key),
        },
        "idp": {
            "entityId": config["entity_id"],
            "singleSignOnService": {
                "url": config.get("sso_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": config.get("idp_slo_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": config.get("idp_x509cert", ""),
        },
    }


def generate_sp_keypair(tenant_id: str) -> tuple[str, str]:
    """Generate RSA 2048-bit SP keypair, store in Secrets Manager.

    Args:
        tenant_id: Tenant UUID used as part of the Secrets Manager path.

    Returns:
        Tuple of (cert_pem, key_pem).

    Raises:
        RuntimeError: If pyOpenSSL is not installed.
    """
    from user_auth.utils.secrets_utils import store_saml_sp_keypair

    try:
        from OpenSSL import crypto
    except ImportError as exc:
        raise RuntimeError("pyOpenSSL is required for SP cert generation") from exc

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = f"cspm-sp-{tenant_id}"
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()
    key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode()

    store_saml_sp_keypair(tenant_id, cert_pem, key_pem)
    logger.info(f"Generated and stored SP keypair for tenant {tenant_id}")
    return cert_pem, key_pem


def fetch_idp_metadata(metadata_url: str) -> dict:
    """Fetch and parse IDP metadata XML to extract sso_url and idp_x509cert.

    Args:
        metadata_url: URL of the IDP SAML metadata XML.

    Returns:
        Dict with keys: sso_url, idp_x509cert, entity_id (may be empty strings).
    """
    try:
        from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
        idp_data = OneLogin_Saml2_IdPMetadataParser.parse_remote(
            metadata_url, timeout=10
        )
        idp = idp_data.get("idp", {})
        sso = idp.get("singleSignOnService", {})
        return {
            "entity_id": idp.get("entityId", ""),
            "sso_url": sso.get("url", ""),
            "idp_x509cert": idp.get("x509cert", ""),
        }
    except Exception as exc:
        logger.warning(f"Failed to parse IDP metadata from {metadata_url}: {exc}")
        return {"entity_id": "", "sso_url": "", "idp_x509cert": ""}
