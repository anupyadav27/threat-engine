"""
AWS Secrets Manager helpers for IDP client secrets and SAML SP keypairs.
Used by OIDC, SAML, and IDP config views.
"""
import json
import logging
from typing import Optional

import boto3
from botocore.exceptions import ClientError
from django.conf import settings

logger = logging.getLogger(__name__)


def _client():
    return boto3.client("secretsmanager", region_name=settings.AWS_REGION)


def get_idp_client_secret(secret_ref: str) -> str:
    """Fetch IDP client_secret from AWS Secrets Manager.

    Args:
        secret_ref: Secrets Manager secret name/ARN stored in TenantIDPConfig.config.

    Returns:
        The raw client_secret string.
    """
    response = _client().get_secret_value(SecretId=secret_ref)
    raw = response["SecretString"]
    try:
        return json.loads(raw).get("client_secret", raw)
    except (json.JSONDecodeError, AttributeError):
        return raw


def store_idp_secret(secret_ref: str, client_secret: str) -> None:
    """Create or update an IDP client_secret in AWS Secrets Manager.

    Args:
        secret_ref: Secret name to create/update.
        client_secret: The raw secret value to store.
    """
    c = _client()
    payload = json.dumps({"client_secret": client_secret})
    try:
        c.create_secret(Name=secret_ref, SecretString=payload)
        logger.info(f"Created secret {secret_ref}")
    except c.exceptions.ResourceExistsException:
        c.update_secret(SecretId=secret_ref, SecretString=payload)
        logger.info(f"Updated secret {secret_ref}")


def get_saml_sp_cert(tenant_id: str) -> Optional[str]:
    """Fetch SP certificate PEM from Secrets Manager. Returns None if not found."""
    try:
        response = _client().get_secret_value(
            SecretId=f"platform/idp/{tenant_id}/saml_sp_cert"
        )
        return response["SecretString"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def get_saml_sp_key(tenant_id: str) -> Optional[str]:
    """Fetch SP private key PEM from Secrets Manager. Returns None if not found."""
    try:
        response = _client().get_secret_value(
            SecretId=f"platform/idp/{tenant_id}/saml_sp_key"
        )
        return response["SecretString"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def store_saml_sp_keypair(tenant_id: str, cert_pem: str, key_pem: str) -> None:
    """Store SP cert + key in Secrets Manager.

    Args:
        tenant_id: Tenant UUID used as part of the secret path.
        cert_pem: PEM-encoded X.509 certificate.
        key_pem: PEM-encoded RSA private key.
    """
    c = _client()
    for suffix, value in (("saml_sp_cert", cert_pem), ("saml_sp_key", key_pem)):
        name = f"platform/idp/{tenant_id}/{suffix}"
        try:
            c.create_secret(Name=name, SecretString=value)
        except c.exceptions.ResourceExistsException:
            c.update_secret(SecretId=name, SecretString=value)
