"""
Stripe client initialisation.

Secrets loaded from AWS Secrets Manager at engine startup.

Secret path resolution:
    APP_ENV=dev      → threat-engine/billing/stripe-dev
    APP_ENV=staging  → threat-engine/billing/stripe-staging
    (default)        → threat-engine/billing/stripe

Secret JSON shape::

    {
        "STRIPE_SECRET_KEY":      "sk_live_xxx",   # or sk_test_xxx in non-prod
        "STRIPE_PUBLISHABLE_KEY": "pk_live_xxx",
        "STRIPE_WEBHOOK_SECRET":  "whsec_xxx"
    }

The module exposes:
    load_stripe_secrets() → dict  — idempotent; raises RuntimeError on missing secret
    get_webhook_secret()  → str   — convenience accessor for the webhook signing secret
"""

from __future__ import annotations

import json
import logging
import os
from typing import Dict

import boto3
import stripe
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Module-level cache — populated once at first call to load_stripe_secrets().
_stripe_config: Dict[str, str] | None = None


def _secret_path() -> str:
    """Return the Secrets Manager path for the current APP_ENV.

    Returns:
        String secret path to use with boto3 get_secret_value.
    """
    env = os.environ.get("APP_ENV", "production")
    if env == "dev":
        return "threat-engine/billing/stripe-dev"
    if env == "staging":
        return "threat-engine/billing/stripe-staging"
    return "threat-engine/billing/stripe"


def load_stripe_secrets() -> Dict[str, str]:
    """Load and cache Stripe credentials from AWS Secrets Manager.

    Sets ``stripe.api_key`` as a side effect so all stripe SDK calls
    in the current process are automatically authenticated.

    Returns:
        Dict containing STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY,
        and STRIPE_WEBHOOK_SECRET.

    Raises:
        RuntimeError: If the secret is missing or malformed — callers
            should surface this as a readiness probe failure so the
            deployment never silently enters a mis-configured state.
    """
    global _stripe_config
    if _stripe_config is not None:
        return _stripe_config

    region = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    path = _secret_path()

    try:
        client = boto3.client("secretsmanager", region_name=region)
        response = client.get_secret_value(SecretId=path)
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        raise RuntimeError(
            f"Failed to retrieve Stripe secret from '{path}': {error_code}"
        ) from exc

    try:
        data: Dict[str, str] = json.loads(response["SecretString"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Stripe secret at '{path}' is not valid JSON: {exc}"
        ) from exc

    required_keys = {"STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"}
    missing = required_keys - data.keys()
    if missing:
        raise RuntimeError(
            f"Stripe secret at '{path}' is missing required keys: {missing}"
        )

    stripe.api_key = data["STRIPE_SECRET_KEY"]
    _stripe_config = data
    logger.info("Stripe secrets loaded from Secrets Manager path='%s'", path)
    return _stripe_config


def get_webhook_secret() -> str:
    """Return the Stripe webhook signing secret.

    Loads secrets on first call (idempotent).

    Returns:
        STRIPE_WEBHOOK_SECRET string.

    Raises:
        RuntimeError: Propagated from load_stripe_secrets if secret missing.
    """
    config = load_stripe_secrets()
    return config["STRIPE_WEBHOOK_SECRET"]
