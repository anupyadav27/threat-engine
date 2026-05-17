"""
Google OAuth helper utilities.

validate_google_hd() enforces the GOOGLE_ALLOWED_DOMAINS restriction (BLOCK-03).
When the env var is empty / not set, all domains are accepted (backward-compatible).
"""
import os
import logging

logger = logging.getLogger(__name__)


def validate_google_hd(id_token_claims: dict) -> bool:
    """Validate the Google ID token's hd (hosted domain) against the allowed list.

    Args:
        id_token_claims: Decoded token claims dict (or any mapping that contains
            an ``hd`` key).  For Google userinfo responses the field is also
            named ``hd``.

    Returns:
        True  — the domain is allowed (or no restriction is configured).
        False — the domain is absent / not in the allowed list; the caller must
                return HTTP 403.

    Notes:
        GOOGLE_ALLOWED_DOMAINS env var: comma-separated list of Google Workspace
        domains, e.g. ``"acme.com,partner.io"``.  When empty or unset, all domains
        (including personal Gmail) are accepted — preserving backward compatibility
        for single-tenant / dev deployments that do not configure the var.

        Personal Gmail accounts carry no ``hd`` claim; they are rejected whenever
        GOOGLE_ALLOWED_DOMAINS is non-empty.
    """
    # Read allowed domains at call-time so changes to the env var take effect
    # without restarting the process (useful in tests / local dev).
    allowed_raw = os.environ.get("GOOGLE_ALLOWED_DOMAINS", "").strip()
    if not allowed_raw:
        # No restriction configured — allow all domains (backward-compatible).
        return True

    allowed_domains = {d.strip().lower() for d in allowed_raw.split(",") if d.strip()}
    hd = (id_token_claims.get("hd") or "").strip().lower()

    if not hd or hd not in allowed_domains:
        logger.warning(
            "Google OAuth rejected: hd='%s' not in allowed_domains=%s",
            hd or "(none — personal Gmail)",
            sorted(allowed_domains),
        )
        return False

    return True
