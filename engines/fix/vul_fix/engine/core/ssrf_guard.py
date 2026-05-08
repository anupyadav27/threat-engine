"""
SSRF Guard — validate git repository URLs before cloning.

Prevents Server-Side Request Forgery attacks where a caller with a valid API key
supplies a git_repo_url pointing at internal infrastructure:
  - Cloud instance metadata endpoints (169.254.169.254, IMDSv2, etc.)
  - Private network ranges (RFC 1918 + RFC 4193)
  - Loopback addresses

Strategy:
  1. Parse the URL and extract the hostname.
  2. If the hostname is a raw IP address, reject private/reserved ranges immediately
     (no DNS needed — fast and reliable).
  3. Block a hardcoded list of well-known metadata/internal hostnames.
  4. Hostnames that are not raw IPs are allowed through — we do NOT perform DNS
     resolution at validation time (that would add latency and be bypassable via
     DNS rebinding anyway; a network-level egress firewall is the correct defence).

Usage:
    from core.ssrf_guard import validate_git_url
    validate_git_url("https://github.com/org/repo.git")  # OK
    validate_git_url("https://169.254.169.254/latest")   # raises ValueError
"""

import ipaddress
from urllib.parse import urlparse

# Known cloud metadata / internal hostnames that must never be cloned from
_BLOCKED_HOSTNAMES: frozenset = frozenset({
    "169.254.169.254",          # AWS/GCP/Azure IMDSv1
    "fd00:ec2::254",            # AWS IMDSv2 IPv6
    "metadata.google.internal", # GCP metadata
    "metadata.azure.com",       # Azure IMDS
    "instance-data",            # legacy EC2 internal alias
    "localhost",
    "localhost.localdomain",
    "0.0.0.0",
})


def validate_git_url(url: str) -> None:
    """
    Raise ValueError if the URL targets a private, loopback, link-local,
    or reserved address / known metadata hostname.

    Args:
        url: The git repository URL to validate.

    Raises:
        ValueError: With a human-readable message describing the problem.
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise ValueError("URL has no hostname — cannot clone.")

    # ── Block known metadata / internal hostnames ─────────────────────────────
    if hostname in _BLOCKED_HOSTNAMES:
        raise ValueError(
            f"git_repo_url targets a reserved or metadata hostname '{hostname}'. "
            "Only public or internal-corporate git hosts are permitted."
        )

    # ── If hostname is a raw IP, validate it is not private/reserved ──────────
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        # Not an IP address — it's a hostname like github.com. Allow it.
        return

    _reasons = []
    if addr.is_loopback:
        _reasons.append("loopback")
    if addr.is_private:
        _reasons.append("private (RFC 1918 / RFC 4193)")
    if addr.is_link_local:
        _reasons.append("link-local (169.254.x.x / fe80::)")
    if addr.is_reserved:
        _reasons.append("reserved")
    if addr.is_unspecified:
        _reasons.append("unspecified (0.0.0.0)")
    if addr.is_multicast:
        _reasons.append("multicast")

    if _reasons:
        raise ValueError(
            f"git_repo_url targets IP address '{hostname}' "
            f"which is {', '.join(_reasons)}. "
            "Only public git hosts are permitted."
        )
