"""
SSRF Guard — validate git repository URLs before cloning.

Prevents Server-Side Request Forgery where a caller supplies a repo_url
pointing at internal infrastructure (metadata endpoints, private networks).

See vul_fix/engine/core/ssrf_guard.py for full documentation.
"""

import ipaddress
from urllib.parse import urlparse

_BLOCKED_HOSTNAMES: frozenset = frozenset({
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata.google.internal",
    "metadata.azure.com",
    "instance-data",
    "localhost",
    "localhost.localdomain",
    "0.0.0.0",
})


def validate_git_url(url: str) -> None:
    """
    Raise ValueError if the URL targets a private/reserved address or
    a known cloud metadata hostname.
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise ValueError("URL has no hostname — cannot clone.")

    if hostname in _BLOCKED_HOSTNAMES:
        raise ValueError(
            f"repo_url targets a reserved or metadata hostname '{hostname}'. "
            "Only public or internal-corporate git hosts are permitted."
        )

    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return  # hostname, not an IP — allow

    _reasons = []
    if addr.is_loopback:    _reasons.append("loopback")
    if addr.is_private:     _reasons.append("private (RFC 1918 / RFC 4193)")
    if addr.is_link_local:  _reasons.append("link-local (169.254.x.x / fe80::)")
    if addr.is_reserved:    _reasons.append("reserved")
    if addr.is_unspecified: _reasons.append("unspecified (0.0.0.0)")
    if addr.is_multicast:   _reasons.append("multicast")

    if _reasons:
        raise ValueError(
            f"repo_url targets IP '{hostname}' which is {', '.join(_reasons)}. "
            "Only public git hosts are permitted."
        )
