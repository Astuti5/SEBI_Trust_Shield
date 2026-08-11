"""
core/security.py — SSRF guard.

Every user-supplied URL in Trust Shield gets fetched (WHOIS target resolution,
SSL handshake, eventually screenshot rendering). Without this module, a user
could submit "http://169.254.169.254/latest/meta-data/" or "http://localhost:5432"
and make the server probe its own internal network / cloud metadata endpoint
on their behalf. This is the #1 vulnerability class in "paste a URL, we fetch
it" tools, and it was named as an open gap in the feasibility review — this
closes it, not just documents it.

Usage:
    from app.core.security import assert_safe_url, SSRFError

    try:
        domain, resolved_ips = assert_safe_url(user_url)
    except SSRFError as e:
        raise HTTPException(status_code=400, detail=str(e))
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}

# Blocks: loopback, private ranges (RFC1918), link-local (incl. cloud metadata
# endpoint 169.254.169.254), unique-local IPv6, and multicast/reserved space.
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # cloud metadata (AWS/GCP/Azure) lives here
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("224.0.0.0/4"),
]

BLOCKED_HOSTNAMES = {
    "localhost", "metadata.google.internal", "metadata.internal",
}

# Explicit deny — even if it *looks* like a domain, never fetch these.
BLOCKED_PORTS = {22, 25, 3306, 5432, 6379, 27017, 9200}


class SSRFError(ValueError):
    """Raised when a URL fails the SSRF safety check. Message is safe to show the user."""


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparsable -> treat as unsafe
    return any(ip in net for net in BLOCKED_NETWORKS) or ip.is_reserved or ip.is_unspecified


def assert_safe_url(raw_url: str) -> tuple[str, list[str]]:
    """
    Validates a user-supplied URL against SSRF vectors.

    Returns (hostname, resolved_ip_list) if safe.
    Raises SSRFError with a user-facing reason if not.
    """
    if not raw_url or len(raw_url) > 2048:
        raise SSRFError("URL is missing or unreasonably long")

    candidate = raw_url if "://" in raw_url else f"http://{raw_url}"
    parsed = urlparse(candidate)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFError(f"Scheme '{parsed.scheme}' is not allowed — only http/https")

    hostname = (parsed.hostname or "").lower().strip(".")
    if not hostname:
        raise SSRFError("Could not parse a hostname from the URL")

    if hostname in BLOCKED_HOSTNAMES:
        raise SSRFError("This hostname is not permitted")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port in BLOCKED_PORTS:
        raise SSRFError("This port is not permitted")

    # If the hostname is itself a raw IP, check it directly.
    try:
        ipaddress.ip_address(hostname)
        if _is_blocked_ip(hostname):
            raise SSRFError("This IP address is not permitted")
        return hostname, [hostname]
    except ValueError:
        pass  # not a raw IP, fall through to DNS resolution

    # Resolve DNS and check every returned address — this stops
    # DNS-rebinding tricks where the hostname resolves to a public IP
    # at check time but an internal one at request time is out of scope
    # for a hackathon MVP, but resolving here at least blocks the naive case.
    try:
        addr_info = socket.getaddrinfo(hostname, port)
    except socket.gaierror as e:
        raise SSRFError(f"DNS resolution failed for '{hostname}': {e}") from e

    resolved_ips = sorted({info[4][0] for info in addr_info})
    if not resolved_ips:
        raise SSRFError("Hostname did not resolve to any address")

    for ip in resolved_ips:
        if _is_blocked_ip(ip):
            raise SSRFError(
                f"'{hostname}' resolves to a non-public address ({ip}) — blocked"
            )

    return hostname, resolved_ips
