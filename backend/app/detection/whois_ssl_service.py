"""
detection/whois_ssl_service.py

Live WHOIS age check + live TLS handshake. Both go through
core.security.assert_safe_url first — this module never touches
a URL that hasn't already passed the SSRF guard.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

import whois

from app.core.security import SSRFError, assert_safe_url


def whois_age_signal(domain: str) -> dict:
    """risk 0-1, younger domain = higher risk. Fails safe (moderate risk) on lookup errors."""
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return {"risk": 0.5, "note": "WHOIS creation date unavailable — treated as moderate risk"}
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - created).days

        if age_days < 30:
            return {"risk": 1.0, "note": f"Domain registered {age_days} days ago — very new"}
        if age_days < 180:
            return {"risk": 0.6, "note": f"Domain registered {age_days} days ago — recently created"}
        if age_days < 365:
            return {"risk": 0.3, "note": f"Domain is {age_days} days old — under a year"}
        return {"risk": 0.0, "note": f"Domain is {age_days // 365}+ years old — established"}
    except Exception as e:
        return {"risk": 0.5, "note": f"WHOIS lookup failed ({e.__class__.__name__}) — treated as moderate risk"}


def ssl_signal(hostname: str, resolved_ip: str | None = None) -> dict:
    """risk 0-1. Connects to the already-resolved IP where possible to avoid a second,
    unchecked DNS lookup happening at socket-connect time."""
    target = resolved_ip or hostname
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    return {"risk": 0.0, "note": "Valid SSL certificate present"}
                return {"risk": 0.7, "note": "SSL handshake succeeded but no certificate details returned"}
    except ssl.SSLCertVerificationError:
        return {"risk": 1.0, "note": "SSL certificate is invalid or untrusted"}
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        return {"risk": 0.8, "note": f"Could not establish HTTPS connection ({e.__class__.__name__})"}


def run_network_checks(raw_url: str) -> dict:
    """
    Single entry point: validates via SSRF guard, then runs WHOIS + SSL.
    Raises SSRFError (caller should turn this into a 400) if the URL is unsafe.
    """
    hostname, resolved_ips = assert_safe_url(raw_url)
    return {
        "domain": hostname,
        "whois": whois_age_signal(hostname),
        "ssl": ssl_signal(hostname, resolved_ip=resolved_ips[0] if resolved_ips else None),
    }
