# src/utils/network.py — shared network utilities
import ipaddress


def is_safe_host(hostname: str) -> bool:
    """Single source of truth for SSRF guard — reject private/loopback/link-local IPs."""
    try:
        addr = ipaddress.ip_address(hostname)
        return not (addr.is_loopback or addr.is_private or addr.is_link_local)
    except ValueError:
        return True  # domain name — allow
