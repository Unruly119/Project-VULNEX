# src/utils/network.py — shared network utilities (SSRF guard, single source of truth)
#
# SECURITY: this module is intentionally stdlib-only. app.py imports is_safe_host on
# the hot path (before the heavy scanner/AI stack) precisely because it is instant —
# do NOT add third-party imports (httpx, etc.) here or that fast first paint regresses.
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

# SECURITY: hostnames that resolve to the local machine but are not IP literals, so
# the ip_address() literal check below would not catch them. "localhost" is the classic
# SSRF bypass (http://localhost:22) that slips past a naive private-IP check.
_BLOCKED_HOSTNAMES = frozenset({
    "localhost", "localhost.localdomain",
    "ip6-localhost", "ip6-loopback",
})

# 3xx codes that carry a Location redirect target we must re-validate.
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


class UnsafeRedirectError(Exception):
    """Raised by the redirect guard when a scan target redirects to a non-public host."""


def _ip_is_blocked(addr) -> bool:
    """SECURITY: True for any address that is not a routable *public* host —
    loopback, RFC1918 private, link-local (incl. 169.254.169.254 cloud metadata),
    reserved, multicast and the unspecified address. IPv4-mapped IPv6 is unwrapped
    first so ::ffff:127.0.0.1 cannot smuggle an internal target past the check."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return bool(
        addr.is_loopback or addr.is_private or addr.is_link_local
        or addr.is_reserved or addr.is_multicast or addr.is_unspecified
    )


def _resolve_ips(hostname: str) -> list:
    """Resolve a hostname to every A/AAAA address. Returns [] on any failure so the
    caller can fail closed (an unresolvable host is treated as unsafe)."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    ips = []
    for info in infos:
        ip = info[4][0].split("%", 1)[0]  # drop IPv6 scope id (fe80::1%eth0)
        ips.append(ip)
    return ips


def is_safe_host(hostname: str) -> bool:
    """Single source of truth for the SSRF guard.

    SECURITY: returns True only when the host is definitively public.
      · IP literal        → validated directly.
      · Domain name       → resolved via DNS; EVERY resolved address must be public.
                            This defends against DNS-based SSRF where a public-looking
                            domain (or an attacker's own domain) resolves to
                            127.0.0.1 / 169.254.169.254 / an RFC1918 address.
    Empty, blocklisted, unresolvable or reserved hosts are unsafe (fail closed).

    Residual risk: this is a check-time validation; httpx/socket re-resolve at connect
    time, so a DNS-rebinding attacker who flips the record between the two could still
    win the race. Fully closing that requires pinning the validated IP for the
    connection (custom transport) — see SECURITY-AUDIT notes.
    """
    if not hostname:
        return False
    host = hostname.strip().rstrip(".").lower()
    if not host or host in _BLOCKED_HOSTNAMES:
        return False

    # Case 1: caller passed a literal IP address.
    try:
        return not _ip_is_blocked(ipaddress.ip_address(host))
    except ValueError:
        pass  # not a literal — treat as a domain name and resolve it

    # Case 2: domain name — resolve and validate every address (fail closed).
    ips = _resolve_ips(host)
    if not ips:
        return False
    for ip in ips:
        try:
            if _ip_is_blocked(ipaddress.ip_address(ip)):
                return False
        except ValueError:
            return False  # unparseable resolver output → unsafe
    return True


def is_safe_url(url: str) -> bool:
    """Convenience wrapper: parse a URL and validate its host with is_safe_host."""
    try:
        return is_safe_host(urlparse(url).hostname or "")
    except ValueError:
        return False


def _guard_redirect(response) -> None:
    """httpx *response* event hook — abort the request chain if a 3xx redirect points
    at a non-public host.

    SECURITY: every scanner uses follow_redirects=True so expired-cert / www→apex
    hops still work. Without this, a public target could 302 to
    http://169.254.169.254/ (or any internal host) and httpx would faithfully follow
    it, turning the scanner into an SSRF proxy. This hook runs on each response —
    including intermediate redirects — before httpx connects to the next hop.
    """
    if response.status_code in _REDIRECT_CODES:
        location = response.headers.get("location", "")
        if location:
            host = urlparse(urljoin(str(response.url), location)).hostname
            if host and not is_safe_host(host):
                raise UnsafeRedirectError(
                    f"SSRF blocked: redirect to non-public host '{host}'"
                )


# Drop-in for httpx.Client(event_hooks=...): re-validates every redirect target.
SSRF_EVENT_HOOKS = {"response": [_guard_redirect]}
