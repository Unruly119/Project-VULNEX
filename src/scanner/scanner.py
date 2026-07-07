# src/scanner/scanner.py — ประตูหลักของ Scanner
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from scanner.headers          import check_headers
from scanner.ssl_check        import check_ssl
from scanner.html_parser      import parse_html
from scanner.dns_security     import check_dns
from scanner.cookie_security  import check_cookies
from scanner.cors_policy      import check_cors
from scanner.http_methods     import check_http_methods  # noqa: F401 — kept; suspended (see _SUSPENDED_MODULES)
from scanner.js_exposure      import check_js_exposure
from scanner.subdomain_recon  import check_subdomains
from scanner.open_files       import check_open_files
from scanner.cms_fingerprint  import check_cms            # noqa: F401 — kept; suspended (see _SUSPENDED_MODULES)
from utils.network            import is_safe_host


# ── Suspended modules ────────────────────────────────────────────────────────
# SECURITY / PASSIVE-SCAN: http_methods and cms_fingerprint issue non-passive
# (write / active-POST) requests, contradicting the "Passive Scan Only" claim
# (SECURITY-AUDIT.md finding A1). They are DISABLED at this call site only — the
# module files and their imports above are intentionally kept so a future update
# can re-enable them by moving the key back into `modules` inside run_scan(). A
# suspended module reports {"suspended": True}, so the UI can show a notice and the
# score engine treats it as neutral (no penalty).
_SUSPENDED_MODULES = ("http_methods", "cms")


def _with_suspended(result: dict) -> dict:
    """Attach a neutral 'suspended' sentinel for every disabled module."""
    for key in _SUSPENDED_MODULES:
        result[key] = {"suspended": True, "error": None}
    return result


def run_scan(url: str) -> dict:
    """รัน Scanner ทั้งหมด ส่งคืน dict รวม — parallel execution + SSRF guard"""

    if not url.startswith("http"):
        url = "https://" + url

    # Active modules — passive only. NOTE: "http_methods" and "cms" are intentionally
    # absent here; they are suspended at this call site (see _SUSPENDED_MODULES) and
    # attached as neutral sentinels via _with_suspended() below.
    modules = {
        "headers":      check_headers,
        "ssl":          check_ssl,
        "html":         parse_html,
        "dns":          check_dns,
        "cookies":      check_cookies,
        "cors":         check_cors,
        "js_exposure":  check_js_exposure,
        "subdomains":   check_subdomains,
        "open_files":   check_open_files,
    }

    parsed = urlparse(url)
    if parsed.hostname and not is_safe_host(parsed.hostname):
        blocked = {"error": "SSRF blocked: private/loopback address"}
        return _with_suspended({"url": url, **{k: dict(blocked) for k in modules}})

    # All modules are I/O-bound (network waits), so give each its own worker —
    # capping below len(modules) only forces the slowest few to queue and adds
    # wall-clock latency for no benefit.
    results = {}
    with ThreadPoolExecutor(max_workers=len(modules)) as pool:
        futures = {pool.submit(fn, url): key for key, fn in modules.items()}
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                results[key] = {"error": str(exc)}

    return _with_suspended({"url": url, **{k: results.get(k, {}) for k in modules}})
