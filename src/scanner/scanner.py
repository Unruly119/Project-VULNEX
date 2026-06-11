# src/scanner/scanner.py — ประตูหลักของ Scanner
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from scanner.headers    import check_headers
from scanner.ssl_check  import check_ssl
from scanner.html_parser import parse_html


def _is_safe_host(hostname: str) -> bool:
    """Reject private/loopback/link-local IPs (SSRF mitigation)."""
    try:
        addr = ipaddress.ip_address(hostname)
        return not (addr.is_loopback or addr.is_private or addr.is_link_local)
    except ValueError:
        return True  # domain name — allow


def run_scan(url: str) -> dict:
    """รัน Scanner ทั้งหมด ส่งคืน dict รวม — parallel execution + SSRF guard"""

    # normalize URL
    if not url.startswith("http"):
        url = "https://" + url

    # SSRF guard — reject private/loopback targets
    parsed = urlparse(url)
    if parsed.hostname and not _is_safe_host(parsed.hostname):
        return {
            "url":     url,
            "headers": {"error": "SSRF blocked: private/loopback address"},
            "ssl":     {"error": "SSRF blocked"},
            "html":    {"error": "SSRF blocked"},
        }

    # Run 3 modules in parallel
    results = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {
            pool.submit(check_headers, url): "headers",
            pool.submit(check_ssl, url):     "ssl",
            pool.submit(parse_html, url):    "html",
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                results[key] = {"error": str(exc)}

    return {
        "url":     url,
        "headers": results.get("headers", {}),
        "ssl":     results.get("ssl", {}),
        "html":    results.get("html", {}),
    }