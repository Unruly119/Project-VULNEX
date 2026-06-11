# src/scanner/scanner.py — ประตูหลักของ Scanner
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from scanner.headers          import check_headers
from scanner.ssl_check        import check_ssl
from scanner.html_parser      import parse_html
from scanner.dns_security     import check_dns
from scanner.cookie_security  import check_cookies
from scanner.cors_policy      import check_cors
from scanner.http_methods     import check_http_methods
from scanner.js_exposure      import check_js_exposure
from scanner.subdomain_recon  import check_subdomains
from scanner.open_files       import check_open_files
from scanner.cms_fingerprint  import check_cms
from utils.network            import is_safe_host


def run_scan(url: str) -> dict:
    """รัน Scanner ทั้งหมด ส่งคืน dict รวม — parallel execution + SSRF guard"""

    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.hostname and not is_safe_host(parsed.hostname):
        blocked = {"error": "SSRF blocked: private/loopback address"}
        return {
            "url":      url,
            "headers":  blocked,
            "ssl":      {"error": "SSRF blocked"},
            "html":     {"error": "SSRF blocked"},
            "dns":      blocked,
            "cookies":  blocked,
            "cors":     blocked,
            "http_methods": blocked,
            "js_exposure": blocked,
            "subdomains": blocked,
            "open_files": blocked,
            "cms":      blocked,
        }

    modules = {
        "headers":      check_headers,
        "ssl":          check_ssl,
        "html":         parse_html,
        "dns":          check_dns,
        "cookies":      check_cookies,
        "cors":         check_cors,
        "http_methods": check_http_methods,
        "js_exposure":  check_js_exposure,
        "subdomains":   check_subdomains,
        "open_files":   check_open_files,
        "cms":          check_cms,
    }

    results = {}
    with ThreadPoolExecutor(max_workers=min(len(modules), 8)) as pool:
        futures = {pool.submit(fn, url): key for key, fn in modules.items()}
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                results[key] = {"error": str(exc)}

    return {"url": url, **{k: results.get(k, {}) for k in modules}}
