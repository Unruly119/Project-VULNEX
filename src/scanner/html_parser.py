# src/scanner/html_parser.py — HTML Security Analysis
import warnings

import httpx
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urlparse

from utils.network import SSRF_EVENT_HOOKS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Max response body size (5 MB) — prevents OOM on huge pages
_MAX_RESPONSE_BYTES = 5 * 1024 * 1024


def _extract_domain(url: str) -> str:
    """Extract the registrable domain for comparison.
    e.g. 'www.school.ac.th' → 'school.ac.th'
    """
    host = urlparse(url).hostname or ""
    parts = host.split(".")
    # Keep at least last 2 parts (domain.tld), or 3 for .ac.th / .co.uk style
    if len(parts) > 2 and len(parts[-2]) <= 3:
        return ".".join(parts[-3:])  # e.g. school.ac.th
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def parse_html(url: str) -> dict:
    """ดึงและวิเคราะห์ HTML จากเว็บไซต์ — with size cap and correct domain comparison"""
    result = {
        "title":              "",
        "meta_description":   "",
        "external_scripts":   [],
        "insecure_forms":     [],
        "scripts_missing_sri": 0,
        "total_links":        0,
        "score":              100,
        "error":              None,
    }

    try:
        with httpx.Client(timeout=15, follow_redirects=True, verify=False,
                          event_hooks=SSRF_EVENT_HOOKS) as client:  # SECURITY: SSRF redirect guard
            # Stream response to enforce size cap
            with client.stream("GET", url) as resp:
                chunks = []
                total  = 0
                for chunk in resp.iter_bytes(chunk_size=8192):
                    total += len(chunk)
                    if total > _MAX_RESPONSE_BYTES:
                        result["error"] = f"Response too large (>{_MAX_RESPONSE_BYTES // (1024*1024)}MB), truncated"
                        break
                    chunks.append(chunk)
                body = b"".join(chunks)

        html_text = body.decode("utf-8", errors="replace")
        soup = BeautifulSoup(html_text, "lxml")

        # ── Title ──
        title_tag = soup.find("title")
        if title_tag:
            result["title"] = title_tag.text.strip()

        # ── Meta description ──
        meta = soup.find("meta", {"name": "description"})
        if meta:
            result["meta_description"] = meta.get("content", "")

        # ── External scripts (domain comparison + SRI check) ──
        base_domain = _extract_domain(url)
        for script in soup.find_all("script", src=True):
            src = script["src"]

            # Normalize protocol-relative URLs (//cdn.evil.com/...)
            if src.startswith("//"):
                src = "https:" + src

            # Skip relative paths (no scheme = same domain)
            if not src.startswith(("http://", "https://")):
                continue

            script_domain = _extract_domain(src)
            if script_domain and script_domain != base_domain:
                has_sri = bool(script.get("integrity"))
                result["external_scripts"].append({
                    "src":     src,
                    "has_sri": has_sri,
                })
                if not has_sri:
                    result["scripts_missing_sri"] += 1

        # ── Insecure forms ──
        is_https_page = url.startswith("https://")
        for form in soup.find_all("form"):
            action   = form.get("action", "")
            has_pass = bool(form.find("input", {"type": "password"}))
            is_insecure = (
                action.startswith("http://") or
                (not is_https_page and not action.startswith("https://"))
            )
            if is_insecure or (has_pass and not is_https_page):
                result["insecure_forms"].append({
                    "action":       action or "(self)",
                    "has_password": has_pass,
                    "reason":       "HTTP form" if is_insecure else "Password on HTTP page",
                })

        # ── Total links ──
        result["total_links"] = len(soup.find_all("a", href=True))

        # ── HTML security score ──
        score = 100
        score -= min(result["scripts_missing_sri"] * 8, 40)
        score -= min(len(result["insecure_forms"]) * 15, 45)
        result["score"] = max(0, score)

    except Exception as e:
        result["error"] = str(e)

    return result
