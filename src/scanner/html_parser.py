# src/scanner/html_parser.py — HTML Security Analysis
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse

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
        "title":            "",
        "meta_description": "",
        "external_scripts": [],
        "insecure_forms":   [],
        "total_links":      0,
        "error":            None,
    }

    try:
        with httpx.Client(timeout=15, follow_redirects=True, verify=False) as client:
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

        # ── External scripts (correct domain comparison) ──
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
                result["external_scripts"].append(src)

        # ── Insecure forms ──
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action.startswith("http://"):
                result["insecure_forms"].append(action)

        # ── Total links ──
        result["total_links"] = len(soup.find_all("a", href=True))

    except Exception as e:
        result["error"] = str(e)

    return result