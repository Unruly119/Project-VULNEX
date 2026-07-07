# src/scanner/open_files.py — Open Directory & Sensitive File Detector
import warnings
from typing import Dict, List
from urllib.parse import urljoin

import httpx
import urllib3

from utils.network import SSRF_EVENT_HOOKS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

_DIR_PATHS = ("/uploads/", "/files/", "/backup/", "/docs/", "/assets/", "/media/")
_SENSITIVE_FILES = (
    ".env", ".env.local", ".env.production",
    "phpinfo.php", "info.php",
    "backup.zip", "backup.tar.gz", "db.sql",
    "web.config", ".htaccess",
    ".git/HEAD", ".svn/entries",
    "wp-config.php.bak", "config.php.bak",
)
_DIR_LISTING_MARKERS = ("Index of /", "Directory listing", "[To Parent Directory]")


def _head_check(client: httpx.Client, base_url: str, path: str) -> Dict:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        resp = client.head(url, follow_redirects=True)
        return {"path": path, "url": url, "status": resp.status_code, "headers": dict(resp.headers)}
    except Exception as exc:
        return {"path": path, "url": url, "status": 0, "error": str(exc)}


def check_open_files(url: str) -> Dict:
    """HEAD requests บน common paths — ไม่ดาวน์โหลดเนื้อหา"""
    result: Dict = {
        "directory_listings": [],
        "sensitive_files": [],
        "robots_disallow": [],
        "sitemap_urls": [],
        "findings": [],
        "score": 100,
        "error": None,
    }

    try:
        with httpx.Client(
            timeout=8,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "VulnexScanner/1.0 (+https://vulnex.example.com/scanner-info)"},
            event_hooks=SSRF_EVENT_HOOKS,  # SECURITY: block redirects to internal hosts (SSRF)
        ) as client:
            score = 100

            # Directory listing — GET first line only via HEAD won't show listing, use GET with limit
            for path in _DIR_PATHS:
                target = urljoin(url.rstrip("/") + "/", path.lstrip("/"))
                try:
                    with client.stream("GET", target) as resp:
                        if resp.status_code != 200:
                            continue
                        snippet = b""
                        for chunk in resp.iter_bytes(4096):
                            snippet = chunk
                            break
                    text = snippet.decode("utf-8", errors="replace")
                    if any(m in text for m in _DIR_LISTING_MARKERS):
                        result["directory_listings"].append(path)
                        result["findings"].append({
                            "severity": "HIGH",
                            "title": f"Directory listing: {path}",
                            "detail": "พบ Index of / — ไฟล์อาจถูกเข้าถึงได้",
                        })
                        score -= 20
                except Exception:
                    pass

            # Sensitive files — HEAD only
            for fname in _SENSITIVE_FILES:
                check = _head_check(client, url, fname)
                status = check.get("status", 0)
                if status in (200, 206):
                    result["sensitive_files"].append({"path": fname, "status": status})
                    sev = "CRITICAL" if fname.startswith(".env") or "backup" in fname else "HIGH"
                    result["findings"].append({
                        "severity": sev,
                        "title": f"Sensitive file accessible: {fname}",
                        "detail": f"HTTP {status} — {check.get('url', fname)}",
                    })
                    score -= 35 if sev == "CRITICAL" else 20

            # robots.txt
            try:
                robots_resp = client.get(urljoin(url.rstrip("/") + "/", "robots.txt"), timeout=5)
                if robots_resp.status_code == 200:
                    for line in robots_resp.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/":
                                result["robots_disallow"].append(path)
            except Exception:
                pass

            # sitemap.xml — enumerate URLs count only
            try:
                sm_resp = client.get(urljoin(url.rstrip("/") + "/", "sitemap.xml"), timeout=5)
                if sm_resp.status_code == 200 and "<url>" in sm_resp.text.lower():
                    count = sm_resp.text.lower().count("<loc>")
                    result["sitemap_urls"] = [f"{count} URLs in sitemap"]
            except Exception:
                pass

            result["score"] = max(0, min(100, score))

    except Exception as exc:
        result["error"] = str(exc)

    return result
