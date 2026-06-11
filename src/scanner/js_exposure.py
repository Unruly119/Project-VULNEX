# src/scanner/js_exposure.py — JavaScript Exposure Scanner
import re
import warnings
from typing import Dict, List
from urllib.parse import urljoin, urlparse

import httpx
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

_MAX_BYTES = 3 * 1024 * 1024
_MAX_SCRIPTS = 15

_SECRET_PATTERNS = [
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "HIGH"),
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key", "CRITICAL"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Token", "CRITICAL"),
    (r"mongodb(\+srv)?://[^\s\"']+", "MongoDB Connection String", "CRITICAL"),
    (r"postgresql://[^\s\"']+", "PostgreSQL Connection String", "CRITICAL"),
    (r"mysql://[^\s\"']+", "MySQL Connection String", "CRITICAL"),
    (r"(?i)(password|passwd|secret)\s*[=:]\s*['\"][^'\"]{4,}['\"]", "Hardcoded Password/Secret", "HIGH"),
    (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "Possible JWT Token", "MEDIUM"),
]

_OUTDATED_LIBS = [
    (r"jquery[/-]([12]\.\d+\.\d+)", "jQuery < 3.x", "MEDIUM"),
    (r"bootstrap[/-]([34]\.\d+\.\d+)", "Bootstrap < 5.x", "LOW"),
]

_SOURCE_MAP_RE = re.compile(r"//#\s*sourceMappingURL=(.+)|/\*\s*#\s*sourceMappingURL=(.+)\s*\*/")


def _fetch_text(client: httpx.Client, url: str, max_bytes: int = 512_000) -> str:
    try:
        with client.stream("GET", url) as resp:
            chunks, total = [], 0
            for chunk in resp.iter_bytes(8192):
                total += len(chunk)
                if total > max_bytes:
                    break
                chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception:
        return ""


def check_js_exposure(url: str) -> Dict:
    """ตรวจ source maps, API keys, outdated libraries ใน JS"""
    result: Dict = {
        "scripts_analyzed": 0,
        "inline_scripts": 0,
        "source_maps_exposed": [],
        "secrets_found": [],
        "outdated_libs": [],
        "findings": [],
        "score": 100,
        "error": None,
    }

    try:
        with httpx.Client(
            timeout=15,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "VulnexScanner/1.0 (+https://vulnex.example.com/scanner-info)"},
        ) as client:
            with client.stream("GET", url) as resp:
                chunks, total = [], 0
                for chunk in resp.iter_bytes(8192):
                    total += len(chunk)
                    if total > _MAX_BYTES:
                        break
                    chunks.append(chunk)
                html_text = b"".join(chunks).decode("utf-8", errors="replace")

            soup = BeautifulSoup(html_text, "lxml")
            score = 100
            scripts_checked = 0

            # Inline scripts
            for script in soup.find_all("script"):
                if script.get("src"):
                    continue
                inline = script.string or script.get_text() or ""
                if not inline.strip():
                    continue
                result["inline_scripts"] += 1
                for pattern, label, sev in _SECRET_PATTERNS:
                    if re.search(pattern, inline):
                        finding = {"type": label, "source": "inline script", "severity": sev}
                        result["secrets_found"].append(finding)
                        result["findings"].append({
                            "severity": sev,
                            "title": label,
                            "detail": "พบใน inline script",
                        })
                        score -= 30 if sev == "CRITICAL" else 15

            # External scripts
            for script in soup.find_all("script", src=True):
                if scripts_checked >= _MAX_SCRIPTS:
                    break
                src = script["src"]
                if src.startswith("//"):
                    src = "https:" + src
                if not src.startswith(("http://", "https://")):
                    src = urljoin(url, src)

                scripts_checked += 1
                js_text = _fetch_text(client, src)
                if not js_text:
                    continue
                result["scripts_analyzed"] += 1

                # Source map in comment
                for m in _SOURCE_MAP_RE.finditer(js_text):
                    map_url = (m.group(1) or m.group(2) or "").strip()
                    if map_url:
                        full_map = urljoin(src, map_url)
                        # HEAD check on .map
                        try:
                            head = client.head(full_map, timeout=5)
                            if head.status_code == 200:
                                result["source_maps_exposed"].append(full_map)
                                result["findings"].append({
                                    "severity": "MEDIUM",
                                    "title": "Source map exposed",
                                    "detail": full_map[:120],
                                })
                                score -= 10
                        except Exception:
                            pass

                for pattern, label, sev in _SECRET_PATTERNS:
                    if re.search(pattern, js_text):
                        result["secrets_found"].append({
                            "type": label, "source": src[:80], "severity": sev,
                        })
                        result["findings"].append({
                            "severity": sev,
                            "title": label,
                            "detail": f"พบใน {src[:80]}",
                        })
                        score -= 30 if sev == "CRITICAL" else 15

                src_lower = src.lower()
                for pattern, label, sev in _OUTDATED_LIBS:
                    if re.search(pattern, src_lower):
                        result["outdated_libs"].append({"lib": label, "src": src[:80]})
                        result["findings"].append({
                            "severity": sev,
                            "title": f"Outdated library: {label}",
                            "detail": src[:80],
                        })
                        score -= 8

            result["score"] = max(0, min(100, score))

    except Exception as exc:
        result["error"] = str(exc)

    return result
