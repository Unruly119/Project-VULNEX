# src/scanner/cms_fingerprint.py — CMS & Framework Fingerprinting
import re
import warnings
from typing import Dict, List, Optional
from urllib.parse import urljoin

import httpx
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

_CMS_SIGNATURES = {
    "WordPress": {
        "html_patterns": [r"wp-content/", r"wp-includes/", r"wp-json"],
        "meta_generator": r"WordPress\s*([\d.]+)?",
        "paths": ["/wp-login.php", "/wp-admin/", "/xmlrpc.php"],
        "cve_note": "WordPress ที่ไม่อัปเดตเป็นเป้าหมาย ransomware",
    },
    "Joomla": {
        "html_patterns": [r"/components/com_", r"/modules/mod_", r"Joomla!"],
        "meta_generator": r"Joomla!\s*([\d.]+)?",
        "paths": ["/administrator/", "/index.php?option=com_"],
        "cve_note": "Joomla core CVE มักถูก exploit ใน education sector",
    },
    "Moodle": {
        "html_patterns": [r"/lib/yui/", r"/theme/", r"moodle"],
        "meta_generator": r"Moodle\s*([\d.]+)?",
        "paths": ["/login/index.php", "/admin/"],
        "cve_note": "Moodle LMS ใช้กันมากในมหาวิทยาลัยไทย",
    },
    "Drupal": {
        "html_patterns": [r"Drupal\.settings", r"sites/default/files", r"/core/misc/drupal"],
        "meta_generator": r"Drupal\s*([\d.]+)?",
        "paths": ["/user/login", "/admin/"],
        "cve_note": "Drupalgeddon-class vulnerabilities",
    },
}

_DEFAULT_PATHS = ("/wp-admin/", "/administrator/", "/phpmyadmin/", "/phpMyAdmin/")


def _detect_version(html: str, pattern: str) -> Optional[str]:
    m = re.search(pattern, html, re.I)
    if m and m.lastindex:
        return m.group(1)
    return None


def check_cms(url: str) -> Dict:
    """ตรวจ CMS จาก HTML patterns, meta generator, default paths"""
    result: Dict = {
        "detected_cms": None,
        "version": None,
        "confidence": "none",
        "indicators": [],
        "default_paths_accessible": [],
        "xmlrpc_enabled": False,
        "findings": [],
        "score": 100,
        "error": None,
    }

    try:
        with httpx.Client(
            timeout=12,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "VulnexScanner/1.0 (+https://vulnex.example.com/scanner-info)"},
        ) as client:
            resp = client.get(url)
            html = resp.text
            soup = BeautifulSoup(html, "lxml")
            score = 100

            # Meta generator
            gen_tag = soup.find("meta", {"name": "generator"})
            generator = gen_tag.get("content", "") if gen_tag else ""

            best_cms = None
            best_score = 0
            version = None

            for cms_name, sig in _CMS_SIGNATURES.items():
                hits = 0
                for pat in sig["html_patterns"]:
                    if re.search(pat, html, re.I):
                        hits += 1
                        result["indicators"].append(f"{cms_name}: HTML pattern {pat}")
                if generator and re.search(sig["meta_generator"], generator, re.I):
                    hits += 2
                    ver = _detect_version(generator, sig["meta_generator"])
                    if ver:
                        version = ver
                if hits > best_score:
                    best_score = hits
                    best_cms = cms_name

            if best_cms and best_score >= 1:
                result["detected_cms"] = best_cms
                result["version"] = version
                result["confidence"] = "high" if best_score >= 2 else "medium"
                sig = _CMS_SIGNATURES[best_cms]
                result["findings"].append({
                    "severity": "INFO",
                    "title": f"CMS detected: {best_cms}",
                    "detail": f"Version: {version or 'unknown'} — {sig['cve_note']}",
                })
                if version:
                    # Penalize if version looks old (simple heuristic)
                    try:
                        major = int(version.split(".")[0])
                        if best_cms == "WordPress" and major < 6:
                            score -= 15
                            result["findings"].append({
                                "severity": "MEDIUM",
                                "title": "WordPress version อาจล้าสมัย",
                                "detail": f"Detected v{version}",
                            })
                    except (ValueError, IndexError):
                        pass
                else:
                    score -= 5  # version hidden is good, but CMS exposed

            # Default paths
            for path in _DEFAULT_PATHS:
                target = urljoin(url.rstrip("/") + "/", path.lstrip("/"))
                try:
                    pr = client.head(target, timeout=5)
                    if pr.status_code in (200, 301, 302, 403):
                        result["default_paths_accessible"].append({"path": path, "status": pr.status_code})
                        if pr.status_code == 200:
                            result["findings"].append({
                                "severity": "MEDIUM",
                                "title": f"Default path accessible: {path}",
                                "detail": f"HTTP {pr.status_code}",
                            })
                            score -= 10
                except Exception:
                    pass

            # WordPress XML-RPC
            if result["detected_cms"] == "WordPress" or "/wp-content/" in html:
                xmlrpc = urljoin(url.rstrip("/") + "/", "xmlrpc.php")
                try:
                    xr = client.post(xmlrpc, content=b"", timeout=5)
                    if xr.status_code == 200 and "XML-RPC" in xr.text:
                        result["xmlrpc_enabled"] = True
                        result["findings"].append({
                            "severity": "MEDIUM",
                            "title": "WordPress XML-RPC enabled",
                            "detail": "brute-force vector — แนะนำปิด xmlrpc.php",
                        })
                        score -= 15
                except Exception:
                    pass

            result["score"] = max(0, min(100, score))

    except Exception as exc:
        result["error"] = str(exc)

    return result
