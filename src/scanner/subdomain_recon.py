# src/scanner/subdomain_recon.py — Subdomain Reconnaissance (passive: crt.sh + SSL SAN)
import json
import re
import ssl
import socket
import warnings
from typing import Dict, List, Set
from urllib.parse import urlparse

import httpx
import urllib3

from utils.network import is_safe_host

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def _extract_domain(url: str) -> str:
    host = urlparse(url).hostname or ""
    parts = host.split(".")
    if len(parts) > 2 and len(parts[-2]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _san_from_cert(hostname: str) -> List[str]:
    """Parse Subject Alternative Names from SSL certificate."""
    names: Set[str] = set()
    try:
        # SECURITY: don't open a raw socket to a non-public host (SSRF).
        if not is_safe_host(hostname):
            return []
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        for typ, val in cert.get("subjectAltName", []):
            if typ == "DNS":
                names.add(val.lower().lstrip("*."))
    except Exception:
        pass
    return sorted(names)


def _crtsh_subdomains(domain: str) -> List[str]:
    """Query crt.sh Certificate Transparency logs — passive."""
    subs: Set[str] = set()
    try:
        # crt.sh is often slow/flaky — cap it (10s connect+read) so this passive
        # recon module never becomes the scan's long pole. On failure we still return
        # whatever the SSL SAN gave us. follow_redirects: crt.sh occasionally 30x.
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        with httpx.Client(timeout=httpx.Timeout(10.0, connect=5.0),
                          verify=True, follow_redirects=True) as client:
            resp = client.get(
                url,
                headers={"User-Agent": "VulnexScanner/1.0 (+https://vulnex.example.com/scanner-info)"},
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            if not isinstance(data, list):
                return []
            for entry in data[:200]:
                name_val = entry.get("name_value", "")
                for name in name_val.split("\n"):
                    name = name.strip().lower()
                    if name.startswith("*."):
                        name = name[2:]
                    if name.endswith(domain) and name != domain:
                        subs.add(name)
    except Exception:
        pass
    return sorted(subs)[:50]


def check_subdomains(url: str) -> Dict:
    """Passive subdomain inventory จาก SSL SAN + crt.sh"""
    hostname = urlparse(url).hostname or ""
    domain = _extract_domain(url)
    result: Dict = {
        "domain": domain,
        "from_cert_san": [],
        "from_crtsh": [],
        "all_subdomains": [],
        "count": 0,
        "warnings": [],
        "findings": [],
        "score": 100,
        "error": None,
    }

    if not domain:
        result["error"] = "Cannot extract domain"
        return result

    san = _san_from_cert(hostname) if url.startswith("https://") else []
    crtsh = _crtsh_subdomains(domain)

    result["from_cert_san"] = [s for s in san if s != domain and s.endswith(domain)]
    result["from_crtsh"] = crtsh

    all_subs = sorted(set(result["from_cert_san"] + result["from_crtsh"]))
    result["all_subdomains"] = all_subs
    result["count"] = len(all_subs)

    # Passive warnings — admin/mail/dev subdomains
    _SENSITIVE = ("admin", "mail", "webmail", "dev", "staging", "test", "api", "portal")
    for sub in all_subs:
        prefix = sub.replace(f".{domain}", "").split(".")[0]
        if prefix in _SENSITIVE:
            result["warnings"].append(f"Subdomain '{sub}' อาจเป็นพื้นที่ sensitive")
            result["findings"].append({
                "severity": "LOW",
                "title": f"Sensitive subdomain: {sub}",
                "detail": "ตรวจสอบว่ามี security controls เพียงพอ",
            })

    if result["count"] > 20:
        result["findings"].append({
            "severity": "INFO",
            "title": "Subdomain inventory ใหญ่",
            "detail": f"พบ {result['count']} subdomains — ตรวจสอบ shadow IT",
        })

    result["score"] = max(60, 100 - len(result["findings"]) * 5)
    return result
