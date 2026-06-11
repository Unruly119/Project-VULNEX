# src/scanner/http_methods.py — HTTP Method & Verb Tampering Scanner
import warnings
from typing import Dict, List

import httpx
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

_DANGEROUS_METHODS = ("TRACE", "TRACK", "PUT", "DELETE", "PROPFIND", "MKCOL", "COPY")
_OVERRIDE_HEADERS = ("X-HTTP-Method-Override", "X-Method-Override")


def check_http_methods(url: str) -> Dict:
    """ตรวจ OPTIONS Allow header และ dangerous HTTP methods — passive only"""
    result: Dict = {
        "allowed_methods": [],
        "dangerous_enabled": [],
        "override_headers_accepted": [],
        "findings": [],
        "score": 100,
        "error": None,
    }

    try:
        with httpx.Client(
            timeout=10,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "VulnexScanner/1.0 (+https://vulnex.example.com/scanner-info)"},
        ) as client:
            # OPTIONS
            opt = client.options(url)
            allow = opt.headers.get("allow", "")
            if allow:
                methods = [m.strip().upper() for m in allow.split(",")]
                result["allowed_methods"] = methods
            else:
                methods = []

            score = 100
            for method in _DANGEROUS_METHODS:
                if method in methods:
                    result["dangerous_enabled"].append(method)
                    sev = "HIGH" if method in ("TRACE", "TRACK") else "MEDIUM"
                    result["findings"].append({
                        "severity": sev,
                        "title": f"HTTP {method} enabled",
                        "detail": f"Allow header ระบุ {method} — attack surface",
                    })
                    score -= 25 if method in ("TRACE", "TRACK") else 15
                else:
                    # probe individual method if not in Allow
                    try:
                        resp = client.request(method, url)
                        if resp.status_code not in (405, 501, 403, 401):
                            result["dangerous_enabled"].append(method)
                            sev = "HIGH" if method in ("TRACE", "TRACK") else "MEDIUM"
                            result["findings"].append({
                                "severity": sev,
                                "title": f"HTTP {method} responds {resp.status_code}",
                                "detail": f"{method} ไม่ return 405 — อาจเปิดใช้งาน",
                            })
                            score -= 20 if method in ("TRACE", "TRACK") else 12
                    except Exception:
                        pass

            # Verb override headers
            for hdr in _OVERRIDE_HEADERS:
                try:
                    resp = client.post(
                        url,
                        headers={hdr: "DELETE", "Content-Length": "0"},
                        content=b"",
                    )
                    if resp.status_code not in (405, 501, 403, 401, 415):
                        result["override_headers_accepted"].append(hdr)
                        result["findings"].append({
                            "severity": "MEDIUM",
                            "title": f"Method override via {hdr}",
                            "detail": f"Server ตอบ {resp.status_code} เมื่อส่ง {hdr}: DELETE",
                        })
                        score -= 10
                except Exception:
                    pass

            result["score"] = max(0, min(100, score))

    except httpx.TimeoutException:
        result["error"] = "Request timed out"
    except Exception as exc:
        result["error"] = str(exc)

    return result
