# src/scanner/http_methods.py — HTTP Method & Verb Tampering Scanner
import warnings
from typing import Dict, List

import httpx
import urllib3

from utils.network import SSRF_EVENT_HOOKS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

_DANGEROUS_METHODS = ("TRACE", "TRACK", "PUT", "DELETE", "PROPFIND", "MKCOL", "COPY")
_OVERRIDE_HEADERS = ("X-HTTP-Method-Override", "X-Method-Override")


def check_http_methods(url: str) -> Dict:
    """ตรวจ OPTIONS Allow header และ dangerous HTTP methods.

    SECURITY / PRODUCT DISCREPANCY (flag — decision required, do not silently change):
    Despite the app-wide "Passive Scan Only" claim, this module ACTIVELY sends
    PUT / DELETE / PROPFIND / MKCOL / COPY and TRACE/TRACK requests, plus a POST
    carrying `X-HTTP-Method-Override: DELETE`, to the target. On a misconfigured
    server these verbs are state-changing (create/delete/move a resource) — i.e.
    NOT passive. Options for the maintainers:
      (a) restrict probing to OPTIONS + the Allow header only (fully passive), or
      (b) gate the active verb probes behind an explicit, documented opt-in and
          update the "Passive Scan Only" wording site-wide.
    Left unchanged here on purpose — see SECURITY-AUDIT.md, finding A1.
    """
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
            event_hooks=SSRF_EVENT_HOOKS,  # SECURITY: block redirects to internal hosts (SSRF)
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
