# src/scanner/cookie_security.py — Cookie Security Analyzer
import re
import warnings
from typing import Dict, List
from urllib.parse import urlparse

import httpx
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

_SESSION_NAMES = frozenset({
    "phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid",
    "sessionid", "session_id", "sid", "cfid", "cftoken",
})
_SET_COOKIE_RE = re.compile(
    r"([^=]+)=([^;]*)(?:;\s*([^=]+)(?:=([^;]*))?)?",
    re.I,
)


def _parse_set_cookie(header_val: str) -> Dict:
    parts = [p.strip() for p in header_val.split(";")]
    if not parts:
        return {}
    name_val = parts[0]
    eq = name_val.find("=")
    name = name_val[:eq].strip() if eq > 0 else name_val
    attrs: Dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[part.strip().lower()] = "true"
    return {
        "name": name,
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": attrs.get("samesite", "").lower(),
        "domain": attrs.get("domain", ""),
        "path": attrs.get("path", "/"),
        "expires": attrs.get("expires", ""),
        "max_age": attrs.get("max-age", ""),
        "is_session_name": name.lower() in _SESSION_NAMES,
    }


def check_cookies(url: str) -> Dict:
    """Parse Set-Cookie headers และตรวจ Secure/HttpOnly/SameSite"""
    is_https = url.startswith("https://")
    result: Dict = {
        "cookies": [],
        "issues": [],
        "findings": [],
        "session_cookies": [],
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
            response = client.get(url)

        raw_cookies = []
        for key, val in response.headers.raw:
            if key.decode("latin-1").lower() == "set-cookie":
                raw_cookies.append(val.decode("latin-1"))
        if not raw_cookies:
            sc = response.headers.get("set-cookie")
            if sc:
                raw_cookies = [sc]

        if not raw_cookies:
            result["score"] = 100  # no cookies = nothing to penalize
            return result

        score = 100
        per_cookie_penalty = max(5, 80 // max(len(raw_cookies), 1))

        for raw in raw_cookies:
            cookie = _parse_set_cookie(raw)
            cookie["raw"] = raw[:120]
            issues: List[str] = []

            if is_https and not cookie["secure"]:
                issues.append("ไม่มี Secure flag บน HTTPS")
            if not cookie["httponly"]:
                issues.append("ไม่มี HttpOnly — JavaScript อ่านได้")
            ss = cookie["samesite"]
            if not ss:
                issues.append("ไม่มี SameSite attribute")
            elif ss == "none" and not cookie["secure"]:
                issues.append("SameSite=None แต่ไม่มี Secure — CSRF risk")

            if cookie["is_session_name"] and not cookie["httponly"]:
                issues.append("Session cookie ไม่มี HttpOnly — session hijacking risk")
                result["session_cookies"].append(cookie["name"])

            domain = cookie.get("domain", "")
            if domain.startswith(".") and domain.count(".") <= 2:
                issues.append(f"Domain scope กว้าง ({domain}) — แชร์ข้าม subdomain")

            cookie["issues"] = issues
            result["cookies"].append(cookie)

            if issues:
                penalty = min(per_cookie_penalty * len(issues), 40)
                score -= penalty
                sev = "HIGH" if cookie["is_session_name"] and not cookie["httponly"] else "MEDIUM"
                result["findings"].append({
                    "severity": sev,
                    "title": f"Cookie '{cookie['name']}' ไม่ปลอดภัย",
                    "detail": "; ".join(issues),
                })

        result["issues"] = [f["detail"] for f in result["findings"]]
        result["score"] = max(0, min(100, score))

    except httpx.TimeoutException:
        result["error"] = "Request timed out"
    except Exception as exc:
        result["error"] = str(exc)

    return result
