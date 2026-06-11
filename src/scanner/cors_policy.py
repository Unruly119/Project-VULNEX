# src/scanner/cors_policy.py — CORS Policy Analyzer (passive preflight)
import warnings
from typing import Dict, List
from urllib.parse import urljoin, urlparse

import httpx
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

_EVIL_ORIGIN = "https://evil.example.com"
_TEST_PATHS = ("/", "/api/", "/api/v1/", "/graphql", "/admin/")


def _test_cors(client: httpx.Client, url: str, path: str) -> Dict:
    target = urljoin(url.rstrip("/") + "/", path.lstrip("/"))
    findings: List[Dict] = []
    score = 100

    headers = {
        "Origin": _EVIL_ORIGIN,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "X-Requested-With",
    }
    try:
        resp = client.options(target, headers=headers)
    except Exception:
        return {"path": path, "tested": False, "findings": [], "score": 100}

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()
    vary = resp.headers.get("vary", "")

    if acao == "*":
        findings.append({"severity": "MEDIUM", "title": "CORS wildcard", "detail": f"{path}: Allow-Origin: *"})
        score -= 20
        if acac == "true":
            findings.append({
                "severity": "CRITICAL",
                "title": "CORS credentials + wildcard",
                "detail": f"{path}: Allow-Credentials: true + Allow-Origin: *",
            })
            score -= 50
    elif acao == _EVIL_ORIGIN or acao == "null":
        findings.append({
            "severity": "CRITICAL",
            "title": "CORS reflects evil origin",
            "detail": f"{path}: Allow-Origin: {acao}",
        })
        score -= 60

    if acao and "origin" not in vary.lower():
        findings.append({
            "severity": "LOW",
            "title": "Missing Vary: Origin",
            "detail": f"{path}: CORS header without Vary: Origin — cache poisoning risk",
        })
        score -= 5

    return {
        "path": path,
        "tested": True,
        "status": resp.status_code,
        "allow_origin": acao,
        "allow_credentials": acac,
        "vary": vary,
        "findings": findings,
        "score": max(0, score),
    }


def check_cors(url: str) -> Dict:
    """ส่ง preflight OPTIONS พร้อม evil origin — passive only"""
    result: Dict = {
        "tests": [],
        "findings": [],
        "score": 100,
        "error": None,
    }

    try:
        with httpx.Client(
            timeout=10,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "VulnexScanner/1.0 (+https://vulnex.example.com/scanner-info)"},
        ) as client:
            scores = []
            for path in _TEST_PATHS:
                test = _test_cors(client, url, path)
                result["tests"].append(test)
                scores.append(test.get("score", 100))
                result["findings"].extend(test.get("findings", []))

        result["score"] = round(sum(scores) / len(scores)) if scores else 100

    except Exception as exc:
        result["error"] = str(exc)

    return result
