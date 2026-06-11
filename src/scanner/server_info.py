# src/scanner/server_info.py
import httpx
import re
from urllib.parse import urlparse

# ── Known vulnerable versions database ─────────────────────────────────────
VULN_DB = {
    "nginx": [
        {"range": (1,0,0,  1,19,9),  "cve": "CVE-2021-23017", "severity": "HIGH",
         "desc": "1-byte memory overwrite via DNS resolver",
         "fix": "อัปเกรดเป็น nginx 1.20.1+ หรือ 1.21.0+"},
        {"range": (1,20,0, 1,20,0),  "cve": "CVE-2021-23017", "severity": "HIGH",
         "desc": "1-byte memory overwrite via DNS resolver",
         "fix": "อัปเกรดเป็น nginx 1.20.1+"},
        {"range": (1,9,5,  1,17,9),  "cve": "CVE-2019-20372", "severity": "MEDIUM",
         "desc": "HTTP request smuggling via crafted URI",
         "fix": "อัปเกรดเป็น nginx 1.17.10+"},
        {"range": (1,0,0,  1,23,4),  "cve": "CVE-2023-44487", "severity": "HIGH",
         "desc": "HTTP/2 Rapid Reset Attack (DoS) — Zero-day 2023",
         "fix": "อัปเกรดเป็น nginx 1.25.3+ หรือ patch limit_conn/limit_req"},
        {"range": (1,1,0,  1,25,3),  "cve": "CVE-2024-24989", "severity": "HIGH",
         "desc": "HTTP/3 NULL pointer dereference (ngx_http_v3)",
         "fix": "อัปเกรดเป็น nginx 1.25.4+"},
        {"range": (1,1,0,  1,25,3),  "cve": "CVE-2024-24990", "severity": "HIGH",
         "desc": "HTTP/3 use-after-free in QUIC connection",
         "fix": "อัปเกรดเป็น nginx 1.25.4+"},
    ],
    "apache": [
        {"range": (2,4,0,  2,4,49),  "cve": "CVE-2021-41773", "severity": "CRITICAL",
         "desc": "Path traversal & RCE — ถูกโจมตีจริงในป่า",
         "fix": "อัปเกรดเป็น Apache 2.4.50+ ทันที"},
        {"range": (2,4,0,  2,4,50),  "cve": "CVE-2021-42013", "severity": "CRITICAL",
         "desc": "Path traversal bypass & RCE (bypass ของ CVE-2021-41773)",
         "fix": "อัปเกรดเป็น Apache 2.4.51+"},
        {"range": (2,4,0,  2,4,55),  "cve": "CVE-2023-25690", "severity": "HIGH",
         "desc": "HTTP request smuggling via mod_proxy",
         "fix": "อัปเกรดเป็น Apache 2.4.56+"},
        {"range": (2,4,0,  2,4,59),  "cve": "CVE-2024-27316", "severity": "HIGH",
         "desc": "HTTP/2 CONTINUATION flood — memory exhaustion DoS",
         "fix": "อัปเกรดเป็น Apache 2.4.59+"},
        {"range": (2,4,0,  2,4,59),  "cve": "CVE-2024-38476", "severity": "HIGH",
         "desc": "SSRF via mod_rewrite with backend UDS",
         "fix": "อัปเกรดเป็น Apache 2.4.60+"},
    ],
    "iis": [
        {"range": (7,0,0, 10,0,17763), "cve": "CVE-2022-21907", "severity": "CRITICAL",
         "desc": "HTTP Protocol Stack Remote Code Execution",
         "fix": "ติดตั้ง Windows Security Update KB5009557"},
    ],
}

# HTTP/2 DoS vuln: nginx < 1.25.3 + HTTP/2 enabled = CVE-2023-44487
H2_DOS_VULN_NGINX_MAX = (1, 25, 3)

def _parse_version(ver_str: str):
    """แปลง version string เป็น tuple เช่น '1.18.0' → (1,18,0)"""
    nums = re.findall(r'\d+', ver_str)
    if len(nums) >= 3:
        return tuple(int(x) for x in nums[:3])
    elif len(nums) == 2:
        return (int(nums[0]), int(nums[1]), 0)
    return None

def _ver_in_range(ver, lo, hi):
    """ตรวจว่า version อยู่ในช่วง [lo, hi]"""
    lo_t = lo if isinstance(lo, tuple) else tuple(lo)
    hi_t = hi if isinstance(hi, tuple) else tuple(hi)
    return lo_t <= ver <= hi_t

def check_server(url: str) -> dict:
    result = {
        "server_raw":     "",       # ค่าดิบจาก Server header
        "server_type":    "",       # nginx / apache / iis / unknown
        "server_version": "",       # version string
        "version_exposed":False,    # เปิดเผย version = ความเสี่ยงต่ำ
        "http_version":   "",       # HTTP/1.1 หรือ HTTP/2
        "h2_enabled":     False,
        "vulnerabilities":[],       # CVE list
        "dos_risk":       False,    # HTTP/2 DoS risk
        "dos_detail":     "",
        "risk_level":     "LOW",    # LOW / MEDIUM / HIGH / CRITICAL
        "error":          None,
    }

    try:
        with httpx.Client(timeout=10, follow_redirects=True, verify=False,
                          http2=True) as client:
            # SECURITY: GET instead of HEAD — some WAF/CDN don't inject headers on HEAD
            resp = client.get(url, headers={"Accept": "text/html"})

        # ── HTTP version ─────────────────────────────────────
        proto = str(resp.http_version)   # "HTTP/1.1" or "HTTP/2"
        result["http_version"] = proto
        result["h2_enabled"]   = "2" in proto

        # ── Server header ─────────────────────────────────────
        raw = resp.headers.get("server", "")
        result["server_raw"] = raw

        raw_lower = raw.lower()
        if "nginx" in raw_lower:
            result["server_type"] = "nginx"
        elif "apache" in raw_lower:
            result["server_type"] = "apache"
        elif "iis" in raw_lower or "microsoft" in raw_lower:
            result["server_type"] = "iis"
        elif raw:
            result["server_type"] = "other"

        # ── ตรวจว่า version โชว์อยู่ ─────────────────────────
        ver_match = re.search(r'[\d]+\.[\d]+[\.\d]*', raw)
        if ver_match:
            result["server_version"]  = ver_match.group()
            result["version_exposed"] = True   # ความเสี่ยงต่ำ แต่ควรซ่อน

        # ── CVE lookup ───────────────────────────────────────
        stype = result["server_type"]
        ver   = _parse_version(result["server_version"]) if result["server_version"] else None

        if stype in VULN_DB and ver:
            for vuln in VULN_DB[stype]:
                lo = vuln["range"][0:3]
                hi = vuln["range"][3:6]
                if _ver_in_range(ver, lo, hi):
                    result["vulnerabilities"].append({
                        "cve":      vuln["cve"],
                        "severity": vuln["severity"],
                        "desc":     vuln["desc"],
                        "fix":      vuln["fix"],
                    })

        # ── HTTP/2 DoS check (nginx CVE-2023-44487) ──────────
        if stype == "nginx" and result["h2_enabled"]:
            if ver and ver < H2_DOS_VULN_NGINX_MAX:
                result["dos_risk"]   = True
                result["dos_detail"] = (
                    f"nginx {result['server_version']} + HTTP/2 enabled "
                    f"→ CVE-2023-44487 (HTTP/2 Rapid Reset DoS) — "
                    f"อัปเกรดเป็น 1.25.3+ หรือปิด HTTP/2 ชั่วคราว"
                )
                # เพิ่มใน vuln list ถ้ายังไม่มี
                if not any(v["cve"]=="CVE-2023-44487" for v in result["vulnerabilities"]):
                    result["vulnerabilities"].append({
                        "cve":      "CVE-2023-44487",
                        "severity": "HIGH",
                        "desc":     "HTTP/2 Rapid Reset Attack (DoS Zero-day 2023)",
                        "fix":      "อัปเกรด nginx เป็น 1.25.3+ หรือเพิ่ม limit_conn/limit_req",
                    })

        # ── คำนวณ risk level รวม ────────────────────────────
        sevs = [v["severity"] for v in result["vulnerabilities"]]
        if "CRITICAL" in sevs:   result["risk_level"] = "CRITICAL"
        elif "HIGH" in sevs:     result["risk_level"] = "HIGH"
        elif "MEDIUM" in sevs:   result["risk_level"] = "MEDIUM"
        elif result["version_exposed"]: result["risk_level"] = "LOW"

    except Exception as e:
        result["error"] = str(e)

    return result

if __name__ == "__main__":
    import json, sys
    url = sys.argv[1] if len(sys.argv)>1 else "https://nginx.org"
    print(json.dumps(check_server(url), indent=2, ensure_ascii=False))
