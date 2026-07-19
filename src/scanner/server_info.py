# src/scanner/server_info.py
import functools
import re

import httpx

from utils.network import SSRF_EVENT_HOOKS

# ── ตาราง CVE: แหล่งข้อมูลจริงอยู่บน Qdrant (collection vulnex_cve) ─────────────
# เดิม VULN_DB ถูก hardcode ในไฟล์นี้ ตอนนี้ย้ายขึ้น Qdrant แล้ว (ต้นฉบับอยู่ที่
# knowledge/cve_database.json → ingest ด้วย scripts/ingest_knowledge.py). scanner โหลด
# ตารางจาก Qdrant ครั้งเดียวต่อโปรเซส (cache) แล้วจับคู่ช่วงเวอร์ชันในเครื่อง (แม่นยำ/เร็ว)
#
# _FALLBACK_VULN_DB = ตาข่ายนิรภัยเล็ก ๆ เฉพาะ CVE ร้ายแรงที่ถูกโจมตีจริง ใช้เมื่อ Qdrant
# เข้าไม่ถึง เพื่อไม่ให้เครื่องมือความปลอดภัย "แจ้งว่าปลอดภัย" ทั้งที่จริงมีช่องโหว่หนัก
_FALLBACK_VULN_DB = {
    "nginx": [
        {"range": (1,0,0, 1,23,4), "cve": "CVE-2023-44487", "severity": "HIGH",
         "desc": "HTTP/2 Rapid Reset Attack (DoS) — Zero-day 2023",
         "fix": "อัปเกรดเป็น nginx 1.25.3+ หรือใช้ limit_conn/limit_req", "dos": True},
        {"range": (0,9,6, 1,30,3), "cve": "CVE-2026-42533", "severity": "HIGH",
         "desc": "Heap buffer overflow เมื่อใช้ map ร่วมกับ regex",
         "fix": "อัปเกรดเป็น nginx 1.30.4+ หรือ 1.31.3+", "dos": False},
    ],
    "apache": [
        {"range": (2,4,0, 2,4,50), "cve": "CVE-2021-42013", "severity": "CRITICAL",
         "desc": "Path traversal bypass & RCE", "fix": "อัปเกรดเป็น Apache 2.4.51+", "dos": False},
        {"range": (2,4,17, 2,4,66), "cve": "CVE-2026-23918", "severity": "CRITICAL",
         "desc": "HTTP/2 double free → DoS/RCE (CVSS 8.8)",
         "fix": "อัปเกรดเป็น Apache 2.4.67+", "dos": True},
    ],
    "openssl": [
        {"range": (1,0,1, 1,0,1), "cve": "CVE-2014-0160", "severity": "CRITICAL",
         "desc": "Heartbleed — อ่านหน่วยความจำเซิร์ฟเวอร์ กุญแจ/รหัสผ่านรั่ว",
         "fix": "อัปเดต OpenSSL เป็น 1.0.1g+ (แนะนำย้ายไป 3.x)", "dos": False},
    ],
    "iis": [
        {"range": (7,0,0, 10,0,17763), "cve": "CVE-2022-21907", "severity": "CRITICAL",
         "desc": "HTTP Protocol Stack Remote Code Execution",
         "fix": "ติดตั้ง Windows Security Update KB5009557", "dos": False},
    ],
}

# HTTP/2 DoS vuln: nginx < 1.25.3 + HTTP/2 enabled = CVE-2023-44487
H2_DOS_VULN_NGINX_MAX = (1, 25, 3)


@functools.lru_cache(maxsize=1)
def _get_vuln_db() -> dict:
    """โหลดตาราง CVE จาก Qdrant (cache ต่อโปรเซส). ถ้าเข้าไม่ถึง → ใช้ fallback ชุดวิกฤต.

    คืน {server_type: [{range(tuple6), cve, severity, desc, fix, dos}]}.
    """
    db: dict = {}
    try:
        from rag import store  # rag/__init__ เป็น lazy → ไม่ลาก google.generativeai มา
        for e in store.load_cve_entries():
            st = e.get("server_type")
            rng = e.get("range")
            if not st or not rng or len(rng) != 6:
                continue
            db.setdefault(st, []).append({
                "range":    tuple(int(x) for x in rng),
                "cve":      e.get("cve", ""),
                "severity": e.get("severity", "MEDIUM"),
                "desc":     e.get("desc", ""),
                "fix":      e.get("fix", ""),
                "dos":      bool(e.get("dos", False)),
            })
    except Exception:  # noqa: BLE001 — เข้า Qdrant ไม่ได้
        db = {}
    return db or _FALLBACK_VULN_DB


def reload_vuln_db() -> None:
    """ล้าง cache ตาราง CVE (เรียกหลัง re-ingest ถ้าต้องการรีเฟรชโดยไม่รีสตาร์ต)."""
    _get_vuln_db.cache_clear()


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


def _component_type(name: str) -> str | None:
    """แมปชื่อ token (เช่น 'Apache-Coyote', 'OpenSSL', 'PHP') → server_type ในตาราง CVE."""
    n = name.lower()
    if "coyote" in n or "tomcat" in n:
        return "tomcat"
    if "nginx" in n or "openresty" in n:   # openresty อิงเวอร์ชัน nginx
        return "nginx"
    if "apache" in n:
        return "apache"
    if "microsoft-iis" in n or n == "iis":
        return "iis"
    if "lighttpd" in n:
        return "lighttpd"
    if "openssl" in n:
        return "openssl"
    if "php" in n:
        return "php"
    return None


def _extract_components(*headers: str) -> list[tuple[str, tuple]]:
    """ดึงทุก token แบบ 'ชื่อ/เวอร์ชัน' จาก header (Server + X-Powered-By) → [(server_type, ver)].

    ทำให้ตรวจได้หลายส่วนพร้อมกัน เช่น 'Apache/2.4.6 OpenSSL/1.0.1e PHP/8.3.7'
    → apache 2.4.6, openssl 1.0.1, php 8.3.7 (แต่ละตัวจับคู่ CVE ของตัวเอง)
    """
    text = " ".join(h for h in headers if h)
    comps: list[tuple[str, tuple]] = []
    seen: set[tuple[str, tuple]] = set()
    for m in re.finditer(r'([A-Za-z][\w.\-]*)/(\d[\d.]*)', text):
        stype = _component_type(m.group(1))
        ver = _parse_version(m.group(2))
        if stype and ver and (stype, ver) not in seen:
            seen.add((stype, ver))
            comps.append((stype, ver))
    return comps


def _primary_type(raw_lower: str) -> str:
    """ระบุชนิดเซิร์ฟเวอร์หลักสำหรับแสดงผล (ตรวจ substring ไม่ต้องมีเวอร์ชัน)."""
    if "coyote" in raw_lower or "tomcat" in raw_lower:
        return "tomcat"
    if "nginx" in raw_lower or "openresty" in raw_lower:
        return "nginx"
    if "apache" in raw_lower:
        return "apache"
    if "iis" in raw_lower or "microsoft" in raw_lower:
        return "iis"
    if "lighttpd" in raw_lower:
        return "lighttpd"
    if raw_lower.strip():
        return "other"
    return ""


def check_server(url: str) -> dict:
    result = {
        "server_raw":     "",       # ค่าดิบจาก Server header
        "server_type":    "",       # nginx / apache / iis / tomcat / lighttpd / other
        "server_version": "",       # version string (ของเซิร์ฟเวอร์หลัก)
        "version_exposed":False,    # เปิดเผย version = ความเสี่ยงต่ำ
        "http_version":   "",       # HTTP/1.1 หรือ HTTP/2
        "h2_enabled":     False,
        "components":     [],        # ส่วนประกอบที่ตรวจเจอ เช่น ['apache 2.4.6','openssl 1.0.1']
        "vulnerabilities":[],       # CVE list
        "dos_risk":       False,    # DoS risk
        "dos_detail":     "",
        "risk_level":     "LOW",    # LOW / MEDIUM / HIGH / CRITICAL
        "error":          None,
    }

    try:
        with httpx.Client(timeout=10, follow_redirects=True, verify=False,
                          http2=True,
                          event_hooks=SSRF_EVENT_HOOKS) as client:  # SECURITY: SSRF redirect guard
            # SECURITY: GET instead of HEAD — some WAF/CDN don't inject headers on HEAD
            resp = client.get(url, headers={"Accept": "text/html"})

        # ── HTTP version ─────────────────────────────────────
        proto = str(resp.http_version)   # "HTTP/1.1" or "HTTP/2"
        result["http_version"] = proto
        result["h2_enabled"]   = "2" in proto

        # ── Server / X-Powered-By headers ────────────────────
        raw = resp.headers.get("server", "")
        powered = resp.headers.get("x-powered-by", "")
        result["server_raw"] = raw
        result["server_type"] = _primary_type(raw.lower())

        # ── ตรวจว่า version ของเซิร์ฟเวอร์หลักโชว์อยู่ ─────────
        ver_match = re.search(r'[\d]+\.[\d]+[\.\d]*', raw)
        if ver_match:
            result["server_version"]  = ver_match.group()
            result["version_exposed"] = True   # ความเสี่ยงต่ำ แต่ควรซ่อน

        # ── CVE lookup: จับคู่ทุกส่วนประกอบ (server + openssl + php ...) ──
        vuln_db = _get_vuln_db()
        components = _extract_components(raw, powered)
        result["components"] = [f"{st} {'.'.join(map(str, v))}" for st, v in components]

        seen_cve: set[str] = set()
        for stype, ver in components:
            for vuln in vuln_db.get(stype, []):
                lo, hi = vuln["range"][0:3], vuln["range"][3:6]
                if _ver_in_range(ver, lo, hi) and vuln["cve"] not in seen_cve:
                    seen_cve.add(vuln["cve"])
                    result["vulnerabilities"].append({
                        "cve":      vuln["cve"],
                        "severity": vuln["severity"],
                        "desc":     vuln["desc"],
                        "fix":      vuln["fix"],
                    })
                    if vuln.get("dos") and not result["dos_risk"]:
                        result["dos_risk"]   = True
                        result["dos_detail"] = f"{vuln['cve']}: {vuln['desc']}"

        # ── HTTP/2 DoS special case (nginx < 1.25.3 + HTTP/2) ─
        prim_ver = _parse_version(result["server_version"]) if result["server_version"] else None
        if result["server_type"] == "nginx" and result["h2_enabled"] \
                and prim_ver and prim_ver < H2_DOS_VULN_NGINX_MAX:
            result["dos_risk"] = True
            if not result["dos_detail"]:
                result["dos_detail"] = (
                    f"nginx {result['server_version']} + HTTP/2 enabled "
                    f"→ CVE-2023-44487 (HTTP/2 Rapid Reset DoS) — อัปเกรดเป็น 1.25.3+"
                )
            if "CVE-2023-44487" not in seen_cve:
                seen_cve.add("CVE-2023-44487")
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
    url = sys.argv[1] if len(sys.argv) > 1 else "https://nginx.org"
    print(json.dumps(check_server(url), indent=2, ensure_ascii=False))
