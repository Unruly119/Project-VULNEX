# src/scanner/headers.py
import re
import httpx
from typing import Dict

# ── Weighted headers — sum = 100 ─────────────────────────────────
# CSP และ HSTS คือ critical สุด, Referrer/Permissions เป็น nice-to-have
HEADER_WEIGHTS: Dict[str, int] = {
    "Content-Security-Policy":   30,
    "Strict-Transport-Security": 25,
    "X-Frame-Options":           20,
    "X-Content-Type-Options":    15,
    "Referrer-Policy":            5,
    "Permissions-Policy":         5,
}
assert sum(HEADER_WEIGHTS.values()) == 100, "weights must sum to 100"

# ── Security headers ที่ตรวจสอบ (ใช้ใน app.py hdr_defs ด้วย) ─────
SECURITY_HEADERS = list(HEADER_WEIGHTS.keys())


def _quality(header: str, value: str) -> float:
    """
    คืน 0.0–1.0 ตาม configuration quality ของ header ที่พบ
    ป้องกัน gamification: header ที่ present แต่ misconfigured ไม่ได้คะแนนเต็ม

    1.0 = configured correctly
    0.5 = present but weakened
    0.2 = present but effectively useless
    """
    v = value.strip().lower()

    if header == "Content-Security-Policy":
        if not v or v == "*":
            return 0.2
        # แต่ละ unsafe directive หักคะแนน
        penalty = (0.30 if "unsafe-inline" in v else 0.0) + \
                  (0.20 if "unsafe-eval"   in v else 0.0)
        return max(0.25, 1.0 - penalty)

    if header == "Strict-Transport-Security":
        m = re.search(r"max-age=(\d+)", v)
        if not m:
            return 0.3
        age = int(m.group(1))
        if age >= 31_536_000: return 1.0   # ≥ 1 ปี ✅
        if age >=  2_592_000: return 0.7   # ≥ 30 วัน
        return 0.4                          # < 30 วัน — สั้นเกินไป

    if header == "X-Frame-Options":
        return 1.0 if v in ("deny", "sameorigin") else 0.3

    if header == "X-Content-Type-Options":
        return 1.0 if "nosniff" in v else 0.3

    # Referrer-Policy, Permissions-Policy: แค่มีก็พอ
    return 1.0


def check_headers(url: str) -> Dict:
    """
    ดึง Security Headers จาก URL และคำนวณ weighted quality score

    Score breakdown:
      - CSP   : 30 pts (quality-adjusted)
      - HSTS  : 25 pts (quality-adjusted)
      - XFO   : 20 pts (quality-adjusted)
      - XCTO  : 15 pts (quality-adjusted)
      - RP    :  5 pts
      - PP    :  5 pts
    """
    result: Dict = {
        "url":             url,
        "headers_found":   {},
        "headers_missing": [],
        "headers_quality": {},   # quality multiplier ต่อ header (0.0–1.0)
        "score":           0,
        "error":           None,
    }

    try:
        # GET แทน HEAD — หลาย server/CDN ไม่ inject security headers บน HEAD
        with httpx.Client(
            timeout=10,
            follow_redirects=True,
            verify=False,  # ยอมรับ expired cert — เพื่อยังสแกนได้
        ) as client:
            response = client.get(url, headers={"Accept": "text/html"})

        weighted_score = 0.0
        for header, weight in HEADER_WEIGHTS.items():
            # httpx headers เป็น case-insensitive dict อยู่แล้ว
            if header.lower() in response.headers:
                val     = response.headers[header.lower()]
                quality = _quality(header, val)
                result["headers_found"][header]   = val
                result["headers_quality"][header] = round(quality, 2)
                weighted_score += weight * quality
            else:
                result["headers_missing"].append(header)

        result["score"] = round(weighted_score)

    except httpx.TimeoutException:
        result["error"] = "Request timed out"
    except Exception as exc:
        result["error"] = str(exc)

    return result