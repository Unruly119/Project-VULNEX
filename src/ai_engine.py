# src/ai_engine.py — เชื่อมต่อ Gemini API
import hashlib
import json
import os
import re
import time
import warnings
from dotenv import load_dotenv
# ปิด FutureWarning จาก google-generativeai (deprecated แต่ยังใช้งานได้)
warnings.filterwarnings("ignore", category=FutureWarning, module="google.generativeai")
import google.generativeai as genai
import google.api_core.exceptions
from cachetools import TTLCache
from prompt_builder import build_prompt

load_dotenv()

# ── Configure API Key ─────────────────────────────────────────────
API_KEY = os.getenv("GEMINI_API_KEY")
if API_KEY:
    genai.configure(api_key=API_KEY)

# ── Model list — fallback จากเบา/เร็วไปหนัก ──────────────────────
# gemini-2.0-flash / 2.0-flash-lite ปิด free tier แล้ว (quota limit: 0)
# ใช้ 2.5 Flash-Lite / 2.5 Flash / 1.5 Flash บน free tier แทน
_DEFAULT_MODELS = [
    "gemini-2.5-flash-lite",
    "gemini-2.5-flash",
    "gemini-1.5-flash",
]

MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite")

_MAX_RETRIES_PER_MODEL = 3
_BASE_BACKOFF_SEC = 2.0
_MAX_BACKOFF_SEC = 60.0

_GEN_CONFIG = {
    "temperature":       0.15,   # ต่ำ = consistent เหมาะ security analysis
    "max_output_tokens": 2048,
}

# คำแนะนำแก้ไข header แบบ rule-based (offline fallback)
_HEADER_FIXES: dict[str, str] = {
    "Content-Security-Policy": (
        "เพิ่ม CSP header เช่น `default-src 'self'; script-src 'self'` "
        "และหลีกเลี่ยง `unsafe-inline` / `unsafe-eval`"
    ),
    "Strict-Transport-Security": (
        "เพิ่ม HSTS: `Strict-Transport-Security: max-age=31536000; includeSubDomains`"
    ),
    "X-Frame-Options": "เพิ่ม `X-Frame-Options: DENY` หรือ `SAMEORIGIN`",
    "X-Content-Type-Options": "เพิ่ม `X-Content-Type-Options: nosniff`",
    "Referrer-Policy": (
        "เพิ่ม `Referrer-Policy: strict-origin-when-cross-origin`"
    ),
    "Permissions-Policy": (
        "เพิ่ม Permissions-Policy เพื่อจำกัด camera, microphone, geolocation"
    ),
}

_HEADER_DESC: dict[str, str] = {
    "Content-Security-Policy":   "ป้องกัน XSS Attack",
    "Strict-Transport-Security": "บังคับใช้ HTTPS เสมอ",
    "X-Frame-Options":           "ป้องกัน Clickjacking",
    "X-Content-Type-Options":    "ป้องกัน MIME Sniffing",
    "Referrer-Policy":           "ควบคุมข้อมูล Referrer",
    "Permissions-Policy":        "จำกัด Browser API",
}


def _build_fallback_models() -> list[str]:
    """รวม GEMINI_MODEL จาก env กับ default list โดยไม่ซ้ำ"""
    models: list[str] = []
    for name in (MODEL_NAME, *_DEFAULT_MODELS):
        if name and name not in models:
            models.append(name)
    return models


def _parse_retry_delay(exc: Exception) -> float | None:
    """ดึง retry delay จากข้อความ API เช่น 'Please retry in 13.66s'"""
    match = re.search(r"retry in ([\d.]+)\s*s", str(exc), re.IGNORECASE)
    if match:
        return min(float(match.group(1)), _MAX_BACKOFF_SEC)
    return None


def _is_quota_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return (
        "quota" in msg
        or "resource exhausted" in msg
        or "429" in msg
        or "rate limit" in msg
        or "limit: 0" in msg
    )


def _format_ai_error(exc: Exception) -> str:
    """ข้อความ error ที่เข้าใจง่าย (ไทย + อังกฤษ)"""
    if isinstance(exc, google.api_core.exceptions.NotFound):
        return "Gemini model not found — โมเดลไม่รองรับหรือถูกปิดใช้งานแล้ว"

    if _is_quota_error(exc):
        return (
            "Gemini API quota exceeded (โควต้าหมด) — "
            "free tier ของโมเดลนี้ไม่พร้อมใช้งาน กรุณารอสักครู่ "
            "หรือเปลี่ยน API key / เปิด billing ใน Google AI Studio"
        )

    if isinstance(exc, google.api_core.exceptions.Unauthenticated):
        return "Gemini API key ไม่ถูกต้อง — ตรวจสอบ GEMINI_API_KEY ในไฟล์ .env"

    if isinstance(exc, google.api_core.exceptions.PermissionDenied):
        return "Gemini API permission denied — API key ไม่มีสิทธิ์ใช้งานโมเดลนี้"

    return f"Gemini API error: {exc}"


def _backoff_seconds(attempt: int, exc: Exception | None = None) -> float:
    """คำนวณเวลารอก่อน retry — ใช้ delay จาก API ถ้ามี"""
    api_delay = _parse_retry_delay(exc) if exc else None
    if api_delay is not None:
        return api_delay + 0.5
    return min(_BASE_BACKOFF_SEC * (2 ** attempt), _MAX_BACKOFF_SEC)


def generate_with_fallback(prompt: str) -> str:
    """
    ลอง model ทีละตัว พร้อม retry + backoff สำหรับ 429/quota
    คืน text string โดยตรง
    """
    models = _build_fallback_models()
    last_exc: Exception | None = None
    quota_hits = 0

    for model_name in models:
        for attempt in range(_MAX_RETRIES_PER_MODEL):
            try:
                m = genai.GenerativeModel(model_name, generation_config=_GEN_CONFIG)
                response = m.generate_content(prompt)
                return response.text
            except google.api_core.exceptions.ResourceExhausted as exc:
                last_exc = exc
                if _is_quota_error(exc):
                    quota_hits += 1
                if attempt < _MAX_RETRIES_PER_MODEL - 1:
                    time.sleep(_backoff_seconds(attempt, exc))
                    continue
                break
            except google.api_core.exceptions.NotFound as exc:
                last_exc = exc
                break
            except google.api_core.exceptions.TooManyRequests as exc:
                last_exc = exc
                quota_hits += 1
                if attempt < _MAX_RETRIES_PER_MODEL - 1:
                    time.sleep(_backoff_seconds(attempt, exc))
                    continue
                break
            except Exception as exc:
                last_exc = exc
                break

    if quota_hits and last_exc and _is_quota_error(last_exc):
        raise RuntimeError(
            f"โควต้า Gemini API หมดแล้ว (ลอง {len(models)} โมเดล) — "
            f"{_format_ai_error(last_exc)}"
        )
    raise RuntimeError(f"ทุก model ล้มเหลว: {_format_ai_error(last_exc)}")


# ── Cache AI text เท่านั้น (score คำนวณใหม่ทุกครั้ง) ──────────────
_analysis_cache: TTLCache = TTLCache(maxsize=50, ttl=3600)


def _make_cache_key(scan_data: dict, server_data: dict) -> str:
    """Cache key based on scan content, not URL."""
    headers_found = scan_data.get("headers", {}).get("headers_found", {}) or {}
    payload = {
        "url":     scan_data.get("url", ""),
        "headers": sorted(headers_found.items()),
        "ssl_ok":  scan_data.get("ssl", {}).get("valid"),
        "tls_ver": scan_data.get("ssl", {}).get("tls_version"),
        "vulns":   sorted(v["cve"] for v in server_data.get("vulnerabilities", [])),
        "dos":     server_data.get("dos_risk", False),
        "sri":     scan_data.get("html", {}).get("scripts_missing_sri", 0),
    }
    raw = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


# ─────────────────────────────────────────────────────────────────
# Score engine
# ─────────────────────────────────────────────────────────────────

def _compute_score(scan_data: dict, server_data: dict) -> tuple[int, str, dict]:
    """
    Composite security score (0–100) จากทุก signal ที่มี

    Sub-scores:
      Headers  40 pts  — weighted + quality-adjusted (จาก headers.py)
      SSL      25 pts  — validity + days remaining
      CVE/DoS  25 pts  — severity-weighted + DoS flag
      Server   10 pts  — version disclosure

    Risk level (ตรวจ harshest condition ก่อน):
      CRITICAL — score < 30  OR  CRITICAL CVE  OR  (DoS AND score < 55)
      HIGH     — score < 50  OR  HIGH CVE
      MEDIUM   — score < 70  OR  SSL invalid
      LOW      — score ≥ 70  AND SSL valid  AND  ไม่มี HIGH+ CVE
    """
    # ── 1. Headers (0–40) ────────────────────────────────────────
    raw_hdr = int(scan_data.get("headers", {}).get("score", 0) or 0)
    hdr_pts = round(raw_hdr * 0.40)   # scale 0-100 → 0-40

    # ── 2. SSL (0–25) ────────────────────────────────────────────
    ssl       = scan_data.get("ssl", {}) or {}
    ssl_ok    = bool(ssl.get("valid", False))
    days_left = int(ssl.get("days_left", 0) or 0)

    ssl_pts = 0
    if ssl_ok:
        ssl_pts += 15
        if   days_left > 60: ssl_pts += 10  # สบาย
        elif days_left > 30: ssl_pts += 5   # ใกล้หมด
        # ≤ 30 วัน: +0 (warning zone)

    # ── 3. CVE / DoS (0–25) ──────────────────────────────────────
    vulns    = server_data.get("vulnerabilities", []) or []
    dos_risk = bool(server_data.get("dos_risk", False))

    _PENALTY = {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 5, "LOW": 2}
    cve_penalty = sum(
        _PENALTY.get(str(v.get("severity", "")).upper(), 2) for v in vulns
    )
    if dos_risk:
        cve_penalty += 15   # CVE-2023-44487 HTTP/2 Rapid Reset

    cve_pts = max(0, 25 - cve_penalty)

    # ── 4. Server hygiene (0–10) ──────────────────────────────────
    srv_pts = 5 if server_data.get("version_exposed") else 10

    # ── Composite ─────────────────────────────────────────────────
    total = min(100, hdr_pts + ssl_pts + cve_pts + srv_pts)

    # ── Risk level ────────────────────────────────────────────────
    sev_set      = {str(v.get("severity", "")).upper() for v in vulns}
    has_critical = "CRITICAL" in sev_set
    has_high     = "HIGH"     in sev_set

    if total < 30 or has_critical or (dos_risk and total < 55):
        risk = "CRITICAL"
    elif total < 50 or has_high:
        risk = "HIGH"
    elif total < 70 or not ssl_ok:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    breakdown = {
        "headers": hdr_pts,
        "ssl":     ssl_pts,
        "cve":     cve_pts,
        "server":  srv_pts,
    }

    return total, risk, breakdown


# ─────────────────────────────────────────────────────────────────
# Offline / rule-based analysis (graceful degradation)
# ─────────────────────────────────────────────────────────────────

def _risk_summary_th(risk: str, score: int) -> str:
    _MAP = {
        "CRITICAL": "วิกฤต — ต้องดำเนินการแก้ไขทันที",
        "HIGH":     "สูง — มีช่องโหว่สำคัญที่ควรแก้ไขโดยเร็ว",
        "MEDIUM":   "ปานกลาง — มีจุดที่ต้องปรับปรุง",
        "LOW":      "ต่ำ — โดยรวมอยู่ในเกณฑ์ที่ยอมรับได้",
    }
    return _MAP.get(risk, f"ระดับ {risk} (คะแนน {score}/100)")


def _build_offline_analysis(
    scan_data: dict,
    server_data: dict,
    score: int,
    risk: str,
    breakdown: dict,
) -> str:
    """สร้างรายงานวิเคราะห์จากกฎอัตโนมัติเมื่อ Gemini ไม่พร้อมใช้งาน"""
    url = scan_data.get("url", "เว็บไซต์")
    headers = scan_data.get("headers", {}) or {}
    ssl     = scan_data.get("ssl", {}) or {}
    html    = scan_data.get("html", {}) or {}

    missing   = headers.get("headers_missing", []) or []
    found     = headers.get("headers_found", {}) or {}
    hdr_score = headers.get("score", 0)
    ssl_ok    = bool(ssl.get("valid", False))
    days_left = int(ssl.get("days_left", 0) or 0)
    tls_ver   = ssl.get("tls_version", "Unknown")
    tls_warns = ssl.get("tls_warnings", []) or []
    vulns     = server_data.get("vulnerabilities", []) or []
    dos_risk  = bool(server_data.get("dos_risk", False))
    ver_exp   = bool(server_data.get("version_exposed", False))
    stype     = server_data.get("server_type", "unknown")
    sver      = server_data.get("server_version", "N/A")
    ext_sc    = html.get("external_scripts", []) or []
    ins_fm    = html.get("insecure_forms", []) or []
    scripts_no_sri = int(html.get("scripts_missing_sri", 0) or 0)

    # ── สรุปภาพรวม ──────────────────────────────────────────────
    overview = (
        f"เว็บไซต์ {url} ได้คะแนนความปลอดภัยรวม **{score}/100** "
        f"ระดับความเสี่ยง **{risk}** — {_risk_summary_th(risk, score)} "
        f"(Headers {breakdown.get('headers', 0)}/40, SSL {breakdown.get('ssl', 0)}/25, "
        f"CVE/DoS {breakdown.get('cve', 0)}/25, Server {breakdown.get('server', 0)}/10)"
    )

    # ── ปัญหาเร่งด่วน ────────────────────────────────────────────
    urgent: list[str] = []

    for v in sorted(vulns, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(
        str(x.get("severity", "")).upper(), 9
    )):
        sev  = v.get("severity", "?")
        cve  = v.get("cve", "?")
        desc = v.get("desc", "")
        urgent.append(f"- **{cve}** ({sev}): {desc}")

    if dos_risk:
        dos_detail = server_data.get("dos_detail", "HTTP/2 Rapid Reset / CONTINUATION flood")
        urgent.append(f"- **HTTP/2 DoS Risk**: {dos_detail}")

    high_missing = [h for h in missing if h in (
        "Content-Security-Policy", "Strict-Transport-Security",
        "X-Frame-Options", "X-Content-Type-Options",
    )]
    for h in high_missing:
        desc = _HEADER_DESC.get(h, "")
        urgent.append(f"- **ขาด {h}** — {desc}")

    if not ssl_ok:
        ssl_warn = ssl.get("warning", "ใบรับรอง SSL ไม่ถูกต้องหรือหมดอายุ")
        urgent.append(f"- **SSL มีปัญหา**: {ssl_warn}")
    elif days_left <= 30:
        urgent.append(f"- **SSL ใกล้หมดอายุ**: เหลือ {days_left} วัน")

    for w in tls_warns:
        urgent.append(f"- **TLS Warning**: {w}")

    if scripts_no_sri > 0:
        urgent.append(
            f"- **External Scripts ไม่มี SRI**: {scripts_no_sri} ตัว — "
            "เสี่ยงต่อ supply-chain attack หาก CDN ถูก compromise"
        )

    if ins_fm:
        urgent.append(
            f"- **Insecure Forms**: {len(ins_fm)} ฟอร์มส่งข้อมูลผ่าน HTTP แทน HTTPS"
        )

    if ver_exp:
        urgent.append(
            f"- **Version Disclosure**: เปิดเผย {stype} {sver} — "
            "ช่วยให้ผู้โจมตีเลือก exploit ได้ตรงเวอร์ชัน"
        )

    urgent_txt = "\n".join(urgent) if urgent else "- ไม่พบปัญหาเร่งด่วนระดับสูงจากข้อมูลสแกน"

    # ── คำแนะนำการแก้ไข ─────────────────────────────────────────
    fixes: list[str] = []

    for v in vulns:
        fix = v.get("fix", "")
        if fix:
            fixes.append(f"- **{v.get('cve', 'CVE')}**: {fix}")

    if dos_risk:
        fixes.append(
            "- **HTTP/2 DoS**: อัปเกรด web server เป็นเวอร์ชันล่าสุด "
            "และเปิดใช้ rate limiting / connection limits"
        )

    for h in missing:
        fix = _HEADER_FIXES.get(h)
        if fix:
            fixes.append(f"- **{h}**: {fix}")

    if not ssl_ok:
        fixes.append(
            "- **SSL**: ติดตั้งใบรับรองจาก CA ที่เชื่อถือได้ "
            "และเปิด redirect HTTP → HTTPS"
        )
    elif days_left <= 60:
        fixes.append(
            f"- **SSL Renewal**: ต่ออายุใบรับรองก่อนหมดอายุ (เหลือ {days_left} วัน)"
        )

    if scripts_no_sri > 0:
        fixes.append(
            "- **SRI**: เพิ่ม `integrity` และ `crossorigin` attribute "
            "ให้ทุก external script tag"
        )

    if ins_fm:
        fixes.append("- **Forms**: เปลี่ยน action ของฟอร์มให้ชี้ไปยัง HTTPS เท่านั้น")

    if ver_exp:
        fixes.append(
            "- **Server Header**: ซ่อนเวอร์ชันใน config "
            "(nginx: `server_tokens off;`, Apache: `ServerTokens Prod`)"
        )

    if hdr_score < 50 and not missing:
        fixes.append(
            "- **Headers Quality**: header มีครบแต่ค่า config อาจอ่อนแอ — "
            "ตรวจสอบ CSP, HSTS max-age และ X-Frame-Options"
        )

    fixes_txt = "\n".join(fixes) if fixes else (
        "- รักษามาตรฐานปัจจุบันและสแกนซ้ำเป็นระยะ"
    )

    # ── จุดที่ดีแล้ว ──────────────────────────────────────────────
    good: list[str] = []

    for h in found:
        good.append(f"- มี **{h}** ({_HEADER_DESC.get(h, 'configured')})")

    if ssl_ok and days_left > 30:
        good.append(f"- **SSL/TLS ปลอดภัย** — {tls_ver}, เหลือ {days_left} วัน")

    if not vulns and not dos_risk:
        good.append("- **ไม่พบ CVE** ที่ตรงกับเวอร์ชัน server ใน database")

    if not ver_exp:
        good.append("- **ซ่อนเวอร์ชัน server** ได้ดี")

    if not ins_fm:
        good.append("- **ฟอร์มทั้งหมดใช้ HTTPS**")

    if scripts_no_sri == 0 and not ext_sc:
        good.append("- **ไม่มี external scripts** ที่ต้องกังวล")
    elif scripts_no_sri == 0:
        good.append("- **External scripts มี SRI** ครบ")

    good_txt = "\n".join(good) if good else "- ยังไม่มีจุดเด่นที่ชัดเจนจากข้อมูลสแกน"

    return f"""## 🔍 สรุปภาพรวม
{overview}

## 🚨 ปัญหาเร่งด่วน (ต้องแก้ทันที)
{urgent_txt}

## 🛠️ คำแนะนำการแก้ไข
{fixes_txt}

## ✅ จุดที่ดีแล้ว
{good_txt}"""


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────

def analyze(scan_data: dict, server_data: dict | None = None) -> dict:
    """
    คำนวณ composite score และดึง AI analysis จาก Gemini

    Args:
        scan_data:   ผลจาก run_scan() — มี headers, ssl
        server_data: ผลจาก check_server() — มี vulnerabilities, dos_risk, version_exposed
                     Optional เพื่อ backward compatibility แต่ควรส่งเสมอ

    Returns dict:
        analysis         — AI analysis text (หรือ offline fallback)
        risk_level       — CRITICAL / HIGH / MEDIUM / LOW
        score            — 0–100 composite
        breakdown        — {"headers": int, "ssl": int, "cve": int, "server": int}
        error            — None หรือ error message
        offline_fallback — True ถ้าใช้ rule-based analysis แทน AI
    """
    server_data = server_data or {}

    # Score คำนวณใหม่ทุกครั้ง (deterministic, ไม่เสีย API quota)
    score, risk, breakdown = _compute_score(scan_data, server_data)

    result = {
        "analysis":         "",
        "risk_level":       risk,
        "score":            score,
        "breakdown":        breakdown,
        "error":            None,
        "offline_fallback": False,
    }

    # AI text — cached by scan fingerprint (หมดอายุ 1 ชั่วโมง)
    cache_key = _make_cache_key(scan_data, server_data)
    if cache_key in _analysis_cache:
        result["analysis"] = _analysis_cache[cache_key]
        return result

    if not API_KEY:
        err_msg = "ไม่พบ GEMINI_API_KEY — ใช้การวิเคราะห์อัตโนมัติแทน"
        result["error"] = err_msg
        result["offline_fallback"] = True
        result["analysis"] = (
            f"> ⚠️ **โหมดวิเคราะห์อัตโนมัติ (Offline)** — {err_msg}\n\n"
            + _build_offline_analysis(scan_data, server_data, score, risk, breakdown)
        )
        return result

    try:
        prompt             = build_prompt(scan_data, server_data, composite_score=score)
        text               = generate_with_fallback(prompt)
        result["analysis"] = text
        _analysis_cache[cache_key] = text
    except Exception as exc:
        err_msg = _format_ai_error(exc)
        result["error"]            = err_msg
        result["offline_fallback"] = True
        offline_body = _build_offline_analysis(
            scan_data, server_data, score, risk, breakdown
        )
        result["analysis"] = (
            f"> ⚠️ **โหมดวิเคราะห์อัตโนมัติ (Offline)** — ไม่สามารถเรียก Gemini AI ได้\n"
            f"> {err_msg}\n\n"
            + offline_body
        )

    return result
