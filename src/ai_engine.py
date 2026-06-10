# src/ai_engine.py — เชื่อมต่อ Gemini API
import os
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
# ตรวจสอบจาก genai.list_models() จริง ณ วันนี้ — models ที่ใช้ generateContent ได้:
#   gemini-2.0-flash-lite, gemini-2.0-flash, gemini-2.5-flash
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-2.0-flash-lite")

_FALLBACK_MODELS = [
    MODEL_NAME,
    "gemini-2.0-flash",
    "gemini-2.5-flash",
]

_GEN_CONFIG = {
    "temperature":       0.15,   # ต่ำ = consistent เหมาะ security analysis
    "max_output_tokens": 2048,
}


def generate_with_fallback(prompt: str) -> str:
    """
    ลอง model ทีละตัว ถ้าเจอ 429 (quota) ให้ retry 1 ครั้ง
    แล้ว fallback model ถัดไป — คืน text string โดยตรง
    """
    last_exc = None
    for model_name in _FALLBACK_MODELS:
        for attempt in range(2):   # max 2 attempts per model
            try:
                m = genai.GenerativeModel(model_name, generation_config=_GEN_CONFIG)
                response = m.generate_content(prompt)
                return response.text
            except google.api_core.exceptions.ResourceExhausted as exc:
                last_exc = exc
                if attempt == 0:
                    time.sleep(5)   # รอ 5 วิ แล้วลองใหม่
                    continue
                break   # retry แล้วยังเจอ → fallback model ถัดไป
            except google.api_core.exceptions.NotFound as exc:
                # 404 model ไม่มี → ลอง model ถัดไปทันที ไม่ต้อง retry
                last_exc = exc
                break
            except Exception as exc:
                last_exc = exc
                break   # error อื่น (auth, network) → ลอง model ถัดไป
    raise RuntimeError(f"ทุก model ล้มเหลว: {last_exc}")


# ── Cache AI text เท่านั้น (score คำนวณใหม่ทุกครั้ง) ──────────────
_analysis_cache: TTLCache = TTLCache(maxsize=50, ttl=3600)


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
        analysis   — AI analysis text
        risk_level — CRITICAL / HIGH / MEDIUM / LOW
        score      — 0–100 composite
        breakdown  — {"headers": int, "ssl": int, "cve": int, "server": int}
        error      — None หรือ error message
    """
    server_data = server_data or {}

    # Score คำนวณใหม่ทุกครั้ง (deterministic, ไม่เสีย API quota)
    score, risk, breakdown = _compute_score(scan_data, server_data)

    result = {
        "analysis":   "",
        "risk_level": risk,
        "score":      score,
        "breakdown":  breakdown,
        "error":      None,
    }

    # AI text — cached per URL (หมดอายุ 1 ชั่วโมง)
    url = scan_data.get("url", "")
    if url and url in _analysis_cache:
        result["analysis"] = _analysis_cache[url]
        return result

    try:
        prompt             = build_prompt(scan_data)
        text               = generate_with_fallback(prompt)
        result["analysis"] = text
        if url:
            _analysis_cache[url] = text   # cache text เท่านั้น ไม่รวม score
    except Exception as exc:
        result["error"]    = str(exc)
        result["analysis"] = f"❌ เรียก AI ไม่สำเร็จ: {exc}"

    return result