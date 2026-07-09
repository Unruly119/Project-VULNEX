# src/ai_engine.py — เชื่อมต่อ Gemini API (+ OpenRouter fallback)
import hashlib
import json
import os
import re
import threading
import time
import warnings
from dotenv import load_dotenv
# ปิด FutureWarning จาก google-generativeai (deprecated แต่ยังใช้งานได้)
warnings.filterwarnings("ignore", category=FutureWarning, module="google.generativeai")
import google.generativeai as genai
import google.api_core.exceptions
import httpx
from cachetools import TTLCache
from prompt_builder import build_prompt, build_chat_prompt

# override=True: ให้ .env เป็นแหล่งความจริงเสมอ — กัน environment variable เก่า
# ที่ค้างในระบบ (เช่น GEMINI_API_KEY เดิม) มาบดบังคีย์ใหม่ใน .env
load_dotenv(override=True)

# ── API Key pool ──────────────────────────────────────────────────
# เก็บคีย์ Gemini ทุกตัวจาก .env เข้าพูลเดียว (เรียงตามความสำคัญ, ตัดซ้ำ)
# รองรับ: GEMINI_API_KEY, GEMINI_API_KEY_Backup, GEMINI_API_KEY_2.._5
_GEMINI_KEY_ENV_NAMES = [
    "GEMINI_API_KEY",
    "GEMINI_API_KEY_Backup",
    "GEMINI_API_KEY_2",
    "GEMINI_API_KEY_3",
    "GEMINI_API_KEY_4",
    "GEMINI_API_KEY_5",
]


def _env_ci(name: str) -> str:
    """Case-insensitive environment lookup.

    Streamlit Cloud runs on Linux where os.environ is CASE-SENSITIVE, while Windows
    (dev) is case-insensitive. A secret typed as GEMINI_API_KEY_BACKUP would then miss
    an exact os.getenv('GEMINI_API_KEY_Backup') on deploy and silently drop that key —
    the kind of env-only bug that never shows up locally. Match by lowercase to be safe."""
    val = os.getenv(name)
    if val is not None:
        return val
    low = name.lower()
    for k, v in os.environ.items():
        if k.lower() == low:
            return v
    return ""


def _load_gemini_keys() -> list[str]:
    keys: list[str] = []
    for name in _GEMINI_KEY_ENV_NAMES:
        val = _env_ci(name).strip()
        if val and val not in keys:
            keys.append(val)
    return keys


GEMINI_KEYS = _load_gemini_keys()
# alias เดิม (backward-compat) — โค้ดเก่าบางจุดยังอ้าง API_KEY / API_KEY_BACKUP
API_KEY = GEMINI_KEYS[0] if GEMINI_KEYS else None
API_KEY_BACKUP = _env_ci("GEMINI_API_KEY_Backup") or None

# ── OpenRouter (ชั้น fallback ถัดจาก Gemini — คีย์ที่ 3) ──────────
OPENROUTER_API_KEY = _env_ci("OPENROUTER_API_KEY").strip() or None
_OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
# ฟรีโมเดลที่ทดสอบแล้วตอบไทยได้ — เรียงฉลาด/เสถียรมากไปน้อย
_OPENROUTER_MODELS = [
    "openai/gpt-oss-120b:free",
    "openai/gpt-oss-20b:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "qwen/qwen3-next-80b-a3b-instruct:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
]
_OPENROUTER_SYSTEM = (
    "You are a Thai cybersecurity expert writing for non-expert school IT staff. "
    "Always respond in Thai. Follow the exact section headings and Markdown format "
    "requested in the user's message. Do not use emoji."
)

if API_KEY:
    genai.configure(api_key=API_KEY)


def _has_any_provider() -> bool:
    """มี AI provider อย่างน้อยหนึ่งตัวพร้อมใช้งานไหม (Gemini คีย์ใดก็ได้ หรือ OpenRouter)"""
    return bool(GEMINI_KEYS or OPENROUTER_API_KEY)


# ── Model list — ฉลาดสุดก่อน แล้วไล่ลงมา ─────────────────────────
# ผู้ใช้ต้องการ "ตัวที่ฉลาดที่สุดก่อน": 2.5-flash (ฉลาดสุดที่ free tier เสถียร)
# → 2.5-flash-lite (เร็ว) → 1.5-flash (สำรอง). ตั้ง GEMINI_MODEL=gemini-2.5-pro
# ใน .env เพื่อดันตัวฉลาดสุดขึ้นหัวแถวได้ (โควต้า free tier น้อย เหมาะงาน traffic ต่ำ)
# gemini-2.0-flash / 2.0-flash-lite ปิด free tier แล้ว (quota limit: 0)
_DEFAULT_MODELS = [
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-1.5-flash",
]

MODEL_NAME = (os.getenv("GEMINI_MODEL") or "").strip()

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


# ── Cooldown ราย (คีย์, โมเดล) — กันยิงคู่ที่โควต้าหมดซ้ำ (สำคัญตอนผู้ใช้เยอะ) ──
# โควต้า Gemini free tier แยกตามโมเดล → flash ของคีย์หนึ่งหมด ไม่ได้แปลว่า
# flash-lite ของคีย์เดียวกันหมด. cooldown จึง key ด้วย (api_key, model_name)
# เพื่อให้ cascade ลดชั้นโมเดลบนคีย์เดิมได้ และคำขอถัดไปข้ามคู่ที่รู้ว่าเต็มทันที
_KEY_COOLDOWN_SEC = 45.0
_key_cooldowns: dict[tuple[str, str], float] = {}
_cooldown_lock = threading.Lock()

# google-generativeai ใช้ global config (genai.configure) — ไม่ thread-safe
# ถ้าผู้ใช้สแกนพร้อมกันหลายคน คีย์อาจถูกเขียนทับกลางคัน ⇒ ล็อกช่วง configure+generate
_genai_lock = threading.Lock()


def _available_keys(keys: list[str], model: str) -> list[str]:
    """คีย์ที่พร้อมใช้กับ 'โมเดลนี้' (คู่ (key,model) ไม่ติด cooldown) — เรียงเดิม;
    ถ้าเต็มหมดคืนตัวที่จะว่างเร็วสุด (เผื่อ cooldown หมดอายุพอดี)"""
    now = time.time()
    with _cooldown_lock:
        ready = [k for k in keys if _key_cooldowns.get((k, model), 0.0) <= now]
        if ready:
            return ready
        return sorted(keys, key=lambda k: _key_cooldowns.get((k, model), 0.0))


def _mark_cooldown(key: str, model: str, seconds: float = _KEY_COOLDOWN_SEC) -> None:
    with _cooldown_lock:
        _key_cooldowns[(key, model)] = time.time() + seconds


def _gemini_generate_once(model_name: str, key: str, prompt: str, gen_config: dict) -> str:
    """เรียก Gemini หนึ่งครั้ง — ล็อก global config ไว้ตลอดช่วง configure+generate
    เพื่อกันคีย์ของผู้ใช้คนอื่นเขียนทับ (concurrency-safe)."""
    with _genai_lock:
        genai.configure(api_key=key)
        m = genai.GenerativeModel(model_name, generation_config=gen_config)
        response = m.generate_content(prompt)
    return response.text


def _generate_gemini(prompt: str, gen_config: dict, keys: list[str]) -> str:
    """Cascade: โมเดลฉลาดสุด "กวาดทุกคีย์" ก่อน แล้วค่อยลดชั้นโมเดล — สลับ "ทันที ไม่มี sleep".

    ลำดับ (โมเดล-นอก / คีย์-ใน):
        flash    → key0,key1,…,keyN      (ฉลาดสุด ลองทุกคีย์ก่อน)
        flash-lite → key0,key1,…,keyN    (ถ้า flash หมดทุกคีย์)
        1.5-flash → key0,key1,…,keyN
    เหตุผล: คีย์แต่ละตัวคือถังโควต้าแยกกัน — ถ้า flash ของ key0 หมด ก็ยังอยากได้
    flash ของ key1 (ฉลาดสุด) ก่อนจะยอมลดชั้น ⇒ ได้ "โมเดลฉลาดสุดที่คีย์ไหนสักตัวยังให้ได้"

    ความเร็ว/ความครบ:
    - โควต้าหมด/429/error ชั่วคราว → cooldown คู่ (key,model) + สลับคีย์ถัดไป *ทันที* (ไม่มี sleep)
    - `dead`: คู่ (key,model) ที่ล้มเหลวในรอบนี้ ไม่ถูกลองซ้ำ
    - โควต้าแยกตามโมเดล ⇒ flash ของ key0 หมด ไม่ปิด flash-lite ของ key0 (ยังไล่ต่อได้)
    - ไล่จนหมด "ทุกโมเดล × ทุกคีย์" จริง ๆ ค่อย raise → ให้ generate_smart เด้งไป OpenRouter
    ทั้งเส้นทางนี้ไม่มี `time.sleep` ⇒ เวลาที่ใช้ = เฉพาะ network round-trip เท่านั้น."""
    models = _build_fallback_models()
    last_exc: Exception | None = None
    quota_hits = 0

    for model_name in models:                    # วงนอก: ฉลาดสุดก่อน (กวาดทุกคีย์)
        dead: set[str] = set()                   # คีย์ที่ตายสำหรับ "โมเดลนี้" ในรอบนี้
        for key in _available_keys(keys, model_name):
            if key in dead:
                continue
            try:
                return _gemini_generate_once(model_name, key, prompt, gen_config)
            except google.api_core.exceptions.NotFound as exc:
                # โมเดลนี้ไม่มี/ถูกปิด → เลิกลูปคีย์ ลดชั้นไปโมเดลถัดไป (คีย์ยังดี)
                last_exc = exc
                break
            except (google.api_core.exceptions.ResourceExhausted,
                    google.api_core.exceptions.TooManyRequests) as exc:
                last_exc = exc
                quota_hits += 1
                _mark_cooldown(key, model_name)  # พักเฉพาะคู่ (คีย์นี้, โมเดลนี้)
                dead.add(key)
                continue                         # → คีย์ถัดไปทันที ไม่มี sleep
            except Exception as exc:
                last_exc = exc
                if _is_quota_error(exc):
                    quota_hits += 1
                    _mark_cooldown(key, model_name)
                    dead.add(key)
                    continue
                # error ชั่วคราวอื่น (500 / timeout) → สลับคีย์ถัดไปทันที ไม่หน่วง
                dead.add(key)
                continue
        # จบโมเดลนี้ (ยังไม่สำเร็จ) → ลดชั้นไปโมเดลถัดไปบนทุกคีย์

    if quota_hits and last_exc and _is_quota_error(last_exc):
        raise RuntimeError(
            f"โควต้า Gemini API หมดทุกคีย์/ทุกโมเดล ({len(keys)} คีย์ × {len(models)} โมเดล) — "
            f"{_format_ai_error(last_exc)}"
        )
    raise RuntimeError(f"ทุก model/คีย์ ล้มเหลว: {_format_ai_error(last_exc)}")


def _generate_openrouter(prompt: str, gen_config: dict | None = None) -> str:
    """ชั้น fallback ถัดจาก Gemini — เรียก OpenRouter (OpenAI-compatible) ผ่าน httpx.
    คีย์ส่งต่อคำขอโดยตรง (ไม่มี global state) ⇒ ปลอดภัยกับ concurrency โดยธรรมชาติ."""
    if not OPENROUTER_API_KEY:
        raise RuntimeError("ไม่พบ OPENROUTER_API_KEY")

    gen_config = gen_config or _GEN_CONFIG
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/Project-VULNEX",
        "X-Title": "Project-VULNEX",
    }
    # timeout รัดกุม: connect 8 วิ, read 30 วิ — กันโมเดลที่ค้างไม่ให้ถ่วง fallback
    last_err: str = "unknown"
    with httpx.Client(timeout=httpx.Timeout(30.0, connect=8.0)) as client:
        for model in _OPENROUTER_MODELS:
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": _OPENROUTER_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                "max_tokens":  gen_config.get("max_output_tokens", 2048),
                "temperature": gen_config.get("temperature", 0.15),
            }
            try:
                r = client.post(_OPENROUTER_URL, headers=headers, json=payload)
                if r.status_code in (429, 402, 502, 503):
                    last_err = f"{model}: HTTP {r.status_code}"
                    continue
                r.raise_for_status()
                data = r.json()
                choices = data.get("choices") or []
                if choices:
                    text = ((choices[0].get("message") or {}).get("content") or "").strip()
                    if text:
                        return text
                last_err = f"{model}: {data.get('error', 'empty response')}"
            except Exception as exc:                     # noqa: BLE001
                last_err = f"{model}: {exc}"
    raise RuntimeError(f"OpenRouter ทุกโมเดลล้มเหลว — {last_err}")


def generate_smart(
    prompt: str,
    gen_config: dict | None = None,
    keys: list[str] | None = None,
) -> tuple[str, str]:
    """Cascade อัจฉริยะ: Gemini (ทุกคีย์/โมเดล) → OpenRouter → ยกข้อผิดพลาด (ให้ผู้เรียกไป offline).

    คืน (text, provider) โดย provider ∈ {"gemini", "openrouter"}."""
    gen_config = gen_config or _GEN_CONFIG
    keys = GEMINI_KEYS if keys is None else keys
    errors: list[str] = []

    if keys:
        try:
            return _generate_gemini(prompt, gen_config, keys), "gemini"
        except Exception as exc:                         # noqa: BLE001
            errors.append(str(exc))

    if OPENROUTER_API_KEY:
        try:
            return _generate_openrouter(prompt, gen_config), "openrouter"
        except Exception as exc:                         # noqa: BLE001
            errors.append(str(exc))

    raise RuntimeError(" | ".join(errors) or "ไม่มี AI provider ที่พร้อมใช้งาน")


def generate_with_fallback(prompt: str) -> str:
    """(คงไว้เพื่อ backward-compat) เรียก cascade แล้วคืนเฉพาะ text."""
    text, _ = generate_smart(prompt)
    return text


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
        "dns":     scan_data.get("dns", {}).get("score"),
        "cookies": scan_data.get("cookies", {}).get("score"),
        "cms":     scan_data.get("cms", {}).get("score"),
        "js_sec":  len((scan_data.get("js_exposure", {}) or {}).get("secrets_found", []) or []),
        "open_f":  len((scan_data.get("open_files", {}) or {}).get("sensitive_files", []) or []),
    }
    raw = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


# ─────────────────────────────────────────────────────────────────
# Score engine
# ─────────────────────────────────────────────────────────────────

def _module_score(scan_data: dict, key: str, default: int = 50) -> int:
    """Get 0-100 score from a scan module, or ``default`` if missing / errored /
    suspended.

    PASSIVE-SCAN: a module disabled at the call site (scanner._SUSPENDED_MODULES)
    returns {"suspended": True}. It is scored at the neutral ``default`` — exactly as
    an unavailable/errored module always has been — so suspending a module does NOT
    lower or otherwise distort the composite score (only CMS carries weight among the
    suspended set; http_methods was never part of the composite)."""
    mod = scan_data.get(key, {}) or {}
    if mod.get("suspended") or mod.get("error"):
        return default
    return int(mod.get("score", default) or default)


def _ssl_subscore(ssl: dict) -> int:
    """Convert SSL data to 0-100 sub-score.

    A *couldn't-measure* failure (connection/other/blocked) stays NEUTRAL (50) — we
    don't punish a site for a network blip. A cert that is present but *invalid*
    (expired / self-signed / untrusted) scores LOW (15); previously any error returned
    50, so expired certs were scored too generously."""
    if not ssl.get("has_ssl"):
        return 0
    # Couldn't establish/verify TLS for a non-cert reason → neutral, not a penalty.
    if not ssl.get("valid") and ssl.get("error_type") in ("connection", "other", "blocked"):
        return 50
    if not ssl.get("valid"):
        return 15   # cert present but expired / self-signed / untrusted
    score = 70
    days = int(ssl.get("days_left", 0) or 0)
    if days > 60:
        score += 20
    elif days > 30:
        score += 10
    elif days > 0:
        score += 5
    score -= len(ssl.get("tls_warnings", []) or []) * 8
    return max(0, min(100, score))


def _server_subscore(server_data: dict) -> int:
    """Convert server/CVE data to 0-100 sub-score."""
    vulns = server_data.get("vulnerabilities", []) or []
    dos_risk = bool(server_data.get("dos_risk", False))
    _PENALTY = {"CRITICAL": 35, "HIGH": 25, "MEDIUM": 12, "LOW": 5}
    penalty = sum(_PENALTY.get(str(v.get("severity", "")).upper(), 5) for v in vulns)
    if dos_risk:
        penalty += 30
    if server_data.get("version_exposed"):
        penalty += 8
    return max(0, min(100, 100 - penalty))


def _html_js_subscore(scan_data: dict) -> int:
    """Combine HTML parser + JS exposure + open-files scores.

    PASSIVE-SCAN: a suspended sub-module (e.g. open_files) is dropped and the
    remaining sub-weights are renormalized, so a paused check adds no phantom score."""
    parts = (("html", 0.50, 80), ("js_exposure", 0.35, 90), ("open_files", 0.15, 90))
    active = [(k, w, d) for k, w, d in parts
              if not (scan_data.get(k, {}) or {}).get("suspended")]
    total_w = sum(w for _, w, _ in active) or 1.0
    return round(sum(_module_score(scan_data, k, d) * w for k, w, d in active) / total_w)


def _renormalize_weights(weights: dict) -> dict:
    """Scale integer weights so they sum back to 100 (largest-remainder rounding).

    Used when a weighted module is suspended: its weight is removed and the rest are
    scaled up, so the composite still spans 0–100 (a perfect active scan can reach 100)
    without crediting the paused module any phantom points."""
    total = sum(weights.values())
    if total in (0, 100):
        return dict(weights)
    scaled = {k: v * 100 / total for k, v in weights.items()}
    out = {k: int(v) for k, v in scaled.items()}
    for k in sorted(scaled, key=lambda x: scaled[x] - out[x], reverse=True)[:100 - sum(out.values())]:
        out[k] += 1
    return out


def _compute_score(scan_data: dict, server_data: dict) -> tuple[int, str, dict]:
    """
    Composite security score (0–100) จากทุก signal

    Base weights (sum 100): Headers 25, SSL/TLS 20, HTML/JS 15, Server/CVE 15,
    DNS 10, Cookies 10, CMS 5. A module SUSPENDED at the call site
    (scanner._SUSPENDED_MODULES) is dropped from the weighted average and the
    remaining weights are renormalized to 100 — so a paused module scores no phantom
    points and never appears in the breakdown at full marks.
    """
    raws = {
        "headers":    _module_score(scan_data, "headers", 0),
        "ssl":        _ssl_subscore(scan_data.get("ssl", {}) or {}),
        "html_js":    _html_js_subscore(scan_data),
        "server_cve": _server_subscore(server_data),
        "dns":        _module_score(scan_data, "dns", 70),
        "cookies":    _module_score(scan_data, "cookies", 100),
        "cms":        _module_score(scan_data, "cms", 90),
    }
    base_weights = {
        "headers": 25, "ssl": 20, "html_js": 15, "server_cve": 15,
        "dns": 10, "cookies": 10, "cms": 5,
    }
    # Drop any weighted component whose scan module is suspended, then renormalize.
    # (html_js/server_cve have no scan_data key → .get(...) is falsy → always kept.)
    active = {k: w for k, w in base_weights.items()
              if not (scan_data.get(k, {}) or {}).get("suspended")}
    weights = _renormalize_weights(active)

    pts = {k: round(raws[k] * weights[k] / 100) for k in weights}
    total = min(100, sum(pts.values()))

    vulns = server_data.get("vulnerabilities", []) or []
    dos_risk = bool(server_data.get("dos_risk", False))
    sev_set = {str(v.get("severity", "")).upper() for v in vulns}
    has_critical = "CRITICAL" in sev_set
    has_high = "HIGH" in sev_set
    ssl_ok = bool((scan_data.get("ssl", {}) or {}).get("valid", False))

    if total < 30 or has_critical or (dos_risk and total < 55):
        risk = "CRITICAL"
    elif total < 50 or has_high:
        risk = "HIGH"
    elif total < 70 or not ssl_ok:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    # breakdown: earned weighted points per ACTIVE component + the effective max
    # weights (_weights, consumed by the UI) + raw sub-scores. Suspended modules are
    # omitted entirely, so the breakdown never lists a paused module at full marks.
    breakdown = {k: pts[k] for k in weights}
    breakdown["_weights"] = dict(weights)
    for k in weights:
        breakdown[f"{k}_raw"] = raws[k]

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
    _brk_lbl = {"headers": "Headers", "ssl": "SSL", "html_js": "HTML/JS",
                "server_cve": "Server", "dns": "DNS", "cookies": "Cookies", "cms": "CMS"}
    _brk_w = breakdown.get("_weights") or {}
    brk_str = ", ".join(
        f"{_brk_lbl[k]} {breakdown.get(k, 0)}/{_brk_w[k]}"
        for k in ("headers", "ssl", "html_js", "server_cve", "dns", "cookies", "cms")
        if k in _brk_w
    )
    overview = (
        f"เว็บไซต์ {url} ได้คะแนนความปลอดภัยรวม **{score}/100** "
        f"ระดับความเสี่ยง **{risk}** — {_risk_summary_th(risk, score)} ({brk_str})"
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

    # New modules
    dns = scan_data.get("dns", {}) or {}
    if not dns.get("error") and not dns.get("spf", {}).get("present"):
        urgent.append("- **SPF ขาด** — เสี่ยง email spoofing หลอกผู้ปกครอง")
    cookies = scan_data.get("cookies", {}) or {}
    for cf in (cookies.get("findings") or [])[:3]:
        urgent.append(f"- **Cookie**: {cf.get('title', '')} — {cf.get('detail', '')}")
    js_exp = scan_data.get("js_exposure", {}) or {}
    for sec in (js_exp.get("secrets_found") or [])[:2]:
        urgent.append(f"- **JS Exposure**: {sec.get('type', 'secret')} ใน {sec.get('source', 'script')}")
    open_f = scan_data.get("open_files", {}) or {}
    for sf in (open_f.get("sensitive_files") or [])[:2]:
        urgent.append(f"- **Sensitive File**: {sf.get('path')} accessible (HTTP {sf.get('status')})")

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

    return f"""## สรุปภาพรวม
{overview}

## ปัญหาเร่งด่วน (ต้องแก้ทันที)
{urgent_txt}

## คำแนะนำการแก้ไข
{fixes_txt}

## จุดที่ดีแล้ว
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
        "provider":         None,
    }

    # AI text — cached by scan fingerprint (หมดอายุ 1 ชั่วโมง)
    cache_key = _make_cache_key(scan_data, server_data)
    if cache_key in _analysis_cache:
        result["analysis"] = _analysis_cache[cache_key]
        result["provider"] = "cache"
        return result

    if not _has_any_provider():
        err_msg = "ไม่พบ API key (Gemini/OpenRouter) — ใช้การวิเคราะห์อัตโนมัติแทน"
        result["error"] = err_msg
        result["offline_fallback"] = True
        result["analysis"] = (
            f"> **โหมดวิเคราะห์อัตโนมัติ (Offline)** — {err_msg}\n\n"
            + _build_offline_analysis(scan_data, server_data, score, risk, breakdown)
        )
        return result

    try:
        prompt               = build_prompt(scan_data, server_data, composite_score=score)
        text, provider       = generate_smart(prompt)
        result["analysis"]   = text
        result["provider"]   = provider
        _analysis_cache[cache_key] = text
    except Exception as exc:
        err_msg = _format_ai_error(exc)
        result["error"]            = err_msg
        result["offline_fallback"] = True
        offline_body = _build_offline_analysis(
            scan_data, server_data, score, risk, breakdown
        )
        result["analysis"] = (
            f"> **โหมดวิเคราะห์อัตโนมัติ (Offline)** — ไม่สามารถเรียก Gemini AI ได้\n"
            f"> {err_msg}\n\n"
            + offline_body
        )

    return result


def _pdf_key_order() -> list[str]:
    """ลำดับคีย์สำหรับสร้าง PDF — เอา 'คีย์ที่ว่างอยู่' ตัวไหนก็ได้ แต่จัดคีย์สำรอง
    (และคีย์เสริมอื่น) ขึ้นก่อนคีย์หลัก เพื่อไม่แย่งโควต้าการวิเคราะห์บนหน้าจอ
    — คีย์หลักถูกเลื่อนไปท้ายสุดเป็นทางเลือกสำรอง."""
    if len(GEMINI_KEYS) > 1:
        return GEMINI_KEYS[1:] + GEMINI_KEYS[:1]
    return list(GEMINI_KEYS)


def generate_report_analysis(
    scan_data: dict,
    server_data: dict | None = None,
    screen_ai_data: dict | None = None,
) -> dict:
    """
    สร้างบทวิเคราะห์สำหรับ "รายงาน" (HTML→PDF) — ใช้ cascade อัจฉริยะเต็มรูปแบบ
    โดยเลือก "คีย์ไหนก็ได้ที่ว่างอยู่" (cooldown-aware) เรียงคีย์สำรองก่อนคีย์หลัก
    เพื่อไม่แย่งโควต้าหน้าจอ แล้วต่อด้วย OpenRouter จนถึง offline

    ลำดับ fallback:
        1) Gemini — คีย์ที่ว่าง (สำรองก่อน) × โมเดลฉลาดสุดก่อน → OpenRouter (ผ่าน generate_smart)
        2) ถ้าล้มเหลว → ใช้บทวิเคราะห์บนหน้าจอ (ถ้ามีและเป็น AI จริง ไม่ใช่ offline)
        3) ถ้ายังไม่ได้ → offline rule-based analysis

    คืน dict โครงสร้างเดียวกับ analyze():
        analysis, risk_level, score, breakdown, error, offline_fallback, provider
    """
    server_data = server_data or {}

    # score คำนวณใหม่เสมอ (deterministic, ไม่เสียโควต้า)
    score, risk, breakdown = _compute_score(scan_data, server_data)
    result = {
        "analysis":         "",
        "risk_level":       risk,
        "score":            score,
        "breakdown":        breakdown,
        "error":            None,
        "offline_fallback": False,
        "provider":         None,
    }

    # 1) คีย์ที่ว่าง (สำรองก่อน) + OpenRouter ผ่าน cascade เดียวกัน
    if _has_any_provider():
        try:
            prompt = build_prompt(scan_data, server_data, composite_score=score)
            text, provider = generate_smart(prompt, keys=_pdf_key_order())
            result["analysis"] = text
            result["provider"] = provider
            return result
        except Exception as exc:           # noqa: BLE001 — เก็บ error ไว้แล้วไป fallback
            result["error"] = _format_ai_error(exc)

    # 2) บทวิเคราะห์บนหน้าจอ (ที่เรียกไปแล้ว) ถ้าใช้งานได้จริง
    if (
        screen_ai_data
        and screen_ai_data.get("analysis")
        and not screen_ai_data.get("offline_fallback")
    ):
        result["analysis"]   = screen_ai_data["analysis"]
        result["risk_level"] = screen_ai_data.get("risk_level", risk)
        result["score"]      = screen_ai_data.get("score", score)
        result["breakdown"]  = screen_ai_data.get("breakdown", breakdown)
        result["provider"]   = screen_ai_data.get("provider", "screen-reuse")
        return result

    # 3) offline rule-based
    note = result["error"] or "ไม่พบ API key (Gemini/OpenRouter) ในไฟล์ .env"
    result["offline_fallback"] = True
    result["analysis"] = (
        f"> **โหมดวิเคราะห์อัตโนมัติ (Offline)** — {note}\n\n"
        + _build_offline_analysis(scan_data, server_data, score, risk, breakdown)
    )
    return result


# ─────────────────────────────────────────────────────────────────
# AI Chat Assistant (Pillar 2.3)
# ─────────────────────────────────────────────────────────────────

_CHAT_CONFIG = {
    "temperature": 0.4,
    "max_output_tokens": 1024,
}


def _offline_chat_reply(user_message: str, scan_data: dict, ai_data: dict) -> str:
    """Rule-based chat fallback when Gemini unavailable."""
    msg = user_message.lower()
    score = ai_data.get("score", 0)
    risk = ai_data.get("risk_level", "HIGH")

    if any(k in msg for k in ("cve", "ช่องโหว่")):
        hdr = scan_data.get("headers", {}) or {}
        missing = hdr.get("headers_missing", [])
        if missing:
            return (
                f"จากผลสแกน คะแนนรวม {score}/100 (ระดับ {risk})\n\n"
                f"Headers ที่ขาด: {', '.join(missing)}\n\n"
                "แนะนำแก้ HSTS และ CSP ก่อน — ใช้เวลาประมาณ 30 นาทีบน nginx/Apache"
            )
        return f"คะแนนรวม {score}/100 — ดูรายละเอียด CVE ในแท็บ Server Info"

    if any(k in msg for k in ("แก้", "fix", "priority", "ก่อน", "ควร")):
        hdr = scan_data.get("headers", {}) or {}
        missing = hdr.get("headers_missing", []) or []
        if "Strict-Transport-Security" in missing:
            return "**แก้ HSTS ก่อน** — ง่ายที่สุด เพิ่ม header บรรทัดเดียว ได้ผลทันที"
        if "Content-Security-Policy" in missing:
            return "**แก้ CSP ก่อน** — ป้องกัน XSS ได้มาก เริ่มจาก `default-src 'self'`"
        ssl = scan_data.get("ssl", {}) or {}
        if not ssl.get("valid"):
            return "**แก้ SSL ก่อน** — ติดตั้ง/ต่ออายุใบรับรอง HTTPS เป็นสิ่งเร่งด่วนที่สุด"
        return f"คะแนน {score}/100 — ดูรายการใน AI Analysis สำหรับลำดับความสำคัญ"

    if any(k in msg for k in ("csp", "content-security", "อธิบาย")):
        return (
            "**Content-Security-Policy (CSP)** คือกฎที่บอก browser ว่าโหลด script/style จากไหนได้บ้าง "
            "ช่วยป้องกัน XSS — ถ้า hacker แทรก script ปลอม CSP จะบล็อกไม่ให้รัน"
        )

    if any(k in msg for k in ("spf", "dmarc", "dkim", "อีเมล", "email")):
        dns = scan_data.get("dns", {}) or {}
        if dns.get("error"):
            return f"ไม่สามารถตรวจ DNS ได้: {dns['error']}"
        spf = dns.get("spf", {})
        dmarc = dns.get("dmarc", {})
        return (
            f"**Email Security (DNS)** — คะแนน {dns.get('score', 'N/A')}/100\n\n"
            f"- **SPF**: {'มี' if spf.get('present') else 'ไม่มี'} "
            f"(policy: {spf.get('policy') or 'none'})\n"
            f"- **DMARC**: {'มี' if dmarc.get('present') else 'ไม่มี'} "
            f"(p={dmarc.get('policy', 'none')})\n"
            f"- **DKIM selectors**: {dns.get('dkim', {}).get('selectors_found', []) or 'ไม่พบ'}\n\n"
            "SPF/DMARC ช่วยป้องกันอีเมลปลอมแอบอ้างชื่อโรงเรียน — แนะนำ SPF `-all` และ DMARC `p=reject`"
        )

    return (
        f"โหมด Offline — ไม่สามารถเรียก Gemini ได้\n\n"
        f"คะแนนรวม: **{score}/100** | ความเสี่ยง: **{risk}**\n\n"
        "ลองถาม: 'ควรแก้อะไรก่อน?', 'อธิบาย CSP', หรือ 'CVE อันตรายแค่ไหน'"
    )


def chat_stream(
    user_message: str,
    scan_data: dict,
    server_data: dict,
    ai_data: dict,
    chat_history: list | None = None,
):
    """Generator yielding text chunks — Gemini (ทุกคีย์) → OpenRouter → offline."""
    if not _has_any_provider():
        yield _offline_chat_reply(user_message, scan_data, ai_data)
        return

    prompt = build_chat_prompt(
        scan_data, server_data, ai_data, user_message, chat_history
    )
    last_exc: Exception | None = None

    # 1) Gemini streaming — วนโมเดล (ฉลาดสุดก่อน) × ทุกคีย์ที่ว่าง (cooldown-aware)
    for model_name in _build_fallback_models():
        model_dead = False
        for key in _available_keys(GEMINI_KEYS, model_name):
            try:
                with _genai_lock:
                    genai.configure(api_key=key)
                    m = genai.GenerativeModel(model_name, generation_config=_CHAT_CONFIG)
                    stream = m.generate_content(prompt, stream=True)
                    got_any = False
                    for chunk in stream:
                        if chunk.text:
                            got_any = True
                            yield chunk.text
                if got_any:
                    return
            except google.api_core.exceptions.NotFound as exc:
                last_exc = exc
                model_dead = True
                break
            except Exception as exc:                     # noqa: BLE001
                last_exc = exc
                if _is_quota_error(exc):
                    _mark_cooldown(key, model_name)
                    continue                             # สลับคีย์
                break
        if model_dead:
            continue

    # 2) OpenRouter (ไม่ stream — ส่งเป็นก้อนเดียว)
    if OPENROUTER_API_KEY:
        try:
            yield _generate_openrouter(prompt, _CHAT_CONFIG)
            return
        except Exception as exc:                         # noqa: BLE001
            last_exc = exc

    # 3) offline
    yield _offline_chat_reply(user_message, scan_data, ai_data)
    if last_exc:
        yield f"\n\n_(AI ไม่พร้อม: {_format_ai_error(last_exc)})_"


def chat(
    user_message: str,
    scan_data: dict,
    server_data: dict,
    ai_data: dict,
    chat_history: list | None = None,
) -> dict:
    """Non-streaming chat — collects full response."""
    parts = list(chat_stream(user_message, scan_data, server_data, ai_data, chat_history))
    return {"reply": "".join(parts), "offline": not _has_any_provider()}
