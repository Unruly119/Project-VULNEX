# src/chat_engine.py — Provider cascade เฉพาะ ChatBOT ("ถามต่อกับ AI" / dotRED)
# ────────────────────────────────────────────────────────────────
#   คีย์พูลนี้แยกจาก ai_engine.py โดยสิ้นเชิง (ไม่ปนกับ GEMINI_API_KEY* ที่ใช้กับ
#   AI Analysis/PDF) เพื่อไม่ให้แชทแย่งโควต้ากับการวิเคราะห์หลัก ดูค่า .env ที่ชื่อ
#   ขึ้นต้นด้วย CHAT_*
#
#   Cascade ลำดับ (เร็ว/ถูกก่อน แพง/ช้าไว้ท้าย):
#     1) Groq   — หลายคีย์ (LPU inference เร็วมาก, เหมาะ real-time chat streaming)
#     2) Gemini — คีย์เดียวสำรอง (context ยาวได้ดี กรณี Groq ล่มทั้งพูล)
#     3) OpenRouter — คีย์คู่สุดท้าย (ฟรีโมเดลหลากหลาย)
#     4) Offline  — ไม่มี network เลยก็ยังตอบได้ (chat_guard เป็นคนเรียก fallback นี้)
#
#   ทุกชั้น fail-soft: ล้มเหลว → คีย์/โมเดลถัดไป ไม่มี time.sleep ยาว ๆ (แชทต้องเร็ว)
# ────────────────────────────────────────────────────────────────
from __future__ import annotations

import os
import time

import httpx
from dotenv import load_dotenv

load_dotenv(override=True)


def _env_ci(*names: str) -> str:
    """Case-insensitive env lookup (Windows dev vs Linux deploy casing)."""
    for name in names:
        val = os.getenv(name)
        if val and val.strip():
            return val.strip()
    lowered = {n.lower() for n in names}
    for k, v in os.environ.items():
        if k.lower() in lowered and v and v.strip():
            return v.strip()
    return ""


# ── คีย์พูล (โหลดครั้งเดียวตอน import) ────────────────────────────
_GROQ_KEY_NAMES = [
    "CHAT_GROQ_API_KEY_1", "CHAT_GROQ_API_KEY_2", "CHAT_GROQ_API_KEY_3",
    "CHAT_GROQ_API_KEY_4", "CHAT_GROQ_API_KEY_5", "CHAT_GROQ_API_KEY_6",
    "CHAT_GROQ_API_KEY_7", "CHAT_GROQ_API_KEY_8",
]
_OPENROUTER_KEY_NAMES = [
    "CHAT_OPENROUTER_API_KEY_1", "CHAT_OPENROUTER_API_KEY_2",
    "CHAT_OPENROUTER_API_KEY_3", "CHAT_OPENROUTER_API_KEY_4",
]


def _load_keys(names: list[str]) -> list[str]:
    out: list[str] = []
    for n in names:
        v = _env_ci(n)
        if v and v not in out:
            out.append(v)
    return out


GROQ_KEYS = _load_keys(_GROQ_KEY_NAMES)
CHAT_GEMINI_KEY = _env_ci("CHAT_GEMINI_API_KEY") or None
OPENROUTER_KEYS = _load_keys(_OPENROUTER_KEY_NAMES)

_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
_OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
_GEMINI_URL_TMPL = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:streamGenerateContent"
    "?alt=sse&key={key}"
)

# โมเดลฟรีที่ทดสอบว่าตอบไทยได้ดี เรียงเร็ว/ฉลาดก่อน
_GROQ_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
]
_GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.5-flash-lite"]
_OPENROUTER_MODELS = [
    "openai/gpt-oss-120b:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "qwen/qwen3-next-80b-a3b-instruct:free",
]

_SYSTEM_PROMPT_NOTE = (
    "You are dotRED. Always respond in Thai unless the user writes in another "
    "language. No emoji. Keep the exact Markdown structure requested."
)

_TIMEOUT = httpx.Timeout(30.0, connect=6.0)
_CHAT_GEN_CONFIG = {"temperature": 0.4, "max_output_tokens": 1024}

# คีย์ที่เจอ 429/quota ล่าสุด → พักชั่วคราวไม่ลองซ้ำในรอบถัดไปทันที (เบากว่า ai_engine
# เพราะแชทต้องการ latency ต่ำ ไม่ใช่ retry แบบ exhaustive)
_COOLDOWN_SEC = 30
_key_cooldowns: dict[str, float] = {}


def _is_cooling(key: str) -> bool:
    until = _key_cooldowns.get(key)
    return bool(until and time.time() < until)


def _mark_cooldown(key: str) -> None:
    _key_cooldowns[key] = time.time() + _COOLDOWN_SEC


def has_any_provider() -> bool:
    return bool(GROQ_KEYS or CHAT_GEMINI_KEY or OPENROUTER_KEYS)


def active_engine_label() -> str:
    """ชื่อ engine ตัวแรกที่พร้อมใช้งาน — สำหรับ badge ใน UI (เดาก่อนยิงจริง)."""
    if any(not _is_cooling(k) for k in GROQ_KEYS):
        return "Groq"
    if CHAT_GEMINI_KEY and not _is_cooling(CHAT_GEMINI_KEY):
        return "Gemini"
    if any(not _is_cooling(k) for k in OPENROUTER_KEYS):
        return "OpenRouter"
    return "Offline"


class _QuotaError(Exception):
    """429/402/502/503 — สัญญาณให้สลับคีย์/โมเดลทันที ไม่ใช่ error ถาวร."""


# ── OpenAI-compatible streaming (ใช้ร่วม Groq + OpenRouter) ──────
def _stream_openai_compatible(
    url: str,
    key: str,
    model: str,
    prompt: str,
    extra_headers: dict | None = None,
):
    """Generator: yield ก้อนข้อความ (SSE 'data: ' chunks) จาก OpenAI-compatible API."""
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT_NOTE},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": _CHAT_GEN_CONFIG["max_output_tokens"],
        "temperature": _CHAT_GEN_CONFIG["temperature"],
        "stream": True,
    }
    with httpx.Client(timeout=_TIMEOUT) as client:
        with client.stream("POST", url, headers=headers, json=payload) as r:
            if r.status_code in (429, 402, 502, 503):
                raise _QuotaError(f"HTTP {r.status_code}")
            r.raise_for_status()
            for line in r.iter_lines():
                if not line or not line.startswith("data: "):
                    continue
                data = line[len("data: "):].strip()
                if data == "[DONE]":
                    return
                try:
                    import json as _json
                    obj = _json.loads(data)
                    delta = (obj.get("choices") or [{}])[0].get("delta", {})
                    text = delta.get("content")
                    if text:
                        yield text
                except Exception:  # noqa: BLE001 — บรรทัดพัง ข้ามไป ไม่ทำ stream ล้ม
                    continue


def _stream_groq(prompt: str):
    for model in _GROQ_MODELS:
        for key in GROQ_KEYS:
            if _is_cooling(key):
                continue
            try:
                got_any = False
                for chunk in _stream_openai_compatible(_GROQ_URL, key, model, prompt):
                    got_any = True
                    yield chunk
                if got_any:
                    return
            except _QuotaError:
                _mark_cooldown(key)
                continue
            except Exception:  # noqa: BLE001 — ลองคีย์ถัดไป
                continue
    raise RuntimeError("Groq ทุกคีย์/โมเดลล้มเหลว")


def _stream_gemini(prompt: str):
    if not CHAT_GEMINI_KEY or _is_cooling(CHAT_GEMINI_KEY):
        raise RuntimeError("ไม่มี Gemini key พร้อมใช้งาน")
    import json as _json

    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": _CHAT_GEN_CONFIG["temperature"],
            "maxOutputTokens": _CHAT_GEN_CONFIG["max_output_tokens"],
        },
    }
    for model in _GEMINI_MODELS:
        url = _GEMINI_URL_TMPL.format(model=model, key=CHAT_GEMINI_KEY)
        try:
            got_any = False
            with httpx.Client(timeout=_TIMEOUT) as client:
                with client.stream("POST", url, json=body) as r:
                    if r.status_code == 429:
                        _mark_cooldown(CHAT_GEMINI_KEY)
                        raise _QuotaError("429")
                    r.raise_for_status()
                    for line in r.iter_lines():
                        if not line or not line.startswith("data: "):
                            continue
                        data = line[len("data: "):].strip()
                        if not data:
                            continue
                        try:
                            obj = _json.loads(data)
                            parts = (
                                obj.get("candidates", [{}])[0]
                                .get("content", {})
                                .get("parts", [])
                            )
                            for p in parts:
                                text = p.get("text")
                                if text:
                                    got_any = True
                                    yield text
                        except Exception:  # noqa: BLE001
                            continue
            if got_any:
                return
        except _QuotaError:
            continue
        except Exception:  # noqa: BLE001 — ลองโมเดลถัดไป
            continue
    raise RuntimeError("Gemini (chat pool) ล้มเหลวทุกโมเดล")


def _stream_openrouter(prompt: str):
    extra = {
        "HTTP-Referer": "https://github.com/Project-VULNEX",
        "X-Title": "Project-VULNEX Chat",
    }
    for key in OPENROUTER_KEYS:
        if _is_cooling(key):
            continue
        for model in _OPENROUTER_MODELS:
            try:
                got_any = False
                for chunk in _stream_openai_compatible(
                    _OPENROUTER_URL, key, model, prompt, extra_headers=extra
                ):
                    got_any = True
                    yield chunk
                if got_any:
                    return
            except _QuotaError:
                _mark_cooldown(key)
                break  # คีย์นี้โดน cooldown แล้ว ไปคีย์ถัดไปเลย ไม่ลองโมเดลอื่นด้วยคีย์เดิม
            except Exception:  # noqa: BLE001
                continue
    raise RuntimeError("OpenRouter (chat pool) ทุกคีย์/โมเดลล้มเหลว")


def stream_chat(prompt: str):
    """Generator หลัก: Groq → Gemini → OpenRouter → (raise → caller ไป offline).

    Yields (text_chunk, provider_label) ทีละคำ/ทีละก้อน — ผู้เรียก (chat_ui.py)
    ใช้ st.write_stream กับ generator นี้เพื่อให้ตัวอักษรไหลออกมาทีละตัวจริง ๆ
    """
    cascades = []
    if GROQ_KEYS:
        cascades.append(("Groq", _stream_groq))
    if CHAT_GEMINI_KEY:
        cascades.append(("Gemini", _stream_gemini))
    if OPENROUTER_KEYS:
        cascades.append(("OpenRouter", _stream_openrouter))

    last_exc: Exception | None = None
    for label, fn in cascades:
        try:
            got_any = False
            for chunk in fn(prompt):
                got_any = True
                yield chunk, label
            if got_any:
                return
        except Exception as exc:  # noqa: BLE001 — ไปตัวถัดไปใน cascade
            last_exc = exc
            continue

    raise RuntimeError(str(last_exc) if last_exc else "ไม่มี AI provider พร้อมใช้งาน (chat pool)")
