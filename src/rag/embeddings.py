"""สร้าง embedding ด้วย Gemini (gemini-embedding-001) พร้อม failover ข้ามคีย์.

- ใช้พูลคีย์ Gemini แบบเดียวกับ ai_engine (GEMINI_API_KEY, _Backup, _2.._8) แต่โหลดเอง
  เพื่อไม่ให้ rag ต้อง import ai_engine (กัน circular import)
- มิติเวกเตอร์ = 768 (ให้ตรงกับ collection บน Qdrant); โมเดลนี้คืนเวกเตอร์ที่ยังไม่
  normalize เมื่อ output_dimensionality < 3072 ซึ่งไม่เป็นไรเพราะ Qdrant ใช้ระยะ COSINE
- task_type: 'retrieval_document' ตอน ingest, 'retrieval_query' ตอนค้น — เพิ่มคุณภาพการค้น
"""
from __future__ import annotations

import os
import threading
import warnings

warnings.filterwarnings("ignore", category=FutureWarning, module="google.generativeai")
import google.generativeai as genai  # noqa: E402

EMBED_MODEL = "models/gemini-embedding-001"
EMBED_DIM = 768

# google-generativeai ใช้ genai.configure() แบบ global (ไม่ thread-safe) — ล็อกรอบการเรียก
_genai_lock = threading.Lock()

_GEMINI_KEY_ENV_NAMES = [
    "GEMINI_API_KEY", "GEMINI_API_KEY_Backup",
    "GEMINI_API_KEY_2", "GEMINI_API_KEY_3", "GEMINI_API_KEY_4",
    "GEMINI_API_KEY_5", "GEMINI_API_KEY_6", "GEMINI_API_KEY_7", "GEMINI_API_KEY_8",
]


def _env_ci(name: str) -> str:
    """ค้น env แบบไม่สนตัวพิมพ์ (Linux/Streamlit Cloud case-sensitive, Windows ไม่)."""
    val = os.getenv(name)
    if val is not None:
        return val
    low = name.lower()
    for k, v in os.environ.items():
        if k.lower() == low:
            return v
    return ""


def load_keys() -> list[str]:
    keys: list[str] = []
    for name in _GEMINI_KEY_ENV_NAMES:
        val = _env_ci(name).strip()
        if val and val not in keys:
            keys.append(val)
    return keys


def has_embedding_provider() -> bool:
    return bool(load_keys())


class EmbeddingError(RuntimeError):
    pass


def _embed_once(texts: list[str], key: str, task_type: str) -> list[list[float]]:
    with _genai_lock:
        genai.configure(api_key=key)
        resp = genai.embed_content(
            model=EMBED_MODEL,
            content=texts,
            task_type=task_type,
            output_dimensionality=EMBED_DIM,
        )
    emb = resp["embedding"]
    # batch → list[list]; single string → list[float]. ทำให้เป็น list[list] เสมอ
    if emb and isinstance(emb[0], (int, float)):
        return [emb]  # type: ignore[list-item]
    return emb


def embed_texts(texts: list[str], task_type: str = "retrieval_document") -> list[list[float]]:
    """แปลงข้อความหลายชิ้นเป็นเวกเตอร์ — วนคีย์จนสำเร็จ ถ้าไม่มีคีย์/ล้มทุกคีย์ raise."""
    if not texts:
        return []
    keys = load_keys()
    if not keys:
        raise EmbeddingError("ไม่พบ GEMINI_API_KEY สำหรับสร้าง embedding")
    last_exc: Exception | None = None
    for key in keys:
        try:
            return _embed_once(texts, key, task_type)
        except Exception as exc:  # noqa: BLE001 — ลองคีย์ถัดไปเมื่อ quota/ชั่วคราวล้ม
            last_exc = exc
            continue
    raise EmbeddingError(f"สร้าง embedding ไม่สำเร็จทุกคีย์: {last_exc}")


def embed_query(text: str) -> list[float]:
    """แปลงคำถามเดี่ยวเป็นเวกเตอร์ (task_type=retrieval_query)."""
    vecs = embed_texts([text], task_type="retrieval_query")
    return vecs[0]
