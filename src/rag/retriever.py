"""ชั้นบนสุดของ RAG: รับคำถาม/บริบทสแกน → ค้นคลังความรู้ → จัดรูปเป็นบล็อกอ้างอิง.

จุดสำคัญ: ทุกอย่าง fail-soft — ถ้า Qdrant/embedding ไม่พร้อม `retrieve()` คืนลิสต์ว่าง
และ `format_context()` คืนสตริงว่าง ทำให้ prompt builder เดิมทำงานต่อได้เหมือนไม่มี RAG
"""
from __future__ import annotations

import functools

from . import embeddings, store

# หมวดของโมดูลสแกน → หมวดในคลังความรู้ ใช้ให้ retrieval เจาะจงเมื่อรู้บริบท
MODULE_TO_CATEGORY = {
    "headers": "headers",
    "cookies": "cookies",
    "dns": "dns",
    "ssl": "ssl",
    "js_exposure": "js_exposure",
    "html": "js_exposure",
    "subdomains": "subdomains",
    "server": "cve",
}


def is_available() -> bool:
    """RAG พร้อมใช้ไหม — ต้องมีทั้งค่า Qdrant และคีย์ embedding."""
    return store.is_configured() and embeddings.has_embedding_provider()


def retrieve(query: str, k: int = 4, categories: list[str] | None = None) -> list[dict]:
    """ค้นชิ้นความรู้ที่เกี่ยวข้องที่สุด k ชิ้น. คืน [] อย่างเงียบ ๆ ถ้า RAG ไม่พร้อม."""
    query = (query or "").strip()
    if not query or not is_available():
        return []
    try:
        qvec = embeddings.embed_query(query)
    except Exception:  # noqa: BLE001 — embedding ล้ม → ไม่มีบริบท RAG แต่แชทยังตอบได้
        return []
    return store.search(qvec, limit=k, categories=categories)


def format_context(chunks: list[dict], max_chars: int = 3500) -> str:
    """จัดชิ้นความรู้เป็นบล็อกอ้างอิงภาษาไทยสำหรับเสียบเข้า prompt (มีเพดานความยาว)."""
    if not chunks:
        return ""
    lines = [
        "=== คลังความรู้อ้างอิง (ข้อมูลมาตรฐานที่ค้นเจอ — ใช้ประกอบคำตอบ อ้างอิงได้) ==="
    ]
    used = 0
    for i, ch in enumerate(chunks, 1):
        title = str(ch.get("title", "")).strip()
        source = str(ch.get("source", "")).strip()
        text = str(ch.get("text", "")).strip()
        refs = ch.get("refs") or []
        ref_txt = f" [อ้างอิง: {', '.join(refs)}]" if refs else ""
        block = f"\n[{i}] {title}{ref_txt}\nที่มา: {source}\n{text}\n"
        if used + len(block) > max_chars:
            # ตัดชิ้นสุดท้ายให้พอดีเพดาน แทนที่จะทิ้งทั้งชิ้น
            remain = max_chars - used
            if remain > 200:
                lines.append(block[:remain] + " …")
            break
        lines.append(block)
        used += len(block)
    lines.append("\n=== จบคลังความรู้อ้างอิง ===")
    return "\n".join(lines)


@functools.lru_cache(maxsize=1)
def get_retriever():
    """คืนอ็อบเจกต์ retriever แบบ callable-ish (เผื่อโค้ดอื่นอยากถือ instance)."""
    return _Retriever()


class _Retriever:
    """ห่อฟังก์ชันไว้เป็นอ็อบเจกต์ เพื่อความสะดวกในการ mock/inject ระหว่างเทสต์."""

    def available(self) -> bool:
        return is_available()

    def retrieve(self, query: str, k: int = 4,
                 categories: list[str] | None = None) -> list[dict]:
        return retrieve(query, k=k, categories=categories)

    def context_for(self, query: str, k: int = 4,
                    categories: list[str] | None = None, max_chars: int = 3500) -> str:
        return format_context(self.retrieve(query, k=k, categories=categories),
                              max_chars=max_chars)
