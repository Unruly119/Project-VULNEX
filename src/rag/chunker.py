"""แปลงไฟล์ knowledge/*.md เป็น "ชิ้นความรู้" (chunk) พร้อม metadata.

รูปแบบไฟล์: YAML frontmatter (category / source / refs) ตามด้วยหลายหัวข้อ `## ...`
โดยแต่ละหัวข้อ = 1 chunk (ขนาดกำลังดี ~1-3 ย่อหน้า เหมาะกับ embedding ตัวเดียว)

ทำ parser เองแบบเบา ๆ (ไม่พึ่ง PyYAML) เพราะ frontmatter ที่ใช้เป็น key: value ธรรมดา
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field


@dataclass
class Chunk:
    chunk_id: str            # id เสถียร (uuid5-friendly) — ใช้เป็น point id ใน Qdrant
    category: str            # owasp_top10 / cve / nist_csf / cis_controls / headers / ...
    source: str              # ที่มาของเอกสาร
    title: str               # หัวข้อ (## ...) — ใช้อ้างอิงตอนแสดงผล
    text: str                # เนื้อหาเต็มของหัวข้อ (รวมหัวข้อไว้ต้นข้อความเพื่อบริบท)
    refs: list[str] = field(default_factory=list)
    doc: str = ""            # ชื่อไฟล์ต้นทาง (เช่น security_headers.md)

    def embed_text(self) -> str:
        """ข้อความที่ใช้สร้าง embedding — นำหัวข้อขึ้นก่อนเพื่อเพิ่มสัญญาณเชิงความหมาย"""
        return f"{self.title}\n\n{self.text}".strip()

    def payload(self) -> dict:
        return {
            "category": self.category,
            "source": self.source,
            "title": self.title,
            "text": self.text,
            "refs": self.refs,
            "doc": self.doc,
        }


def _parse_frontmatter(raw: str) -> tuple[dict, str]:
    """ดึง frontmatter (--- ... ---) ออกมาเป็น dict แบบง่าย + คืนเนื้อหาที่เหลือ"""
    meta: dict = {}
    body = raw
    m = re.match(r"^﻿?---\s*\n(.*?)\n---\s*\n(.*)$", raw, re.DOTALL)
    if m:
        fm, body = m.group(1), m.group(2)
        for line in fm.splitlines():
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key, val = key.strip(), val.strip()
            if not key:
                continue
            # refs อาจเขียนเป็น "A, B, C" — แตกเป็นลิสต์
            if key == "refs":
                meta[key] = [x.strip() for x in val.split(",") if x.strip()]
            else:
                meta[key] = val
    return meta, body


def _stable_id(doc: str, title: str) -> str:
    """id คงที่ต่อ (ไฟล์, หัวข้อ) — ให้ re-ingest แล้ว upsert ทับตัวเดิมไม่เกิดซ้ำ"""
    h = hashlib.sha1(f"{doc}::{title}".encode("utf-8")).hexdigest()
    # จัดรูปเป็น UUID (Qdrant รับ point id เป็น uuid หรือ int)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def chunk_markdown(raw: str, doc: str = "") -> list[Chunk]:
    """แปลงข้อความ markdown หนึ่งไฟล์เป็นลิสต์ของ Chunk (แยกตามหัวข้อ ##)"""
    meta, body = _parse_frontmatter(raw)
    category = str(meta.get("category", "general"))
    source = str(meta.get("source", ""))
    refs = meta.get("refs", []) if isinstance(meta.get("refs"), list) else []

    chunks: list[Chunk] = []
    # แยกตามหัวข้อระดับ 2 (## ...) — เก็บหัวข้อไว้กับเนื้อหาของมัน
    parts = re.split(r"^##\s+(.+?)\s*$", body, flags=re.MULTILINE)
    # parts[0] = ข้อความก่อนหัวข้อแรก (มักว่าง); ที่เหลือสลับ (title, content)
    for i in range(1, len(parts), 2):
        title = parts[i].strip()
        text = parts[i + 1].strip() if i + 1 < len(parts) else ""
        if not text:
            continue
        chunks.append(
            Chunk(
                chunk_id=_stable_id(doc, title),
                category=category,
                source=source,
                title=title,
                text=text,
                refs=list(refs),
                doc=doc,
            )
        )
    return chunks


def iter_knowledge_chunks(knowledge_dir: str) -> list[Chunk]:
    """อ่านทุกไฟล์ .md ในโฟลเดอร์คลังความรู้ แล้วคืนลิสต์ Chunk ทั้งหมด"""
    out: list[Chunk] = []
    if not os.path.isdir(knowledge_dir):
        return out
    for name in sorted(os.listdir(knowledge_dir)):
        if not name.endswith(".md"):
            continue
        path = os.path.join(knowledge_dir, name)
        try:
            with open(path, encoding="utf-8") as f:
                raw = f.read()
        except OSError:
            continue
        out.extend(chunk_markdown(raw, doc=name))
    return out
