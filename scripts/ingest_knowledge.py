"""Ingest คลังความรู้ → Qdrant Cloud.

อ่าน knowledge/*.md (แหล่งข้อมูลในเครื่อง, gitignored) + สร้างชิ้น CVE จาก
scanner.server_info.VULN_DB โดยอัตโนมัติ (ให้ตรงกับ CVE ที่ scanner ใช้จริงเสมอ)
→ สร้าง embedding ด้วย Gemini → upsert ลง Qdrant collection 'vulnex_knowledge'

รันครั้งเดียว (หรือทุกครั้งที่แก้คลังความรู้):
    python scripts/ingest_knowledge.py            # upsert เพิ่ม/ทับ
    python scripts/ingest_knowledge.py --recreate # ลบ collection แล้วสร้างใหม่หมด

ต้องตั้ง .env: Qdrant_Cluster_Endpoint, Qdrant_API_Key, GEMINI_API_KEY(_*)
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(os.path.join(_ROOT, ".env"), override=True)

from rag import embeddings, store  # noqa: E402
from rag.chunker import Chunk, iter_knowledge_chunks  # noqa: E402

KNOWLEDGE_DIR = os.path.join(_ROOT, "knowledge")
BATCH = 32


def _stable_id(doc: str, title: str) -> str:
    h = hashlib.sha1(f"{doc}::{title}".encode("utf-8")).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def cve_chunks() -> list[Chunk]:
    """สร้างชิ้นความรู้ CVE จาก VULN_DB ของ scanner (แหล่งความจริงเดียว)."""
    from scanner.server_info import VULN_DB

    out: list[Chunk] = []
    for stype, vulns in VULN_DB.items():
        seen: set[str] = set()
        for v in vulns:
            cve = v["cve"]
            if cve in seen:
                continue
            seen.add(cve)
            lo = ".".join(str(x) for x in v["range"][0:3])
            hi = ".".join(str(x) for x in v["range"][3:6])
            title = f"{cve} — {stype} ({v['severity']})"
            text = (
                f"ช่องโหว่ {cve} ระดับความรุนแรง {v['severity']} มีผลกับ {stype} "
                f"เวอร์ชัน {lo} ถึง {hi}\n"
                f"รายละเอียด: {v['desc']}\n"
                f"วิธีแก้: {v['fix']}\n"
                f"คำแนะนำ: หากเว็บใช้ {stype} ในช่วงเวอร์ชันนี้ ควรอัปเดตเป็นเวอร์ชันล่าสุด"
                f"ที่แก้ช่องโหว่แล้วโดยเร็ว และซ่อนหมายเลขเวอร์ชันของเซิร์ฟเวอร์"
            )
            out.append(Chunk(
                chunk_id=_stable_id("cve_db", cve + stype),
                category="cve",
                source=f"VULNEX CVE DB / {stype} security advisories",
                title=title,
                text=text,
                refs=[cve, stype],
                doc="cve_db",
            ))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--recreate", action="store_true",
                    help="ลบ collection แล้วสร้างใหม่ก่อน ingest")
    args = ap.parse_args()

    if not store.is_configured():
        print("[ERROR] ไม่พบค่า Qdrant (Qdrant_Cluster_Endpoint / Qdrant_API_Key) ใน .env")
        return 1
    if not embeddings.has_embedding_provider():
        print("[ERROR] ไม่พบ GEMINI_API_KEY สำหรับสร้าง embedding")
        return 1

    chunks = iter_knowledge_chunks(KNOWLEDGE_DIR) + cve_chunks()
    print(f"[info] เตรียมชิ้นความรู้ {len(chunks)} ชิ้น "
          f"(จาก {KNOWLEDGE_DIR} + CVE DB)")
    if not chunks:
        print("[ERROR] ไม่พบชิ้นความรู้ — ตรวจว่าโฟลเดอร์ knowledge/ มีไฟล์ .md")
        return 1

    if not store.ensure_collection(recreate=args.recreate):
        print("[ERROR] สร้าง/เข้าถึง collection ไม่สำเร็จ")
        return 1
    print(f"[info] collection '{store.COLLECTION}' พร้อม (recreate={args.recreate})")

    total = 0
    for i in range(0, len(chunks), BATCH):
        batch = chunks[i:i + BATCH]
        vectors = embeddings.embed_texts([c.embed_text() for c in batch],
                                         task_type="retrieval_document")
        points = [
            {"id": c.chunk_id, "vector": vec, "payload": c.payload()}
            for c, vec in zip(batch, vectors)
        ]
        total += store.upsert_points(points)
        print(f"[info] upsert {total}/{len(chunks)}")

    print(f"[done] ingest สำเร็จ — Qdrant มีทั้งหมด {store.count()} จุด")
    # สรุปหมวด
    cats: dict[str, int] = {}
    for c in chunks:
        cats[c.category] = cats.get(c.category, 0) + 1
    print("[summary] ชิ้นความรู้ตามหมวด: "
          + ", ".join(f"{k}={v}" for k, v in sorted(cats.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
