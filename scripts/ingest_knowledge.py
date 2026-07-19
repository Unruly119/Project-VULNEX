"""Ingest คลังความรู้ → Qdrant Cloud (สอง collection).

แหล่งความจริงเดียวคือ knowledge/ (แผนที่ในเครื่อง, gitignored):
  (1) knowledge/cve_database.json — ตาราง CVE แบบมีโครงสร้าง → upsert 2 ทาง:
        • collection 'vulnex_cve'       = เอนทรีมีโครงสร้าง (range/severity/dos)
          ที่ scanner โหลดมาจับคู่ช่วงเวอร์ชัน (scanner.server_info._get_vuln_db)
        • collection 'vulnex_knowledge' = แปลงเป็นชิ้น prose ให้ RAG ค้นเชิงความหมาย
  (2) knowledge/*.md — คลังความรู้ (OWASP/CWE/NIST/CIS/RFC) → embedding ด้วย Gemini
        → upsert ลง 'vulnex_knowledge'

รันครั้งเดียว (หรือทุกครั้งที่แก้คลังความรู้/CVE):
    python scripts/ingest_knowledge.py            # upsert เพิ่ม/ทับ
    python scripts/ingest_knowledge.py --recreate # ลบทั้งสอง collection แล้วสร้างใหม่หมด

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

from rag import store  # noqa: E402
from rag import embeddings  # embeddings pulled via lazy path below; explicit import ok
from rag.chunker import Chunk, iter_knowledge_chunks  # noqa: E402

KNOWLEDGE_DIR = os.path.join(_ROOT, "knowledge")
CVE_DB_FILE = os.path.join(KNOWLEDGE_DIR, "cve_database.json")
BATCH = 32


def _stable_id(doc: str, title: str) -> str:
    h = hashlib.sha1(f"{doc}::{title}".encode("utf-8")).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _load_cve_db() -> dict:
    """อ่านตาราง CVE ต้นฉบับจาก knowledge/cve_database.json (แหล่งความจริงเดียว)."""
    import json
    with open(CVE_DB_FILE, encoding="utf-8") as f:
        raw = json.load(f)
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def cve_structured_points(cve_db: dict) -> list[dict]:
    """แปลงตาราง CVE เป็น points โครงสร้างสำหรับ collection vulnex_cve (scanner ใช้)."""
    out: list[dict] = []
    for stype, vulns in cve_db.items():
        for v in vulns:
            out.append({
                "id": _stable_id("cve_struct", stype + v["cve"] + str(v["range"])),
                "payload": {
                    "server_type": stype,
                    "range": v["range"],
                    "cve": v["cve"],
                    "severity": v["severity"],
                    "desc": v["desc"],
                    "fix": v["fix"],
                    "dos": bool(v.get("dos", False)),
                },
            })
    return out


def cve_chunks(cve_db: dict) -> list[Chunk]:
    """สร้างชิ้นความรู้ CVE (prose) สำหรับ RAG จากตาราง CVE เดียวกัน (dedupe ต่อ CVE+server)."""
    out: list[Chunk] = []
    for stype, vulns in cve_db.items():
        seen: set[str] = set()
        for v in vulns:
            key = v["cve"] + stype
            if key in seen:
                continue
            seen.add(key)
            lo = ".".join(str(x) for x in v["range"][0:3])
            hi = ".".join(str(x) for x in v["range"][3:6])
            title = f"{v['cve']} — {stype} ({v['severity']})"
            text = (
                f"ช่องโหว่ {v['cve']} ระดับความรุนแรง {v['severity']} มีผลกับ {stype} "
                f"เวอร์ชัน {lo} ถึง {hi}\n"
                f"รายละเอียด: {v['desc']}\n"
                f"วิธีแก้: {v['fix']}\n"
                f"คำแนะนำ: หากเว็บใช้ {stype} ในช่วงเวอร์ชันนี้ ควรอัปเดตเป็นเวอร์ชันล่าสุด"
                f"ที่แก้ช่องโหว่แล้วโดยเร็ว และซ่อนหมายเลขเวอร์ชันของเซิร์ฟเวอร์"
            )
            out.append(Chunk(
                chunk_id=_stable_id("cve_db", v["cve"] + stype),
                category="cve",
                source=f"VULNEX CVE DB / {stype} security advisories",
                title=title,
                text=text,
                refs=[v["cve"], stype],
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

    cve_db = _load_cve_db()
    chunks = iter_knowledge_chunks(KNOWLEDGE_DIR) + cve_chunks(cve_db)
    print(f"[info] เตรียมชิ้นความรู้ {len(chunks)} ชิ้น (จาก {KNOWLEDGE_DIR} + CVE DB prose)")
    if not chunks:
        print("[ERROR] ไม่พบชิ้นความรู้ — ตรวจว่าโฟลเดอร์ knowledge/ มีไฟล์ .md")
        return 1

    # ── (1) ตาราง CVE แบบมีโครงสร้าง → collection vulnex_cve (scanner ใช้จับคู่เวอร์ชัน) ──
    struct_points = cve_structured_points(cve_db)
    if not store.ensure_cve_collection(recreate=args.recreate):
        print("[ERROR] สร้าง/เข้าถึง collection vulnex_cve ไม่สำเร็จ")
        return 1
    cve_total = 0
    for i in range(0, len(struct_points), BATCH):
        cve_total += store.upsert_cve_entries(struct_points[i:i + BATCH])
    print(f"[info] อัปโหลดตาราง CVE {cve_total} รายการ → '{store.CVE_COLLECTION}' "
          f"({len(cve_db)} server types)")

    # ── (2) ชิ้นความรู้ (prose/semantic) → collection vulnex_knowledge (RAG ค้นความหมาย) ──
    if not store.ensure_collection(recreate=args.recreate):
        print("[ERROR] สร้าง/เข้าถึง collection vulnex_knowledge ไม่สำเร็จ")
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

    print(f"[done] ingest สำเร็จ — vulnex_knowledge {store.count()} จุด, "
          f"vulnex_cve {store.count(store.CVE_COLLECTION)} จุด")
    # สรุปหมวด
    cats: dict[str, int] = {}
    for c in chunks:
        cats[c.category] = cats.get(c.category, 0) + 1
    print("[summary] ชิ้นความรู้ตามหมวด: "
          + ", ".join(f"{k}={v}" for k, v in sorted(cats.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
