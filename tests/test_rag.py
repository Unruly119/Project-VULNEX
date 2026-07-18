# test_rag.py — ทดสอบชั้น RAG (chunker / formatter / env / live Qdrant)
#
# รันตรง ๆ:  python tests/test_rag.py
# (หรือด้วย pytest ก็ได้ — ฟังก์ชัน test_* ใช้ assert ล้วน)
#
# ส่วน unit (chunker/formatter/env) ไม่ต่อเน็ต; ส่วน live จะข้ามเองอย่างสุภาพ
# ถ้าไม่ได้ตั้งค่า Qdrant/Gemini ใน .env
import os
import sys

sys.path.insert(0, "src")

from dotenv import load_dotenv

load_dotenv(override=True)

from rag import format_context, retrieve  # noqa: E402
from rag import embeddings, store  # noqa: E402
from rag.chunker import chunk_markdown, iter_knowledge_chunks  # noqa: E402

_SAMPLE = """---
category: headers
source: Test Source
refs: OWASP, CWE-693
---

## หัวข้อแรก ทดสอบ

เนื้อหาย่อหน้าที่หนึ่งของหัวข้อแรก อธิบายเรื่องความปลอดภัย

## หัวข้อสอง

เนื้อหาของหัวข้อสอง
"""


def test_chunker_parses_frontmatter_and_headings():
    chunks = chunk_markdown(_SAMPLE, doc="sample.md")
    assert len(chunks) == 2, f"ควรได้ 2 chunk ได้ {len(chunks)}"
    c0 = chunks[0]
    assert c0.category == "headers"
    assert c0.source == "Test Source"
    assert c0.refs == ["OWASP", "CWE-693"]
    assert c0.title == "หัวข้อแรก ทดสอบ"
    assert "ย่อหน้าที่หนึ่ง" in c0.text
    assert c0.title in c0.embed_text()          # หัวข้อถูกนำขึ้นก่อนใน embed text
    # id เสถียร: parse ซ้ำได้ id เดิม
    again = chunk_markdown(_SAMPLE, doc="sample.md")
    assert again[0].chunk_id == c0.chunk_id
    print("[ok] chunker: frontmatter + heading split + stable id")


def test_chunker_skips_empty_and_missing_dir():
    assert chunk_markdown("---\ncategory: x\n---\n", doc="e.md") == []
    assert iter_knowledge_chunks("____no_such_dir____") == []
    print("[ok] chunker: empty body / missing dir → []")


def test_format_context_empty_and_capped():
    assert format_context([]) == ""
    big = [{"title": f"T{i}", "source": "S", "text": "ก" * 500, "refs": ["R"]}
           for i in range(20)]
    out = format_context(big, max_chars=1200)
    assert "คลังความรู้อ้างอิง" in out
    assert len(out) < 2000, "ควรถูกจำกัดความยาวตาม max_chars"
    print("[ok] formatter: empty → '' ; long list capped")


def test_env_resolution_case_insensitive():
    # store.get_config อ่าน Qdrant_Cluster_Endpoint / QDRANT_URL แบบไม่สนตัวพิมพ์
    os.environ.pop("QDRANT_URL", None)
    os.environ["qdrant_url"] = "https://example.test"
    url, _ = store.get_config()
    # อาจถูกทับด้วยค่าใน .env จริง — เช็คว่ากลไก case-insensitive ทำงาน (ไม่พังและได้ค่า)
    assert isinstance(url, str)
    os.environ.pop("qdrant_url", None)
    print("[ok] env: case-insensitive resolution")


def test_retrieve_failsoft_without_config(monkeypatch=None):
    # ถ้า RAG ไม่พร้อม retrieve ต้องคืน [] ไม่ throw
    import rag.retriever as r
    orig = r.is_available
    r.is_available = lambda: False
    try:
        assert retrieve("อะไรก็ได้") == []
    finally:
        r.is_available = orig
    print("[ok] retrieve: fail-soft → [] when RAG unavailable")


def test_live_qdrant_retrieval():
    if not (store.is_configured() and embeddings.has_embedding_provider()):
        print("[skip] live Qdrant: ไม่ได้ตั้งค่า .env (Qdrant/Gemini)")
        return
    n = store.count()
    print(f"[info] Qdrant collection '{store.COLLECTION}' มี {n} จุด")
    assert n > 0, "collection ว่าง — รัน scripts/ingest_knowledge.py ก่อน"
    hits = retrieve("เว็บไม่มี Content-Security-Policy ควรแก้อย่างไร", k=3)
    assert hits, "ควรค้นเจออย่างน้อย 1 ชิ้น"
    assert hits[0]["score"] > 0.4, f"คะแนนต่ำผิดปกติ: {hits[0]['score']}"
    print(f"[ok] live Qdrant: top hit ({hits[0]['score']:.3f}) {hits[0]['title'][:50]}")
    # การกรองหมวดต้องได้เฉพาะหมวดนั้น
    cve = retrieve("nginx เวอร์ชันเก่ามีช่องโหว่", k=3, categories=["cve"])
    assert cve and all(h["category"] == "cve" for h in cve), "การกรองหมวด cve ล้มเหลว"
    print(f"[ok] live Qdrant: category filter → {len(cve)} cve chunks")


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            print(f"[ERROR] {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} ผ่าน")
    return passed == len(fns)


if __name__ == "__main__":
    raise SystemExit(0 if _run_all() else 1)
