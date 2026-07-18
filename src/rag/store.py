"""ตัวเชื่อม Qdrant Cloud — สร้าง/ค้น/เพิ่มข้อมูลใน collection ของคลังความรู้.

อ่านค่าเชื่อมต่อจาก env: Qdrant_Cluster_Endpoint + Qdrant_API_Key
(รองรับชื่อพิมพ์เล็ก/ใหญ่และ QDRANT_URL/QDRANT_API_KEY เป็น alias)

ดีไซน์: collection เดียว 'vulnex_knowledge' (เวกเตอร์ dense 768d, COSINE) + payload
field 'category' สำหรับกรองตามหมวด (owasp_top10 / cve / nist_csf / ...) — ค้นข้ามทุก
หมวดได้ในคำสั่งเดียว ซึ่งเหมาะกับ RAG ที่ต้องหยิบความรู้ที่ตรงที่สุดไม่ว่ามาจากแหล่งใด

ทุกฟังก์ชัน fail-soft: ถ้าไม่ได้ตั้งค่า/เชื่อมต่อไม่ได้ ให้คืนค่าว่างแทนการโยน error
ออกไปยัง UI (ยกเว้น ingest ที่ตั้งใจให้ดังเพื่อรู้ว่าล้มเหลว)
"""
from __future__ import annotations

import os

COLLECTION = "vulnex_knowledge"
VECTOR_DIM = 768


def _env_ci(*names: str) -> str:
    for name in names:
        val = os.getenv(name)
        if val:
            return val.strip()
    # ไม่สนตัวพิมพ์
    lowered = {n.lower() for n in names}
    for k, v in os.environ.items():
        if k.lower() in lowered and v:
            return v.strip()
    return ""


def get_config() -> tuple[str, str]:
    """คืน (endpoint, api_key) จาก env — ค่าว่างถ้าไม่ได้ตั้ง."""
    url = _env_ci("Qdrant_Cluster_Endpoint", "QDRANT_URL", "QDRANT_ENDPOINT")
    key = _env_ci("Qdrant_API_Key", "QDRANT_API_KEY")
    return url, key


def is_configured() -> bool:
    url, key = get_config()
    return bool(url and key)


_client = None
_client_failed = False


def get_client():
    """คืน QdrantClient (สร้างครั้งเดียว, cache) — None ถ้าไม่ได้ตั้งค่า/เชื่อมต่อไม่ได้."""
    global _client, _client_failed
    if _client is not None:
        return _client
    if _client_failed or not is_configured():
        return None
    url, key = get_config()
    try:
        from qdrant_client import QdrantClient
        _client = QdrantClient(url=url, api_key=key, timeout=20)
        return _client
    except Exception:  # noqa: BLE001 — เชื่อมต่อไม่ได้ → ทำงานแบบไม่มี RAG
        _client_failed = True
        return None


def ensure_collection(recreate: bool = False) -> bool:
    """ทำให้มี collection พร้อมสคีมาที่ถูกต้อง (dense 768d COSINE).

    recreate=True → ลบแล้วสร้างใหม่ (ใช้ตอน ingest รอบเต็ม). คืน True ถ้าพร้อมใช้งาน.
    """
    client = get_client()
    if client is None:
        return False
    from qdrant_client.models import Distance, VectorParams

    try:
        exists = client.collection_exists(COLLECTION)
    except Exception:  # noqa: BLE001
        return False

    if exists and not recreate:
        _ensure_category_index(client)
        return True
    try:
        if exists and recreate:
            client.delete_collection(COLLECTION)
        client.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=VECTOR_DIM, distance=Distance.COSINE),
        )
        _ensure_category_index(client)
        return True
    except Exception:  # noqa: BLE001
        return False


def _ensure_category_index(client) -> None:
    """สร้าง keyword payload index บน 'category' — Qdrant Cloud บังคับต้องมี index
    ก่อนถึงจะกรองด้วย field ได้ (ไม่งั้น query_points ที่มี filter จะคืน 400)."""
    from qdrant_client.models import PayloadSchemaType

    try:
        client.create_payload_index(
            collection_name=COLLECTION,
            field_name="category",
            field_schema=PayloadSchemaType.KEYWORD,
        )
    except Exception:  # noqa: BLE001 — มีอยู่แล้ว/สร้างไม่ได้ ก็ข้ามไป
        pass


def upsert_points(points: list[dict]) -> int:
    """เพิ่ม/อัปเดตจุด — points = [{'id','vector','payload'}]. คืนจำนวนที่ upsert."""
    client = get_client()
    if client is None or not points:
        return 0
    from qdrant_client.models import PointStruct

    structs = [
        PointStruct(id=p["id"], vector=p["vector"], payload=p["payload"])
        for p in points
    ]
    client.upsert(collection_name=COLLECTION, points=structs, wait=True)
    return len(structs)


def search(query_vector: list[float], limit: int = 5,
           categories: list[str] | None = None) -> list[dict]:
    """ค้นความรู้ที่ใกล้ที่สุด — คืน [{'score', ...payload}]. ว่างถ้าไม่มี RAG."""
    client = get_client()
    if client is None:
        return []
    query_filter = None
    if categories:
        from qdrant_client.models import FieldCondition, Filter, MatchAny
        query_filter = Filter(
            must=[FieldCondition(key="category", match=MatchAny(any=list(categories)))]
        )
    try:
        resp = client.query_points(
            collection_name=COLLECTION,
            query=query_vector,
            limit=limit,
            query_filter=query_filter,
            with_payload=True,
        )
    except Exception:  # noqa: BLE001 — ค้นไม่ได้ → คืนว่าง ให้ pipeline เดินต่อ
        return []
    out: list[dict] = []
    for pt in resp.points:
        payload = dict(pt.payload or {})
        payload["score"] = float(pt.score) if pt.score is not None else 0.0
        out.append(payload)
    return out


def count() -> int:
    """จำนวนจุดใน collection (0 ถ้าไม่มี/เชื่อมต่อไม่ได้)."""
    client = get_client()
    if client is None:
        return 0
    try:
        return int(client.count(COLLECTION, exact=True).count)
    except Exception:  # noqa: BLE001
        return 0
