# src/module_insight.py — per-module "AI summary" for the Scan Modules dropdowns
#
# Each active module gets a 3-part card shown when its dropdown is expanded:
#   · วิธีสแกน     — how we scanned it (static, authored — never AI-generated → no hallucination)
#   · จุดที่พบปัญหา — what's wrong (derived from the module's own scan data)
#   · วิธีแก้       — how to fix it (derived from the scan data)
#
# Hybrid generation (user choice "AI จริง + สำรองกฎอัตโนมัติ"):
#   1. a rule-based builder turns each module's findings into grounding FACTS — this is
#      also the guaranteed fallback, so a dropdown is never empty even with no AI/quota;
#   2. a SINGLE batched generate_smart() call rewrites those facts into friendly Thai
#      prose for every module at once (cached by scan fingerprint, best-effort). If the
#      call or its parse fails, each module silently keeps its rule-based text.
import hashlib
import json
import re
from typing import Dict, List, Tuple

from cachetools import TTLCache

# Modules that get an AI summary card. "headers" has its own tab; the other four are
# dropdowns in the "Scan Modules" tab. The suspended modules (http_methods, cms, cors,
# open_files) are intentionally NOT here — left untouched.
ACTIVE_MODULES: Tuple[str, ...] = ("headers", "dns", "cookies", "js_exposure", "subdomains")

_MODULE_NAME: Dict[str, str] = {
    "headers":      "HTTP Security Headers",
    "dns":          "DNS & Email Security",
    "cookies":      "Cookie Security",
    "js_exposure":  "JavaScript Exposure",
    "subdomains":   "Subdomain Recon",
}

# Authored, accurate "how we scan" — never sent to the model, so it can't be distorted.
_SCAN_METHOD: Dict[str, str] = {
    "headers": ("ส่งคำขอ GET หนึ่งครั้ง แล้วอ่าน HTTP response header ด้านความปลอดภัย 6 ตัว "
                "(CSP, HSTS, X-Frame-Options ฯลฯ) — ตรวจทั้ง 'มีครบไหม' และ 'ตั้งค่ารัดกุมพอไหม' "
                "ไม่ใช่แค่มี/ไม่มี จึงเป็นเหตุผลที่บางเว็บมี header ครบแต่ยังได้คะแนนไม่เต็ม"),
    "dns": ("ส่งคำขอ DNS แบบอ่านอย่างเดียวไปยัง public resolver (8.8.8.8 / 1.1.1.1) "
            "เพื่อดูระเบียน SPF, DMARC, DKIM, DNSSEC และ CAA — ไม่แตะเซิร์ฟเวอร์ของเว็บเลย"),
    "cookies": ("เปิดหน้าเว็บด้วยคำขอ GET หนึ่งครั้ง แล้วอ่านเฉพาะส่วนหัว Set-Cookie "
                "เพื่อตรวจว่าคุกกี้แต่ละตัวตั้งค่า Secure / HttpOnly / SameSite ครบหรือไม่"),
    "js_exposure": ("ดาวน์โหลดหน้า HTML และไฟล์ JavaScript ภายนอก (อ่านอย่างเดียว) "
                    "แล้วค้นหา API key/รหัสลับที่หลุด, source map ที่เปิดสาธารณะ และไลบรารีเวอร์ชันเก่า"),
    "subdomains": ("ค้นหาโดเมนย่อยแบบ passive จาก Certificate Transparency log (crt.sh) "
                   "และรายชื่อในใบรับรอง SSL — ไม่ยิงทดสอบและไม่สุ่มเดาชื่อกับเซิร์ฟเวอร์"),
}

_insight_cache: TTLCache = TTLCache(maxsize=50, ttl=3600)


# ─────────────────────────────────────────────────────────────────
# Rule-based fact extractors (→ (problems, fixes)); also the fallback text source
# ─────────────────────────────────────────────────────────────────
_HDR_DESC = {
    "Content-Security-Policy":   "ป้องกัน XSS",
    "Strict-Transport-Security": "บังคับใช้ HTTPS เสมอ",
    "X-Frame-Options":           "ป้องกัน clickjacking",
    "X-Content-Type-Options":    "ป้องกัน MIME sniffing",
    "Referrer-Policy":           "ควบคุมข้อมูล referrer",
    "Permissions-Policy":        "จำกัดสิทธิ์ browser API",
}
_HDR_FIX = {
    "Content-Security-Policy":   "ตั้ง CSP เช่น `default-src 'self'; script-src 'self'` และเลี่ยง `unsafe-inline`/`unsafe-eval`",
    "Strict-Transport-Security": "ตั้ง `Strict-Transport-Security: max-age=31536000; includeSubDomains`",
    "X-Frame-Options":           "ตั้ง `X-Frame-Options: DENY` (หรือ `SAMEORIGIN`)",
    "X-Content-Type-Options":    "ตั้ง `X-Content-Type-Options: nosniff`",
    "Referrer-Policy":           "ตั้ง `Referrer-Policy: strict-origin-when-cross-origin`",
    "Permissions-Policy":        "ตั้ง Permissions-Policy จำกัด camera/microphone/geolocation",
}


def _hdr_weak_reason(h: str, val: str) -> str:
    """อธิบายว่าทำไม header ที่ 'มีอยู่' ถึงยังได้คะแนนไม่เต็ม (อิงค่าจริงที่ตรวจพบ)."""
    v = val.lower()
    if h == "Content-Security-Policy":
        if "unsafe-inline" in v and "unsafe-eval" in v:
            return "มีทั้ง unsafe-inline และ unsafe-eval"
        if "unsafe-inline" in v:
            return "มี unsafe-inline"
        if "unsafe-eval" in v:
            return "มี unsafe-eval"
        if v.strip() in ("", "*"):
            return "นโยบายกว้างเกินไป"
        return "ยังมีคำสั่งที่เสี่ยงอยู่"
    if h == "Strict-Transport-Security":
        return "อายุ (max-age) สั้นเกินไป — ควร ≥ 1 ปี (31536000)"
    if h == "X-Frame-Options":
        return "ควรตั้งเป็น DENY หรือ SAMEORIGIN"
    if h == "X-Content-Type-Options":
        return "ควรเป็น nosniff"
    if h == "Referrer-Policy":
        return "ค่าที่ตั้งยังเปิดเผยข้อมูล referrer มากไป"
    return "การตั้งค่ายังไม่รัดกุมพอ"


def _headers_facts(m: dict) -> Tuple[List[str], List[str]]:
    if m.get("error"):
        return [f"ตรวจ security header ไม่สำเร็จ ({m['error']})"], ["ลองสแกนใหม่อีกครั้ง"]
    problems: List[str] = []
    fixes: List[str] = []
    found = m.get("headers_found") or {}
    missing = m.get("headers_missing") or []
    quality = m.get("headers_quality") or {}
    # 1) header ที่ขาดไปเลย
    for h in missing:
        problems.append(f"ขาด {h} — {_HDR_DESC.get(h, '')}")
        fixes.append(_HDR_FIX.get(h, f"เพิ่ม header {h}"))
    # 2) header ที่ 'มี' แต่คุณภาพ < เต็ม (นี่คือเหตุผลที่คะแนนไม่เต็มทั้งที่ไม่ขาดตัวไหน)
    for h, q in quality.items():
        try:
            qf = float(q)
        except (TypeError, ValueError):
            continue
        if qf >= 1.0:
            continue
        reason = _hdr_weak_reason(h, str(found.get(h, "")))
        problems.append(f"มี {h} แล้ว แต่ตั้งค่ายังไม่รัดกุม ({reason}) จึงยังได้คะแนนไม่เต็ม")
        fixes.append(_HDR_FIX.get(h, f"ปรับ {h} ให้รัดกุมขึ้น"))
    return problems, fixes


def _dns_facts(m: dict) -> Tuple[List[str], List[str]]:
    if m.get("error"):
        return [f"ตรวจ DNS ไม่สำเร็จ ({m['error']})"], ["ลองสแกนใหม่ หรือตรวจว่าโดเมนสะกดถูกต้อง"]
    problems: List[str] = []
    fixes: List[str] = []
    spf = m.get("spf") or {}
    if not spf.get("present"):
        problems.append("ไม่มี SPF — บุคคลอื่นแอบส่งอีเมลปลอมในนามโรงเรียนได้ง่าย")
        fixes.append("เพิ่ม SPF record ที่ลงท้ายด้วย `-all` เช่น `v=spf1 include:_spf.google.com -all`")
    elif spf.get("policy") in ("~all", "?all", "+all", "none", ""):
        problems.append(f"SPF ตั้งค่าหลวม (`{spf.get('policy') or 'ไม่ระบุ'}`) ยังไม่บล็อกอีเมลปลอมจริง")
        fixes.append("เปลี่ยนท้าย SPF ให้เป็น `-all` เพื่อบังคับใช้")
    dmarc = m.get("dmarc") or {}
    if not dmarc.get("present"):
        problems.append("ไม่มี DMARC — ไม่มีนโยบายบอกปลายทางว่าจะจัดการอีเมลปลอมอย่างไร")
        fixes.append("เพิ่ม TXT ที่ `_dmarc.<โดเมน>`: `v=DMARC1; p=reject; rua=mailto:admin@...`")
    elif str(dmarc.get("policy", "")).lower() == "none":
        problems.append("DMARC ตั้ง `p=none` (แค่เฝ้าดู ยังไม่บังคับใช้)")
        fixes.append("ไล่ระดับ DMARC เป็น `p=quarantine` แล้วค่อยเป็น `p=reject`")
    if not (m.get("dkim") or {}).get("present"):
        problems.append("ไม่พบ DKIM — อีเมลขาออกไม่มีลายเซ็นดิจิทัลยืนยันตัวตน")
        fixes.append("เปิด DKIM ในผู้ให้บริการอีเมล แล้วประกาศ public key เป็น DNS TXT")
    if not (m.get("dnssec") or {}).get("signed"):
        problems.append("ยังไม่เปิด DNSSEC — ผลลัพธ์ DNS ถูกปลอมแปลงได้")
        fixes.append("เปิด DNSSEC ที่ผู้ให้บริการโดเมน (registrar)")
    return problems, fixes


def _cookies_facts(m: dict) -> Tuple[List[str], List[str]]:
    if m.get("error"):
        return [f"อ่านคุกกี้ไม่สำเร็จ ({m['error']})"], ["ลองสแกนใหม่อีกครั้ง"]
    if not (m.get("cookies") or []):
        return [], []   # ไม่มีคุกกี้ → ไม่มีอะไรต้องแก้
    problems: List[str] = []
    fixes: List[str] = []
    for f in (m.get("findings") or [])[:4]:
        detail = f.get("detail", "")
        problems.append(f"{f.get('title', 'คุกกี้ไม่ปลอดภัย')}{(' — ' + detail) if detail else ''}")
    if problems:
        fixes.append("ตั้งค่าคุกกี้ให้มี `Secure`, `HttpOnly` และ `SameSite=Lax` (หรือ `Strict`) ครบทุกตัว")
    return problems, fixes


def _js_facts(m: dict) -> Tuple[List[str], List[str]]:
    if m.get("error"):
        return [f"ตรวจ JavaScript ไม่สำเร็จ ({m['error']})"], ["ลองสแกนใหม่อีกครั้ง"]
    problems: List[str] = []
    fixes: List[str] = []
    for s in (m.get("secrets_found") or [])[:3]:
        problems.append(f"พบ{s.get('type', 'ข้อมูลลับ')}หลุดอยู่ใน {s.get('source', 'สคริปต์')}")
    if m.get("secrets_found"):
        fixes.append("ย้ายคีย์/รหัสลับออกจากโค้ดฝั่งหน้าเว็บ และเพิกถอน (revoke) คีย์ที่หลุดทันที")
    smaps = m.get("source_maps_exposed") or []
    if smaps:
        problems.append(f"เปิด source map สู่สาธารณะ {len(smaps)} ไฟล์ (เปิดเผยซอร์สโค้ดต้นฉบับ)")
        fixes.append("ปิดการนำไฟล์ .map ขึ้น production")
    for lib in (m.get("outdated_libs") or [])[:3]:
        problems.append(f"ใช้ไลบรารีเวอร์ชันเก่า: {lib.get('lib', '')}")
    if m.get("outdated_libs"):
        fixes.append("อัปเดตไลบรารี JavaScript เป็นเวอร์ชันล่าสุด")
    return problems, fixes


def _subdomain_facts(m: dict) -> Tuple[List[str], List[str]]:
    if m.get("error"):
        return [f"ค้นหาโดเมนย่อยไม่สำเร็จ ({m['error']})"], ["ลองสแกนใหม่อีกครั้ง"]
    problems: List[str] = []
    fixes: List[str] = []
    for f in (m.get("findings") or [])[:4]:
        detail = f.get("detail", "")
        problems.append(f"{f.get('title', '')}{(' — ' + detail) if detail else ''}")
    if problems:
        fixes.append("ตรวจว่าโดเมนย่อยที่ละเอียดอ่อน (เช่น admin/dev/test) จำกัดสิทธิ์การเข้าถึงเพียงพอ "
                     "และปิดตัวที่ไม่ได้ใช้งานแล้ว")
    return problems, fixes


_EXTRACTORS = {
    "headers":     _headers_facts,
    "dns":         _dns_facts,
    "cookies":     _cookies_facts,
    "js_exposure": _js_facts,
    "subdomains":  _subdomain_facts,
}


def _rule_narrative(problems: List[str], fixes: List[str]) -> str:
    if not problems:
        return "ไม่พบปัญหาที่ต้องแก้จากข้อมูลที่สแกนได้ — หัวข้อนี้อยู่ในเกณฑ์ดีแล้ว"
    lines = ["**จุดที่พบปัญหา**"]
    lines += [f"- {p}" for p in problems]
    if fixes:
        lines += ["", "**วิธีแก้**"]
        lines += [f"- {f}" for f in fixes]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# AI batch (one call, cached) — rewrites the facts into friendly Thai
# ─────────────────────────────────────────────────────────────────
def _facts_all(scan_data: dict) -> Dict[str, dict]:
    facts: Dict[str, dict] = {}
    for key in ACTIVE_MODULES:
        mod = scan_data.get(key, {}) or {}
        if mod.get("suspended"):
            continue
        problems, fixes = _EXTRACTORS[key](mod)
        facts[key] = {"name": _MODULE_NAME[key], "problems": problems, "fixes": fixes}
    return facts


def _cache_key(scan_data: dict) -> str:
    payload = {}
    for key in ACTIVE_MODULES:
        m = scan_data.get(key, {}) or {}
        payload[key] = {
            "score":    m.get("score"),
            "error":    bool(m.get("error")),
            "findings": sorted(str(f.get("title", "")) for f in (m.get("findings") or [])),
        }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _ai_prompt(facts: Dict[str, dict]) -> str:
    blocks = []
    for key, f in facts.items():
        prob = "; ".join(f["problems"]) or "ไม่พบปัญหา"
        fix = "; ".join(f["fixes"]) or "-"
        blocks.append(f"[{key}] {f['name']}\n- ปัญหาที่ตรวจพบ: {prob}\n- แนวทางแก้ที่แนะนำ: {fix}")
    data = "\n\n".join(blocks)
    header_fmt = "".join(f"[{k}] <สรุป>\n" for k in facts)
    return (
        "คุณเป็นผู้เชี่ยวชาญความปลอดภัยไซเบอร์ที่อธิบายให้ครูและเจ้าหน้าที่ไอทีของโรงเรียนเข้าใจง่าย "
        "โดยไม่ใช้ศัพท์เทคนิคเกินจำเป็น\n\n"
        "ด้านล่างคือผลการสแกนแต่ละหัวข้อพร้อมข้อเท็จจริงที่ตรวจพบ ให้เขียน 'สรุปสั้น 2-3 ประโยค' "
        "ต่อหนึ่งหัวข้อ อธิบายว่าพบปัญหาตรงไหนและควรแก้อย่างไร ด้วยภาษาไทยที่เป็นกันเองแต่ถูกต้อง "
        "หากหัวข้อใดไม่พบปัญหา ให้ชมสั้น ๆ ว่าทำได้ดี\n"
        "กติกา: ห้ามแต่งข้อมูลเกินจากที่ให้ไว้ ห้ามใช้อีโมจิ ตอบเป็นภาษาไทยเท่านั้น\n\n"
        "ตอบตามรูปแบบนี้ (ขึ้นต้นแต่ละหัวข้อด้วย [key] ตามที่กำหนด ห้ามเปลี่ยน key):\n"
        f"{header_fmt}\n"
        f"ข้อมูลผลสแกน:\n{data}"
    )


def _parse_ai(text: str, keys: set) -> Dict[str, str]:
    out: Dict[str, str] = {}
    matches = list(re.finditer(r"\[(\w+)\]", text))
    for i, mt in enumerate(matches):
        k = mt.group(1)
        if k not in keys:
            continue
        start = mt.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        seg = text[start:end].strip(" :\n\r\t-*")
        if seg:
            out[k] = seg
    return out


def build_module_insights(scan_data: dict, server_data: dict | None = None) -> Dict[str, dict]:
    """Return {module_key: {method, summary, source ('ai'|'rule'), status ('ok'|'issues')}}.

    Never raises — rule-based text is always present; AI just upgrades the wording."""
    facts = _facts_all(scan_data)
    result: Dict[str, dict] = {}
    for key, f in facts.items():
        result[key] = {
            "method":  _SCAN_METHOD.get(key, ""),
            "summary": _rule_narrative(f["problems"], f["fixes"]),
            "source":  "rule",
            "status":  "issues" if f["problems"] else "ok",
        }
    if not facts:
        return result

    # AI enhancement — single batched call, cached by scan fingerprint, best-effort.
    ck = _cache_key(scan_data)
    ai_map = _insight_cache.get(ck)
    if ai_map is None:
        ai_map = {}
        try:
            from ai_engine import generate_smart
            txt, _prov = generate_smart(
                _ai_prompt(facts),
                {"temperature": 0.3, "max_output_tokens": 1024},
            )
            parsed = _parse_ai(txt, set(facts))
            if parsed:
                _insight_cache[ck] = parsed   # cache only a usable result → allow retry
            ai_map = parsed
        except Exception:
            ai_map = {}                       # any failure → keep rule-based text
    for key, seg in ai_map.items():
        if key in result and seg:
            result[key]["summary"] = seg
            result[key]["source"] = "ai"
    return result
