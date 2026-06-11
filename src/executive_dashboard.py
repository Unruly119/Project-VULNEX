# src/executive_dashboard.py — Executive Dashboard helpers (Pillar 4.2)
from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

# Static sector benchmarks — Thai vocational education (demo)
SECTOR_BENCHMARKS = {
    "vocational": {"label": "วิทยาลัยอาชีวศึกษา (เฉลี่ย)", "avg_score": 58, "p25": 42, "p75": 71},
    "university": {"label": "มหาวิทยาลัยรัฐ (เฉลี่ย)", "avg_score": 65, "p25": 52, "p75": 78},
    "secondary":  {"label": "โรงเรียนมัธยม (เฉลี่ย)", "avg_score": 52, "p25": 38, "p75": 65},
    "primary":    {"label": "โรงเรียนประถม (เฉลี่ย)", "avg_score": 48, "p25": 35, "p75": 60},
}

TRAFFIC_LIGHT = {
    "green":  {"emoji": "🟢", "label": "ดี", "min_score": 70},
    "yellow": {"emoji": "🟡", "label": "ควรปรับปรุง", "min_score": 40},
    "red":    {"emoji": "🔴", "label": "เสี่ยงสูง", "min_score": 0},
}


def traffic_light(score: int) -> Tuple[str, str, str]:
    """Return (emoji, label, css_class) for composite score."""
    if score >= 70:
        return TRAFFIC_LIGHT["green"]["emoji"], TRAFFIC_LIGHT["green"]["label"], "col-good"
    if score >= 40:
        return TRAFFIC_LIGHT["yellow"]["emoji"], TRAFFIC_LIGHT["yellow"]["label"], "col-warn"
    return TRAFFIC_LIGHT["red"]["emoji"], TRAFFIC_LIGHT["red"]["label"], "col-crit"


def build_trend_history(
    current_score: int,
    session_history: List[Dict] | None = None,
) -> List[Dict]:
    """
    Build 12-month trend data.
    Uses session_history if available; otherwise simulates plausible history from current score.
    """
    if session_history and len(session_history) >= 2:
        # Pad or trim to 12 months from session scans
        points = session_history[-12:]
        while len(points) < 12:
            prev = points[0]["score"] if points else current_score
            points.insert(0, {
                "month": (datetime.now() - timedelta(days=30 * (12 - len(points)))).strftime("%Y-%m"),
                "score": max(0, min(100, prev + random.randint(-5, 5))),
            })
        return points

    # Simulated demo trend anchored to current score
    rng = random.Random(current_score * 17 + 42)
    scores = []
    base = current_score
    for i in range(11, -1, -1):
        drift = rng.randint(-4, 4)
        base = max(20, min(95, base + drift))
        month_dt = datetime.now() - timedelta(days=30 * i)
        scores.append({"month": month_dt.strftime("%Y-%m"), "score": base})
    scores[-1]["score"] = current_score
    return scores


def top_urgent_risks_plain(
    scan_data: dict,
    server_data: dict,
    ai_data: dict,
    max_items: int = 3,
) -> List[str]:
    """Rule-based top risks in plain Thai for executives."""
    risks: List[Tuple[int, str]] = []

    vulns = server_data.get("vulnerabilities", []) or []
    for v in vulns:
        sev = str(v.get("severity", "")).upper()
        priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(sev, 3)
        cve = v.get("cve", "ช่องโหว่")
        desc = v.get("desc", "")
        risks.append((priority, f"พบ {cve} บนเซิร์ฟเวอร์ — {desc[:80]}"))

    if server_data.get("dos_risk"):
        risks.append((0, "เซิร์ฟเวอร์เสี่ยงถูกโจมตีแบบทำให้เว็บล่ม (HTTP/2 DoS) — อาจกระทบการสอบออนไลน์"))

    ssl = scan_data.get("ssl", {}) or {}
    if not ssl.get("valid"):
        risks.append((1, "ใบรับรอง SSL มีปัญหา — ข้อมูลล็อกอินอาจถูกดักจับได้"))
    elif int(ssl.get("days_left", 0) or 0) <= 30:
        risks.append((2, f"SSL จะหมดอายุใน {ssl['days_left']} วัน — นักเรียนอาจเข้าเว็บไม่ได้"))

    dns = scan_data.get("dns", {}) or {}
    if not dns.get("error"):
        if not dns.get("spf", {}).get("present"):
            risks.append((1, "ไม่มี SPF — อีเมลหลอกแอบอ้างชื่อโรงเรียนได้"))
        if dns.get("dmarc", {}).get("policy") == "none":
            risks.append((2, "DMARC ยังไม่บังคับใช้ — อีเมลปลอมยังส่งถึงผู้ปกครองได้"))

    cookies = scan_data.get("cookies", {}) or {}
    for f in (cookies.get("findings") or [])[:2]:
        risks.append((2, f.get("detail", f.get("title", "Cookie ไม่ปลอดภัย"))))

    open_f = scan_data.get("open_files", {}) or {}
    for sf in (open_f.get("sensitive_files") or [])[:2]:
        risks.append((0, f"ไฟล์สำคัญ '{sf.get('path')}' เปิดให้เข้าถึงได้จากภายนอก"))

    js = scan_data.get("js_exposure", {}) or {}
    for s in (js.get("secrets_found") or [])[:2]:
        risks.append((0, f"พบ {s.get('type', 'ข้อมูลลับ')} ใน JavaScript — อาจถูกนำไปใช้โจมตี"))

    hdr = scan_data.get("headers", {}) or {}
    missing = hdr.get("headers_missing", []) or []
    if "Strict-Transport-Security" in missing:
        risks.append((2, "ไม่มี HSTS — ผู้ใช้ WiFi สาธารณะอาจถูกดักข้อมูลล็อกอิน"))
    if "Content-Security-Policy" in missing:
        risks.append((2, "ไม่มี CSP — เว็บเสี่ยงถูกแทรกโค้ดอันตราย (XSS)"))

    risks.sort(key=lambda x: x[0])
    plain = [r[1] for r in risks[:max_items]]
    if not plain:
        risk_level = ai_data.get("risk_level", "LOW")
        if risk_level in ("CRITICAL", "HIGH"):
            plain.append("คะแนนรวมต่ำ — ควรให้ทีม IT ตรวจสอบรายละเอียดและแก้ไขตามลำดับความสำคัญ")
        else:
            plain.append("ไม่พบความเสี่ยงเร่งด่วนระดับสูง — รักษามาตรฐานและสแกนซ้ำเป็นระยะ")
    return plain


def cost_of_inaction(score: int, risk: str) -> str:
    """Plain-language cost of inaction message."""
    if risk == "CRITICAL" or score < 30:
        return (
            "ถ้าไม่แก้ไขภายใน 30 วัน — ความเสี่ยงระดับ **วิกฤต** จะเพิ่มขึ้น "
            "อาจเกิดการรั่วไหลข้อมูลนักเรียน/ผู้ปกครอง, เว็บถูก deface, หรือ ransomware "
            "ค่าเสียหายโดยประมาณ 500,000–5,000,000 บาท (recovery + ชื่อเสียง + กฎหมาย PDPA)"
        )
    if risk == "HIGH" or score < 50:
        return (
            "ถ้าไม่แก้ไขภายใน 30 วัน — ความเสี่ยงระดับ **สูง** จะคงอยู่ "
            "โอกาสถูกโจมตีผ่านช่องโหว่ที่รู้แล้ว ~40% ภายใน 90 วัน "
            "แนะนำจัดสรรงบ IT security อย่างน้อย 1 รายการเร่งด่วนต่อเดือน"
        )
    if score < 70:
        return (
            "ถ้าไม่ปรับปรุงต่อเนื่อง — คะแนนอาจลดลง 10–15 จุดภายใน 6 เดือน "
            "จาก SSL หมดอายุ, CMS ไม่อัปเดต, หรือมาตรฐาน sector ที่สูงขึ้น"
        )
    return (
        "สถานะโดยรวมอยู่ในเกณฑ์ดี — หากไม่บำรุงรักษา คะแนนอาจลดลงเมื่อ cert หมดอายุ "
        "หรือมี CVE ใหม่ที่ affect software ในระบบ"
    )


def benchmark_comparison(score: int, sector: str = "vocational") -> Dict:
    """Compare score vs static Thai education sector benchmark."""
    bench = SECTOR_BENCHMARKS.get(sector, SECTOR_BENCHMARKS["vocational"])
    avg = bench["avg_score"]
    diff = score - avg
    if diff >= 10:
        percentile = min(95, 50 + diff)
        verdict = f"สูงกว่าค่าเฉลี่ย sector {diff} คะแนน — อยู่ในกลุ่มที่ดีกว่า ~{percentile:.0f}% ของสถาบันในกลุ่ม"
    elif diff >= 0:
        verdict = f"ใกล้เคียงค่าเฉลี่ย sector ({avg}/100) — ควรปรับปรุงให้เหนือ {bench['p75']} เพื่อความปลอดภัยที่ดี"
    else:
        percentile = max(5, 50 + diff)
        verdict = f"ต่ำกว่าค่าเฉลี่ย sector {abs(diff)} คะแนน — อยู่ในกลุ่มล่าง ~{100 - percentile:.0f}% ของสถาบันในกลุ่ม"
    return {
        "sector_label": bench["label"],
        "sector_avg": avg,
        "sector_p25": bench["p25"],
        "sector_p75": bench["p75"],
        "your_score": score,
        "diff": diff,
        "verdict": verdict,
    }


def record_scan_history(session_state, url: str, score: int, org: str) -> None:
    """Append scan to session history for trend chart."""
    history = session_state.setdefault("scan_history", [])
    history.append({
        "timestamp": datetime.now().isoformat(),
        "month": datetime.now().strftime("%Y-%m"),
        "url": url,
        "org": org,
        "score": score,
    })
    # Keep last 24 scans
    if len(history) > 24:
        session_state["scan_history"] = history[-24:]


def build_executive_summary_text(
    org: str,
    url: str,
    score: int,
    risk: str,
    scan_data: dict,
    server_data: dict,
    ai_data: dict,
    sector: str = "vocational",
) -> str:
    """One-page executive summary for printing or download."""
    tl_emoji, tl_label, _ = traffic_light(score)
    risks = top_urgent_risks_plain(scan_data, server_data, ai_data)
    bench = benchmark_comparison(score, sector)
    return f"""# VULNEX Executive Summary
องค์กร: {org}
URL: {url}
วันที่: {datetime.now().strftime('%d/%m/%Y %H:%M')}
คะแนน: {score}/100 {tl_emoji} ({tl_label})
ความเสี่ยง: {risk}

Top Risks:
""" + "\n".join(f"- {r}" for r in risks) + f"""

Cost of Inaction: {cost_of_inaction(score, risk)}

Benchmark: {bench['verdict']}
"""
