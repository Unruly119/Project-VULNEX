# src/report_generator.py — Project VULNEX  (rewrite v3)
# ─────────────────────────────────────────────────────────────────
# บทบาทใหม่:  แปลง "HTML 1 หน้า" → "PDF 1 หน้า"  เท่านั้น
#
#   workflow ใหม่ (เริ่มจากตอนผู้ใช้กด "สร้างรายงาน PDF"):
#       html_generator.build_report_html(...)  → สตริง HTML 1 หน้า
#       report_generator.html_to_pdf(html)      → bytes PDF 1 หน้า   ← ไฟล์นี้
#
#   ทำไมเปลี่ยนมาใช้ HTML→PDF:
#       - การจัดเลย์เอาต์/แก้สไตล์ทำใน HTML/CSS ง่ายกว่าวาดด้วย ReportLab มาก
#       - เรนเดอร์ด้วย Chromium (Playwright) → ฟอนต์ไทย + เลย์เอาต์ตรงกับเบราว์เซอร์เป๊ะ
#
#   การันตี 1 หน้า:
#       HTML มี .page ขนาด A4 (overflow hidden) ครอบ .content
#       _fit_one_page() วัดความสูง .content เทียบพื้นที่ว่างใน .page แล้วย่อด้วย
#       CSS `zoom` จนพอดี → page.pdf(prefer_css_page_size) ได้ PDF หน้าเดียวเสมอ
from __future__ import annotations

import concurrent.futures


class PdfEngineError(RuntimeError):
    """ข้อผิดพลาดระดับเอนจิน — Playwright/Chromium ไม่พร้อมใช้งาน หรือ render ล้มเหลว"""


# JS: วัดพื้นที่ว่างของหน้า (.page) เทียบความสูงเนื้อหา (.content) ที่ zoom ปัจจุบัน
_FIT_JS = """
() => {
  const pg = document.querySelector('.page');
  const ct = document.querySelector('.content');
  if (!pg || !ct) return null;
  const cs = getComputedStyle(pg);
  const avail = pg.clientHeight
              - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom);
  const zoom = parseFloat(ct.style.zoom || '1') || 1;
  // ใช้ getBoundingClientRect — สะท้อนค่า CSS zoom (scrollHeight ไม่สะท้อน)
  return { avail: avail, needed: ct.getBoundingClientRect().height, zoom: zoom };
}
"""


def _fit_one_page(page) -> None:
    """ย่อ .content ด้วย CSS zoom จนความสูงพอดีกับพื้นที่ของ .page (1 หน้า A4)."""
    for _ in range(6):
        m = page.evaluate(_FIT_JS)
        if not m or m["needed"] <= m["avail"] + 1:
            return
        new_zoom = max(0.55, m["zoom"] * (m["avail"] / m["needed"]) * 0.99)
        if abs(new_zoom - m["zoom"]) < 0.005:
            return
        page.evaluate(
            "z => { document.querySelector('.content').style.zoom = z; }", new_zoom
        )


def _render(html: str) -> bytes:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:        # ไลบรารียังไม่ติดตั้ง
        raise PdfEngineError(
            "ไม่พบไลบรารี Playwright — ติดตั้งด้วย `pip install playwright` "
            "แล้วรัน `python -m playwright install chromium`"
        ) from exc

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])
            try:
                page = browser.new_page()
                page.set_content(html, wait_until="load")
                page.emulate_media(media="print")
                # รอให้ฟอนต์ (Prompt ฝัง base64) โหลดเสร็จก่อนวัดความสูง
                page.evaluate("async () => { await document.fonts.ready; }")
                _fit_one_page(page)
                return page.pdf(prefer_css_page_size=True, print_background=True)
            finally:
                browser.close()
    except PdfEngineError:
        raise
    except Exception as exc:          # noqa: BLE001
        msg = str(exc)
        if "Executable doesn't exist" in msg or "playwright install" in msg:
            raise PdfEngineError(
                "ไม่พบเบราว์เซอร์ Chromium ของ Playwright — "
                "รัน `python -m playwright install chromium` ก่อน"
            ) from exc
        raise PdfEngineError(f"แปลง HTML เป็น PDF ไม่สำเร็จ: {exc}") from exc


def html_to_pdf(html: str) -> bytes:
    """
    แปลงสตริง HTML 1 หน้า → bytes ของ PDF 1 หน้า (A4)

    รันใน worker thread แยกต่างหาก เพื่อเลี่ยงข้อจำกัดของ Playwright sync API
    ที่เรียกใต้ event loop (เช่นบางบริบทของ Streamlit) ไม่ได้
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_render, html).result()


# ─────────────────────────────────────────────────────────────────
# Self-test — ประกอบ HTML จาก mock แล้วแปลงเป็น PDF
#   รัน:  python -m report_generator   (จากโฟลเดอร์ src)
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from html_generator import build_report_html

    mock_scan = {
        "url": "https://www.apache-secure-demo.co.th",
        "headers": {"score": 40, "headers_found": {"X-Content-Type-Options": "nosniff"},
                    "headers_missing": ["Content-Security-Policy", "X-Frame-Options",
                                        "Strict-Transport-Security", "Referrer-Policy"]},
        "ssl": {"has_ssl": True, "valid": True, "days_left": 120, "issuer": "DigiCert",
                "warning": ""},
        "dns": {"score": 70, "spf": {"present": True}, "dmarc": {"policy": "none"},
                "error": None},
        "html": {"title": "Demo Site", "external_scripts": [], "insecure_forms": [],
                 "total_links": 10},
    }
    mock_ai = {
        "score": 55, "risk_level": "MEDIUM",
        "analysis": ("## สรุปภาพรวม\nระบบติดตั้งซอฟต์แวร์เวอร์ชันล่าสุดและใช้ HTTP/1.1 "
                     "ซึ่งปลอดภัยจาก DoS บน HTTP/2 แต่ยังต้องปรับปรุงการตั้งค่าเพื่อซ่อน"
                     "ป้ายเวอร์ชันและเสริม Security Headers"),
    }
    mock_srv = {
        "server_raw": "Apache/2.4.62", "server_type": "apache", "server_version": "2.4.62",
        "version_exposed": True, "http_version": "HTTP/1.1", "h2_enabled": False,
        "vulnerabilities": [], "dos_risk": False, "dos_detail": "",
    }

    html = build_report_html(mock_scan, mock_ai, mock_srv, "โรงเรียนสาธิตทดสอบ")
    pdf = html_to_pdf(html)
    with open("report_selftest.pdf", "wb") as fh:
        fh.write(pdf)
    print(f"wrote report_selftest.pdf ({len(pdf):,} bytes)")
