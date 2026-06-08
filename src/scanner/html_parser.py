import httpx
from bs4 import BeautifulSoup  

def parse_html(url: str) -> dict:
    """ดึงและวิเคราะห์ HTML จากเว็บไซต์"""
    result = {
        "title": "",              # ชื่อเว็บ
        "meta_description": "",   # คำอธิบายเว็บ
        "external_scripts": [],   # script จาก domain อื่น
        "insecure_forms": [],     # form ที่ส่งข้อมูลไป http
        "total_links": 0,        # จำนวน link ทั้งหมด
        "error": None
    }

    try:
        # GET request ดึง HTML ทั้งหน้า
        resp = httpx.get(url, timeout=15, follow_redirects=True, verify=False)

        # ให้ BeautifulSoup "อ่าน" HTML
        # "lxml" คือ parser ที่เร็วที่สุด
        soup = BeautifulSoup(resp.text, "lxml")  

        # ── ดึง title ──
        title_tag = soup.find("title")  
        if title_tag:
            result["title"] = title_tag.text.strip()

        # ── ดึง meta description ──
        meta = soup.find("meta", {"name": "description"})  
        if meta:
            result["meta_description"] = meta.get("content", "")

        # ── ตรวจ external scripts (อันตราย!) ──
        from urllib.parse import urlparse
        base_domain = urlparse(url).netloc
        for script in soup.find_all("script", src=True):  
            src = script["src"]
            if src.startswith("http") and base_domain not in src:
                result["external_scripts"].append(src)  

        # ── ตรวจ forms ที่ action ไป http:// (ส่งข้อมูลไม่เข้ารหัส) ──
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action.startswith("http://"):  
                result["insecure_forms"].append(action)

        # นับ links ทั้งหมด
        result["total_links"] = len(soup.find_all("a", href=True))

    except Exception as e:
        result["error"] = str(e)

    return result