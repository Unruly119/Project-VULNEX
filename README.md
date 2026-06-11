# Project-VULNEX

ระบบตรวจสอบความปลอดภัยเว็บไซต์สถานศึกษาด้วย AI — Passive Scan Only

## Quick Start

```bash
# 1. Clone and enter project
cd Project-VULNEX

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API key
cp .env.example .env
# Edit .env and set GEMINI_API_KEY

# 5. Run the app
streamlit run app.py
```

Open http://localhost:8501 in your browser.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GEMINI_API_KEY` | Yes | — | Google Gemini API key |
| `GEMINI_MODEL` | No | `gemini-2.5-flash-lite` | Model override |

## Project Structure

```
app.py                  # Streamlit UI
src/
  ai_engine.py          # Score engine + Gemini AI
  prompt_builder.py     # AI prompt construction
  report_generator.py   # ISO/IEC 27001 PDF reports
  scanner/              # Passive scan modules
    headers.py          # Security headers
    ssl_check.py        # SSL/TLS certificate
    html_parser.py      # HTML security analysis
    server_info.py      # Server/CVE detection
  utils/
    network.py          # SSRF guard
```

## Testing

```bash
# Test Gemini API connection
python test_gemini.py

# Full scan + AI pipeline
python test_ai.py
```

## Dev Container

Open in GitHub Codespaces or VS Code Dev Containers — dependencies install automatically on attach.
