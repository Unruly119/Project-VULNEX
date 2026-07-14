# supabase_client.py — Project-VULNEX backend data layer
# ────────────────────────────────────────────────────────────────
#   Talks to Supabase Postgres through the PostgREST HTTP API using the
#   project's SECRET key (service_role tier). The secret key bypasses RLS and
#   MUST live only server-side (st.secrets / .env) — it is never sent to the
#   browser. The DB is hardened so anon/authenticated (browser keys) can touch
#   NOTHING; every read/write here goes through the secret key.
#
#   Design rules:
#     · Uses httpx only (already a project dep) — no supabase-py, no bcrypt.
#     · Passwords are hashed with stdlib PBKDF2-HMAC-SHA256 (format starts with
#       '$' to satisfy the DB's chk_pwd_is_hash constraint). No plaintext ever.
#     · Session tokens: 256-bit random, stored in the DB only as a SHA-256 hash
#       (matches chk_as_token_hash). A leaked DB row can't be turned into a cookie.
#     · Every LOGGING call is best-effort: it swallows errors and returns None so
#       a telemetry hiccup can never break a scan or a login. Auth calls DO report
#       errors (the user must know if signup/login failed).
# ────────────────────────────────────────────────────────────────
from __future__ import annotations

import os
import hashlib
import hmac
import secrets
import json
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

import httpx

# Local dev: make .env visible + AUTHORITATIVE before the auth gate runs (auth
# imports this module at the top of app.py, BEFORE ai_engine — which is what
# normally calls load_dotenv). override=True mirrors ai_engine and, crucially,
# beats STALE machine env vars (e.g. a leftover SUPABASE_URL from an old project)
# so .env always decides which Supabase project we talk to. On Streamlit Cloud
# there is no .env file, so this is a no-op and the st.secrets→env bridge (which
# runs first on deploy) remains authoritative.
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except Exception:
    pass

# ── config ───────────────────────────────────────────────────────
_SESSION_DAYS   = 7          # login cookie / session lifetime
_MAX_FAILED     = 5          # wrong-password attempts before lockout
_LOCK_MINUTES   = 15         # lockout duration after _MAX_FAILED
_PBKDF2_ITERS   = 210_000    # OWASP-ish floor for PBKDF2-SHA256
_TIMEOUT        = httpx.Timeout(12.0, connect=8.0)

# The current privacy-policy version the user consents to at signup. Bump when
# the policy text materially changes (stored per-user in app_users.privacy_version).
PRIVACY_VERSION = "2026-07-14"


def _env(*names: str) -> str:
    for n in names:
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()
        # case-insensitive fallback (st.secrets casing vs .env casing)
        for k, val in os.environ.items():
            if k.lower() == n.lower() and val and val.strip():
                return val.strip()
    return ""


def _cfg() -> tuple[str, str]:
    """(base_url, secret_key) or ('','') if not configured."""
    url = _env("SUPABASE_URL")
    key = _env("SUPABASE_SERVICE_KEY", "SUPABASE_SECRET_KEY", "SUPABASE_SERVICE_ROLE_KEY")
    if url and key:
        return url.rstrip("/"), key
    return "", ""


def is_configured() -> bool:
    url, key = _cfg()
    return bool(url and key)


_client: httpx.Client | None = None


def _http() -> httpx.Client | None:
    """Lazy, process-wide httpx client pointed at the PostgREST base with the
    secret key baked into the default headers."""
    global _client
    if _client is not None:
        return _client
    url, key = _cfg()
    if not url:
        return None
    _client = httpx.Client(
        base_url=f"{url}/rest/v1",
        headers={
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        timeout=_TIMEOUT,
    )
    return _client


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    return (dt or _now()).isoformat()


# ── low-level PostgREST helpers ──────────────────────────────────
def _select(table: str, params: dict) -> list[dict] | None:
    c = _http()
    if c is None:
        return None
    try:
        r = c.get(f"/{table}", params=params)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _insert(table: str, row: dict, *, representation: bool = False) -> list[dict] | None:
    c = _http()
    if c is None:
        return None
    prefer = "return=representation" if representation else "return=minimal"
    try:
        r = c.post(f"/{table}", content=json.dumps(row).encode("utf-8"),
                   headers={"Prefer": prefer})
        if r.status_code in (200, 201):
            if representation:
                try:
                    return r.json()
                except Exception:
                    return []
            return []
        # surface conflict for callers that care (create_user)
        if r.status_code == 409:
            return {"__conflict__": True, "body": r.text}  # type: ignore[return-value]
    except Exception:
        pass
    return None


def _update(table: str, params: dict, patch: dict) -> bool:
    c = _http()
    if c is None:
        return False
    try:
        r = c.patch(f"/{table}", params=params,
                    content=json.dumps(patch).encode("utf-8"),
                    headers={"Prefer": "return=minimal"})
        return r.status_code in (200, 204)
    except Exception:
        return False


# ── password hashing (stdlib PBKDF2-HMAC-SHA256) ─────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERS)
    return f"$pbkdf2-sha256${_PBKDF2_ITERS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, algo, iters_s, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2-sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt_hex), int(iters_s))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ── users / auth ─────────────────────────────────────────────────
def get_user_by_email(email: str) -> dict | None:
    rows = _select("app_users", {
        "gmail": f"eq.{email.strip().lower()}",
        "select": "*", "limit": 1,
    })
    return rows[0] if rows else None


def create_user(email: str, password: str, privacy_version: str = PRIVACY_VERSION) -> tuple[dict | None, str | None]:
    """Returns (user, None) on success or (None, thai_error)."""
    email = email.strip().lower()
    if not is_configured():
        return None, "ระบบสมาชิกยังไม่พร้อมใช้งาน (ยังไม่ได้ตั้งค่าฐานข้อมูล)"
    row = {
        "gmail": email,
        "password_hash": hash_password(password),
        "privacy_accepted_at": _iso(),
        "privacy_version": privacy_version[:16],
    }
    res = _insert("app_users", row, representation=True)
    if isinstance(res, dict) and res.get("__conflict__"):
        return None, "อีเมลนี้ถูกใช้สมัครไปแล้ว — กรุณาเข้าสู่ระบบ"
    if res:
        return res[0], None
    return None, "สมัครสมาชิกไม่สำเร็จ กรุณาลองใหม่อีกครั้ง"


def authenticate(email: str, password: str) -> tuple[dict | None, str | None]:
    """Verify credentials with brute-force lockout. Returns (user, None) or
    (None, thai_error)."""
    email = email.strip().lower()
    if not is_configured():
        return None, "ระบบสมาชิกยังไม่พร้อมใช้งาน"
    user = get_user_by_email(email)
    if not user:
        return None, "อีเมลหรือรหัสผ่านไม่ถูกต้อง"

    locked_until = user.get("locked_until")
    if locked_until:
        try:
            lu = datetime.fromisoformat(locked_until.replace("Z", "+00:00"))
            if _now() < lu:
                mins = int((lu - _now()).total_seconds() // 60) + 1
                return None, f"บัญชีถูกล็อกชั่วคราวจากการกรอกรหัสผิดหลายครั้ง — ลองใหม่ในอีก {mins} นาที"
        except Exception:
            pass

    if not verify_password(password, user.get("password_hash", "")):
        failed = int(user.get("failed_logins", 0) or 0) + 1
        patch = {"failed_logins": failed}
        if failed >= _MAX_FAILED:
            patch["locked_until"] = _iso(_now() + timedelta(minutes=_LOCK_MINUTES))
        _update("app_users", {"id": f"eq.{user['id']}"}, patch)
        if failed >= _MAX_FAILED:
            return None, f"กรอกรหัสผิดเกิน {_MAX_FAILED} ครั้ง — บัญชีถูกล็อก {_LOCK_MINUTES} นาที"
        left = _MAX_FAILED - failed
        return None, f"อีเมลหรือรหัสผ่านไม่ถูกต้อง (เหลืออีก {left} ครั้งก่อนถูกล็อก)"

    # success — clear counters, stamp last login
    _update("app_users", {"id": f"eq.{user['id']}"},
            {"failed_logins": 0, "locked_until": None, "last_login_at": _iso()})
    return user, None


# ── sessions (cookie-backed) ─────────────────────────────────────
def create_session(user_id: str, client_ip: str | None = None,
                   user_agent: str | None = None, days: int = _SESSION_DAYS) -> tuple[str | None, str | None]:
    """Create a session; returns (raw_token, expires_iso). The RAW token goes in
    the user's cookie; the DB stores only its SHA-256."""
    token = secrets.token_urlsafe(32)
    expires = _now() + timedelta(days=days)
    row = {
        "user_id": user_id,
        "token_hash": _sha256(token),
        "expires_at": _iso(expires),
        "client_ip": client_ip or None,
        "user_agent": (user_agent or "")[:1024] or None,
    }
    res = _insert("auth_sessions", row)
    if res is None:
        return None, None
    return token, _iso(expires)


def get_session_user(token: str) -> dict | None:
    """Validate a cookie token → return the user dict, or None if the session is
    missing / expired / revoked. Touches last_seen_at (best-effort)."""
    if not token:
        return None
    th = _sha256(token)
    rows = _select("auth_sessions", {
        "token_hash": f"eq.{th}",
        "revoked_at": "is.null",
        "select": "id,user_id,expires_at",
        "limit": 1,
    })
    if not rows:
        return None
    sess = rows[0]
    try:
        exp = datetime.fromisoformat(sess["expires_at"].replace("Z", "+00:00"))
        if _now() >= exp:
            return None
    except Exception:
        return None
    _update("auth_sessions", {"id": f"eq.{sess['id']}"}, {"last_seen_at": _iso()})
    users = _select("app_users", {
        "id": f"eq.{sess['user_id']}",
        "select": "id,gmail,created_at,last_login_at", "limit": 1,
    })
    if not users:
        return None
    u = users[0]
    u["_session_id"] = sess["id"]
    return u


def revoke_session(token: str) -> None:
    if not token:
        return
    _update("auth_sessions", {"token_hash": f"eq.{_sha256(token)}"},
            {"revoked_at": _iso()})


# ── audit / activity logging (all best-effort) ───────────────────
_SEV_OK = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_RISK_OK = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def _host(url: str) -> str | None:
    try:
        return (urlparse(url).hostname or "").lower() or None
    except Exception:
        return None


def log_login_event(user_id: str, session_id: str | None, meta: dict | None = None) -> str | None:
    meta = meta or {}
    row = {
        "user_id": user_id,
        "session_id": session_id,
        "client_ip": meta.get("client_ip") or None,
        "forwarded_for": meta.get("forwarded_for") or None,
        "user_agent": (meta.get("user_agent") or "")[:1024] or None,
        "device_type": meta.get("device_type"),
        "browser": meta.get("browser"),
        "browser_version": meta.get("browser_version"),
        "os_name": meta.get("os_name"),
        "os_version": meta.get("os_version"),
    }
    res = _insert("login_events", {k: v for k, v in row.items() if v is not None},
                  representation=True)
    return res[0]["id"] if res else None


def mark_logout(session_id: str | None) -> None:
    if session_id:
        _update("login_events", {"session_id": f"eq.{session_id}"},
                {"logged_out_at": _iso()})


def insert_scan(*, user_id: str | None, url: str, scan_data: dict, server_data: dict,
                ai_data: dict, started_at: str | None, finished_at: str | None,
                duration_ms: int | None, meta: dict | None = None) -> str | None:
    """Persist one scan (wide columns + full JSONB blobs). Returns scan_id."""
    meta = meta or {}
    scan_data = scan_data or {}
    server_data = server_data or {}
    ai_data = ai_data or {}
    vulns = server_data.get("vulnerabilities", []) or []
    risk = str(ai_data.get("risk_level", "") or "").upper()
    html = scan_data.get("html", {}) or {}
    has_err = bool(server_data.get("error")) or any(
        isinstance(v, dict) and v.get("error")
        for v in scan_data.values() if isinstance(v, dict)
    )
    row = {
        "user_id": user_id,
        "target_url": url[:2048],
        "target_host": _host(url),
        "site_title": (html.get("title") or None),
        "scanned_at": _iso(),
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_ms": duration_ms,
        "client_ip": meta.get("client_ip") or None,
        "forwarded_for": meta.get("forwarded_for") or None,
        "user_agent": (meta.get("user_agent") or "")[:1024] or None,
        "device_type": meta.get("device_type"),
        "browser": meta.get("browser"),
        "browser_version": meta.get("browser_version"),
        "os_name": meta.get("os_name"),
        "os_version": meta.get("os_version"),
        "composite_score": _int(ai_data.get("score")),
        "risk_level": risk if risk in _RISK_OK else None,
        "cve_count": len(vulns),
        "dos_risk": bool(server_data.get("dos_risk", False)),
        "ai_provider": "offline" if ai_data.get("offline_fallback") else "ai",
        "ai_offline_fallback": bool(ai_data.get("offline_fallback", False)),
        "has_errors": has_err,
        "scan_data": scan_data,
        "server_data": server_data,
        "ai_data": ai_data,
    }
    res = _insert("scans", {k: v for k, v in row.items() if v is not None},
                  representation=True)
    if not res:
        return None
    scan_id = res[0]["id"]
    # child rows — best effort, don't block on failure
    try:
        _insert_scan_modules(scan_id, scan_data)
    except Exception:
        pass
    try:
        _insert_vulnerabilities(scan_id, vulns)
    except Exception:
        pass
    return scan_id


def _insert_scan_modules(scan_id: str, scan_data: dict) -> None:
    keys = ("headers", "ssl", "html", "dns", "cookies", "js_exposure", "subdomains",
            "cors", "http_methods", "open_files", "cms")
    rows = []
    for k in keys:
        mod = scan_data.get(k)
        if not isinstance(mod, dict):
            continue
        if mod.get("suspended"):
            status = "suspended"
        elif mod.get("error"):
            status = "error"
        else:
            status = "ok"
        rows.append({
            "scan_id": scan_id,
            "module_key": k,
            "status": status,
            "score": _int(mod.get("score")) if status == "ok" else None,
            "error": (str(mod.get("error"))[:2000] if mod.get("error") else None),
            "findings": mod.get("findings", []) if isinstance(mod.get("findings"), list) else [],
            "raw": mod,
        })
    for r in rows:
        _insert("scan_modules", {k: v for k, v in r.items() if v is not None})


def _insert_vulnerabilities(scan_id: str, vulns: list) -> None:
    for v in vulns or []:
        if not isinstance(v, dict):
            continue
        sev = str(v.get("severity", "INFO") or "INFO").upper()
        _insert("scan_vulnerabilities", {
            "scan_id": scan_id,
            "cve": (v.get("cve") or None),
            "severity": sev if sev in _SEV_OK else "INFO",
            "description": (v.get("desc") or v.get("description") or None),
            "fix": (v.get("fix") or None),
        })


def mark_scan_pdf(scan_id: str, duration_ms: int | None) -> None:
    """Bump the pdf_* counters on a scan after a report is built."""
    if not scan_id:
        return
    rows = _select("scans", {"id": f"eq.{scan_id}", "select": "pdf_count", "limit": 1})
    cur = int((rows[0].get("pdf_count") or 0)) if rows else 0
    _update("scans", {"id": f"eq.{scan_id}"}, {
        "pdf_generated": True,
        "pdf_count": cur + 1,
        "pdf_last_duration_ms": duration_ms,
        "pdf_last_generated_at": _iso(),
    })


def insert_report_event(*, scan_id: str | None, user_id: str | None, status: str,
                        ai_provider: str | None = None, ai_offline_fallback: bool = False,
                        duration_ms: int | None = None, page_count: int | None = None,
                        file_size_bytes: int | None = None, error_type: str | None = None,
                        error_message: str | None = None,
                        requested_at: str | None = None) -> None:
    if status not in ("requested", "success", "error"):
        status = "requested"
    row = {
        "scan_id": scan_id,
        "user_id": user_id,
        "status": status,
        "ai_provider": ai_provider,
        "ai_offline_fallback": bool(ai_offline_fallback),
        "duration_ms": duration_ms,
        "page_count": page_count,
        "file_size_bytes": file_size_bytes,
        "error_type": error_type,
        "error_message": (error_message or "")[:8000] or None,
        "requested_at": requested_at,
        "finished_at": _iso() if status in ("success", "error") else None,
    }
    _insert("report_events", {k: v for k, v in row.items() if v is not None})


def log_user_event(*, user_id: str | None, session_id: str | None, event_type: str,
                   scan_id: str | None = None, target_url: str | None = None,
                   detail: dict | None = None, duration_ms: int | None = None,
                   meta: dict | None = None) -> None:
    """Post-login audit trail. event_type must be snake_case (DB-constrained)."""
    meta = meta or {}
    detail = detail or {}
    dj = json.dumps(detail, ensure_ascii=False)
    if len(dj) > 90_000:              # stay under the 100 KB DB cap
        detail = {"_truncated": True}
    row = {
        "user_id": user_id,
        "session_id": session_id,
        "event_type": event_type[:64],
        "scan_id": scan_id,
        "target_url": (target_url or "")[:2048] or None,
        "detail": detail,
        "duration_ms": duration_ms,
        "client_ip": meta.get("client_ip") or None,
        "forwarded_for": meta.get("forwarded_for") or None,
        "user_agent": (meta.get("user_agent") or "")[:1024] or None,
        "device_type": meta.get("device_type"),
        "browser": meta.get("browser"),
        "browser_version": meta.get("browser_version"),
        "os_name": meta.get("os_name"),
        "os_version": meta.get("os_version"),
    }
    _insert("user_events", {k: v for k, v in row.items() if v is not None})


def log_error(*, scan_id: str | None = None, user_id: str | None = None,
              module_key: str | None = None, error_type: str | None = None,
              error_message: str = "", context: dict | None = None) -> None:
    row = {
        "scan_id": scan_id,
        "user_id": user_id,
        "module_key": module_key,
        "error_type": (error_type or "")[:120] or None,
        "error_message": (error_message or "unknown")[:8000],
        "context": context or {},
    }
    _insert("error_logs", {k: v for k, v in row.items() if v is not None})


def _int(v) -> int | None:
    try:
        if v is None:
            return None
        return int(v)
    except (TypeError, ValueError):
        return None
