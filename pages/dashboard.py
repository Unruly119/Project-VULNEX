# pages/dashboard.py — VULNEX real-time scan-operations dashboard (hidden page)
# ────────────────────────────────────────────────────────────────
#   Reachable ONLY by typing the URL (…/dashboard) — no button or link
#   anywhere on the site points here, mirroring how /user_manual is addressed.
#   Reads live scan telemetry from Supabase through supabase_client's
#   dashboard read layer (service key, server-side; no emails/IPs shown —
#   hosts and aggregates only) and re-polls every _REFRESH_SEC seconds via
#   @st.fragment(run_every=…), so the page updates itself while open.
#
#   Charts: Plotly, chosen because st.plotly_chart renders in the MAIN
#   document (not an iframe) — the SVG text inherits the base64-embedded
#   Prompt/AnthropicSans faces and the Fable palette applies 1:1. Ranked
#   lists and the live feed are hand-built HTML (every DB value escaped).
# ────────────────────────────────────────────────────────────────
import sys

sys.path.insert(0, "src")          # must precede src/* module imports

import html as _htmlmod
import os
from datetime import datetime, timedelta, timezone

import streamlit as st

st.set_page_config(
    page_title="Dashboard · Project-VULNEX",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="collapsed",   # sidebar removed — keep it shut
)

# ── Secrets → env bridge (same as app.py; must follow set_page_config) ──
# A visitor can land on /dashboard directly in a fresh process on Streamlit
# Cloud, where app.py's bridge has not run — so this page bridges too.
try:
    for _sk, _sv in st.secrets.items():
        if isinstance(_sv, str) and _sv and not (os.environ.get(_sk) or "").strip():
            os.environ[_sk] = _sv
except Exception:
    pass  # no secrets.toml (local dev) — .env drives everything

import pandas as pd

try:                               # charts degrade to a notice if plotly is absent
    import plotly.graph_objects as go
except Exception:                  # pragma: no cover
    go = None

from ui_shared import inject_base_styles, render_footer
import supabase_client as _db

inject_base_styles()

# ── Constants ────────────────────────────────────────────────────
_ICT = timezone(timedelta(hours=7))          # display timezone (Thai time)
_REFRESH_SEC = 10                            # fragment poll cadence
_TREND_DAYS = 14

_FONT_STACK = "Prompt, AnthropicSans, system-ui, sans-serif"
_INK, _INK2, _MUTED = "#141413", "#3d3b38", "#706d67"
_GRID = "rgba(20,20,19,0.07)"
_PARCHMENT = "#faf8f4"

_RISK_COLOR = {"CRITICAL": "#b91c1c", "HIGH": "#c4622d",
               "MEDIUM": "#92700a", "LOW": "#2d6a4f"}
_RISK_TH = {"CRITICAL": "วิกฤต", "HIGH": "สูง", "MEDIUM": "ปานกลาง", "LOW": "ต่ำ"}
_SEV_CHIP = {"CRITICAL": "c-crit", "HIGH": "c-high", "MEDIUM": "c-med",
             "LOW": "c-low", "INFO": "c-info"}
_SEV_TH = {"CRITICAL": "วิกฤต", "HIGH": "สูง", "MEDIUM": "ปานกลาง",
           "LOW": "ต่ำ", "INFO": "ข้อมูล"}
_COMPONENT_TH = {"headers": "HTTP Headers", "ssl": "SSL/TLS",
                 "html_js": "HTML & JavaScript", "server_cve": "เซิร์ฟเวอร์ & CVE",
                 "dns": "DNS", "cookies": "คุกกี้", "cms": "CMS"}
_MODULE_TH = {"headers": "HTTP Headers", "ssl": "SSL/TLS", "html": "HTML",
              "dns": "DNS", "cookies": "คุกกี้", "js_exposure": "JavaScript",
              "subdomains": "ซับโดเมน", "cors": "CORS",
              "http_methods": "HTTP Methods", "open_files": "ไฟล์เปิดเผย",
              "cms": "CMS"}
_THAI_MON = ("ม.ค.", "ก.พ.", "มี.ค.", "เม.ย.", "พ.ค.", "มิ.ย.",
             "ก.ค.", "ส.ค.", "ก.ย.", "ต.ค.", "พ.ย.", "ธ.ค.")


def _esc(v) -> str:
    return _htmlmod.escape(str(v), quote=True)


def _score_band(s) -> str:
    """CSS modifier for a 0–100 score — same thresholds as the risk engine."""
    if s is None or (isinstance(s, float) and pd.isna(s)):
        return "sb-med"
    s = float(s)
    if s < 30:
        return "sb-crit"
    if s < 50:
        return "sb-high"
    if s < 70:
        return "sb-med"
    return "sb-good"


def _score_hex(s) -> str:
    if s is None or (isinstance(s, float) and pd.isna(s)):
        return _MUTED
    s = float(s)
    if s < 30:
        return _RISK_COLOR["CRITICAL"]
    if s < 50:
        return _RISK_COLOR["HIGH"]
    if s < 70:
        return _RISK_COLOR["MEDIUM"]
    return _RISK_COLOR["LOW"]


def _rel_th(ts: datetime, now: datetime) -> str:
    """Thai relative time — 'เมื่อสักครู่' → '3 นาทีที่แล้ว' → date."""
    secs = (now - ts).total_seconds()
    if secs < 60:
        return "เมื่อสักครู่"
    if secs < 3600:
        return f"{int(secs // 60)} นาทีที่แล้ว"
    if secs < 86400:
        return f"{int(secs // 3600)} ชม. ที่แล้ว"
    local = ts.astimezone(_ICT)
    return f"{local.day} {_THAI_MON[local.month - 1]} {local:%H:%M}"


def _icon(paths: str, size: int = 16) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}"'
        ' viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
        f' stroke-linecap="round" stroke-linejoin="round">{paths}</svg>'
    )


I_ACTIVITY = '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>'
I_PIE      = '<path d="M21.21 15.89A10 10 0 1 1 8 2.83"/><path d="M22 12A10 10 0 0 0 12 2v10z"/>'
I_BARS     = '<path d="M3 3v18h18"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/>'
I_GAUGE    = '<path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/>'
I_ALERT    = ('<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16'
              'a2 2 0 0 0 1.73-3z"/><line x1="12" y1="9" x2="12" y2="13"/>'
              '<line x1="12" y1="17" x2="12.01" y2="17"/>')
I_GLOBE    = ('<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>'
              '<path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10'
              ' 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>')
I_RADIO    = ('<path d="M4.9 19.1C1 15.2 1 8.8 4.9 4.9"/>'
              '<path d="M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5"/><circle cx="12" cy="12" r="2"/>'
              '<path d="M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5"/><path d="M19.1 4.9C23 8.8 23 15.2 19.1 19.1"/>')
I_RADAR    = ('<path d="M19.07 4.93A10 10 0 0 0 6.99 3.34"/><path d="M4 6h.01"/>'
              '<path d="M2.29 9.62a10 10 0 1 0 19.02-1.27"/><path d="M16.24 7.76a6 6 0 1 0-8.01 8.91"/>'
              '<path d="M12 18h.01"/><path d="M17.99 11.66a6 6 0 0 1-2.22 4.58"/>'
              '<circle cx="12" cy="12" r="2"/><path d="m13.41 10.59 5.66-5.66"/>')


# ── Data ─────────────────────────────────────────────────────────
@st.cache_data(ttl=_REFRESH_SEC - 2, show_spinner=False)
def _load() -> dict:
    """Shared across sessions: many open dashboards → one DB poll per TTL."""
    return _db.fetch_dashboard_data()


# ── Plotly scaffolding ───────────────────────────────────────────
def _base_layout(**overrides) -> dict:
    lay = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=_FONT_STACK, size=12.5, color=_INK2),
        margin=dict(l=6, r=6, t=10, b=6),
        showlegend=False,
        hoverlabel=dict(bgcolor=_INK, bordercolor="rgba(0,0,0,0)",
                        font=dict(family=_FONT_STACK, size=12, color=_PARCHMENT)),
    )
    lay.update(overrides)
    return lay


def _chart(fig, key: str) -> None:
    # theme=None so Streamlit's built-in template cannot restyle the Fable look
    st.plotly_chart(fig, key=key, theme=None, width="stretch",
                    config={"displayModeBar": False})


def _panel_head(icon: str, title: str, note: str = "") -> None:
    note_html = f'<span class="db-panel-note">{note}</span>' if note else ""
    st.markdown(
        f'<div class="db-panel-head"><span class="db-panel-icon">{_icon(icon)}</span>'
        f'<span class="db-panel-title">{title}</span>{note_html}</div>',
        unsafe_allow_html=True,
    )


def _panel_empty(msg: str = "ยังไม่มีข้อมูลเพียงพอ") -> None:
    st.markdown(f'<div class="db-panel-empty">{msg}</div>', unsafe_allow_html=True)


# ── Header ───────────────────────────────────────────────────────
def _render_header(online: bool) -> None:
    now = datetime.now(_ICT)
    if online:
        badge = ('<span class="db-live-dot"></span>LIVE'
                 f'<span class="db-live-time">อัปเดต {now:%H:%M:%S}</span>')
    else:
        badge = ('<span class="db-live-dot is-off"></span>ออฟไลน์'
                 f'<span class="db-live-time">{now:%H:%M:%S}</span>')
    st.markdown(
        '<div class="db-head"><div>'
        '<h1 class="db-title">แดชบอร์ดการสแกน</h1>'
        '<p class="db-sub">ภาพรวมการใช้งาน Project-VULNEX จากฐานข้อมูลจริง · '
        f'อัปเดตอัตโนมัติทุก {_REFRESH_SEC} วินาที</p>'
        f'</div><div class="db-live">{badge}</div></div>',
        unsafe_allow_html=True,
    )


# ── Stat band ────────────────────────────────────────────────────
def _render_stats(df: pd.DataFrame, totals: dict, now_utc: datetime) -> None:
    total_scans = totals.get("scans")
    total_scans = int(total_scans) if total_scans is not None else len(df)
    total_findings = totals.get("findings")
    total_findings = (int(total_findings) if total_findings is not None
                      else int(df["findings_count"].fillna(0).sum()))
    total_vulns = totals.get("vulns")
    total_vulns = (int(total_vulns) if total_vulns is not None
                   else int(df["cve_count"].fillna(0).sum()))

    last24 = int((df["scanned_at"] >= now_utc - timedelta(hours=24)).sum())
    hosts = int(df["target_host"].nunique())
    avg = df["composite_score"].mean()
    avg_txt = f"{avg:.0f}" if pd.notna(avg) else "—"
    high = int(df["risk_level"].isin(("HIGH", "CRITICAL")).sum())
    high_pct = f"{high / len(df) * 100:.0f}%" if len(df) else "0%"
    per_scan = f"{total_findings / total_scans:.1f}" if total_scans else "0"

    delta24 = (f'<span class="db-stat-delta is-up">+{last24} ใน 24 ชม.</span>'
               if last24 else '<span class="db-stat-delta">ไม่มีใน 24 ชม.</span>')

    def cell(val: str, lbl: str, sub: str = "", val_cls: str = "",
             i: int = 0, lead: bool = False, pill: bool = False) -> str:
        # `lead=True` gives the two risk-bearing cells (avg score, high/
        # critical count) a tinted body instead of plain text-color-only
        # emphasis — the two numbers a non-technical admin actually needs
        # first now visually outrank "total scans" etc. `pill=True` wraps
        # the value in the same pill shape as .db-score-pill/.db-chip used
        # elsewhere on this page, so "score" reads as one visual language
        # across the whole dashboard rather than a one-off text color here.
        lead_cls = " is-lead" if lead else ""
        if pill and val_cls:
            val_html = (f'<span class="db-stat-pill" style="background:{val_cls}1a;'
                        f'color:{val_cls}">{val}</span>')
        elif val_cls:
            val_html = f'<span style="color:{val_cls}">{val}</span>'
        else:
            val_html = val
        return (f'<div class="db-stat{lead_cls}" style="--i:{i}">'
                f'<span class="db-stat-val">{val_html}</span>'
                f'<span class="db-stat-lbl">{lbl}</span>{sub}</div>')

    st.markdown(
        '<div class="db-stats">'
        + cell(f"{total_scans:,}", "การสแกนทั้งหมด", delta24, i=0)
        + cell(f"{hosts:,}", "เว็บไซต์ที่ตรวจ",
               '<span class="db-stat-delta">โดเมนไม่ซ้ำ</span>', i=1)
        + cell(avg_txt, "คะแนนเฉลี่ย",
               '<span class="db-stat-delta">จากคะแนนเต็ม 100</span>',
               val_cls=_score_hex(avg), i=2, lead=True, pill=True)
        + cell(f"{high:,}", "เสี่ยงสูง–วิกฤต",
               f'<span class="db-stat-delta">{high_pct} ของการสแกน</span>',
               val_cls=_RISK_COLOR["CRITICAL"] if high else "",
               i=3, lead=bool(high), pill=bool(high))
        + cell(f"{total_findings:,}", "ข้อค้นพบรวม",
               f'<span class="db-stat-delta">เฉลี่ย {per_scan} ต่อสแกน</span>', i=4)
        + cell(f"{total_vulns:,}", "ช่องโหว่ CVE",
               '<span class="db-stat-delta">จากทุกการสแกน</span>',
               val_cls=_RISK_COLOR["HIGH"] if total_vulns else "", i=5)
        + "</div>",
        unsafe_allow_html=True,
    )


# ── Charts ───────────────────────────────────────────────────────
def _fig_trend(df: pd.DataFrame):
    today = datetime.now(_ICT).date()
    days = [today - timedelta(days=i) for i in range(_TREND_DAYS - 1, -1, -1)]
    local_day = df["scanned_at"].dt.tz_convert(_ICT).dt.date
    grp = df.assign(day=local_day).groupby("day").agg(
        n=("id", "count"), avg=("composite_score", "mean"))
    counts = [int(grp["n"].get(d, 0)) for d in days]
    avgs = [round(float(grp["avg"][d]), 1)
            if d in grp.index and pd.notna(grp["avg"][d]) else None
            for d in days]
    labels = [f"{d.day} {_THAI_MON[d.month - 1]}" for d in days]

    fig = go.Figure()
    fig.add_bar(x=labels, y=counts, name="จำนวนสแกน",
                marker=dict(color="rgba(196,98,45,0.55)"),
                hovertemplate="%{x} · สแกน %{y} ครั้ง<extra></extra>")
    fig.add_scatter(x=labels, y=avgs, name="คะแนนเฉลี่ย", yaxis="y2",
                    mode="lines+markers", connectgaps=True,
                    line=dict(color=_INK, width=2), marker=dict(size=5),
                    hovertemplate="%{x} · คะแนนเฉลี่ย %{y}<extra></extra>")
    max_n = max(counts) if counts else 0
    fig.update_layout(**_base_layout(
        height=286, bargap=0.45, showlegend=True,
        legend=dict(orientation="h", x=1, xanchor="right", y=1.18,
                    font=dict(size=11.5), bgcolor="rgba(0,0,0,0)"),
        xaxis=dict(showgrid=False, automargin=True,
                   tickfont=dict(size=11, color=_MUTED)),
        yaxis=dict(gridcolor=_GRID, zeroline=False, rangemode="tozero",
                   automargin=True, dtick=max(1, -(-max_n // 4)),
                   tickfont=dict(size=11, color=_MUTED)),
        yaxis2=dict(overlaying="y", side="right", range=[0, 105],
                    showgrid=False, automargin=True,
                    tickfont=dict(size=11, color=_MUTED)),
    ))
    return fig


def _render_risk_donut(df: pd.DataFrame) -> None:
    order = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    counts = df["risk_level"].value_counts()
    rows = [(r, int(counts.get(r, 0))) for r in order if int(counts.get(r, 0))]
    if not rows:
        _panel_empty()
        return
    total = sum(n for _, n in rows)
    fig = go.Figure(go.Pie(
        labels=[_RISK_TH[r] for r, _ in rows],
        values=[n for _, n in rows],
        marker=dict(colors=[_RISK_COLOR[r] for r, _ in rows],
                    line=dict(color=_PARCHMENT, width=2)),
        hole=0.62, sort=False, direction="clockwise", textinfo="none",
        hovertemplate="ความเสี่ยง%{label} · %{value} สแกน (%{percent})<extra></extra>",
    ))
    fig.update_layout(**_base_layout(height=228))
    # Center total now tints toward whichever risk band is most common
    # (rather than staying plain ink) — the chart's own headline number
    # reinforces severity at a glance, matching PRODUCT.md's "show
    # severity, not noise" instead of reading as a neutral count.
    dominant = max(rows, key=lambda r: r[1])[0]
    total_color = _RISK_COLOR[dominant] if dominant != "LOW" else _INK
    fig.add_annotation(text=(f'<b style="font-size:26px">{total:,}</b><br>'
                             '<span style="font-size:12px">สแกน</span>'),
                       x=0.5, y=0.5, showarrow=False,
                       font=dict(family=_FONT_STACK, color=total_color))
    _chart(fig, "db_c_risk")
    legend = "".join(
        f'<span class="db-legend-item">'
        f'<span class="db-legend-dot" style="background:{_RISK_COLOR[r]}"></span>'
        f'{_RISK_TH[r]} <span class="db-legend-n">{n:,} · {n / total * 100:.0f}%</span></span>'
        for r, n in rows
    )
    st.markdown(f'<div class="db-legend">{legend}</div>', unsafe_allow_html=True)


def _fig_hist(df: pd.DataFrame):
    scores = df["composite_score"].dropna()
    edges = list(range(0, 101, 10))                     # 0-9 … 90-100
    labels = [f"{lo}–{lo + 9}" if lo < 90 else "90–100" for lo in edges[:-1]]
    binned = pd.cut(scores, bins=edges[:-1] + [101], right=False,
                    labels=labels).value_counts().reindex(labels, fill_value=0)
    colors = [_score_hex(lo + 5) for lo in edges[:-1]]
    fig = go.Figure(go.Bar(
        x=labels, y=[int(v) for v in binned],
        marker=dict(color=colors, opacity=0.82),
        hovertemplate="คะแนน %{x} · %{y} สแกน<extra></extra>",
    ))
    max_n = int(binned.max()) if len(binned) else 0
    fig.update_layout(**_base_layout(
        height=250, bargap=0.25,
        xaxis=dict(showgrid=False, automargin=True,
                   tickfont=dict(size=10.5, color=_MUTED)),
        yaxis=dict(gridcolor=_GRID, zeroline=False, automargin=True,
                   dtick=max(1, -(-max_n // 4)), tickfont=dict(size=11, color=_MUTED)),
    ))
    return fig


def _fig_modules(bdf: pd.DataFrame):
    avg = (bdf.dropna(subset=["raw_subscore"])
              .groupby("component")["raw_subscore"].mean())
    rows = [(c, float(avg[c])) for c in _COMPONENT_TH if c in avg.index]
    if not rows:
        return None
    # plotly draws the LAST horizontal bar at the top — sort best→worst so the
    # weakest component lands on top ("show severity, not noise")
    rows.sort(key=lambda x: x[1], reverse=True)
    fig = go.Figure(go.Bar(
        x=[v for _, v in rows],
        y=[_COMPONENT_TH[c] for c, _ in rows],
        orientation="h",
        marker=dict(color=[_score_hex(v) for _, v in rows], opacity=0.82),
        text=[f"{v:.0f}" for _, v in rows],
        textposition="auto",
        textfont=dict(size=11.5, family=_FONT_STACK, color=_INK2),
        hovertemplate="%{y} · คะแนนเฉลี่ย %{x:.1f}/100<extra></extra>",
    ))
    fig.update_layout(**_base_layout(
        height=250,
        xaxis=dict(range=[0, 105], gridcolor=_GRID, zeroline=False,
                   automargin=True, tickvals=[0, 25, 50, 75, 100],
                   tickfont=dict(size=11, color=_MUTED)),
        yaxis=dict(tickfont=dict(size=12, color=_INK2), automargin=True),
        margin=dict(l=6, r=6, t=10, b=2),
    ))
    return fig


# ── Ranked lists ─────────────────────────────────────────────────
def _render_top_problems(fdf: pd.DataFrame) -> None:
    prob = fdf[fdf["severity"].isin(("CRITICAL", "HIGH", "MEDIUM", "LOW"))]
    prob = prob.dropna(subset=["title"])
    if prob.empty:
        _panel_empty("ยังไม่พบปัญหาจากการสแกน")
        return
    grp = (prob.groupby("title")
               .agg(n=("title", "size"),
                    severity=("severity", lambda s: s.mode().iat[0]),
                    module=("module_key", lambda s: s.mode().iat[0]))
               .sort_values("n", ascending=False).head(6))
    rows = []
    for i, (title, r) in enumerate(grp.iterrows(), start=1):
        sev = str(r["severity"])
        mod = _MODULE_TH.get(str(r["module"]), str(r["module"]))
        rows.append(
            '<div class="db-rank-row">'
            f'<span class="db-rank-num">{i}</span>'
            f'<span class="db-rank-title">{_esc(title)} '
            f'<span class="db-rank-sub">· {_esc(mod)}</span></span>'
            f'<span class="db-chip {_SEV_CHIP.get(sev, "c-info")}">{_SEV_TH.get(sev, sev)}</span>'
            f'<span class="db-rank-count">× {int(r["n"]):,}</span></div>'
        )
    st.markdown(f'<div class="db-rank">{"".join(rows)}</div>', unsafe_allow_html=True)


def _render_top_hosts(df: pd.DataFrame, now_utc: datetime) -> None:
    grp = (df.groupby("target_host")
             .agg(n=("id", "count"), avg=("composite_score", "mean"),
                  last=("scanned_at", "max"))
             .sort_values(["n", "last"], ascending=False).head(6))
    if grp.empty:
        _panel_empty()
        return
    rows = []
    for i, (host, r) in enumerate(grp.iterrows(), start=1):
        avg = r["avg"]
        avg_txt = f"{avg:.0f}" if pd.notna(avg) else "—"
        rows.append(
            '<div class="db-rank-row">'
            f'<span class="db-rank-num">{i}</span>'
            f'<span class="db-rank-title">{_esc(host)} '
            f'<span class="db-rank-sub">· ล่าสุด {_rel_th(r["last"], now_utc)}</span></span>'
            f'<span class="db-score-pill {_score_band(avg)}">{avg_txt}</span>'
            f'<span class="db-rank-count">{int(r["n"]):,} ครั้ง</span></div>'
        )
    st.markdown(f'<div class="db-rank">{"".join(rows)}</div>', unsafe_allow_html=True)


# ── Live feed ────────────────────────────────────────────────────
def _render_feed(df: pd.DataFrame, now_utc: datetime) -> None:
    head = ("<thead><tr><th>เว็บไซต์</th><th>เวลา</th><th>คะแนน</th>"
            "<th>ความเสี่ยง</th><th class='num'>ข้อค้นพบ</th>"
            "<th class='num'>CVE</th><th class='num'>ใช้เวลา</th></tr></thead>")
    body = []
    for r in df.head(10).itertuples():
        ts = r.scanned_at
        fresh = (now_utc - ts).total_seconds() < 150
        new_chip = '<span class="db-new-chip">ใหม่</span>' if fresh else ""
        title = (f'<span class="db-host-title">{_esc(r.site_title)}</span>'
                 if isinstance(r.site_title, str) and r.site_title else "")
        score = r.composite_score
        score_txt = f"{int(score)}" if pd.notna(score) else "—"
        risk = str(r.risk_level) if isinstance(r.risk_level, str) else ""
        risk_html = (f'<span class="risk-badge risk-{risk}">{_RISK_TH.get(risk, risk)}</span>'
                     if risk in _RISK_TH else
                     '<span class="db-rank-sub">—</span>')
        dos = (' <span class="db-chip c-crit">DoS</span>'
               if bool(getattr(r, "dos_risk", False)) else "")
        dur = r.duration_ms
        dur_txt = f"{dur / 1000:.1f} วิ" if pd.notna(dur) else "—"
        findings = int(r.findings_count) if pd.notna(r.findings_count) else 0
        cves = int(r.cve_count) if pd.notna(r.cve_count) else 0
        host = r.target_host if isinstance(r.target_host, str) and r.target_host else "—"
        body.append(
            f'<tr class="{"db-row-new" if fresh else ""}">'
            f'<td><span class="db-host">{_esc(host)}</span>'
            f'{dos}{new_chip}{title}</td>'
            f'<td class="db-time" title="{ts.astimezone(_ICT):%d/%m/%Y %H:%M:%S}">'
            f'{_rel_th(ts, now_utc)}</td>'
            f'<td><span class="db-score-pill {_score_band(score)}">{score_txt}</span></td>'
            f'<td>{risk_html}</td>'
            f'<td class="num">{findings:,}</td>'
            f'<td class="num">{cves:,}</td>'
            f'<td class="num">{dur_txt}</td></tr>'
        )
    st.markdown(
        f'<div class="db-feed-wrap"><table class="db-feed">{head}'
        f'<tbody>{"".join(body)}</tbody></table></div>',
        unsafe_allow_html=True,
    )


# ── States ───────────────────────────────────────────────────────
def _render_not_configured() -> None:
    st.markdown(
        '<div class="db-notice"><b>ยังไม่ได้เชื่อมต่อฐานข้อมูล</b><br>'
        'ตั้งค่า <b>SUPABASE_URL</b> และ <b>SUPABASE_SERVICE_KEY</b> ใน .env '
        '(หรือ secrets.toml บน Streamlit Cloud) แล้วรีเฟรชหน้านี้อีกครั้ง</div>',
        unsafe_allow_html=True,
    )


def _render_db_error() -> None:
    st.markdown(
        '<div class="db-notice"><b>เชื่อมต่อฐานข้อมูลไม่สำเร็จ</b><br>'
        f'ระบบจะลองเชื่อมต่อใหม่อัตโนมัติทุก {_REFRESH_SEC} วินาที — '
        'ไม่ต้องรีเฟรชหน้า</div>',
        unsafe_allow_html=True,
    )


def _render_empty() -> None:
    st.markdown(
        '<div class="empty-state">'
        f'<span class="empty-icon">{_icon(I_RADAR, 44)}</span>'
        '<div class="empty-title">ยังไม่มีข้อมูลการสแกน</div>'
        '<div class="empty-hint">เมื่อมีการสแกนเว็บไซต์ครั้งแรก ผลจะปรากฏบนแดชบอร์ดนี้ทันที<br>'
        '<a href="./" target="_self">ไปที่หน้าตรวจสอบเพื่อเริ่มสแกน</a></div></div>',
        unsafe_allow_html=True,
    )


def _plotly_missing_note() -> None:
    _panel_empty("ต้องติดตั้งไลบรารี plotly ก่อน (pip install plotly) จึงจะแสดงกราฟได้")


# ── Page body (re-runs every _REFRESH_SEC seconds) ───────────────
@st.fragment(run_every=f"{_REFRESH_SEC}s")
def _dashboard() -> None:
    data = _load()
    scans = data.get("scans")
    now_utc = datetime.now(timezone.utc)

    if scans is None:                       # DB unreachable — keep polling
        _render_header(online=False)
        _render_db_error()
        return

    _render_header(online=True)

    if not scans:
        _render_empty()
        return

    df = pd.DataFrame(scans)
    df["scanned_at"] = pd.to_datetime(df["scanned_at"], utc=True, format="ISO8601")
    fdf = pd.DataFrame(data.get("findings") or [])
    bdf = pd.DataFrame(data.get("breakdown") or [])

    # quiet real-time cue: a scan arrived since the previous poll
    latest_id = str(df.iloc[0]["id"])
    prev_id = st.session_state.get("db_latest_scan_id")
    if prev_id is not None and prev_id != latest_id:
        host = df.iloc[0]["target_host"]
        host = host if isinstance(host, str) and host else "ไม่ทราบโฮสต์"
        st.toast(f"สแกนใหม่: {host}", icon=":material/radar:")
    st.session_state["db_latest_scan_id"] = latest_id

    _render_stats(df, data.get("totals") or {}, now_utc)

    total_all = (data.get("totals") or {}).get("scans")
    window_note = f"จาก {len(df):,} สแกนล่าสุด" if (total_all or 0) > len(df) else ""

    col_a, col_b = st.columns([8, 4], gap="medium")
    with col_a, st.container(key="db_panel_trend"):
        _panel_head(I_ACTIVITY, "แนวโน้มการสแกน", f"{_TREND_DAYS} วันล่าสุด")
        if go is None:
            _plotly_missing_note()
        else:
            _chart(_fig_trend(df), "db_c_trend")
    with col_b, st.container(key="db_panel_risk"):
        _panel_head(I_PIE, "ระดับความเสี่ยง", window_note)
        if go is None:
            _plotly_missing_note()
        else:
            _render_risk_donut(df)

    col_c, col_d = st.columns([5, 7], gap="medium")
    with col_c, st.container(key="db_panel_hist"):
        _panel_head(I_BARS, "การกระจายคะแนน", "ช่วงละ 10 คะแนน")
        if go is None:
            _plotly_missing_note()
        elif df["composite_score"].dropna().empty:
            _panel_empty()
        else:
            _chart(_fig_hist(df), "db_c_hist")
    with col_d, st.container(key="db_panel_modules"):
        _panel_head(I_GAUGE, "คะแนนเฉลี่ยรายด้าน", "คะแนนดิบ 0–100")
        if go is None:
            _plotly_missing_note()
        else:
            fig = _fig_modules(bdf) if not bdf.empty else None
            if fig is None:
                _panel_empty()
            else:
                _chart(fig, "db_c_modules")

    col_e, col_f = st.columns([7, 5], gap="medium")
    with col_e, st.container(key="db_panel_problems"):
        _panel_head(I_ALERT, "ปัญหาที่พบบ่อย", "ไม่รวมระดับข้อมูล")
        if fdf.empty:
            _panel_empty("ยังไม่พบปัญหาจากการสแกน")
        else:
            _render_top_problems(fdf)
    with col_f, st.container(key="db_panel_hosts"):
        _panel_head(I_GLOBE, "เว็บไซต์ที่ตรวจบ่อย", "")
        _render_top_hosts(df, now_utc)

    with st.container(key="db_panel_feed"):
        _panel_head(I_RADIO, "การสแกนล่าสุด", "10 รายการล่าสุด")
        _render_feed(df, now_utc)


_dashboard()
render_footer()
