# src/chat_ui.py — "ถามต่อกับ AI" chat panel (Streamlit view layer)
# ────────────────────────────────────────────────────────────────────
#   Renders the chat box that sits below the AI-analysis sections in the
#   "AI Analysis" tab. All the model/hardware logic lives in local_llm.py;
#   all the scope/guardrail logic lives in chat_assistant.py. This file is
#   ONLY the view: state machine, streaming into placeholders, and the
#   Fable-styled markup. It is wrapped in one @st.fragment so asking a
#   question reruns just this panel — never the scan, never the PDF section.
#
#   HYBRID engine: it prefers a READY local model (private, free), and otherwise
#   falls back to the cloud Gemini/OpenRouter cascade (ai_engine.chat_stream) so
#   the box works on Streamlit Cloud and on phones too. The pre-flight scope gate,
#   the untrusted-data fence, and the output sanitiser apply to BOTH engines.
#
#   Engine resolution (render_chat_panel): ready local model → "local"; else any
#   API key → "cloud"; else the setup states (install / start / download /
#   unsupported / none). Setup states only appear when NEITHER engine is usable.
#
#   The chat content is rendered with plain st.markdown (NO unsafe_allow_html),
#   so even though the reply comes from a local model it cannot inject HTML
#   into the page. Only our own chrome uses unsafe_allow_html, and never
#   interpolates model or scan text into it un-escaped.
# ────────────────────────────────────────────────────────────────────
from __future__ import annotations

import html as _html

import streamlit as st

import local_llm as L
import chat_assistant as C

_CHAT_KEY = "vulnex-chat"          # st.container(key=...) → CSS scope .st-key-vulnex-chat

# Inline SVGs (Lucide), currentColor-driven so CSS controls their tint.
_SVG_SPARK = (
    '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor"'
    ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936'
    'A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .962 0L14.063 8.5A2 2 0 0 0 15.5 9.937'
    'l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.962 0z"/>'
    '<path d="M20 3v4"/><path d="M22 5h-4"/><path d="M4 17v2"/><path d="M5 18H3"/></svg>'
)
_SVG_CPU = (
    '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor"'
    ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/>'
    '<path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/>'
    '<path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>'
)
_SVG_SHIELD = (
    '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"'
    ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1'
    'c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>'
    '<path d="m9 12 2 2 4-4"/></svg>'
)
_SVG_DOWNLOAD = (
    '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"'
    ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>'
    '<polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>'
)
_SVG_CLOUD = (
    '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"'
    ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M17.5 19a4.5 4.5 0 0 0 .5-8.972 6 6 0 0 0-11.64-1.5A4 4 0 1 0 6.5 19z"/></svg>'
)


def _cloud_available() -> bool:
    """Does the Gemini/OpenRouter cascade have any usable key? (hybrid fallback).

    Lazy import so a machine that only ever uses local never pays ai_engine's
    google-generativeai import here — it's already loaded post-scan anyway."""
    try:
        from ai_engine import _has_any_provider
        return bool(_has_any_provider())
    except Exception:      # noqa: BLE001
        return False

# Use the DEFAULT role avatars (no custom avatar=): a custom icon collapses both
# roles to the same `stChatMessageAvatarCustom` test-id, whereas the defaults
# keep the distinct AvatarUser / AvatarAssistant test-ids the scoped CSS needs to
# tint the two speakers differently.


def _esc(v, maxlen: int = 200) -> str:
    return _html.escape(str(v).strip()[:maxlen])


# ── State keys (namespaced so they never collide with app.py's) ──────
_K_MODE    = "chat_mode"        # "fast" | "deep"
_K_PENDING = "chat_pending"     # a queued question (from a suggestion chip)


def _engine_badge(engine: str, plan: L.Plan, model: L.LocalModel | None) -> str:
    """Header chip naming the ACTIVE engine — 'Local · <model> · <accel>' or
    'Cloud · AI ออนไลน์' — so it's always clear where the reply comes from."""
    if engine == "local":
        dot, kind, label = "on", "Local", f"{_esc(model.label, 40)} · {_esc(plan.hw.accel, 12)}"
    elif engine == "cloud":
        dot, kind, label = "on", "Cloud", "AI ออนไลน์"
    elif engine == "download":
        dot, kind, label = "warn", "Local", f"รอดาวน์โหลด · {_esc(model.label, 40) if model else ''}"
    elif engine == "start":
        dot, kind, label = "warn", "Local", "กำลังเริ่มเอนจิน"
    elif engine == "install":
        dot, kind, label = "off", "Local", "ยังไม่ได้ติดตั้ง"
    elif engine == "unsupported":
        dot, kind, label = "warn", "Local", "เครื่องไม่รองรับ"
    else:
        dot, kind, label = "off", "AI", "ไม่พร้อมใช้งาน"
    return (
        '<span class="chat-badge">'
        f'<span class="chat-badge-dot chat-dot-{dot}"></span>'
        f'<span class="chat-badge-kind">{kind}</span>'
        f'<span class="chat-badge-model">{label}</span>'
        '</span>'
    )


def _header(engine: str, plan: L.Plan, model: L.LocalModel | None) -> None:
    sub = ("ผู้ช่วยในเครื่อง · ตอบจากผลสแกนของเว็บนี้เท่านั้น" if engine == "local"
           else "ตอบจากผลสแกนของเว็บนี้เท่านั้น")
    st.markdown(
        '<div class="chat-head">'
        '<div class="chat-head-title">'
        f'<span class="chat-head-icon">{_SVG_SPARK}</span>'
        '<div class="chat-head-text">'
        '<span class="chat-head-name">ถามต่อกับ AI</span>'
        f'<span class="chat-head-sub">{sub}</span>'
        '</div></div>'
        f'{_engine_badge(engine, plan, model)}'
        '</div>',
        unsafe_allow_html=True,
    )


def _state_card(icon: str, title: str, body_html: str, tone: str = "info") -> None:
    """A centred setup/notice card used by the not-ready states."""
    st.markdown(
        f'<div class="chat-state chat-state-{tone}">'
        f'<span class="chat-state-icon">{icon}</span>'
        f'<div class="chat-state-title">{title}</div>'
        f'<div class="chat-state-body">{body_html}</div>'
        '</div>',
        unsafe_allow_html=True,
    )


def _cloud_caveat() -> None:
    st.markdown(
        '<div class="chat-caveat">'
        'โมเดลในเครื่อง (ผ่าน Ollama) ทำงานบนเครื่องที่รันแอปและไม่ส่งข้อมูลออกนอกเครื่อง '
        'เหมาะกับความเป็นส่วนตัวสูงสุด — ถ้าเครื่องนี้ไม่มีโมเดลในเครื่อง (เช่นบน Streamlit Cloud '
        'หรือเปิดผ่านมือถือ) ระบบจะใช้ AI ออนไลน์ตอบให้อัตโนมัติ จึงถามได้จากทุกอุปกรณ์'
        '</div>',
        unsafe_allow_html=True,
    )


def _render_thread() -> None:
    """Replay the conversation so far."""
    for turn in st.session_state.get("chat_history", []):
        role = turn.get("role")
        if role not in ("user", "assistant"):
            continue
        with st.chat_message(role):
            st.markdown(turn.get("content", ""))     # plain markdown → HTML-safe


def _suggestion_chips(scan_data: dict, server_data: dict, ai_data: dict) -> None:
    """Empty-state starter questions, grounded in this scan. Clicking one queues
    it as a pending question and reruns the fragment to answer it."""
    st.markdown(
        '<div class="chat-empty">'
        f'<span class="chat-empty-icon">{_SVG_SHIELD}</span>'
        '<div class="chat-empty-title">เริ่มถามได้เลย</div>'
        '<div class="chat-empty-hint">พิมพ์คำถามด้านล่าง หรือเลือกคำถามที่พบบ่อยจากผลสแกนนี้</div>'
        '</div>',
        unsafe_allow_html=True,
    )
    for i, q in enumerate(C.suggested_questions(scan_data, server_data, ai_data)):
        if st.button(q, key=f"chat_sugg_{i}", use_container_width=True):
            st.session_state[_K_PENDING] = q
            st.rerun(scope="fragment")


def _run_turn(engine: str, ready_tag: str, prompt: str, scan_data: dict,
              server_data: dict, ai_data: dict, mode: str) -> None:
    """Run one chat turn: append the question, stream the reply, persist both.

    Engine-agnostic — the same bubble/streaming/persist logic drives both the
    local Ollama model and the cloud Gemini/OpenRouter cascade. Called only after
    the pre-flight scope gate has passed. The pre-flight gate, the untrusted-data
    fence, and the output sanitiser all apply to BOTH engines, so the guardrails
    are identical whichever one answers."""
    history = st.session_state.setdefault("chat_history", [])
    history.append({"role": "user", "content": prompt})
    prior = history[:-1]                       # context excludes the new question

    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        placeholder = st.empty()
        thinking = ("กำลังคิดอย่างละเอียด (โหมดคิดนาน อาจใช้เวลาสักครู่)…"
                    if mode == "deep" else "กำลังพิมพ์…")
        placeholder.markdown(f"_{thinking}_")

        acc, err = "", ""
        try:
            if engine == "local":
                stream = L.chat_stream(
                    ready_tag,
                    C.build_messages(prompt, scan_data, server_data, ai_data, prior, mode),
                    mode,
                )
            else:                              # cloud — Gemini/OpenRouter cascade
                from ai_engine import chat_stream as _ai_chat_stream
                stream = _ai_chat_stream(prompt, scan_data, server_data, ai_data, prior, mode)
            for chunk in stream:
                acc += chunk
                placeholder.markdown(C.sanitize_reply(acc) + " ▍")
        except Exception as exc:               # noqa: BLE001
            err = str(exc)

        if err and not acc:
            reply = f"ขออภัย ประมวลผลไม่สำเร็จครับ: {err}"
        else:
            reply = C.sanitize_reply(acc) or "ขออภัย ยังไม่มีคำตอบที่ชัดเจนจากผลสแกนนี้ครับ"
            if err:
                reply += f"\n\n_(หมายเหตุ: การเชื่อมต่อสะดุดกลางทาง — {err})_"
        placeholder.markdown(reply)

    history.append({"role": "assistant", "content": reply})


def _refuse(prompt: str, refusal: str) -> None:
    """Handle an out-of-scope message without ever calling the model."""
    history = st.session_state.setdefault("chat_history", [])
    history.append({"role": "user", "content": prompt})
    history.append({"role": "assistant", "content": refusal})
    with st.chat_message("user"):
        st.markdown(prompt)
    with st.chat_message("assistant"):
        st.markdown(refusal)


# ── Not-ready states ─────────────────────────────────────────────────
def _render_install_state() -> None:
    cmd = _esc(L.install_command(), 120)
    _state_card(
        _SVG_DOWNLOAD, "เปิดใช้ผู้ช่วย AI ในเครื่อง",
        "ช่องแชทนี้ใช้โมเดลภาษาที่รัน <b>ในเครื่องของคุณเอง</b> ผ่าน Ollama "
        "ยังไม่พบ Ollama บนเครื่องนี้ ติดตั้งได้ด้วยคำสั่ง:"
        f'<div class="chat-code">{cmd}</div>'
        "เมื่อติดตั้งเสร็จ กด “ตรวจอีกครั้ง” ด้านล่าง",
    )
    if st.button("ตรวจอีกครั้ง", key="chat_recheck_install"):
        st.rerun(scope="fragment")
    _cloud_caveat()


def _render_start_state() -> None:
    _state_card(
        _SVG_CPU, "เริ่มการทำงานของเอนจิน AI",
        "พบ Ollama บนเครื่องแล้ว แต่บริการยังไม่ทำงาน กด “เริ่มเอนจิน” เพื่อเปิดใช้งาน",
        tone="warn",
    )
    if st.button("เริ่มเอนจิน", key="chat_start_daemon", type="primary"):
        with st.spinner("กำลังเริ่มบริการ Ollama…"):
            L.start_daemon(wait_sec=15)
        st.rerun(scope="fragment")


def _render_unsupported_state(plan: L.Plan) -> None:
    _state_card(
        _SVG_CPU, "เครื่องนี้ยังไม่รองรับโมเดลในเครื่อง",
        f"หน่วยความจำที่ใช้ได้ประมาณ <b>{plan.hw.budget_gb:.1f} GB</b> "
        f"({_esc(plan.hw.summary, 60)}) ซึ่งยังไม่พอต่อโมเดลที่เล็กที่สุดในระบบ "
        "และยังไม่ได้ตั้งค่า AI ออนไลน์ไว้ — เพิ่ม API key (Gemini/OpenRouter) "
        "เพื่อให้ช่องแชทตอบผ่านคลาวด์ได้ หรือใช้เครื่องที่มี RAM/การ์ดจอมากกว่านี้",
        tone="warn",
    )


def _pull_with_progress(model: L.LocalModel) -> None:
    """Download `model` with a live progress bar; on success re-run the fragment
    so the panel flips to the ready (local) state. Shared by the download card and
    the cloud-mode 'enable local' expander."""
    bar = st.progress(0.0, text="กำลังเริ่มดาวน์โหลด…")

    def _on(p: L.PullProgress) -> None:
        label = p.status or "กำลังดาวน์โหลด"
        if p.total:
            gb_done, gb_all = p.completed / 1024**3, p.total / 1024**3
            bar.progress(min(1.0, p.pct), text=f"{label} · {gb_done:.1f}/{gb_all:.1f} GB")
        else:
            bar.progress(0.03, text=label)

    tag, err = L.pull_model(model, on_progress=_on)
    bar.empty()
    if tag:
        L.register_exit_cleanup()
        st.success(f"ดาวน์โหลด {model.label} สำเร็จ พร้อมใช้งานแล้ว")
        st.rerun(scope="fragment")
    else:
        st.error(f"ดาวน์โหลดไม่สำเร็จ: {err}")


def _render_download_state(model: L.LocalModel, plan: L.Plan) -> None:
    tier_note = ("โมเดลที่ฉลาดที่สุดเท่าที่เครื่องนี้รับไหว"
                 if plan.hw.tier in ("cpu", "entry")
                 else "โมเดลที่เหมาะกับสเปกเครื่องนี้มากที่สุด")
    _state_card(
        _SVG_DOWNLOAD, "ดาวน์โหลดโมเดลเพื่อเริ่มใช้งาน",
        f"ระบบเลือก <b>{_esc(model.label)}</b> ({_esc(model.params)}) ให้อัตโนมัติ — {tier_note} "
        f"ต้องดาวน์โหลดครั้งเดียวราว <b>{model.size_label}</b> "
        "โมเดลจะถูกลบออกจากเครื่องอัตโนมัติเมื่อปิดแอป",
    )
    st.caption(f"เหตุผลที่เลือกรุ่นนี้: {model.why}")
    if st.button(f"ดาวน์โหลดโมเดล ({model.size_label})",
                 key="chat_pull", type="primary", use_container_width=True):
        _pull_with_progress(model)
    _cloud_caveat()


def _render_no_ai_state() -> None:
    _state_card(
        _SVG_CLOUD, "ยังไม่มี AI ที่พร้อมใช้งาน",
        "ช่องแชทต้องการอย่างใดอย่างหนึ่ง: โมเดลในเครื่อง (Ollama) หรือ API key ของ AI ออนไลน์ "
        "(Gemini/OpenRouter) — ตั้งค่าอย่างใดอย่างหนึ่งแล้วลองใหม่อีกครั้ง",
        tone="warn",
    )
    if st.button("ตรวจอีกครั้ง", key="chat_recheck_none"):
        st.rerun(scope="fragment")


def _render_enable_local_expander(model: L.LocalModel, plan: L.Plan) -> None:
    """Shown in CLOUD mode when this machine COULD run a local model — a
    non-blocking offer to download it and switch to fully-private local mode."""
    with st.expander("ใช้โมเดลในเครื่องแทน (ส่วนตัว ไม่ส่งข้อมูลออกนอกเครื่อง)"):
        st.caption(
            f"เครื่องนี้รองรับ {model.label} ({model.size_label}) — ดาวน์โหลดครั้งเดียว "
            "เพื่อสลับมาตอบด้วยโมเดลในเครื่องแทน AI ออนไลน์ (โมเดลจะถูกลบเมื่อปิดแอป)"
        )
        if st.button(f"ดาวน์โหลด {model.label} ({model.size_label})",
                     key="chat_pull_opt", use_container_width=True):
            _pull_with_progress(model)


def _render_manage_row(plan: L.Plan) -> None:
    """Small footer: mode explainer + disk-cleanup control for managed models."""
    managed = L.managed_tags()
    if not managed:
        return
    size = L.managed_size_gb()
    col1, col2 = st.columns([3, 1], vertical_alignment="center")
    with col1:
        st.caption(
            f"โมเดลในเครื่องที่ VULNEX จัดการ: {len(managed)} รายการ "
            f"({size:.1f} GB) · จะถูกลบอัตโนมัติเมื่อปิดแอป"
        )
    with col2:
        if st.button("ลบโมเดลออก", key="chat_cleanup", use_container_width=True):
            with st.spinner("กำลังลบโมเดล…"):
                removed = L.cleanup_managed()
            st.success(f"ลบแล้ว {len(removed)} รายการ (คืนพื้นที่ ~{size:.1f} GB)")
            st.rerun(scope="fragment")


# ════════════════════════════════════════════════════════════════════
# Public entry point
# ════════════════════════════════════════════════════════════════════
@st.fragment
def render_chat_panel(scan_data: dict, server_data: dict, ai_data: dict) -> None:
    """The whole 'ถามต่อกับ AI' box. Call once, inside the AI Analysis tab."""
    st.session_state.setdefault(_K_MODE, "fast")

    with st.container(key=_CHAT_KEY):
        status = L.backend_status(autostart=True)
        plan   = L.resolve_plan()
        mode   = st.session_state[_K_MODE]
        model  = plan.pick(mode)
        ready_tag = L.resolve_tag(model) if (status.running and model) else ""
        cloud_ok  = _cloud_available()

        # Arm the on-exit disk sweep whenever the engine is live — this also
        # cleans up a manifest left behind by a previous hard-killed session.
        if status.running:
            L.register_exit_cleanup()

        # ── Hybrid engine resolution ─────────────────────────────────
        # Prefer a READY local model (private, free); otherwise fall back to the
        # cloud Gemini/OpenRouter cascade so the box works on Streamlit Cloud and
        # on phones. The setup states below only appear when NEITHER is usable.
        if status.running and model and ready_tag:
            engine = "local"
        elif cloud_ok:
            engine = "cloud"
        elif status.running and model and not ready_tag:
            engine = "download"          # local possible, no cloud → must download
        elif not status.installed:
            engine = "install"
        elif not status.running:
            engine = "start"
        elif model is None:
            engine = "unsupported"
        else:
            engine = "none"

        _header(engine, plan, model)

        # ── Setup-only states (no usable engine yet) ─────────────────
        if engine == "download":
            _render_download_state(model, plan)
            return
        if engine == "install":
            _render_install_state()
            return
        if engine == "start":
            _render_start_state()
            return
        if engine == "unsupported":
            _render_unsupported_state(plan)
            return
        if engine == "none":
            _render_no_ai_state()
            return

        # ── Ready (local OR cloud): mode toggle · thread · input ─────
        mode_help = ("ตอบเร็ว: โมเดลที่ตอบไว · คิดนาน: โมเดลที่คิดละเอียดกว่าเพื่อคำตอบที่ดีขึ้น"
                     if engine == "local"
                     else "ตอบเร็ว: ตอบกระชับรวดเร็ว · คิดนาน: วิเคราะห์ละเอียดขึ้น (ใช้โทเคนมากขึ้น)")
        mode_label = st.segmented_control(
            "โหมดการตอบ",
            options=["ตอบเร็ว", "คิดนาน"],
            default="คิดนาน" if mode == "deep" else "ตอบเร็ว",
            key="chat_mode_control",
            help=mode_help,
            label_visibility="collapsed",
        )
        new_mode = "deep" if mode_label == "คิดนาน" else "fast"
        if new_mode != mode:
            st.session_state[_K_MODE] = new_mode
            st.rerun(scope="fragment")

        if st.session_state.get("chat_history"):
            _render_thread()
        else:
            _suggestion_chips(scan_data, server_data, ai_data)

        typed = st.chat_input("ถามเกี่ยวกับผลสแกนของเว็บนี้…", key="chat_input_box")
        pending = st.session_state.pop(_K_PENDING, None)
        prompt = (typed or pending or "").strip()

        if prompt:
            allowed, refusal = C.in_scope(prompt)
            if allowed:
                _run_turn(engine, ready_tag, prompt, scan_data, server_data,
                          ai_data, st.session_state[_K_MODE])
            else:
                _refuse(prompt, refusal)
            st.rerun(scope="fragment")

        # ── Footer ───────────────────────────────────────────────────
        # In cloud mode on a machine that COULD run a local model, offer the
        # private local option (non-blocking). Managed-model cleanup shows
        # whenever VULNEX has pulled any model.
        if engine == "cloud" and status.running and model and not ready_tag:
            _render_enable_local_expander(model, plan)
        _render_manage_row(plan)
