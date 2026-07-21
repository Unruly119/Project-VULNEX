# src/chat_ui.py — dotRED · ChatBOT panel ("ถามต่อกับ AI") ใน AI Analysis tab
# ────────────────────────────────────────────────────────────────
#   สถาปัตยกรรม:
#     chat_context.py  → ความจำบทสนทนา (session_state, ไม่แตะ Supabase)
#     chat_guard.py    → scope gate ก่อนเรียก AI + sanitize คำตอบ + suggested Qs
#     prompt_builder.py→ build_chat_prompt() ประกอบบริบท: AI summary หน้าเว็บ
#                        + raw scan data ทุกโมดูล + Qdrant RAG (มีอยู่แล้ว ไม่แก้)
#     chat_engine.py   → provider cascade (Groq → Gemini → OpenRouter) คีย์แยก
#                        จาก ai_engine.py โดยสิ้นเชิง, stream_chat() ให้ token
#                        ไหลออกมาทีละก้อนจริง ๆ (ไม่ใช่ตอบมาเป็นก้อนเดียวแล้วพ่นทีหลัง)
#
#   HTML rendering convention (matches app.py's .sec-card pattern exactly):
#   every decorative wrapper is assembled as ONE Python f-string and passed to
#   a SINGLE st.markdown(..., unsafe_allow_html=True) call — st.markdown() and
#   st.write_stream() calls render as sibling DOM nodes in Streamlit, so
#   opening a <div> in one call and closing it in another produces three flat
#   siblings, not a nested wrapper. Only live Streamlit widgets (buttons, the
#   form, the streaming placeholder) get their own st.container(key=...), and
#   index.css themes those keyed containers directly.
#
#   ทั้ง panel อยู่ใน @st.fragment แยกจาก full-page rerun (เหมือน
#   render_pdf_report_section) กันไม่ให้ทั้งหน้า ghost ระหว่างสตรีมคำตอบ
# ────────────────────────────────────────────────────────────────
from __future__ import annotations

import html as _html
import re

import streamlit as st

import chat_context
import chat_engine
import chat_guard
from prompt_builder import build_chat_prompt

_MD_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_MD_CODE_RE = re.compile(r"`([^`]+?)`")


def _render_inline_md(text: str) -> str:
    """Escape then apply a tiny safe Markdown subset (bold, inline code).
    Full Markdown parsing is intentionally out of scope — dotRED's replies
    are short structured prose, not documents."""
    escaped = _html.escape(text)
    escaped = _MD_BOLD_RE.sub(r"<strong>\1</strong>", escaped)
    escaped = _MD_CODE_RE.sub(r"<code>\1</code>", escaped)
    paras = [f"<p>{p}</p>" for p in escaped.split("\n\n") if p.strip()]
    return "".join(paras) if paras else f"<p>{escaped}</p>"


def _message_html(role: str, content: str) -> str:
    is_user = role == "user"
    row_cls = "dotred-msg is-user" if is_user else "dotred-msg is-assistant"
    avatar = "คุณ" if is_user else "dR"
    body = f"<p>{_html.escape(content)}</p>" if is_user else _render_inline_md(content)
    return (
        f'<div class="{row_cls}">'
        f'<div class="dotred-avatar-sm">{avatar}</div>'
        f'<div class="dotred-bubble">{body}</div>'
        f'</div>'
    )


def _engine_badge_html(label: str) -> str:
    is_offline = label == "Offline"
    cls = "dotred-engine-badge is-offline" if is_offline else "dotred-engine-badge"
    return (
        f'<span class="{cls}"><span class="dotred-engine-dot"></span>'
        f'{_html.escape(label)}</span>'
    )


def _run_dotred_turn(
    user_message: str,
    scan_data: dict,
    server_data: dict,
    ai_data: dict,
) -> None:
    """ประมวลผลคำถามหนึ่งครั้ง: scope gate → build prompt (มี context ครบ + ความจำ)
    → stream คำตอบทีละตัวอักษรผ่าน st.write_stream → sanitize → บันทึกความจำ.

    เรียกก่อน rerun ครั้งถัดไป ผลลัพธ์จะถูกเก็บใน history แล้วแสดงผลตามปกติใน
    ลำดับ thread — คำตอบที่ยิง stream สด ๆ ในคอลนี้ใช้แค่ระหว่างรอ AI ตอบเท่านั้น."""
    ok, refusal = chat_guard.in_scope(user_message)
    chat_context.append_turn("user", user_message)

    if not ok:
        chat_context.append_turn("assistant", refusal)
        return

    prompt = build_chat_prompt(
        scan_result=scan_data,
        server_data=server_data,
        ai_data=ai_data,
        user_message=user_message,
        chat_history=chat_context.recent_turns_for_prompt(),
    )

    def _token_generator():
        """Adapter generator: stream_chat yields (chunk, engine_label); this
        yields plain str chunks for st.write_stream (true incremental
        rendering — dotRED's answer appears letter-by-letter, matching the
        ChatGPT/Claude/Gemini streaming feel) while remembering which engine
        ended up serving the request."""
        engine_used = None
        try:
            for chunk, label in chat_engine.stream_chat(prompt):
                engine_used = label
                yield chunk
        except Exception as exc:  # noqa: BLE001 — cascade หมดจริง ๆ → offline fallback
            st.session_state["dotred_last_error"] = str(exc)
            fallback = (
                "ขออภัยครับ ตอนนี้ dotRED เชื่อมต่อ AI ไม่ได้ชั่วคราว "
                "(ลองใหม่อีกครั้งในอีกสักครู่ หรือดูผลสแกนแบบละเอียดในแท็บ Raw Data "
                "ระหว่างนี้ได้เลยครับ)"
            )
            for ch in fallback:
                yield ch
            engine_used = "Offline"
        st.session_state["dotred_engine_used"] = engine_used or "Offline"

    with st.container(key="dotred_stream_row"):
        full_reply = st.write_stream(_token_generator())

    clean_reply = chat_guard.sanitize_reply(full_reply)
    chat_context.append_turn("assistant", clean_reply)


@st.fragment
def render_dotred_panel(scan_data: dict, server_data: dict, ai_data: dict) -> None:
    """Render the dotRED chat panel. Called from app.py under the AI Analysis
    tab, right after render_ai_analysis(...). Isolated in @st.fragment so
    streaming a reply never reruns (or ghosts) the rest of the page."""
    chat_context.ensure_history_for_scan(scan_data)
    history = chat_context.get_history()
    engine_label = chat_engine.active_engine_label()

    # ── Card shell: header + thread in ONE markdown call ──────────────
    # Matches app.py's own .sec-card convention — the whole visible card
    # chrome (header through the last message bubble) is a single Python
    # f-string passed to one st.markdown() call, so it genuinely nests as
    # one DOM tree instead of producing flat sibling <div>s.
    if not history:
        thread_inner = (
            '<div class="dotred-empty"><div class="dotred-empty-hint">'
            'dotRED อ่านผลสแกนนี้ทั้งหมดแล้ว (คะแนน, headers, SSL, DNS, cookies, '
            'CVE และคลังความรู้ความปลอดภัย) ลองเริ่มด้วยคำถามด้านล่าง หรือพิมพ์'
            'คำถามของคุณเองก็ได้ครับ</div></div>'
        )
    else:
        thread_inner = "".join(_message_html(m["role"], m["content"]) for m in history)

    card_html = f'''
<div class="dotred-card">
  <div class="dotred-header">
    <div class="dotred-header-left">
      <div class="dotred-avatar">dR</div>
      <div>
        <div class="dotred-title">dotRED</div>
        <div class="dotred-subtitle">ถามต่อเกี่ยวกับผลสแกนนี้ได้เลย</div>
      </div>
    </div>
    {_engine_badge_html(engine_label)}
  </div>
  <div class="dotred-thread">{thread_inner}</div>
</div>'''
    st.markdown(card_html, unsafe_allow_html=True)

    # ── Chips + input, wrapped in a keyed container so index.css can
    # continue the card's visual (background/border/radius) underneath the
    # markdown-rendered part above — these are real Streamlit widgets and
    # cannot live inside the <div> from the st.markdown() call above. ──────
    with st.container(key="dotred_panel_below"):
        # Suggested chips (empty state only — real st.button so they stay
        # keyboard-reachable, sharing focus-visible behavior with the app).
        if not history:
            chips = chat_guard.suggested_questions(scan_data, server_data, ai_data)
            cols = st.columns(len(chips))
            for i, (col, q) in enumerate(zip(cols, chips)):
                with col:
                    if st.button(q, key=f"dotred_chip_{i}", use_container_width=True):
                        st.session_state["dotred_pending_input"] = q
                        st.rerun(scope="fragment")

        pending = st.session_state.pop("dotred_pending_input", "")
        with st.form(key="dotred_form", clear_on_submit=True, border=False):
            in_col, send_col, clear_col = st.columns([6, 1, 1])
            with in_col:
                user_message = st.text_input(
                    "ถามคำถาม",
                    value=pending,
                    key="dotred_input_box",
                    placeholder="เช่น: ควรแก้ปัญหาไหนก่อน?",
                    label_visibility="collapsed",
                )
            with send_col:
                submitted = st.form_submit_button(
                    "ส่ง", key="dotred_send_btn", use_container_width=True
                )
            with clear_col:
                cleared = st.form_submit_button(
                    "ล้าง", key="dotred_clear_btn", use_container_width=True
                )

    if cleared:
        chat_context.clear_history()
        st.rerun(scope="fragment")

    if submitted and user_message.strip():
        _run_dotred_turn(user_message.strip(), scan_data, server_data, ai_data)
        st.rerun(scope="fragment")
