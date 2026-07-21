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

import streamlit as st

import chat_context
import chat_engine
import chat_guard
from prompt_builder import build_chat_prompt


def _render_message(role: str, content: str, index: int = 0) -> None:
    """Render one message as REAL Streamlit markdown (st.markdown(content),
    unsafe_allow_html=False) inside a keyed container that CSS themes as a
    bubble — instead of hand-rolling a tiny regex-based markdown subset into
    a raw HTML string. This is what actually fixes table/list rendering:
    Streamlit's own markdown engine already supports GFM tables, ordered/
    unordered lists, bold, code spans and blocks, etc. — the old
    _render_inline_md() only understood **bold** and `code`, so anything
    else (tables especially) rendered as literal pipe-and-dash text.

    Key is positional and role-prefixed (dotred_msg_user_N / dotred_msg_ai_N)
    — NOT content-hashed — so CSS can select on the stable prefix
    (`st-key-dotred_msg_user_` vs `st-key-dotred_msg_ai_`) for role styling,
    and on the trailing index for the entrance stagger, without needing a
    per-message injected <style> tag."""
    is_user = role == "user"
    prefix = "dotred_msg_user" if is_user else "dotred_msg_ai"
    key = f"{prefix}_{index}"
    avatar = "คุณ" if is_user else "dR"
    with st.container(key=key):
        st.markdown(f'<span class="dotred-role-tag">{avatar}</span>', unsafe_allow_html=True)
        st.markdown(content)


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
    streaming a reply never reruns (or ghosts) the rest of the page.

    STREAMING LAYOUT FIX: previously the live st.write_stream placeholder
    rendered as a sibling AFTER the input form (st.container(key=...) calls
    append at the point they're called in Python, and _run_dotred_turn() ran
    at the very end of this function) — so the in-flight answer visibly
    appeared BELOW the input box, outside the scrolling .dotred-thread box,
    then "jumped" up into its correct position only once the fragment
    rerun landed. Fixed by opening .dotred-thread's wrapper as a REAL
    Streamlit container (not a closed markdown string) so the live stream
    can be placed inside it, in the correct final position, from the start.
    """
    chat_context.ensure_history_for_scan(scan_data)
    history = chat_context.get_history()
    pending_question = st.session_state.pop("dotred_inflight_question", None)

    # ── Header (its own markdown call — static, never touched by streaming) ──
    header_html = '''
<div class="dotred-card dotred-card-head">
  <div class="dotred-header">
    <div class="dotred-header-left">
      <div class="dotred-avatar">dR</div>
      <div>
        <div class="dotred-title">dotRED</div>
        <div class="dotred-subtitle">ถามต่อเกี่ยวกับผลสแกนนี้ได้เลย</div>
      </div>
    </div>
  </div>
</div>'''
    st.markdown(header_html, unsafe_allow_html=True)

    # ── Thread — now a real st.container(key=...) instead of a closed-off
    # markdown string, specifically so the live streaming placeholder (used
    # only while pending_question is set) can be placed INSIDE it, in the
    # correct scroll position, instead of appearing after the input row. ──
    with st.container(key="dotred_thread"):
        if not history and not pending_question:
            st.markdown(
                '<div class="dotred-empty"><div class="dotred-empty-hint">'
                'dotRED อ่านผลสแกนนี้ทั้งหมดแล้ว (คะแนน, headers, SSL, DNS, cookies, '
                'CVE และคลังความรู้ความปลอดภัย) ลองเริ่มด้วยคำถามด้านล่าง หรือพิมพ์'
                'คำถามของคุณเองก็ได้ครับ</div></div>',
                unsafe_allow_html=True,
            )
        else:
            for i, m in enumerate(history):
                _render_message(m["role"], m["content"], index=len(history) - 1 - i)

            if pending_question:
                # The user's own message renders IMMEDIATELY (optimistic —
                # before any network call), directly under the existing
                # thread, so there's zero perceived delay for their own
                # bubble. This is the single biggest lag-reduction: the
                # previous version showed nothing at all until the AI's
                # full reply streamed in.
                _render_message("user", pending_question, index=0)
                _run_dotred_turn(pending_question, scan_data, server_data, ai_data)
                st.rerun(scope="fragment")

    # ── Chips + input, wrapped in a keyed container so index.css can
    # continue the card's visual (background/border/radius) underneath the
    # thread above — these are real Streamlit widgets and cannot live inside
    # a markdown-rendered <div>. ──────────────────────────────────────────
    with st.container(key="dotred_panel_below"):
        if not history and not pending_question:
            chips = chat_guard.suggested_questions(scan_data, server_data, ai_data)
            cols = st.columns(len(chips))
            for i, (col, q) in enumerate(zip(cols, chips)):
                with col:
                    if st.button(q, key=f"dotred_chip_{i}", use_container_width=True):
                        st.session_state["dotred_pending_input"] = q
                        st.rerun(scope="fragment")

        pending_input_val = st.session_state.pop("dotred_pending_input", "")
        with st.form(key="dotred_form", clear_on_submit=True, border=False):
            in_col, send_col, clear_col = st.columns([6, 1, 1])
            with in_col:
                user_message = st.text_input(
                    "ถามคำถาม",
                    value=pending_input_val,
                    key="dotred_input_box",
                    placeholder="เช่น: ควรแก้ปัญหาไหนก่อน?",
                    label_visibility="collapsed",
                    disabled=bool(pending_question),
                )
            with send_col:
                submitted = st.form_submit_button(
                    "ส่ง", key="dotred_send_btn", use_container_width=True,
                    disabled=bool(pending_question),
                )
            with clear_col:
                cleared = st.form_submit_button(
                    "ล้าง", key="dotred_clear_btn", use_container_width=True,
                    disabled=bool(pending_question),
                )

    if cleared:
        chat_context.clear_history()
        st.rerun(scope="fragment")

    if submitted and user_message.strip():
        # Two-phase submit: this rerun's ONLY job is to record the question
        # and immediately rerun again — the actual AI call happens on the
        # NEXT pass, inside the thread container above, so the user's own
        # bubble can render (and the input can visibly disable) before any
        # network latency is felt at all.
        st.session_state["dotred_inflight_question"] = user_message.strip()
        st.rerun(scope="fragment")
