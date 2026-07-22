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


# ── Inline SVG icons ────────────────────────────────────────────────
# Local copy of app.py's _i() Lucide-style helper (not imported — app.py
# itself imports chat_ui, so importing back would create a circular import).
# Same convention: stroke=currentColor, so icon color always follows CSS.
def _i(p: str, s: int, xs: str = "") -> str:
    st_v = f"vertical-align:middle;flex-shrink:0{';' + xs if xs else ''}"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}"'
        f' viewBox="0 0 24 24" fill="none" stroke="currentColor"'
        f' stroke-width="2" stroke-linecap="round" stroke-linejoin="round"'
        f' style="{st_v}">{p}</svg>'
    )


_P_SHIELD_CHECK = (
    '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>'
    '<path d="m9 12 2 2 4-4"/>'
)
_P_MSG_CIRCLE = '<path d="M7.9 20A9 9 0 1 0 4 16.1L2 22Z"/>'
_P_FILE_SHIELD = (
    '<path d="M4 22V4a2 2 0 0 1 2-2h9l5 5v4"/><path d="M14 2v5h5"/>'
    '<path d="M18 22a3 3 0 0 0 3-3v-1a2 2 0 0 0-2-2h-2a2 2 0 0 0-2 2v1a3 3 0 0 0 3 3Z"/>'
)
_P_TRIANGLE_ALERT = (
    '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/>'
    '<path d="M12 9v4"/><path d="M12 17h.01"/>'
)
_P_SEND = '<path d="M14.536 21.686a.5.5 0 0 0 .937-.024l6.5-19a.496.496 0 0 0-.635-.635l-19 6.5a.5.5 0 0 0-.024.937l7.93 3.18a2 2 0 0 1 1.112 1.11z"/><path d="m21.854 2.147-10.94 10.939"/>'
_P_TRASH = '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" x2="10" y1="11" y2="17"/><line x1="14" x2="14" y1="11" y2="17"/>'
_P_LIGHTBULB = '<path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5"/><path d="M9 18h6"/><path d="M10 22h4"/>'
_P_CHEVRON_RIGHT = '<path d="m9 18 6-6-6-6"/>'

_CHIP_ICON_PATHS = {
    "file_shield": _P_FILE_SHIELD,
    "alert": _P_TRIANGLE_ALERT,
}


def _svg_data_uri(paths: str, color: str) -> str:
    """Build a background-image-ready data: URI for an inline SVG icon.
    Used to draw chip icons via CSS background-image instead of an extra
    st.markdown() call — same zero-extra-DOM-node principle as the message
    avatar ::before fix above, applied here to keep st.button()'s label as
    plain text (buttons can't render arbitrary raw <svg> in their label)."""
    import urllib.parse

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
        f'fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" '
        f'stroke-linejoin="round">{paths}</svg>'
    )
    return "data:image/svg+xml," + urllib.parse.quote(svg)


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
    per-message injected <style> tag.

    BUGFIX: the role avatar used to be its OWN st.markdown() call (a
    <span class="dotred-role-tag">) placed before the content markdown call.
    Two st.markdown() calls in the same keyed container = two separate
    stMarkdownContainer DOM siblings — and the bubble CSS targets ALL
    stMarkdownContainer elements inside the key wrapper, not just the
    "real" one. Result: the avatar span rendered as its OWN full-width
    empty-ish bubble stacked in the same row (the two-box bug). Fixed by
    dropping the avatar into a CSS ::before pseudo-element on the container
    itself instead — zero extra markdown call, so there's only ever ONE
    stMarkdownContainer per message, guaranteed."""
    is_user = role == "user"
    prefix = "dotred_msg_user" if is_user else "dotred_msg_ai"
    key = f"{prefix}_{index}"
    with st.container(key=key):
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
    # Mockup match: adds a decorative sparkle + chat-bubble + shield-check
    # cluster on the right of the header — purely visual (no live status
    # meaning, unlike the removed engine badge), drawn as inline SVG so it
    # stays crisp at any zoom instead of a screenshotted raster asset.
    header_html = f'''
<div class="dotred-card dotred-card-head">
  <div class="dotred-header">
    <div class="dotred-header-left">
      <div class="dotred-avatar">dR</div>
      <div>
        <div class="dotred-title">dotRED</div>
        <div class="dotred-subtitle">ถามต่อเกี่ยวกับผลสแกนนี้ได้เลย</div>
      </div>
    </div>
    <div class="dotred-header-deco" aria-hidden="true">
      <span class="dotred-deco-spark dotred-deco-spark-a">✦</span>
      <span class="dotred-deco-spark dotred-deco-spark-b">✧</span>
      <span class="dotred-deco-spark dotred-deco-spark-c">✦</span>
      <div class="dotred-deco-bubble">{_i(_P_MSG_CIRCLE, 20)}</div>
      <div class="dotred-deco-shield">{_i(_P_SHIELD_CHECK, 22)}</div>
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
            for i, (col, item) in enumerate(zip(cols, chips)):
                with col:
                    chip_key = f"dotred_chip_{i}"
                    icon_uri = _svg_data_uri(
                        _CHIP_ICON_PATHS.get(item["icon"], _P_FILE_SHIELD),
                        "%23b8794f",  # URL-escaped var(--accent-2)-ish terracotta; CSS vars aren't valid inside a data: URI, so this is a fixed hex fallback matched to the Fable accent
                    )
                    st.markdown(
                        f'<style>div[class*="st-key-{chip_key}"] '
                        f'button::before{{background-image:url(\'{icon_uri}\')}}</style>',
                        unsafe_allow_html=True,
                    )
                    # Streamlit's st.button label supports basic Markdown
                    # (bold, line breaks via two trailing spaces + \n) since
                    # 1.36 — used here for the title/subtitle two-line card
                    # text instead of a second markdown call, keeping this a
                    # single real click target with zero extra DOM nodes.
                    label = f"**{item['q']}**  \n{item['hint']}"
                    if st.button(label, key=chip_key, use_container_width=True):
                        st.session_state["dotred_pending_input"] = item["q"]
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
                # NOTE: st.form_submit_button's label is plain text/Markdown
                # only — a raw <svg> string embedded in the label would NOT
                # render as an icon (same restriction as st.button above), it
                # would show as literal escaped text. Icons for these two
                # buttons are drawn via CSS ::before instead (see index.css),
                # keeping the label pure text.
                submitted = st.form_submit_button(
                    "ส่ง", key="dotred_send_btn",
                    use_container_width=True, disabled=bool(pending_question),
                )
            with clear_col:
                cleared = st.form_submit_button(
                    "ล้าง", key="dotred_clear_btn",
                    use_container_width=True, disabled=bool(pending_question),
                )

        # Footer tip bar (mockup match) — static hint, no live logic; only
        # shown once a conversation exists, mirroring the mockup's placement
        # directly under the input row rather than as permanent chrome that
        # would compete with the empty-state's own onboarding hint.
        st.markdown(
            f'<div class="dotred-tip-bar">{_i(_P_LIGHTBULB, 16)}'
            f'<span><strong>Tips:</strong> ความเป็นประโยชน์ที่ดี ๆ จะได้คำตอบที่ตรงประเด็นมากขึ้น</span>'
            f'</div>',
            unsafe_allow_html=True,
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
