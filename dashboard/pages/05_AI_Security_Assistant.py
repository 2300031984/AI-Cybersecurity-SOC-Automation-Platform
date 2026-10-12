import streamlit as st
from dashboard.components.ui import (
    inject_custom_css,
    render_top_navbar,
    render_page_header
)
from dashboard.components.auth import check_authentication, api_post

# Page configuration
st.set_page_config(
    page_title="AI Security Assistant | ThreatScope",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="collapsed"
)
inject_custom_css()

# Authentication Guard
if not check_authentication():
    st.stop()

# Top Navigation Bar & Context Bar
render_top_navbar(
    title="AI Security Assistant",
    breadcrumb="AI Assistant"
)

# Page Header
render_page_header(
    title="AI Security Assistant & Telemetry Copilot",
    description="Query tenant telemetry, synthesize threat posture, and investigate CVE data using grounded natural language translation."
)

# Prompt shortcuts card
st.markdown('<div class="soc-card" style="margin-bottom: 1rem;">', unsafe_allow_html=True)
st.markdown(
    """
    <div class="soc-card-header">
        <div>
            <h3 class="soc-card-title">Analyst Prompt Shortcuts</h3>
            <p class="soc-card-subtitle">Click any inquiry chip below to immediately populate the security investigation workspace</p>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

prompt_cols = st.columns(5)
preset_clicked = None
with prompt_cols[0]:
    if st.button("Explain a CVE in simple terms", key="p_1", use_container_width=True):
        preset_clicked = "Explain CVE-2021-44228 in simple terms including potential impact and affected components."
with prompt_cols[1]:
    if st.button("Why is this vulnerability high priority?", key="p_2", use_container_width=True):
        preset_clicked = "Why is CVE-2023-23397 considered high priority in our tracked registry?"
with prompt_cols[2]:
    if st.button("Which vulnerabilities appear in CISA KEV?", key="p_3", use_container_width=True):
        preset_clicked = "Which tracked vulnerabilities in our organization are actively catalogued in CISA KEV?"
with prompt_cols[3]:
    if st.button("Summarize remediation guidance", key="p_4", use_container_width=True):
        preset_clicked = "Summarize the available containment and patching guidance for critical vulnerabilities."
with prompt_cols[4]:
    if st.button("Compare CVSS and EPSS values", key="p_5", use_container_width=True):
        preset_clicked = "Compare the CVSS base scores and EPSS probability metrics across our catalogued exposures."

st.markdown('</div>', unsafe_allow_html=True)

# Initialize Chat Memory
if "assistant_chat_history" not in st.session_state:
    st.session_state["assistant_chat_history"] = []

# Action toolbar
t_col1, t_col2 = st.columns([4, 1])
with t_col2:
    if st.button("Clear Conversation History", use_container_width=True):
        st.session_state["assistant_chat_history"] = []
        st.rerun()

# Display Thread History
for chat in st.session_state["assistant_chat_history"]:
    role = chat["role"]
    content = chat["content"]
    
    with st.chat_message(role):
        st.write(content)
        
        if role == "assistant":
            sql = chat.get("sql")
            data = chat.get("data")
            if sql:
                with st.expander("🔍 Grounded Relational SQL Query"):
                    st.code(sql, language="sql")
            if data:
                with st.expander("📋 Verified Telemetry Records"):
                    st.dataframe(data, use_container_width=True)

# Chat Input Handler
user_input = st.chat_input("Ask a security or vulnerability query (e.g. 'Show critical exposures with EPSS > 0.8')")

active_query = preset_clicked if preset_clicked else user_input

if active_query:
    st.session_state["assistant_chat_history"].append({"role": "user", "content": active_query})
    with st.chat_message("user"):
        st.write(active_query)

    history_payload = []
    for h in st.session_state["assistant_chat_history"][:-1]:
        history_payload.append({"role": h["role"], "content": h["content"]})

    with st.chat_message("assistant"):
        with st.spinner("ThreatScope Assistant synthesizing grounded database response..."):
            response = api_post(
                "/chat",
                json_data={"message": active_query, "history": history_payload}
            )

        if response:
            answer = response.get("answer", "No reply received from AI service.")
            sql = response.get("source_query")
            data = response.get("source_data")

            st.markdown(
                """
                <div class="soc-callout soc-callout-info" style="margin-bottom: 8px;">
                    <b>🤖 AI Analyst Assessment:</b> Grounded against organization relational telemetry via Gemini RAG pipeline
                </div>
                """,
                unsafe_allow_html=True
            )
            st.write(answer)

            if sql:
                with st.expander("🔍 Grounded Relational SQL Query"):
                    st.code(sql, language="sql")
            if data:
                with st.expander("📋 Verified Telemetry Records"):
                    st.dataframe(data, use_container_width=True)

            st.session_state["assistant_chat_history"].append({
                "role": "assistant",
                "content": answer,
                "sql": sql,
                "data": data
            })
        else:
            st.error("Failed to communicate with AI Assistant service. Ensure Gemini API key or backend service is active.")
