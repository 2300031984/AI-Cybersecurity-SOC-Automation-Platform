import streamlit as st
from dashboard.components.ui import inject_custom_css, render_banner
from dashboard.components.auth import check_authentication, clear_session, api_post

# Page configuration
st.set_page_config(page_title="AI SOC Copilot", page_icon="🤖", layout="wide")
inject_custom_css()

# Authentication Guard
if not check_authentication():
    st.stop()

# Sidebar Controls
st.sidebar.markdown("### 🛡️ SOC CONTROL CENTER")
st.sidebar.markdown(f"User: **{st.session_state.username}**")
st.sidebar.markdown(f"Role: `{st.session_state.user_role}`")
st.sidebar.markdown(f"Organization: **{st.session_state.org_name}**")

if st.sidebar.button("Log Out", key="logout_copilot_page", use_container_width=True):
    clear_session()
    st.rerun()

render_banner(
    "AI Security Copilot",
    "Interact with your tenant's database using natural language (SQL RAG Translation)"
)

# Initialize chat history
if "chat_history" not in st.session_state:
    st.session_state["chat_history"] = []

# Clear Chat button
if st.button("Clear Thread Memory"):
    st.session_state["chat_history"] = []
    st.rerun()

# Display chat messages
for chat in st.session_state["chat_history"]:
    role = chat["role"]
    content = chat["content"]
    
    with st.chat_message(role):
        st.write(content)
        
        # Display SQL/Data logs if available in the historical object
        if role == "assistant" and "sql" in chat:
            with st.expander("🔍 SQL Compilation Log"):
                st.code(chat["sql"], language="sql")
            if "data" in chat and chat["data"]:
                with st.expander("📋 Query Context Dataset"):
                    st.dataframe(chat["data"], use_container_width=True)

# User query input
user_inquiry = st.chat_input("Ask a security question (e.g. 'Show critical vulnerabilities affecting Microsoft' or 'Any active KEV entries?')")

if user_inquiry:
    # Append user question
    st.session_state["chat_history"].append({"role": "user", "content": user_inquiry})
    with st.chat_message("user"):
        st.write(user_inquiry)
        
    # Get conversational context
    history_payload = []
    for h in st.session_state["chat_history"][:-1]:
        history_payload.append({"role": h["role"], "content": h["content"]})
        
    with st.chat_message("assistant"):
        with st.spinner("AI Security Copilot compiling query..."):
            response = api_post(
                "/chat",
                json_data={"message": user_inquiry, "history": history_payload}
            )
            
        if response:
            answer = response.get("answer", "No reply received.")
            sql = response.get("source_query")
            data = response.get("source_data")
            
            st.write(answer)
            
            # Show compilation expanders
            if sql:
                with st.expander("🔍 SQL Compilation Log"):
                    st.code(sql, language="sql")
            if data:
                with st.expander("📋 Query Context Dataset"):
                    st.dataframe(data, use_container_width=True)
                    
            # Save history with metadata
            st.session_state["chat_history"].append({
                "role": "assistant",
                "content": answer,
                "sql": sql,
                "data": data
            })
        else:
            st.error("Failed to query AI Copilot service.")
