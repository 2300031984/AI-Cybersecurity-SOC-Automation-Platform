import streamlit as st
from dashboard.components.ui import inject_custom_css

# Set Page Configuration
st.set_page_config(
    page_title="AI Cybersecurity Threat Monitor & SOC Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

inject_custom_css()

# Session State checking
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    st.switch_page("pages/01_Login.py")
else:
    st.switch_page("pages/02_SOC_Overview.py")
