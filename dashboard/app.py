import streamlit as st
from dashboard.components.ui import inject_custom_css
from dashboard.components.auth import check_authentication

# Set Global ThreatScope SOC Configuration
st.set_page_config(
    page_title="ThreatScope | Cybersecurity Intelligence & Risk Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

inject_custom_css()

# Session State checking and route dispatch
if check_authentication():
    st.switch_page("pages/01_Overview.py")
