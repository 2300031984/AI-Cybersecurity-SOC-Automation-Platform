import os
import requests
import streamlit as st

# Resolve backend URL dynamically from environment (defaulting to http://localhost:8000/api/v1)
BASE_URL = os.getenv("BACKEND_URL", "http://localhost:8000/api/v1")

def get_auth_headers() -> dict:
    """
    Builds authorization headers if access token exists in session state.
    """
    token = st.session_state.get("access_token")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}

def get_data(endpoint: str, params: dict = None):
    """
    Perform authenticated GET request to backend.
    """
    # Clean URL concatenation
    endpoint_path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    url = f"{BASE_URL}{endpoint_path}"
    
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        url = endpoint

    headers = get_auth_headers()
    response = requests.get(url, headers=headers, params=params, timeout=15)
    response.raise_for_status()
    return response.json()

def post_data(endpoint: str, json_data: dict = None):
    """
    Perform authenticated POST request to backend.
    """
    endpoint_path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    url = f"{BASE_URL}{endpoint_path}"
    
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        url = endpoint

    headers = get_auth_headers()
    response = requests.post(url, headers=headers, json=json_data, timeout=30)
    response.raise_for_status()
    return response.json()
