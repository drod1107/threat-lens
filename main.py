import streamlit as st
from scripts.fetch_abuse_data import fetch_blacklisted_ips

st.set_page_config(
    page_title="ThreatLens IOC Dashboard",
    page_icon=":guardsman:",
    layout="wide"
)

st.title("ThreatLens IOC Dashboard")
st.caption("High-confidence malicious IP addresses sourced live from AbuseIPDB")

with st.spinner("Fetching threat intel..."):
    df = fetch_blacklisted_ips(limit=100)
    
st.success("Threat intel fetched successfully!")

st.dataframe(
    df,
    use_container_width=True
)