# scripts/threat_map.py

import pandas as pd
import pycountry
import plotly.express as px
from scripts.fetch_abuse_data import fetch_blacklisted_ips
from scripts.otx_api import fetch_ip_reports
import streamlit as st

@st.cache_data(ttl=3600)
def build_global_threat_map():
    df = fetch_blacklisted_ips(limit=500)

    def enrich_ip(ip):
        print(f"Enriching IP: {ip}")
        try:
            report = fetch_ip_reports(ip)
            return report.get("country_name", "Unknown")
        except Exception as e:
            print(f"Error fetching {ip}: {e}")
            return "Unknown"

    df["country"] = df["ipAddress"].apply(enrich_ip)

    def to_iso3(name):
        try:
            return pycountry.countries.lookup(name).alpha_3
        except:
            return None

    df["iso_alpha"] = df["country"].apply(to_iso3)
    df = df.dropna(subset=["iso_alpha"])

    if df.empty:
        raise ValueError("No IPs had valid country codes. Map cannot be built.")

    country_counts = df.groupby(["country", "iso_alpha"]).size().reset_index(name="count")

    fig = px.choropleth(
        country_counts,
        locations="iso_alpha",
        color="count",
        hover_name="country",
        color_continuous_scale="Reds",
        title="Threat Indicators per Country - Top 500 aggregated threats"
    )
    return fig
