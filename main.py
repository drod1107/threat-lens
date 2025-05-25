import streamlit as st
import pandas as pd
from scripts.fetch_abuse_data import fetch_blacklisted_ips, fetch_phishing_urls
from scripts.fetch_abuse_data import fetch_all_pulse_indicators  # optional: full list
from scripts.otx_api           import fetch_ip_reports              # for drilldowns

def make_clickable_ip(ip):
    """
    Generate a clickable link for the given IP address.
    """
    return f'<a href="?ip={ip}" style="color: #ff4b4b; text-decoration: none;">{ip}</a>'

def make_clickable_url(url):
    """
    Generate a clickable link for URLs (opens in new tab for safety).
    """
    # Truncate long URLs for display
    display_url = url if len(url) <= 50 else url[:47] + "..."
    return f'<a href="{url}" target="_blank" style="color: #ff6b35; text-decoration: none;" title="{url}">{display_url}</a>'

# Get query parameters
query_params = st.query_params
selected_ip = query_params.get("ip")

st.set_page_config(
    page_title="ThreatLens IOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS for better table styling
st.markdown("""
<style>
table {
    width: 100%;
    border-collapse: collapse;
    font-family: 'Source Sans Pro', sans-serif;
    font-size: 14px;
}
table th, table td {
    padding: 8px 12px;
    text-align: left;
    border-bottom: 1px solid #e6e9ef;
}
table th {
    background-color: #f0f2f6;
    font-weight: 600;
    color: #262730;
}
table tr:hover {
    background-color: purple;
    color: white;
}
.threat-badge {
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
}
.ssh-badge { background-color: #ffebee; color: #c62828; }
.scan-badge { background-color: #fff3e0; color: #ef6c00; }
.iot-badge { background-color: #f3e5f5; color: #7b1fa2; }
.phish-badge { background-color: #e8f5e8; color: #2e7d32; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ ThreatLens IOC Dashboard")
st.caption("Real-time threat intelligence from AlienVault OTX feeds")

@st.cache_data(ttl=7200)  # Cache for 2 hours
def cached_blacklist():
    """
    Fetches malicious IP addresses from multiple OTX pulses and caches the result.
    """
    return fetch_blacklisted_ips(limit=10)

@st.cache_data(ttl=7200)  # Cache for 2 hours
def cached_phishing_urls():
    """
    Fetches phishing URLs from OTX PhishTank pulse and caches the result.
    """
    return fetch_phishing_urls(limit=10)

# Handle IP drilldown if selected
if selected_ip:
    st.markdown(f"## 🔍 Detailed Report for {selected_ip}")
    
    col1, col2 = st.columns([1, 4])
    with col1:
        if st.button("← Back to Main Dashboard"):
            st.query_params.clear()
            st.rerun()
    
    try:
        with st.spinner("Fetching detailed threat intelligence..."):
            report_data = fetch_ip_reports(selected_ip)
        
        # Display general information
        if report_data:
            st.subheader("General Information")
            
            # Create metrics row
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Reputation", report_data.get('reputation', 'Unknown'))
            with col2:
                st.metric("Country", report_data.get('country_name', 'Unknown'))
            with col3:
                st.metric("ASN", report_data.get('asn', 'Unknown'))
            with col4:
                pulse_count = len(report_data.get('pulse_info', {}).get('pulses', []))
                st.metric("Associated Pulses", pulse_count)
            
            # Display pulse information if available
            pulse_info = report_data.get('pulse_info', {})
            if pulse_info.get('pulses'):
                st.subheader("Associated Threat Pulses")
                pulse_data = []
                for pulse in pulse_info['pulses'][:10]:  # Show top 10 pulses
                    pulse_data.append({
                        'Pulse Name': pulse.get('name', 'Unknown'),
                        'Created': pulse.get('created', 'Unknown'),
                        'Tags': ', '.join(pulse.get('tags', [])),
                        'References': len(pulse.get('references', []))
                    })
                
                if pulse_data:
                    pulse_df = pd.DataFrame(pulse_data)
                    st.dataframe(pulse_df, use_container_width=True)
            
            # Display malware families if available
            malware = report_data.get('malware', {})
            if malware.get('data'):
                st.subheader("Associated Malware")
                malware_data = []
                for mal in malware['data'][:5]:  # Show top 5
                    malware_data.append({
                        'Family': mal.get('detections', {}).get('avast', 'Unknown'),
                        'Hash': mal.get('hash', 'Unknown')
                    })
                
                if malware_data:
                    malware_df = pd.DataFrame(malware_data)
                    st.dataframe(malware_df, use_container_width=True)
        else:
            st.warning(f"No detailed information available for {selected_ip}")
            
    except Exception as e:
        st.error(f"Error fetching detailed report: {str(e)}")
        
    st.divider()

# Main dashboard view
col1, col2 = st.columns([3, 2])

with col1:
    st.markdown("### 🚨 Malicious IP Addresses")
    
    try:
        with st.spinner("Fetching IP threat intelligence..."):
            df_ips = cached_blacklist()
        
        if not df_ips.empty:
            # Prepare display DataFrame
            df_display = df_ips.copy()
            df_display['ipAddress'] = df_display['ipAddress'].apply(make_clickable_ip)
            
            # Add threat type badges
            def format_threat_type(threat_type):
                badge_class = {
                    'SSH Brute Force': 'ssh-badge',
                    'Port Scanning': 'scan-badge',
                    'IoT/Telnet Attack': 'iot-badge'
                }.get(threat_type, 'scan-badge')
                return f'<span class="threat-badge {badge_class}">{threat_type}</span>'
            
            df_display['threat_type'] = df_display['threat_type'].apply(format_threat_type)
            
            # Select columns for display
            display_columns = ['ipAddress', 'abuseConfidenceScore', 'threat_type', 'source']
            df_final = df_display[display_columns].rename(columns={
                'ipAddress': 'IP Address',
                'abuseConfidenceScore': 'Confidence',
                'threat_type': 'Threat Type',
                'source': 'Source Feed'
            })
            
            st.write(df_final.to_html(escape=False, index=False), unsafe_allow_html=True)
            st.caption(f"Showing {len(df_ips)} malicious IP addresses. Click any IP for detailed analysis.")
        else:
            st.warning("No malicious IP data available")
            
    except Exception as e:
        st.error(f"Error fetching IP data: {str(e)}")

with col2:
    st.markdown("### 🎣 Recent Phishing URLs")
    
    try:
        with st.spinner("Fetching phishing intelligence..."):
            df_phishing = cached_phishing_urls()
        
        if not df_phishing.empty:
            # Prepare display DataFrame
            df_phish_display = df_phishing.copy()
            df_phish_display['url'] = df_phish_display['url']
            df_phish_display['threat_type'] = df_phish_display['threat_type'].apply(
                lambda x: f'<span class="threat-badge phish-badge">{x}</span>'
            )
            
            # Select columns for display
            display_columns = ['url', 'type', 'threat_type']
            df_phish_final = df_phish_display[display_columns].rename(columns={
                'url': 'Phishing URL',
                'type': 'Type',
                'threat_type': 'Category'
            })
            
            st.write(df_phish_final.to_html(escape=False, index=False), unsafe_allow_html=True)
            st.caption(f"Showing {len(df_phishing)} recent phishing URLs from PhishTank")
        else:
            st.info("No phishing URL data available")
            
    except Exception as e:
        st.error(f"Error fetching phishing data: {str(e)}")

# Summary statistics
if not selected_ip:  # Only show on main dashboard
    st.divider()
    st.markdown("### 📊 Threat Intelligence Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    try:
        with col1:
            ip_count = len(cached_blacklist()) if 'df_ips' in locals() and not df_ips.empty else 0
            st.metric("Total Malicious IPs", ip_count)
        
        with col2:
            phish_count = len(cached_phishing_urls()) if 'df_phishing' in locals() and not df_phishing.empty else 0
            st.metric("Phishing URLs", phish_count)
        
        with col3:
            # Count high-confidence IPs (score > 90)
            high_conf = len(df_ips[df_ips['abuseConfidenceScore'] > 90]) if 'df_ips' in locals() and not df_ips.empty else 0
            st.metric("High Confidence Threats", high_conf)
        
        with col4:
            # Count unique sources
            unique_sources = df_ips['source'].nunique() if 'df_ips' in locals() and not df_ips.empty else 0
            st.metric("Active Threat Feeds", unique_sources)
            
    except Exception as e:
        st.error(f"Error calculating summary statistics: {str(e)}")

st.markdown("---")
st.markdown("**Data Sources:** AlienVault OTX • TCP Portscan Feed • SSH Brute-Force Feed • Telnet Honeypot Feed • PhishTank URLs")
st.markdown("**Refresh Rate:** Data cached for 2 hours • Click refresh browser to force update")