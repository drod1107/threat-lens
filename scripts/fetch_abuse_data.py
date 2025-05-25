import pandas as pd
from scripts.pulse_loader import load_pulse_list
from scripts.otx_api import fetch_pulse_indicators, fetch_ip_reports
from scripts.indicator_utils import get_confidence_score, get_threat_type

"""
The provided Python script fetches threat indicators from AlienVault OTX pulses, aggregates
malicious IPs and phishing URLs, and provides detailed threat intelligence for specific IPs.

:param pulse_id: A unique identifier for a specific threat feed in AlienVault OTX (Open Threat
Exchange). It is used to fetch indicators and threat intelligence related to that particular threat
feed
:param pulse_name: The `pulse_name` parameter in the provided code refers to the name or identifier
of a specific threat feed pulse in AlienVault OTX (Open Threat Exchange). It is used to fetch
indicators and threat intelligence data associated with that particular pulse. The `pulse_name` is
used as a key to retrieve
:return: The code provided includes functions to fetch threat intelligence data from AlienVault OTX
(Open Threat Exchange) API. Here is a summary of the main functions:
"""

# Load pulse IDs from CSV
pulse_dicts = load_pulse_list("data/pulse_list.csv")

# loop over each pulse to fetch indicators from API

def fetch_all_pulse_indicators(pulse_dicts):
    """
    Fetches indicators for every pulse in pulse_dicts.
    Returns a list of dicts: [{'pulse': ..., 'indicators': [...]}, ...]
    """
    results = []
    for pulse in pulse_dicts:
        pulse_id = pulse["id"]
        pulse_name = pulse["name"]
        indicators = fetch_pulse_indicators(pulse_id, pulse_name)
        results.append({
            "pulse": pulse,
            "indicators": indicators
        })
        print(f"Fetched {len(indicators.get('results', []) if isinstance(indicators, dict) else indicators)} indicators from pulse '{pulse_name}' (ID: {pulse_id})")
    return results
   
def fetch_blacklisted_ips(limit=100):
    """
    Aggregate malicious IPs from multiple OTX pulses and return as DataFrame.
    Combines TCP portscan, SSH brute-force, and Telnet honeypot indicators.
    """
    pulses = load_pulse_list("data/pulse_list.csv")
    all_ips = []
    
    # Fetch IP indicators from every pulse
    for pulse in pulses:
        pulse_name = pulse["name"]
        pulse_id   = pulse["id"]
        try:
            indicators_data = fetch_pulse_indicators(pulse_id, pulse_name)
            
            # Extract IP indicators
            for indicator in indicators_data.get('results', []):
                if indicator.get('type') == 'IPv4':
                    ip_info = {
                        'ipAddress':           indicator['indicator'],
                        'source':              pulse_name,
                        'description':         indicator.get('description', ''),
                        'created':             indicator.get('created', ''),
                        'modified':            indicator.get('modified', ''),
                        'abuseConfidenceScore':get_confidence_score(pulse_name),
                        'threat_type':         get_threat_type(pulse_name)
                    }
                    all_ips.append(ip_info)
                    
        except Exception as e:
            print(f"Warning: Failed to fetch {pulse_name}: {e}")
            continue
    
    if not all_ips:
        raise RuntimeError("No IP indicators found from any pulse feeds")
    
    # Convert to DataFrame and sort by confidence
    df = pd.DataFrame(all_ips)
    df = df.drop_duplicates(subset=['ipAddress'], keep='first')
    df = df.sort_values(by='abuseConfidenceScore', ascending=False)
    
    return df.head(limit)

def fetch_phishing_urls(limit=50):
    """
    Fetch phishing URLs from PhishTank pulse.
    Returns DataFrame with URL indicators.
    """
    pulses = load_pulse_list("data/pulse_list.csv")
    phishing_urls = []

    for pulse in pulses:
        name = pulse["name"]
        if "phishtank" not in name.lower():
            continue

        pulse_id = pulse["id"]
        indicators_data = fetch_pulse_indicators(pulse_id, name)

        for rec in indicators_data.get("results", []):
            if rec.get("type") in ("URL", "hostname", "domain"):
                phishing_urls.append({
                    "url":         rec["indicator"],
                    "type":        rec.get("type", "URL"),
                    "description": rec.get("description", ""),
                    "created":     rec.get("created", ""),
                    "modified":    rec.get("modified", ""),
                    "threat_type": "Phishing",
                })

    df = pd.DataFrame(phishing_urls)
    return df.head(limit)
