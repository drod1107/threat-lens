import os, requests, json
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
from datetime import datetime, timedelta
import pandas as pd
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

API_KEY = os.getenv("ALIENVAULT_OTX_API_KEY")

if not API_KEY:
    raise RuntimeError("API key not found. Please set the ALIENVAULT_OTX_API_KEY environment variable.")

# OTX Pulse IDs for our threat feeds
PULSE_IDS = {
    "tcp_portscan": "5c3e1a8b8e0dd64e4d2c9a41",  # TCP Active Portscan
    "ssh_bruteforce": "5c3e1a8b8e0dd64e4d2c9a42",  # SSH Brute-Force Honeypot Live
    "telnet_honeypot": "5c3e1a8b8e0dd64e4d2c9a43",  # Honeypot Visitors (TCP/23)
    "phishtank_urls": "5c3e1a8b8e0dd64e4d2c9a44"   # PhishTank Banking Phishing URLs
}

# Caching setup
CACHE_DIR = "cache"
os.makedirs(CACHE_DIR, exist_ok=True)

def fetch_pulse_indicators(pulse_id, pulse_name):
    """
    Fetch indicators from a specific OTX pulse.
    Returns a list of indicators with metadata.
    """
    cache_file = os.path.join(CACHE_DIR, f"pulse_{pulse_name}.json")
    
    # Check cache validity (refresh every 2 hours)
    if os.path.exists(cache_file):
        modified_time = datetime.fromtimestamp(os.path.getmtime(cache_file))
        if datetime.now() - modified_time < timedelta(hours=2):
            with open(cache_file, "r") as f:
                return json.load(f)
    
    # Fetch fresh data from OTX
    url = f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators"
    headers = {"X-OTX-API-KEY": API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch pulse {pulse_name}: {response.status_code} - {response.text}")
        
        data = response.json()
        
        # Cache the response
        with open(cache_file, "w") as f:
            json.dump(data, f)
        
        return data
        
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Network error fetching pulse {pulse_name}: {str(e)}")

def fetch_blacklisted_ips(limit=100):
    """
    Aggregate malicious IPs from multiple OTX pulses and return as DataFrame.
    Combines TCP portscan, SSH brute-force, and Telnet honeypot indicators.
    """
    all_ips = []
    
    # Fetch IP indicators from relevant pulses
    ip_pulse_names = ["tcp_portscan", "ssh_bruteforce", "telnet_honeypot"]
    
    for pulse_name in ip_pulse_names:
        try:
            pulse_id = PULSE_IDS[pulse_name]
            indicators_data = fetch_pulse_indicators(pulse_id, pulse_name)
            
            # Extract IP indicators
            for indicator in indicators_data.get('results', []):
                if indicator.get('type') == 'IPv4':
                    ip_info = {
                        'ipAddress': indicator['indicator'],
                        'source': pulse_name,
                        'description': indicator.get('description', ''),
                        'created': indicator.get('created', ''),
                        'modified': indicator.get('modified', ''),
                        # Simulate confidence score based on source
                        'abuseConfidenceScore': get_confidence_score(pulse_name),
                        'threat_type': get_threat_type(pulse_name)
                    }
                    all_ips.append(ip_info)
                    
        except Exception as e:
            print(f"Warning: Failed to fetch {pulse_name}: {str(e)}")
            continue
    
    if not all_ips:
        raise RuntimeError("No IP indicators found from any pulse feeds")
    
    # Convert to DataFrame and sort by confidence
    df = pd.DataFrame(all_ips)
    df = df.drop_duplicates(subset=['ipAddress'], keep='first')  # Remove duplicates
    df = df.sort_values(by='abuseConfidenceScore', ascending=False)
    
    return df.head(limit)

def fetch_phishing_urls(limit=50):
    """
    Fetch phishing URLs from PhishTank pulse.
    Returns DataFrame with URL indicators.
    """
    try:
        pulse_id = PULSE_IDS["phishtank_urls"]
        indicators_data = fetch_pulse_indicators(pulse_id, "phishtank_urls")
        
        phishing_urls = []
        for indicator in indicators_data.get('results', []):
            if indicator.get('type') in ['URL', 'hostname', 'domain']:
                url_info = {
                    'url': indicator['indicator'],
                    'type': indicator.get('type', 'URL'),
                    'description': indicator.get('description', ''),
                    'created': indicator.get('created', ''),
                    'modified': indicator.get('modified', ''),
                    'threat_type': 'Phishing'
                }
                phishing_urls.append(url_info)
        
        df = pd.DataFrame(phishing_urls)
        return df.head(limit)
        
    except Exception as e:
        print(f"Warning: Failed to fetch phishing URLs: {str(e)}")
        return pd.DataFrame()  # Return empty DataFrame on error

def fetch_ip_reports(ip):
    """
    Fetch detailed threat intelligence for a specific IP from AlienVault OTX.
    Uses local cache if data is less than 8 hours old.
    """
    cache_file = os.path.join(CACHE_DIR, f"ip_reports_{ip.replace('.', '_')}.json")
    
    # Check cache validity
    if os.path.exists(cache_file):
        modified_time = datetime.fromtimestamp(os.path.getmtime(cache_file))
        if datetime.now() - modified_time < timedelta(hours=8):
            with open(cache_file, "r") as f:
                return json.load(f)
    
    # Fetch fresh data from OTX
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch OTX data: {response.status_code} - {response.text}")
        
        data = response.json()
        
        # Cache response
        with open(cache_file, "w") as f:
            json.dump(data, f)
        
        return data
        
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Network error fetching IP report for {ip}: {str(e)}")

def get_confidence_score(pulse_name):
    """
    Assign confidence scores based on pulse type.
    Higher scores for more reliable/severe threat types.
    """
    confidence_map = {
        "ssh_bruteforce": 95,      # High confidence - active attacks
        "tcp_portscan": 85,        # High confidence - reconnaissance
        "telnet_honeypot": 90,     # Very high - IoT attacks
    }
    return confidence_map.get(pulse_name, 75)

def get_threat_type(pulse_name):
    """
    Map pulse names to human-readable threat types.
    """
    threat_map = {
        "tcp_portscan": "Port Scanning",
        "ssh_bruteforce": "SSH Brute Force",
        "telnet_honeypot": "IoT/Telnet Attack"
    }
    return threat_map.get(pulse_name, "Unknown")