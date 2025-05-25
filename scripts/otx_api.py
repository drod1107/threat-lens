import os
import json
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

API_KEY = os.getenv("ALIENVAULT_OTX_API_KEY")

if not API_KEY:
    raise RuntimeError("API key not found. Please set the ALIENVAULT_OTX_API_KEY environment variable.")

CACHE_DIR = "cache"
os.makedirs(CACHE_DIR, exist_ok=True)

def fetch_pulse_indicators(pulse_id, pulse_name):
    """
    Fetch indicators from a specific OTX pulse.
    Returns a list of indicators with metadata.
    """
    # replace any path-separators in pulse_name with underscores
    safe_name  = pulse_name.replace("/", "_")
    cache_file = os.path.join(CACHE_DIR, f"pulse_{safe_name}.json")
    
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
