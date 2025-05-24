import os, requests
import pandas as pd
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not API_KEY:
    raise RuntimeError("API key not found. Please set the ABUSEIPDB_API_KEY environment variable.")

# funtion to fetch blacklisted IPs from AbuseIPDB
def fetch_blacklisted_ips(limit=100):
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    
    params = {
        "limit": limit,
        "confidenceMinimum": 90,
    }
    
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code != 200:
        raise RuntimeError(f"Failed to fetch data: {response.status_code} - {response.text}")
    
    data = response.json()
    
    df = pd.DataFrame(data['data'])
    df.sort_values(by='abuseConfidenceScore', ascending=False, inplace=True)
    
    return df
