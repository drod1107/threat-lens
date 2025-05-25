from scripts.pulse_loader import load_pulse_list
from scripts.otx_api    import fetch_pulse_indicators
from dotenv             import load_dotenv
import os

load_dotenv()  # ensure API key is loaded

pulses = load_pulse_list("data/pulse_list.csv")

for p in pulses:
    name = p["name"]
    if "phishtank" not in name.lower():
        continue

    # Derive the pulse ID from the URL to ensure it's up-to-date
    pulse_id = p["url"].rstrip("/").split("/pulse/")[-1]
    print(f"\nTesting '{name}' with ID {pulse_id}")

    try:
        data = fetch_pulse_indicators(pulse_id, name)
        count = len(data.get("results", []))
        print(f"→ Success: {count} indicators fetched")
    except Exception as e:
        print(f"→ Error: {e}")
