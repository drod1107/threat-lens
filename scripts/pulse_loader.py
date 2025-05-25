import pandas as pd

def load_pulse_list(csv_path):
    """
    Load the pulse list from a CSV file.
    """
    df = pd.read_csv(csv_path)
    pulse_dicts = []
    for _, row in df.iterrows():
        url = row["Pulse URL"].strip()
        
        try:
            pulse_id = url.rstrip('/').split("/pulse/")[-1]
        except Exception as e:
            print(f"Warning: Failed to extract pulse ID from URL '{url}' (row {row.to_dict()}): {e}")
            pulse_id = None
            
        pulse_dicts.append({
            "category": row["Category"].strip(),
            "name": row["Pulse Name"].strip(),
            "url": url,
            "id": pulse_id
        })
        
    return pulse_dicts
