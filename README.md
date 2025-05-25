# ThreatMap

## _Interactive cyber threat intelligence dashboard with global IOC heatmapping and IP-level drilldowns_

### Executive Summary

**ThreatMap** is a modern threat intelligence dashboard built with real-time data from public threat feeds. It provides instant visibility into global Indicators of Compromise (IOCs), featuring interactive geospatial heatmaps, detailed IP-level reports, and summarized metrics. The project showcases practical skills in cybersecurity operations, data ingestion, enrichment, and live visualization.

> Live demo: [https://threatmap.streamlit.app](https://threatmap.streamlit.app)

### Project Goals

- Integrate and normalize threat indicators from public threat intelligence APIs.
- Enrich malicious IP addresses with metadata like country and ASN.
- Visualize the global threat landscape with interactive maps and tabular summaries.
- Demonstrate SOC-style investigation capabilities with real-time drilldowns.
- Design for modularity, caching, and future real-time scaling.

## Live Features

### ✔ IOC Data Aggregation

- Fetches IPv4 threat indicators from AlienVault OTX pulses
- Supports dynamic addition of new threat feeds via CSV

### ✔ Streamlit Dashboard

- Malicious IP table with clickable drilldowns
- Phishing URL table with category badges
- Summary metrics (confidence, source diversity, total IOCs)

### ✔ Global Threat Heatmap

- Choropleth world map based on country-level IOC frequency
- ISO3 conversion via `pycountry`
- Fully cached with per-IP enrichment (via AlienVault API)

### ✔ Drilldown Reports

- Country, reputation, ASN, malware families, pulse tags
- Live data fetched from OTX on demand
- Caching to JSON per-IP to avoid rate limiting

## Tech Stack

| Layer              | Toolset                                                                 |
|-------------------|-------------------------------------------------------------------------|
| Language           | Python 3                                                                |
| Data Ingestion     | `requests`, `dotenv`, `json`                                            |
| Enrichment         | AlienVault OTX API, `fetch_ip_reports()`                                |
| Visualization      | `Streamlit`, `Plotly Express`, `pandas`                                 |
| Mapping            | `pycountry` for ISO3 mapping, Plotly choropleth                         |
| Caching            | `streamlit.cache_data`, local disk cache for IP and pulse fetches       |

## File Structure

```bash

threatmap/
├── main.py                 # Streamlit entry point
├── requirements.txt        # Dependencies
├── .env.example            # API key config template
├── data/
│   └── pulse_list.csv      # Source list of OTX pulses
├── cache/                  # JSON cache of IP and pulse reports
├── scripts/
│   ├── fetch_abuse_data.py    # Core data ingestion logic
│   ├── otx_api.py             # OTX-specific API handling and caching
│   ├── pulse_loader.py        # Pulse feed CSV loader
│   ├── indicator_utils.py     # Threat type + confidence mapping
│   └── threat_map.py          # Global choropleth map builder

```

### Roadmap (Next Priorities)

- IP geolocation and global threat map (DONE)
- Date filtering & time-window slider for map and tables
- Search, filter, and tag-based IOC triage
- Threat clustering (group by malware family, country, pulse)
- Export to CSV or SOC incident report template
- Dockerize app for reproducible container deployment
- CI/CD with GitHub Actions to auto-deploy on commit

## Getting Started

### Prerequisites

- Python 3.9+
- Streamlit installed (`pip install -r requirements.txt`)
- Valid API key for [OTX](https://otx.alienvault.com)

### Run Locally

```bash
git clone https://github.com/yourusername/threatmap.git
cd threatmap
cp .env.example .env  # Add your ALIENVAULT_OTX_API_KEY
pip install -r requirements.txt
streamlit run main.py
```

---

### License

MIT License (customize if needed)

### Author

#### David Rodriguez

- GitHub: [@drod1107](https://github.com/drod1107)
- Live app: [https://threatmap.streamlit.app](https://threatmap.streamlit.app)
- Email: [click here to get in touch](mailto:80010850+drod1107@users.noreply.github.com)

---
