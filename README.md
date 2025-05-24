# ThreatLens Dashboard

### _Unified threat monitoring and analysis dashboard for cybersecurity signal detection_

## Executive Summary

ThreatLens Dashboard is a professional-grade cybersecurity data visualization tool that merges real-time threat intelligence, web-scraped disclosures, and static data logs into a single, interactive dashboard. The project demonstrates hands-on experience in cybersecurity operations, data engineering, and visualization by simulating realistic analyst workflows and SOC-level insights.

## Project Objective

The ThreatLens Dashboard was created to demonstrate practical, cross-disciplinary fluency in cybersecurity operations, data ingestion, and transformation, and real-time data visualization. The primary goals of this project are:

- To showcase end-to-end technical capability in parsing and integrating heterogenous data sources, including APIs, web scrapers, and static data sets.
- To simluate real-world security analyst worflows by processing and analyzing threat indicators, logs, and breach disclosures
- To provide an interactive, analyst-facing dashboard capable of delivering both the immediate threat overviews and investigative insight

## Tech Stack

### Data Ingestion

- ```requests``` - for RESTful API calls
- ```BeautifulSoup``` - for structured HTML scraping
- ```pandas``` - for data normalization and transformation
- ```json``` - for structured data parsing and serialization

### Backend/Processing

- ```Python 3``` - core scripting language
- ```os/dotenv``` - environment management for API keys and secrets

### Visualization/Dashboard

- ```Streamlit``` - lightweight web app framework for Python
- ```matplotlib``` - for interactive and static data visualizations

### Deployment (Planned)

- Github Pages or custom domain deployment using CI/CD workflows
- Docker (Planned for future containerization and maximum reproducability)


## Current Capabilities (MVP Scope)

- Integrations with a public threat intelligence API (e.g., AlienVault OTX or AbuselPDB) for live IOC (Indicators of Compromise) retrieval
- Web Scarping of recent breach headlines from cybersecurity news sources
- Ingestion and parsing of static datasets representing system logs or threat reports.
- Normalization and unification of data from multiple formats into a common schema.
- Interactive dashboard prototype (Streamlit) displaying indicator data in tabular format.
- Clean, modular codebase prepared for scaling across multiple data sources.
- GitHub Project board configured to manage agile development in public.

## Planned Extensions

-Incorporation of geolocation enrichment for IP-based IOCs (via IPinfo or IP-API).
-Visual geospatial mapping of IP threats on a global coordinate grid.
-Anomaly detection logic applied to time-series log data (e.g., failed login spikes).
-Filter and search functionality for IOC tables by type, severity, or source.
-Scheduled API pulls and auto-refresh logic for near real-time visibility.
-Static report export options (PDF or CSV) for SOC or compliance documentation.
-Docker containerization for consistent deployment across environments.
-CI/CD pipeline configuration for automated deployment and testing.

## File and Directory Structure

threatlens-dashboard/
│
├── app/                  # Streamlit or Flask app files (UI logic, main launch)
├── data/                 # Static datasets and local cache of API responses
├── scripts/              # Web scraper, API client, data normalization routines
├── utils/                # Helper functions, schema definitions, config loaders
├── .env.example          # Environment variable template for API keys
├── requirements.txt      # Python package dependencies
├── README.md             # Project documentation
└── LICENSE               # Licensing information (if applicable)

## Usage Instructions

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- Git (for cloning the repository)

### Environment Setup

1. Clone the repository

    ```bash
    git clone git@github.com:yourusername/threatlens-dashboard.git
    cd threatlens-dashboard
    ```

2. Create a virtual environment and activate it. This helps to avoid conflicts between python versions and package management

    **On macOS/Linux:**

    ```bash
    python -m venv venv 
    source venv/bin/activate
    ```

    **On Windows:**

    ```bash
    venv\Scripts\activate
    ```

3. Install Dependencies

    ```bash
    pip install -r requirements.txt
    ```

4. Setup API keys

    - Copy .env.example to .env
    - Fill in required API tokens and credentials

### Running the Dashboard

```bash
streamlit run app/main.py
```

## Deployment

(planned for future development)

## Author and Contact

**Developer:** David Rodriguez

**GitHub:** [drod1107](https://github.com/drod1107)

**Email:** [Click here](mailto:80010850+drod1107@users.noreply.github.com)

**Professional Focus:** Applied cybersecurity, data analysis, Big Data Ops, systems automation, applied AI, software engineering, quality assurance, automated testing
