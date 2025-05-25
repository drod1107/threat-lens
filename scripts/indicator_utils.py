"""
Helper functions for indicator scoring, threat mapping, and normalization.
"""

def get_confidence_score(pulse_name):
    name = pulse_name.lower()
    if "ssh" in name:
        return 95
    if "portscan" in name:
        return 85
    if "honeypot" in name or "potnet" in name:
        return 90
    if "phishtank" in name:
        return 80  # or whatever makes sense
    return 75



def get_threat_type(pulse_name):
    """
    Map pulse names to human-readable threat types.
    """
    name = pulse_name.lower()
    # SSH feeds
    if "ssh" in name:
        return "SSH Brute Force"
    # Telnet or IoT honeypots
    if "honeypot" in name or "potnet" in name:
        return "IoT/Telnet Attack"
    # Portscan feeds
    if "portscan" in name:
        return "Port Scanning"
    # PhishTank URLs
    if "phishtank" in name:
        return "Phishing"
    # Fallback
    return "Unknown"
