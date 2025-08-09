import requests
import json

# Threat intelligence API URL (I have cho
THREAT_INTELLIGENCE_API_URL = 'https://www.virustotal.com/api/v3/ip_addresses'

# Your VirusTotal API Key (replace with your actual API key)
API_KEY = 'your-api-key-here'

def get_threat_data(ip_address):
    """Fetch threat intelligence data for a given IP address from VirusTotal."""
    headers = {
        'x-apikey': API_KEY  # Replace with your actual API key
    }
    url = f'{THREAT_INTELLIGENCE_API_URL}/{ip_address}'
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching threat data for IP: {ip_address}")
        return None

def enrich_logs(cloudtrail_log):
    """Enrich CloudTrail log entries with threat data."""
    enriched_logs = []
    for log_entry in cloudtrail_log:
        ip_address = log_entry.get('sourceIPAddress', '')
        if ip_address:
            # Fetch threat data for the IP address
            threat_data = get_threat_data(ip_address)
            if threat_data:
                log_entry['threat_data'] = threat_data
            enriched_logs.append(log_entry)
    
    return enriched_logs

# Example CloudTrail log entries (replace with actual CloudTrail logs)
cloudtrail_logs = [
    {"eventName": "ConsoleLogin", "sourceIPAddress": "192.168.1.1", "userName": "admin"},
    {"eventName": "CreateBucket", "sourceIPAddress": "203.0.113.45", "userName": "user123"}
]

# Enrich CloudTrail logs
enriched_logs = enrich_logs(cloudtrail_logs)

# Save enriched logs to a file
with open('enriched_cloudtrail_logs.json', 'w') as file:
    json.dump(enriched_logs, file, indent=4)

print("CloudTrail logs enriched and saved.")
