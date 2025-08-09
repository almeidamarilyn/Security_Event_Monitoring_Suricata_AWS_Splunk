import json

def load_logs(file_path):
    """Load log data from a JSON file."""
    with open(file_path, 'r') as file:
        return json.load(file)

def correlate_logs(cloudtrail_logs, suricata_alerts):
    """Correlate CloudTrail logs with Suricata IDS alerts."""
    correlated_data = []
    
    for cloudtrail_log in cloudtrail_logs:
        ip_address = cloudtrail_log.get('sourceIPAddress')
        if not ip_address:
            continue
        
        # Find matching Suricata alerts for the IP address
        matching_alerts = [alert for alert in suricata_alerts if alert['src_ip'] == ip_address]
        
        if matching_alerts:
            # Add Suricata alert data to the CloudTrail log
            cloudtrail_log['suricata_alerts'] = matching_alerts
            correlated_data.append(cloudtrail_log)
    
    return correlated_data

# Example Suricata IDS alerts (added more examples)
suricata_alerts = [
    {"alert": "Suspicious Activity", "src_ip": "192.168.1.1", "dst_ip": "8.8.8.8", "protocol": "TCP", "severity": "medium", "timestamp": "2022-08-10T12:34:56"},
    {"alert": "SQL Injection Attempt", "src_ip": "203.0.113.45", "dst_ip": "10.0.0.1", "protocol": "HTTP", "severity": "high", "timestamp": "2022-08-10T12:35:00"},
    {"alert": "Port Scan Detected", "src_ip": "192.168.1.5", "dst_ip": "192.168.1.100", "protocol": "TCP", "severity": "low", "timestamp": "2022-08-10T12:36:10"},
    {"alert": "Cross-Site Scripting (XSS)", "src_ip": "198.51.100.50", "dst_ip": "172.16.0.2", "protocol": "HTTP", "severity": "high", "timestamp": "2022-08-10T12:37:15"},
    {"alert": "DDoS Attack", "src_ip": "203.0.113.67", "dst_ip": "192.168.0.10", "protocol": "UDP", "severity": "critical", "timestamp": "2022-08-10T12:38:22"},
    {"alert": "Malware Beaconing", "src_ip": "10.0.0.50", "dst_ip": "185.60.48.1", "protocol": "TCP", "severity": "medium", "timestamp": "2022-08-10T12:39:00"},
    {"alert": "Command and Control Traffic", "src_ip": "10.0.0.100", "dst_ip": "45.67.89.23", "protocol": "DNS", "severity": "high", "timestamp": "2022-08-10T12:40:12"},
    {"alert": "Remote Code Execution Attempt", "src_ip": "198.51.100.80", "dst_ip": "172.16.1.5", "protocol": "TCP", "severity": "high", "timestamp": "2022-08-10T12:41:30"},
    {"alert": "Suspicious File Transfer", "src_ip": "203.0.113.90", "dst_ip": "192.168.2.50", "protocol": "FTP", "severity": "medium", "timestamp": "2022-08-10T12:42:10"},
    {"alert": "Brute Force Login Attempt", "src_ip": "203.0.113.120", "dst_ip": "192.168.2.5", "protocol": "SSH", "severity": "high", "timestamp": "2022-08-10T12:43:00"},
    {"alert": "Unauthorized File Access", "src_ip": "198.51.100.25", "dst_ip": "192.168.0.50", "protocol": "SMB", "severity": "medium", "timestamp": "2022-08-10T12:44:05"},
    {"alert": "Data Exfiltration Attempt", "src_ip": "10.1.1.50", "dst_ip": "45.67.89.100", "protocol": "HTTP", "severity": "critical", "timestamp": "2022-08-10T12:45:00"}
]

# Load enriched CloudTrail logs
cloudtrail_logs = [
    {"eventName": "ConsoleLogin", "sourceIPAddress": "192.168.1.1", "userName": "admin"},
    {"eventName": "CreateBucket", "sourceIPAddress": "203.0.113.45", "userName": "user123"},
    {"eventName": "ConsoleLogin", "sourceIPAddress": "198.51.100.50", "userName": "admin"},
    {"eventName": "StartInstances", "sourceIPAddress": "10.0.0.50", "userName": "user456"},
    {"eventName": "StopInstances", "sourceIPAddress": "203.0.113.67", "userName": "user789"}
]

# Correlate CloudTrail logs with Suricata alerts
correlated_data = correlate_logs(cloudtrail_logs, suricata_alerts)

# Save correlated data to a file
with open('correlated_security_data.json', 'w') as file:
    json.dump(correlated_data, file, indent=4)

print("Logs correlated and saved.")
