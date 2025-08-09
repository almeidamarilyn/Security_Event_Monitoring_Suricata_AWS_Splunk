import json

def parse_cloudtrail_logs(file_path):
    """Parse CloudTrail logs and extract relevant data."""
    with open(file_path, 'r') as file:
        logs = json.load(file)
    
    parsed_logs = []
    
    for log in logs:
        parsed_entry = {
            'event_name': log.get('eventName'),
            'user': log.get('userIdentity', {}).get('userName', 'Unknown'),
            'ip_address': log.get('sourceIPAddress', 'N/A'),
            'event_time': log.get('eventTime'),
        }
        parsed_logs.append(parsed_entry)
    
    return parsed_logs

# Example CloudTrail logs file
cloudtrail_log_path = 'cloudtrail_logs.json'

# Parse CloudTrail logs
parsed_logs = parse_cloudtrail_logs(cloudtrail_log_path)

# Save parsed logs to a file
with open('parsed_cloudtrail_logs.json', 'w') as file:
    json.dump(parsed_logs, file, indent=4)

print("CloudTrail logs parsed and saved.")
