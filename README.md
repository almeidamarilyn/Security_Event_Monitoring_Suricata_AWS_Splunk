# Security Event Monitoring Framework  
This project integrates **AWS CloudTrail**, **Suricata IDS**, and **Splunk** to enable centralized security monitoring. The system uses custom enrichment scripts and dashboards to streamline incident response, reduce false positives, and correlate security events from multiple sources for faster detection.

## Tech Stack
- **AWS CloudTrail**: Monitors and records account activity across your AWS infrastructure.
- **Suricata IDS/IPS**: Monitors network traffic and generates alerts for malicious activity.
- **Splunk**: Collects and analyzes log data from different sources for real-time security monitoring.
- **Python**: Used for creating scripts that enrich and correlate logs.
- **PowerShell**: Used for automation and extraction of logs on Windows systems.

## Features
- **CloudTrail and Suricata Integration**: Centralized logging of AWS activity and network traffic for real-time monitoring.
- **Threat Intelligence Enrichment**: Enrich logs with external threat data (e.g., from VirusTotal or other providers) to provide context for detected threats.
- **Custom Correlation Rules in Splunk**: Correlate CloudTrail logs with Suricata alerts to identify potential security incidents.
- **Custom Splunk Dashboards**: Visualize security events and alerts from AWS and Suricata logs.

## Setup Instructions

### Prerequisites
Before you begin, ensure you have the following installed and configured:
- **Splunk**: Install Splunk and configure it to receive data from AWS CloudTrail and Suricata.
- **AWS Account**: Ensure you have access to AWS CloudTrail logs for your envir
### 1. **Setting Up Splunk**
- Install Splunk on a server or use Splunk Cloud.
- Configure Splunk to receive CloudTrail and Suricata logs. For CloudTrail, configure the AWS Splunk app to pull logs. For Suricata, use the **Suricata app for Splunk**.

### 2. **Deploy Suricata IDS**
- Install Suricata on your network monitoring devices.
- Configure Suricata to send **EVE JSON** alerts to Splunk.
- Suricata should be running and generating alerts for network traffic.

### 3. **Set Up AWS CloudTrail Integration**
- In the AWS console, enable CloudTrail logging across all regions for your account.
- Configure CloudTrail to send logs to **Splunk** or a centralized log server for processing.

### 4. **Install Required Python Libraries**
To run the Python scripts, you’ll need some additional Python libraries. Install them using pip:

```bash
pip install requests
```
### 5. **Download and Set Up the Project**
Clone this repository to your local machine or server:

```bash
git clone https://github.com/your-username/Security-Event-Monitoring-AWS-Splunk-Suricata.git
cd Security-Event-Monitoring-AWS-Splunk-Suricata
```
### 6. **Configure the Python Scripts**
#### **`enrich_threat_data.py`**:
- Replace the `THREAT_INTELLIGENCE_API_URL` with the actual URL of the threat intelligence provider you want to use (e.g., VirusTotal, or any other API you have access to).

#### **`incident_correlation.py`**:
- Ensure the paths to the log files (`enriched_cloudtrail_logs.json`, `suricata_alerts.json`) are correct.

#### **`parse_cloudtrail_logs.py`**:
- Ensure your raw CloudTrail log file is correctly referenced in the script.

### 7. **Import Custom Dashboards into Splunk**
- Import the custom dashboards created for **CloudTrail** and **Suricata** into Splunk.
- Use the **Splunk UI** to import the dashboard configuration files (found in the `splunk_dashboards` directory) and ensure that they are set up correctly to visualize the data.

### 8. **Enrich Data in Splunk**
The enriched data will be automatically indexed by Splunk if you have configured it correctly. You can use the provided **Splunk correlation rules** to identify incidents in real time.
