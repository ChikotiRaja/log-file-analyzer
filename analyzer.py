import re
import requests
import pandas as pd
from datetime import datetime
from collections import defaultdict

# CONFIGURATION
log_file = "sample_log.txt"
start_time = "Apr 15 08:00:00"
end_time = "Apr 15 09:00:00"
threshold = 3  # Flag IPs with >= this many failed attempts
geolocation = True  # Set to False to skip location lookup

# Convert string to datetime
def parse_time(log_time_str):
    return datetime.strptime(log_time_str, "%b %d %H:%M:%S")

# Extract timestamp and IP from log
def extract_log_info(line):
    pattern = r"^([A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}).*Failed password.*from\s+(\d+\.\d+\.\d+\.\d+)"
    match = re.search(pattern, line)
    if match:
        timestamp = parse_time(match.group(1))
        ip = match.group(2)
        return timestamp, ip
    return None, None

# Fetch geolocation from ip-api.com
def get_location(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = res.json()
        if data['status'] == 'success':
            return f"{data['country']} - {data['city']}"
    except:
        pass
    return "Unknown"

# Main analysis
start_dt = parse_time(start_time)
end_dt = parse_time(end_time)

failed_logins = defaultdict(int)
log_entries = []

with open(log_file, "r") as f:
    for line in f:
        timestamp, ip = extract_log_info(line)
        if timestamp and start_dt <= timestamp <= end_dt:
            failed_logins[ip] += 1

for ip, count in failed_logins.items():
    if count >= threshold:
        location = get_location(ip) if geolocation else "Skipped"
        log_entries.append({"IP": ip, "Attempts": count, "Location": location})

# Output results
df = pd.DataFrame(log_entries)
print("\nSuspicious IPs Detected:")
print(df.to_string(index=False))

# Save to files
df.to_csv("suspicious_ips.csv", index=False)
df.to_json("suspicious_ips.json", orient="records", indent=2)

print("\nReports saved as 'suspicious_ips.csv' and 'suspicious_ips.json'")
