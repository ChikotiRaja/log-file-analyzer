import streamlit as st
import pandas as pd
import re
from datetime import datetime
from collections import defaultdict
import requests
import matplotlib.pyplot as plt

# Function to parse time
def parse_time(log_time_str):
    return datetime.strptime(log_time_str, "%b %d %H:%M:%S")

# Function to extract log data
def extract_log_info(line):
    pattern = r"^([A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}).*Failed password.*from\s+(\d+\.\d+\.\d+\.\d+)"
    match = re.search(pattern, line)
    if match:
        timestamp = parse_time(match.group(1))
        ip = match.group(2)
        return timestamp, ip
    return None, None

# Function to get location
def get_location(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = res.json()
        if data['status'] == 'success':
            return f"{data['country']} - {data['city']}"
    except:
        pass
    return "Unknown"

# Streamlit UI
st.title("🔐 Cybersecurity Log Analyzer Dashboard")

uploaded_file = st.file_uploader("Upload your log file", type=["txt"])
threshold = st.slider("Suspicious IP Threshold", 1, 10, 3)
geo_lookup = st.checkbox("Enable IP Geolocation", value=True)

start_time = st.text_input("Start Time (e.g., Apr 15 08:00:00)", "Apr 15 08:00:00")
end_time = st.text_input("End Time (e.g., Apr 15 12:00:00)", "Apr 15 12:00:00")

if uploaded_file:
    failed_logins = defaultdict(int)
    logs = uploaded_file.read().decode("utf-8").splitlines()

    start_dt = parse_time(start_time)
    end_dt = parse_time(end_time)

    for line in logs:
        timestamp, ip = extract_log_info(line)
        if timestamp and start_dt <= timestamp <= end_dt:
            failed_logins[ip] += 1

    log_entries = []

    for ip, count in failed_logins.items():
        if count >= threshold:
            location = get_location(ip) if geo_lookup else "Skipped"
            log_entries.append({"IP": ip, "Attempts": count, "Location": location})

    df = pd.DataFrame(log_entries)
    
    if not df.empty:
        st.success("Suspicious IPs Detected:")
        st.dataframe(df)

        # Save report
        df.to_csv("suspicious_ips.csv", index=False)
        df.to_json("suspicious_ips.json", orient="records", indent=2)

        st.download_button("Download CSV", data=df.to_csv(index=False), file_name="suspicious_ips.csv")
        st.download_button("Download JSON", data=df.to_json(orient="records", indent=2), file_name="suspicious_ips.json")

        # Plot
        st.subheader("📊 Visualization")
        st.bar_chart(df.set_index("IP")["Attempts"])
    else:
        st.warning("No suspicious IPs found in the selected time window.")

