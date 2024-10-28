### Analyzing `conn.log` for Anomalous Behaviors

1. **Identify Unusual Number of Connections from a Single IP**:
   Detect IPs that establish an unusually high number of connections within a specific timeframe, indicating possible scanning:
   ```bash
   cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -nr | awk '$1 > 100'
   ```
   This command lists source IPs (`id.orig_h`) with more than 100 connections.

2. **Detect Connections to Uncommon Ports**:
   Identify connections made to uncommon ports, which may indicate scanning for open services:
   ```bash
   cat conn.log | zeek-cut id.resp_p | sort | uniq -c | sort -nr | awk '$1 > 20 && $2 < 1024'
   ```
   This query filters for connections to ports less than 1024 that have high connection counts.

3. **Monitor for Failed Connection Attempts**:
   Look for source IPs with multiple failed connection attempts, which could indicate brute-force attacks or scanning:
   ```bash
   cat conn.log | zeek-cut id.orig_h id.resp_p resp_code | grep -c "RST" | sort | uniq -c | sort -nr | awk '$1 > 10'
   ```
   This command focuses on connections with a reset response code (`resp_code`).

4. **Analyze Connection Duration**:
   Identify connections with abnormally short or long durations, which may indicate scanning or other unusual activity:
   ```bash
   cat conn.log | zeek-cut id.orig_h id.resp_p duration | awk '$3 < 1 || $3 > 300' | sort | uniq -c | sort -nr
   ```
   This query checks for connections lasting less than 1 second or more than 5 minutes.

5. **Detect Large Data Transfers**:
   Identify source IPs that are transferring unusually large amounts of data, which may indicate data exfiltration:
   ```bash
   cat conn.log | zeek-cut id.orig_h id.resp_h bytes | awk '$3 > 1000000' | sort | uniq -c | sort -nr
   ```
   This query highlights IPs transferring over 1 MB of data.

6. **Identify Repeated Connections to the Same Destination**:
   Look for source IPs that repeatedly connect to the same destination, indicating possible reconnaissance:
   ```bash
   cat conn.log | zeek-cut id.orig_h id.resp_h | sort | uniq -c | sort -nr | awk '$1 > 10'
   ```
   This command finds source-destination pairs with more than 10 connections.

7. **Monitor Connections from Internal to External Networks**:
   Identify any connections from internal networks to external addresses that may indicate a potential compromise:
   ```bash
   cat conn.log | zeek-cut id.orig_h id.resp_h | grep "192.168.0." | grep "8.8.8.8" | sort | uniq -c | sort -nr
   ```
   This query checks for internal IPs connecting to a known external DNS server (e.g., Google DNS).

8. **Identify New or Unrecognized Hostnames**:
   If DNS logs are available, check for new or unfamiliar hostnames resolving to IPs that have multiple connections in `conn.log`:
   ```bash
   cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -nr | awk '$1 > 5' | grep "unknown"
   ```
   This command highlights IPs that are connecting to unrecognized hostnames.

9. **Check for Connection Patterns Based on Time of Day**:
   Analyze connections based on the time of day to identify unusual activity during off-hours:
   ```bash
   cat conn.log | zeek-cut id.orig_h id.resp_p start_time | awk '{print strftime("%H", $3)}' | sort | uniq -c | sort -nr
   ```
   This command analyzes connection patterns by hour, helping to detect anomalies during non-business hours.
