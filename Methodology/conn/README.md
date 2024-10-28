---

### Analyzing `conn.log` for Anomalous Behaviors

As a SOC analyst focusing exclusively on `conn.log`, here are several relevant queries to analyze anomalous behaviors that may indicate reconnaissance or other suspicious activities, along with interpretations of the results:

1. **Identify Unusual Number of Connections from a Single IP**:
   ```bash
   cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -nr | awk '$1 > 100'
   ```
   **Interpretation**:  
   - **Normal**: A few hundred connections from known and trusted sources (e.g., web servers, email servers) within a short timeframe.  
   - **Abnormal**: Any source IP establishing more than 100 connections in a short period may indicate a scanning activity.

2. **Detect Connections to Uncommon Ports**:
   ```bash
   cat conn.log | zeek-cut id.resp_p | sort | uniq -c | sort -nr | awk '$1 > 20 && $2 < 1024'
   ```
   **Interpretation**:  
   - **Normal**: Connections to common ports like 80 (HTTP), 443 (HTTPS), and 53 (DNS).  
   - **Abnormal**: A high volume of connections to uncommon or high-numbered ports, especially those less than 1024, may indicate probing for vulnerabilities.

3. **Monitor for Failed Connection Attempts**:
   ```bash
   cat conn.log | zeek-cut id.orig_h id.resp_p resp_code | grep -c "RST" | sort | uniq -c | sort -nr | awk '$1 > 10'
   ```
   **Interpretation**:  
   - **Normal**: Isolated failed connection attempts from legitimate users or services (e.g., due to misconfigurations).  
   - **Abnormal**: Multiple reset response codes from the same source IP (more than 10) could indicate a brute-force attempt or systematic scanning.

4. **Analyze Connection Duration**:
   ```bash
   cat conn.log | zeek-cut id.orig_h id.resp_p duration | awk '$3 < 1 || $3 > 300' | sort | uniq -c | sort -nr
   ```
   **Interpretation**:  
   - **Normal**: Most connections should fall within a typical duration (e.g., a few seconds for HTTP requests).  
   - **Abnormal**: Connections lasting less than 1 second may indicate failed scanning attempts, while connections exceeding 5 minutes may signal persistence or lateral movement.

5. **Detect Large Data Transfers**:
   ```bash
   cat conn.log | zeek-cut id.orig_h id.resp_h bytes | awk '$3 > 1000000' | sort | uniq -c | sort -nr
   ```
   **Interpretation**:  
   - **Normal**: Typical data transfers for legitimate services (e.g., file sharing, backups).  
   - **Abnormal**: Transfers over 1 MB from unknown or untrusted sources could indicate unauthorized data exfiltration.

6. **Identify Repeated Connections to the Same Destination**:
   ```bash
   cat conn.log | zeek-cut id.orig_h id.resp_h | sort | uniq -c | sort -nr | awk '$1 > 10'
   ```
   **Interpretation**:  
   - **Normal**: Repeated connections from a source IP to a trusted service (e.g., frequent access to a web server).  
   - **Abnormal**: More than 10 connections to the same destination within a short timeframe may indicate automated scanning or reconnaissance.

7. **Monitor Connections from Internal to External Networks**:
   ```bash
   cat conn.log | zeek-cut id.orig_h id.resp_h | grep "192.168.0." | grep "8.8.8.8" | sort | uniq -c | sort -nr
   ```
   **Interpretation**:  
   - **Normal**: Internal IPs connecting to known external services (e.g., DNS).  
   - **Abnormal**: Frequent connections from internal IPs to various external IPs, especially if those IPs are not related to legitimate business needs.

8. **Identify New or Unrecognized Hostnames**:
   ```bash
   cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -nr | awk '$1 > 5' | grep "unknown"
   ```
   **Interpretation**:  
   - **Normal**: Connections to known and recognized hostnames.  
   - **Abnormal**: Multiple connections to unrecognized hostnames could suggest phishing attempts or other malicious activities.

9. **Check for Connection Patterns Based on Time of Day**:
   ```bash
   cat conn.log | zeek-cut id.orig_h id.resp_p start_time | awk '{print strftime("%H", $3)}' | sort | uniq -c | sort -nr
   ```
   **Interpretation**:  
   - **Normal**: Consistent connection patterns aligned with business hours.  
   - **Abnormal**: Significant activity during off-hours (e.g., late-night connections) may indicate unauthorized access attempts.