---

### Analyzing `http.log` for Anomalous Behaviors

As a SOC analyst focusing on `http.log`, here are several relevant queries to analyze anomalous behaviors that may indicate reconnaissance or other suspicious activities, along with interpretations of the results:

1. **Identify High Volume of Requests from a Single IP**:
   ```bash
   cat http.log | zeek-cut id.orig_h | sort | uniq -c | sort -nr | awk '$1 > 100'
   ```
   **Interpretation**:  
   - **Normal**: A moderate number of requests (e.g., dozens) from known devices within a typical timeframe.  
   - **Abnormal**: More than 100 requests from a single IP in a short period may indicate a potential denial-of-service attack or automated scanning.

2. **Detect Requests to Uncommon or Suspicious Endpoints**:
   ```bash
   cat http.log | zeek-cut url | grep -E '/admin|/config|/backup' | sort | uniq -c | sort -nr
   ```
   **Interpretation**:  
   - **Normal**: Access to common URLs related to user activities (e.g., homepage, product pages).  
   - **Abnormal**: Frequent requests to sensitive endpoints (like `/admin` or `/config`) could indicate attempts to exploit vulnerabilities.

3. **Monitor for Unusual HTTP Methods**:
   ```bash
   cat http.log | zeek-cut method | sort | uniq -c | sort -nr | grep -E 'OPTIONS|DELETE|PUT'
   ```
   **Interpretation**:  
   - **Normal**: Standard methods like `GET` and `POST` for regular web traffic.  
   - **Abnormal**: Presence of unusual methods (like `DELETE` or `PUT`) may indicate an attempt to modify or delete resources.

4. **Identify Long Response Times**:
   ```bash
   cat http.log | zeek-cut id.orig_h id.resp_p duration | awk '$2 > 2' | sort | uniq -c | sort -nr
   ```
   **Interpretation**:  
   - **Normal**: Occasional delays due to heavy server load or large files.  
   - **Abnormal**: Long response times (> 2 seconds) from specific IPs may indicate application issues or potential attacks.

5. **Analyze User-Agent Strings for Anomalies**:
   ```bash
   cat http.log | zeek-cut user_agent | sort | uniq -c | sort -nr | awk '$1 > 5'
   ```
   **Interpretation**:  
   - **Normal**: Common browsers and bots (like Googlebot).  
   - **Abnormal**: Frequent use of rare or suspicious User-Agent strings may indicate automated tools or scrapers.

6. **Monitor for Repeated Access to the Same URL**:
   ```bash
   cat http.log | zeek-cut url | sort | uniq -c | sort -nr | awk '$1 > 10'
   ```
   **Interpretation**:  
   - **Normal**: Isolated repeated access to popular pages (like login or homepage).  
   - **Abnormal**: More than 10 requests to the same URL may indicate scraping or malicious behavior.

7. **Identify Requests with 4xx or 5xx Response Codes**:
   ```bash
   cat http.log | zeek-cut resp_mime_type | grep -E '4|5' | sort | uniq -c | sort -nr
   ```
   **Interpretation**:  
   - **Normal**: A few error responses may occur due to user mistakes.  
   - **Abnormal**: Frequent 4xx (client errors) or 5xx (server errors) responses could indicate probing or misconfigured applications.

8. **Check for Access to Known Malicious URLs**:
   ```bash
   cat http.log | zeek-cut url | grep -f known_malicious_urls.txt | sort | uniq -c | sort -nr
   ```
   **Interpretation**:  
   - **Normal**: Rare access to potentially risky URLs.  
   - **Abnormal**: Frequent requests to known malicious URLs could indicate compromised systems or phishing attempts.

9. **Identify Patterns of Access Based on Time of Day**:
   ```bash
   cat http.log | zeek-cut id.orig_h url start_time | awk '{print strftime("%H", $3)}' | sort | uniq -c | sort -nr
   ```
   **Interpretation**:  
   - **Normal**: Regular access during business hours.  
   - **Abnormal**: Significant activity during off-hours (e.g., late-night requests) may indicate unauthorized access.

10. **Check for Suspicious Query Parameters**:
    ```bash
    cat http.log | zeek-cut query | grep -E '(\?id=|&session=|&token=)' | sort | uniq -c | sort -nr
    ```
    **Interpretation**:  
    - **Normal**: Standard query parameters for tracking or navigation.  
    - **Abnormal**: Requests with suspicious parameters could indicate attempts to exploit application vulnerabilities.

11. **Identify IP Addresses Accessing the Same URL Repeatedly**:
    ```bash
    cat http.log | zeek-cut id.orig_h url | sort | uniq -c | sort -nr | awk '$1 > 5'
    ```
    **Interpretation**:  
    - **Normal**: Standard access patterns for frequently visited URLs.  
    - **Abnormal**: More than 5 requests from the same IP to a specific URL could suggest automated scraping or a potential attack.

12. **Monitor for Unusual Content Types in Responses**:
    ```bash
    cat http.log | zeek-cut resp_mime_type | sort | uniq -c | sort -nr | awk '$1 > 5'
    ```
    **Interpretation**:  
    - **Normal**: Common content types like text/html or application/json.  
    - **Abnormal**: Frequent unexpected content types (like application/x-executable) could indicate malware distribution.

--- 