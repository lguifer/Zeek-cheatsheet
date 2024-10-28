
---

## 1. Identify Multiple `PUT` Requests
Detect multiple `PUT` requests from the same IP address, which can indicate potential data exfiltration or unauthorized modifications.
```bash
cat http.log | zeek-cut id.orig_h method | grep 'PUT' | sort | uniq -c | sort -nr | awk '$1 > 3'
```
**Interpretation**:  
- **Normal**: Occasional `PUT` requests from trusted hosts.  
- **Abnormal**: More than 3 `PUT` requests from a single IP could suggest suspicious upload activities.

---

## 2. Analyze Requests with Large Request Body
Check for requests with a significant size of the request body, which could indicate file uploads or data exfiltration attempts.
```bash
cat http.log | zeek-cut id.orig_h request_body_len | awk '$1 > 10000' | sort | uniq -c | sort -nr
```
**Interpretation**:  
- **Normal**: Small request bodies for standard web operations.  
- **Abnormal**: Request bodies larger than 10,000 bytes may suggest file uploads, which could be benign or malicious.

---

## 3. Monitor for HTTP Status Codes Indicating Errors or Redirects
Identify requests resulting in 3xx, 4xx, or 5xx status codes that indicate issues with the request or server errors.
```bash
cat http.log | zeek-cut status_code | grep -E '^[34|5][0-9]{2}' | sort | uniq -c | sort -nr
```
**Interpretation**:  
- **Normal**: Occasional errors and redirects.  
- **Abnormal**: A high volume of 4xx (client errors) or 5xx (server errors) could indicate user issues or application vulnerabilities.

---

## 4. Identify Requests from Internal IP to External Hosts
Monitor for requests originating from internal IPs to external hosts that may indicate compromised machines trying to communicate with C2 servers.
```bash
cat http.log | zeek-cut id.orig_h id.resp_h | awk '$1 ~ /^10\.|^192\.|^172\./ && $2 !~ /^10\.|^192\.|^172\./' | sort | uniq -c | sort -nr
```
**Interpretation**:  
- **Normal**: Internal communication to external services (e.g., updates).  
- **Abnormal**: Unusual patterns of internal IPs contacting external hosts may suggest potential malware activity.

---

## 5. Analyze User-Agent for Known Malicious Patterns
Identify requests using User-Agent strings that match known malicious patterns or suspicious tools.
```bash
cat http.log | zeek-cut user_agent | grep -E 'curl|wget|python|java|httpclient' | sort | uniq -c | sort -nr
```
**Interpretation**:  
- **Normal**: Standard User-Agent strings from browsers and legitimate applications.  
- **Abnormal**: Frequent usage of automated tool User-Agents could indicate scrapers or attackers.

---

## 6. Check for Missing Referrer on Sensitive Requests
Analyze requests to sensitive endpoints without a referrer, which may indicate direct access attempts or probing.
```bash
cat http.log | zeek-cut uri referrer | grep -E '/admin|/config|/api' | awk '$2 == "-" {print $0}' | sort | uniq -c | sort -nr
```
**Interpretation**:  
- **Normal**: Legitimate users accessing resources directly.  
- **Abnormal**: Direct access to sensitive URIs without a referrer could suggest unauthorized scanning.

---

## 7. Identify Patterns in Status Codes for the Same Endpoint
Monitor the response codes returned for repeated requests to the same endpoint, which can indicate persistent probing.
```bash
cat http.log | zeek-cut uri status_code | sort | uniq -c | sort -nr | awk '$1 > 5'
```
**Interpretation**:  
- **Normal**: Occasional response codes for a specific endpoint.  
- **Abnormal**: More than 5 repeated requests to the same URI with varying response codes may indicate attack attempts.

---

## 8. Check for Anomalous Status Messages
Identify status messages that may indicate suspicious behavior or malicious activities.
```bash
cat http.log | zeek-cut status_msg | sort | uniq -c | sort -nr | grep -E 'Error|Redirect|Not Found|Unauthorized'
```
**Interpretation**:  
- **Normal**: Standard status messages indicating user actions.  
- **Abnormal**: Frequent occurrences of error messages may suggest exploitation attempts.

---

## 9. Analyze HTTP Methods Usage Across All Requests
Monitor for the use of HTTP methods other than the standard `GET` and `POST`, which may indicate potential attacks.
```bash
cat http.log | zeek-cut method | sort | uniq -c | sort -nr | grep -E 'OPTIONS|PATCH|DELETE|HEAD'
```
**Interpretation**:  
- **Normal**: Occasional usage of HTTP methods for legitimate purposes.  
- **Abnormal**: Frequent usage of non-standard methods may indicate potential probing or attacks.

---

## 10. Identify External Requests Returning High Latency
Monitor external requests that have longer durations, which may indicate potential service interruptions or issues.
```bash
cat http.log | zeek-cut id.resp_h duration | awk '$1 > 2' | sort | uniq -c | sort -nr
```
**Interpretation**:  
- **Normal**: Occasional delays due to network congestion.  
- **Abnormal**: Long durations for specific external requests could indicate performance issues or attacks.

---