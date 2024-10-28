
---

# Normal vs. Abnormal Behaviors

## 1. SQL Injection Attempts
- **Normal**: Requests containing typical query parameters without suspicious characters or patterns.
- **Abnormal**: Requests including SQL keywords (`SELECT`, `UNION`, `DROP`) or unusual URL encoding patterns.
- **Query**:
  ```bash
  cat http.log | zeek-cut uri | grep -E '(\%27)|(\')|(\%22)|(\")|(\%3D)|(\=)|(\%2B)|(\+)|(\%3B)|(;)' | sort | uniq -c | sort -nr
  ```

## 2. XSS Attack Attempts
- **Normal**: Standard requests that do not include script tags or event handlers.
- **Abnormal**: Requests with payloads attempting to inject scripts or manipulate DOM events.
- **Query**:
  ```bash
  cat http.log | zeek-cut uri | grep -E '(<script>|%3Cscript%3E|%3C|%3E|document\.cookie|alert\(|onload=|javascript:|%22%3E|%27%3E)' | sort | uniq -c | sort -nr
  ```

## 3. Potential SSRF Attempts
- **Normal**: Requests targeting external resources or valid URLs.
- **Abnormal**: Requests directed at internal resources (like `localhost` or cloud metadata) that should not be accessible from external networks.
- **Query**:
  ```bash
  cat http.log | zeek-cut uri | grep -E 'http://localhost|http://127\.0\.0\.1|http://169\.254\.169\.254|http://metadata\.google\.internal|http://169\.254' | sort | uniq -c | sort -nr
  ```

## 4. Command Injection Attempts
- **Normal**: Requests with standard parameters and syntax.
- **Abnormal**: Requests containing shell metacharacters (like `;`, `&&`, or `|`).
- **Query**:
  ```bash
  cat http.log | zeek-cut uri | grep -E '(\;|\&|\||\`|\\|%26|%3B|%60|%7C|%5C|%27)' | sort | uniq -c | sort -nr
  ```

## 5. Path Traversal Attempts
- **Normal**: Requests for legitimate files or resources.
- **Abnormal**: Requests attempting to access parent directories (using `..` or encoded sequences).
- **Query**:
  ```bash
  cat http.log | zeek-cut uri | grep -E '(\.\./|\.\.\\|%2E%2E|%2E%2E%2F|%2E%2E%5C)' | sort | uniq -c | sort -nr
  ```

## 6. Unusual HTTP Methods
- **Normal**: Requests using standard methods (`GET`, `POST`, etc.).
- **Abnormal**: Usage of uncommon methods (`OPTIONS`, `TRACE`, `PATCH`, `CONNECT`) that could be indicative of probing or exploitation.
- **Query**:
  ```bash
  cat http.log | zeek-cut method | grep -E 'OPTIONS|TRACE|PATCH|CONNECT' | sort | uniq -c | sort -nr
  ```

## 7. Suspicious Parameters
- **Normal**: Requests with standard parameters without injection indicators.
- **Abnormal**: Requests containing parameters with SQL keywords or injection patterns.
- **Query**:
  ```bash
  cat http.log | zeek-cut uri | grep -E '(\?|\&|\=)(.*)(select|union|insert|drop|delete|update|;|\%27|\')' | sort | uniq -c | sort -nr
  ```

## 8. Reflected XSS Patterns
- **Normal**: Requests without input reflection or harmful scripts.
- **Abnormal**: URLs that reflect user input combined with XSS patterns.
- **Query**:
  ```bash
  cat http.log | zeek-cut uri | grep -E '(\?|\&)(.*)(<|>|%3C|%3E|%22|%27|javascript:|alert\()' | sort | uniq -c | sort -nr
  ```

## 9. Frequent Parameter Manipulation
- **Normal**: Standard requests with fixed parameters.
- **Abnormal**: Requests with rapidly changing parameters indicative of testing or exploitation attempts.
- **Query**:
  ```bash
  cat http.log | zeek-cut uri | grep -E '(\?|\&)(id|user|session|token|action|cmd|file|path)' | sort | uniq -c | sort -nr
  ```

## 10. Large Response Sizes
- **Normal**: Expected response sizes based on content type.
- **Abnormal**: Responses significantly larger than typical, possibly indicating data exfiltration or malicious payload delivery.
- **Query**:
  ```bash
  cat http.log | zeek-cut resp_body_len | awk '$1 > 100000' | sort | uniq -c | sort -nr
  ```

## 11. Suspicious User Agents
- **Normal**: Requests from standard browsers and legitimate tools.
- **Abnormal**: Requests from known bad user agents or automated tools.
- **Query**:
  ```bash
  cat http.log | zeek-cut user_agent | grep -E 'sqlmap|Nmap|curl|wget|python|libwww-perl|httperf' | sort | uniq -c | sort -nr
  ```

## 12. HTTP Status Code Anomalies
- **Normal**: Common HTTP status codes (200, 301, 404).
- **Abnormal**: Frequent 4xx or 5xx errors, indicating scanning or exploitation attempts.
- **Query**:
  ```bash
  cat http.log | zeek-cut status_code | grep -E '4[0-9]{2}|5[0-9]{2}' | sort | uniq -c | sort -nr
  ```

## 13. High Request Volumes from Single IP
- **Normal**: Typical request patterns from users.
- **Abnormal**: Sudden spikes in requests from a single IP, possibly indicating a DDoS or brute-force attack.
- **Query**:
  ```bash
  cat http.log | zeek-cut id.orig_h | sort | uniq -c | awk '$1 > 100' | sort -nr
  ```

## 14. Unusual Content Types
- **Normal**: Requests with standard content types (like `text/html`, `application/json`).
- **Abnormal**: Requests with non-standard content types that could indicate exploits.
- **Query**:
  ```bash
  cat http.log | zeek-cut orig_mime_types | grep -E 'application/x-php|application/x-executable|application/x-shockwave-flash|text/html' | sort | uniq -c | sort -nr
  ```

## 15. Referrals from Malicious Domains
- **Normal**: Legitimate referrals from known sites.
- **Abnormal**: Requests referred from known malicious domains indicating potential phishing or malware.
- **Query**:
  ```bash
  cat http.log | zeek-cut referrer | grep -E '(maliciousdomain\.com|badsite\.net|phishingexample\.org)' | sort | uniq -c | sort -nr
  ```

## 16. Anomalous Activity Timing
- **Normal**: Requests occurring during business hours.
- **Abnormal**: Requests occurring late at night or during unusual hours indicating potential unauthorized access.
- **Query**:
  ```bash
  cat http.log | zeek-cut ts | awk '{if (strftime("%H", $1) < 6 || strftime("%H", $1) > 22) print $1}' | sort | uniq -c | sort -nr
  ```

## 17. Excessive Query String Lengths
- **Normal**: Typical query string lengths.
- **Abnormal**: Requests with unusually long query strings, potentially indicating exploitation attempts.
- **Query**:
  ```bash
  cat http.log | zeek-cut uri | awk -F'\\?' '{if (length($2) > 100) print}' | sort | uniq -c | sort -nr
  ```

## 18. Missing Host Headers
- **Normal**: Requests with proper `Host` headers.
- **Abnormal**: Requests lacking `Host` headers that may indicate scanning or probing.
- **Query**:
  ```bash
  cat http.log | zeek-cut host | grep -E '^-|^$' | sort | uniq -c | sort -nr
  ```

## 19. POST Requests with No Content
- **Normal**: POST requests with expected payloads.
- **Abnormal**: POST requests without content, indicating possible testing or exploitation.
- **Query**:
  ```bash
  cat http.log | zeek-cut method resp_body_len | grep 'POST' | awk '$2 == 0'
  ```

## 20. Monitor GET Requests with Abnormal Query Strings
Check for GET requests containing suspicious or unusually long query strings, which may indicate attempts to exploit vulnerabilities.

```bash
cat http.log | zeek-cut method uri | grep 'GET' | awk -

F'\\?' '{if (length($2) > 100) print}' | sort | uniq -c | sort -nr
```

## 21. Analyze PUT Requests for Unusual File Extensions
Monitor PUT requests for uncommon or suspicious file extensions that should not be uploaded to the server.

```bash
cat http.log | zeek-cut method uri | grep 'PUT' | grep -E '\.(php|exe|sh|pl|asp|jsp|dll)$' | sort | uniq -c | sort -nr
```

Certainly! Below is a Zeek cut query that captures details about `PUT` requests, including the source and destination IP addresses and ports. This will help you monitor `PUT` requests more effectively.

## 22. Zeek `PUT` Request Monitoring Query

This query will extract information about `PUT` requests, including the source IP address, source port, destination IP address, destination port, and the requested URI.

```bash
cat http.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p uri | grep 'PUT'
```


---
