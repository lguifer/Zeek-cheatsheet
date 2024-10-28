### 1. **List All HTTP Requests**

This command shows all HTTP requests recorded in `http.log`, including the originating IP, HTTP method, host, and requested URI.

```bash
cat http.log | zeek-cut id.orig_h method host uri
```

### 2. **Identify HTTP Responses with 4xx or 5xx Status Codes**

4xx (client errors) and 5xx (server errors) responses might indicate issues or suspicious activity, like attempts to access restricted resources or application failures.

```bash
cat http.log | zeek-cut id.orig_h id.resp_h status_code uri | grep -E "4[0-9]{2}|5[0-9]{2}"
```

### 3. **Detect File Downloads**

To find file downloads (e.g., `.exe`, `.zip`, `.pdf`), you can search for certain extensions in HTTP traffic:

```bash
cat http.log | zeek-cut id.orig_h id.resp_h uri | grep -E "\.exe$|\.zip$|\.pdf$"
```

### 4. **Extract URLs with User-Agent Headers**

User-Agent headers are helpful to identify the client type (browser, OS, bots, etc.) making the request. This command extracts the requested URLs along with User-Agent headers:

```bash
cat http.log | zeek-cut id.orig_h host uri user_agent
```

### 5. **Identify Unsecured HTTP Traffic**

Detecting HTTP (port 80) connections is useful, especially if HTTPS is expected. This could indicate misconfigurations or unencrypted traffic:

```bash
cat http.log | zeek-cut id.orig_h id.resp_h id.resp_p host uri | awk '$3 == 80'
```

### 6. **Detect Suspicious User-Agents**

Search for specific User-Agents of interest (e.g., linked to bots or scanning tools like `curl`, `python-requests`, `wget`):

```bash
cat http.log | zeek-cut id.orig_h user_agent | grep -i -E "curl|python|wget|scanner"
```

### 7. **Extract HTTP Traffic with Specific Methods**

To review HTTP requests with unusual methods like `PUT` or `DELETE` that may indicate modification attempts on the server:

```bash
cat http.log | zeek-cut id.orig_h method uri | grep -E "PUT|DELETE"
```

### 8. **Identify Long Sessions or Large Downloads**

If you need to analyze long HTTP sessions or large downloads, filter for data transfers above a certain byte threshold:

```bash
cat http.log | zeek-cut id.orig_h id.resp_h uri resp_bytes | awk '$4 > 1000000'
```

This example filters for responses larger than 1 MB.

### 9. **Search HTTP Queries to Login or Authentication Pages**

You can search for URLs containing terms like `login`, `auth`, `signin`, which may be points of interest to detect authentication attempts or brute force attacks:

```bash
cat http.log | zeek-cut id.orig_h uri | grep -i -E "login|auth|signin"
```

### 10. **Extract Sensitive HTTP Fields (Referer and Host)**

The Referer header can help trace where a request originated, while Host indicates the destination. This can be useful to identify redirection behavior or attempts to access internal pages.

```bash
cat http.log | zeek-cut id.orig_h id.resp_h host uri referrer
```

### 11. **Analyze URLs Accessed by a Specific IP**

To investigate a specific IP’s behavior (e.g., during an incident), you can filter all URLs accessed by an IP address:

```bash
cat http.log | zeek-cut id.orig_h host uri | grep "1.2.3.4"
```

Replace `1.2.3.4` with the IP of interest.

### 12. **Detect Possible SQL Injection or XSS Attacks**

You can filter requests containing characters or patterns typical of attacks like SQL Injection or Cross-Site Scripting (XSS):

```bash
cat http.log | zeek-cut id.orig_h uri | grep -i -E "\'|\"|<|>|union|select|insert|drop|script"
```

### 13. **Identify HTTP Sessions by Country**

If you are using geolocation in Zeek, you can filter sessions from uncommon or unexpected countries (e.g., IPs from countries with no usual traffic):

```bash
cat http.log | zeek-cut id.orig_h id.resp_h country
```

### 14. **HTTP Traffic by Hour of Peak Activity**

Analyzing HTTP traffic by hour can help identify unusual activity patterns. This example extracts the hour of each request (requires a timestamp field in `http.log`):

```bash
cat http.log | zeek-cut ts | awk '{print strftime("%H", $1)}' | sort | uniq -c
```

### 15. **Extract 200 OK Status Code Traffic**

To identify successful requests, you can filter traffic by the 200 status code:

```bash
cat http.log | zeek-cut id.orig_h id.resp_h uri status_code | awk '$4 == 200'
```

---