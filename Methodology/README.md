# SOC Analyst Investigation Playbook

This playbook provides a structured approach for SOC analysts investigating suspicious network activity using Zeek logs. It moves from general steps to specific investigation techniques.

---

## Table of Contents
1. [Introduction](#introduction)
2. [Preparation](#preparation)
3. [Initial Detection](#initial-detection)
4. [Threat Enrichment](#threat-enrichment)
5. [Correlation and Analysis](#correlation-and-analysis)
6. [Investigation and Classification](#investigation-and-classification)
7. [Reporting and Response](#reporting-and-response)
8. [Conclusion](#conclusion)

---

## 1. Introduction

In SOC operations, a clear, methodical approach is essential for effectively identifying and analyzing potential threats. This guide serves as a high-level methodology for investigating network traffic, starting from broad preparations and moving toward specific investigative actions.

---

## 2. Preparation

1. **Define the Scope**:
   - Identify network segments, time frames, and specific events relevant to the investigation.

2. **Gather Resources**:
   - Collect necessary tools and resources:
     - **Zeek logs** (e.g., `conn.log`, `dns.log`, `http.log`)
     - **Threat intelligence feeds** (IPs, domains, file hashes)
     - **Internal lists** (whitelists and blacklists)

3. **Set Baselines**:
   - Establish typical network behavior, including:
     - Common ports, protocols, and IPs
     - Typical connection durations and data volumes

---

## 3. Initial Detection

## 3. Initial Detection

The Initial Detection phase is crucial for flagging unusual or suspicious network activity that could indicate a security incident. This stage involves examining `conn.log` for key indicators of malicious behavior and using specific filters to identify abnormal patterns in network connections.

### 3.1 Identify Suspicious Traffic Patterns

In this step, we use Zeek-cut queries to detect traffic anomalies that deviate from normal baseline behaviors. These anomalies could be indicative of data exfiltration, command-and-control (C2) communications, or unauthorized network scans.

#### **3.1.1 High Data Transfers (Potential Data Exfiltration)**

Large volumes of data transferred from internal to external IPs can signal data exfiltration. By setting a threshold on byte count, you can flag connections with unusually high data transfer volumes for further investigation.

- **Command**:
    ```bash
    cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes duration | awk '$3 > 1000000 || $4 > 1000000'
    ```
- **Description**:
  - This command flags connections where `orig_bytes` or `resp_bytes` (bytes sent or received) exceed 1 MB.
- **Next Steps**:
  - Investigate the flagged IPs and examine if the high data transfer aligns with known business activities.
  - Cross-reference with internal IP lists to see if these are authorized systems.

#### **3.1.2 Frequent Short-Lived Connections (Potential C2 Beaconing)**

Short, repetitive connections are often associated with beaconing activity used by malware to communicate with a command-and-control (C2) server. To detect such behavior, filter for connections with very short durations and low byte transfers.

- **Command**:
    ```bash
    cat conn.log | zeek-cut id.orig_h id.resp_h duration orig_bytes resp_bytes | awk '$3 < 2 && $4 < 100 && $5 < 100'
    ```
- **Description**:
  - This command filters for connections with a duration less than 2 seconds and byte transfers under 100 bytes, which may indicate beaconing.
- **Next Steps**:
  - Correlate the source IP with known internal assets; if unknown, prioritize for deeper investigation.
  - Review correlated logs (e.g., DNS and HTTP) for additional C2 indicators, such as uncommon domain requests.

#### **3.1.3 Long-Lived Connections (Potential Persistence)**

Connections with an unusually long duration may indicate persistence mechanisms where attackers maintain a continuous presence on the network.

- **Command**:
    ```bash
    cat conn.log | zeek-cut id.orig_h id.resp_h duration | awk '$3 > 3600'
    ```
- **Description**:
  - This command flags connections lasting over one hour, which could indicate unauthorized persistence.
- **Next Steps**:
  - Identify if the source or destination IPs are associated with known persistent services (e.g., VPNs).
  - Analyze further logs for additional signs of unauthorized long-term access.

---

### 3.2 Filter for Common Indicators of Malicious Activity

Certain indicators can point more directly to malicious intent, such as failed connection attempts, unusual port usage, and repetitive access attempts from single IP addresses. These indicators can help SOC analysts prioritize potential threats for further investigation.

#### **3.2.1 High Volume of Failed Connections (Potential Brute-Forcing)**

A high number of failed connection attempts can be indicative of brute-force attacks. These attempts often result in connection states of `S0` (no response) or `REJ` (connection rejected).

- **Command**:
    ```bash
    cat conn.log | zeek-cut id.orig_h id.resp_h conn_state | grep -E "(S0|REJ)" | sort | uniq -c | sort -nr | head
    ```
- **Description**:
  - This command lists IP addresses with the most failed attempts, sorting by frequency. `S0` and `REJ` are common connection states for failed attempts.
- **Next Steps**:
  - If the source IP is internal, consider monitoring for unusual user authentication attempts.
  - For external IPs, check against threat intelligence to determine if the IP is associated with known brute-force or scanning activity.

#### **3.2.2 Repeated Connections from a Single IP (Potential Horizontal Scanning)**

Attackers often use horizontal scans to probe multiple IP addresses across the same port to find open services. By identifying a single IP making numerous connection attempts, SOC analysts can detect potential scanning behavior.

- **Command**:
    ```bash
    cat conn.log | zeek-cut id.orig_h id.resp_h | sort | uniq -c | sort -nr | head
    ```
- **Description**:
  - This command reveals source IPs making repeated connection attempts to multiple hosts.
- **Next Steps**:
  - Prioritize IPs with high connection counts and determine if they are scanning internal assets.
  - Correlate with external intelligence feeds to see if the source IP has a history of malicious activity.

#### **3.2.3 Unusual Port and Protocol Usage (Potential Obfuscation or Malware)**

Malware or unauthorized services often use non-standard ports or `unknown` protocols to avoid detection. By focusing on uncommon ports and protocols, analysts can identify suspicious activity that might otherwise go unnoticed.

- **Command**:
    ```bash
    cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service | grep -i "unknown"
    ```
- **Description**:
  - This command filters connections where the protocol or service is listed as `unknown`, which can indicate obfuscation or unexpected traffic.
- **Next Steps**:
  - Check the flagged IPs and ports to see if they align with any known or permitted network services.
  - Follow up by analyzing DNS logs to see if the IPs are associated with any unusual domain queries.

---

### 3.3 Documentation and Flagging

After identifying suspicious patterns, it’s essential to document these initial findings and flag potential issues for further analysis in subsequent phases.

- **Record Identified Patterns**:
  - Document the connection parameters (source IP, destination IP, ports, duration, bytes transferred) for each flagged connection.
  - Include information on the observed behavior (e.g., high data transfer, short-lived connections, failed connection states).

- **Prioritize for Further Investigation**:
  - Assign a priority level to each flagged activity based on risk factors such as data transfer volume, frequency, and connection state.
  - These priorities will guide the Threat Enrichment and Correlation phases.

---

## 4. Threat Enrichment

1. **Cross-Reference with Threat Feeds**:
   - **IPs and Domains**: Verify against threat intelligence feeds (e.g., AbuseIPDB, VirusTotal).
   - **Suspicious Ports and Protocols**: Cross-check connections using rare or undefined protocols.

2. **Geolocation Analysis**:
   - Use IP geolocation data to flag connections from unexpected or high-risk regions.

3. **Internal Contextualization**:
   - Cross-reference flagged IPs and domains with internal lists (e.g., whitelists/blacklists).

---

## 5. Correlation and Analysis

1. **Correlate Across Zeek Logs**:
   - **DNS Analysis**: Check DNS logs (`dns.log`) for suspicious domain queries associated with flagged IPs.
   - **HTTP Analysis**: Review HTTP logs (`http.log`) for suspicious URIs, user agents, or file downloads.
   - **SSL/TLS Analysis**: Examine SSL logs (`ssl.log`) for connections lacking Server Name Indication (SNI) or using untrusted certificates.

2. **Identify Patterns in Logs**:
   - Confirm the presence of multiple indicators (e.g., unusual DNS queries alongside high-frequency connections) to strengthen the case for further action.

---

## 6. Investigation and Classification

1. **Examine Each Flagged Connection**:
   - Review all associated events for each IP/domain to understand the context of the flagged connections.

2. **Classify Activity by Risk Level**:
   - **Critical**: Confirmed malicious activity requiring immediate action.
   - **Warning**: Suspicious activity that requires monitoring.
   - **Informational**: Benign or expected behavior.

3. **Determine Intent**:
   - Assess whether the activity aligns with known attack patterns (e.g., scanning, exfiltration, or C2 beaconing).

---

## 7. Reporting and Response

1. **Document Findings**:
   - Compile an incident report that includes:
     - Details of suspicious activity
     - IPs, ports, and protocols involved
     - Threat intelligence and correlation findings

2. **Initiate Containment and Mitigation**:
   - Take immediate action if necessary, such as blocking malicious IPs, isolating affected systems, or enhancing monitoring on flagged entities.

3. **Share Findings**:
   - Report findings to relevant teams (e.g., threat intelligence, SOC, or incident response) for further action and visibility.

---

## 8. Conclusion

This structured approach enables SOC analysts to move systematically from broad preparation to specific investigation, ensuring thorough, efficient analysis of potential threats. By following this guideline, analysts can improve their ability to detect, classify, and respond to incidents in a timely and organized manner.

--- 

