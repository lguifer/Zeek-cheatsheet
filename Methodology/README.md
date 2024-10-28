# SOC Analyst Investigation Playbook Aligned with MITRE ATT&CK Framework

This playbook provides a structured approach to investigating network activity using the MITRE ATT&CK phases. Each phase outlines general steps and queries to detect specific behaviors using Zeek logs.

---

## Table of Contents

1. [Introduction](# 1. Introduction)
2. [Reconnaissance](#reconnaissance)
3. [Initial Access](#initial-access)
4. [Execution](#execution)
5. [Persistence](#persistence)
6. [Privilege Escalation](#privilege-escalation)
7. [Defense Evasion](#defense-evasion)
8. [Credential Access](#credential-access)
9. [Discovery](#discovery)
10. [Lateral Movement](#lateral-movement)
11. [Collection](#collection)
12. [Command and Control (C2)](#command-and-control-c2)
13. [Exfiltration](#exfiltration)
14. [Impact](#impact)
15. [Conclusion](#conclusion)

---


## 1. Introduction

This playbook provides a structured approach for SOC analysts to investigate network activity through the lens of the MITRE ATT&CK framework using Zeek logs. Before diving into the investigative phases, it's crucial to set up the necessary tools and environment. This section outlines the installation of prerequisites, focusing on Zeek, a powerful network analysis framework that captures and analyzes network traffic.

### Prerequisites Installation

To begin, ensure you have a Debian-based distribution (such as Debian, Ubuntu, or Kali Linux) running on your system. Follow the steps below to install Zeek and its dependencies:

1. **Update Your System**:  
   Open a terminal and run the following command to update your package list and upgrade installed packages:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install Required Packages**:  
   Install essential packages and libraries needed for Zeek:
   ```bash
   sudo apt install -y build-essential cmake git python3-dev libssl-dev    libpcap-dev bison flex zlib1g-dev
   ```

3. **Download and Install Zeek**:  
   - Clone the Zeek repository from GitHub:
     ```bash
     git clone --recursive https://github.com/zeek/zeek.git
     ```
   - Navigate into the cloned directory:
     ```bash
     cd zeek
     ```
   - Create a build directory and navigate into it:
     ```bash
     mkdir build && cd build
     ```
   - Run CMake to configure the build environment:
     ```bash
     cmake ..
     ```
   - Compile and install Zeek:
     ```bash
     make && sudo make install
     ```

4. **Configure Zeek**:  
   After installation, configure Zeek to start capturing network traffic. Edit the Zeek configuration file as needed (typically located in `/usr/local/zeek/share/zeek/site/local.zeek`).

5. **Start Zeek**:  
   Use the following command to start Zeek:
   ```bash
   sudo zeekctl deploy
   ```

With Zeek installed and running, analysts can begin utilizing its capabilities to capture and analyze network traffic, thereby enhancing their investigations aligned with the MITRE ATT&CK framework.



### Prerequisites Installation

To begin, ensure you have a Debian-based distribution (such as Debian, Ubuntu, or Kali Linux) running on your system. Follow the steps below to install Zeek and its dependencies:

1. **Update Your System**:  
   Open a terminal and run the following command to update your package list and upgrade installed packages:
   ```bash
   sudo apt update && sudo apt upgrade -y


---


## 2. Reconnaissance

**Objective**: Detect initial probing and scanning activities by adversaries to gather information about the network.

### Overview

Reconnaissance is the first phase of the attack lifecycle where adversaries attempt to gather information about the target environment. This can include identifying open ports, active services, and potentially vulnerable hosts. Detecting reconnaissance activities early can help in mitigating further attacks by recognizing the intent before it escalates.

### General Steps

1. **Identify Unusual Traffic Patterns**: Monitor for increased amounts of traffic directed at specific hosts or services that are not typically accessed.
2. **Analyze DNS Queries**: Look for abnormal patterns in DNS queries that may indicate reconnaissance activities targeting multiple hosts.
3. **Monitor for Port Scanning Activities**: Use network logs to identify potential port scanning, which may involve a high number of connection attempts to various ports within a short time frame.

### Specific Log Queries

The following Zeek log queries can be used to detect reconnaissance activities:

1. **Detect Port Scanning**:
   Identify multiple connection attempts from a single source IP address to various ports on a destination host:
   ```bash
   zeek-cut -d$'	' conn.log | awk '{if ($5 ~ /[0-9]+/) {print $1, $5}}' | sort | uniq -c | sort -nr | awk '$1 > 10'
   ```
   This command checks for any source IP that connects to more than 10 different ports on the same destination.

2. **Identify Suspicious DNS Queries**:
   Monitor for DNS queries that resolve to multiple IP addresses or unusual domains that may indicate domain generation algorithms (DGA):
   ```bash
   zeek-cut -d$'	' dns.log | awk '{if ($6 ~ /\.xyz$|\.top$|\.online$/) {print $1, $6}}' | sort | uniq -c | sort -nr
   ```
   This query focuses on domains with common DGA patterns, which can be indicative of reconnaissance.

3. **Analyze Connection Attempts**:
   Check for a high number of connection attempts to a single port, which may indicate scanning behavior:
   ```bash
   zeek-cut -d$'	' conn.log | awk '$5 == "80" || $5 == "443" {print $1, $2, $5}' | sort | uniq -c | sort -nr | awk '$1 > 20'
   ```
   This command filters for HTTP and HTTPS traffic, indicating potential scanning for web services.

4. **Examine Unusual User-Agent Strings**:
   Identify unusual or malformed user-agent strings in HTTP requests, which may suggest automated scanning tools:
   ```bash
   zeek-cut -d$'	' http.log | awk '{print $4}' | sort | uniq -c | sort -nr | awk '$1 > 10'
   ```
   This query helps identify any user-agent strings that appear suspicious or are overly frequent.

---

## 3. Initial Access

**Objective**: Identify first-stage network access attempts made by adversaries to gain entry into the target environment.

### Overview

The Initial Access phase involves the methods that attackers use to enter a network or system. This could be through various means, including phishing emails, exploiting vulnerabilities, or unauthorized access to accounts. Detecting these access attempts is crucial to preventing further infiltration and potential damage.

### General Steps

1. **Monitor Authentication Logs**: Keep an eye on failed login attempts and unusual access times, which could indicate unauthorized access attempts.
2. **Analyze Web Traffic for Exploit Attempts**: Look for traffic patterns indicative of exploit attempts, such as access to known vulnerable services or applications.
3. **Detect Phishing Attempts**: Review email logs and identify any suspicious attachments or links that may have been delivered as part of a phishing campaign.

### Specific Log Queries

The following Zeek log queries can be utilized to detect initial access attempts:

1. **Identify Failed Login Attempts**:
   Monitor for multiple failed authentication attempts from the same source IP:
   ```bash
   zeek-cut -d$'\t' auth.log | awk '{print $1, $3, $4}' | sort | uniq -c | sort -nr | awk '$1 > 5'


---

## 4. Execution

**Objective**: Detect suspicious execution of commands or protocols.

---

## 5. Persistence

**Objective**: Identify indicators of sustained access by adversaries.

---

## 6. Privilege Escalation

**Objective**: Detect attempts to gain elevated privileges.

---

## 7. Defense Evasion

**Objective**: Identify tactics used to bypass detection.

---

## 8. Credential Access

**Objective**: Detect attempts to obtain user credentials.

---

## 9. Discovery

**Objective**: Identify adversary’s efforts to explore the network environment.

---

## 10. Lateral Movement

**Objective**: Detect adversary’s attempts to move within the network.

---

## 11. Collection

**Objective**: Identify data gathering activities before exfiltration.

---

## 12. Command and Control (C2)

**Objective**: Detect beaconing and outbound C2 communications.

---

## 13. Exfiltration

**Objective**: Detect unauthorized data transfers from the network.

---

## 14. Impact

**Objective**: Identify adversary actions aimed at disrupting systems or data.

---

## 15. Conclusion

Summarize the SOC analyst’s investigation approach using the MITRE ATT&CK framework.

---
