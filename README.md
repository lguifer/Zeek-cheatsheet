# Zeek-cheatsheet
Cheatsheet to use with zeek-cut and useful queries

# Zeek Log Fields Cheatsheet

## 1. `conn.log` (Network Connections)
| Field             | Description                                       |
|-------------------|---------------------------------------------------|
| `ts`              | Connection start timestamp                        |
| `uid`             | Unique connection ID                              |
| `id.orig_h`       | Origin IP                                         |
| `id.orig_p`       | Origin port                                       |
| `id.resp_h`       | Destination IP                                    |
| `id.resp_p`       | Destination port                                  |
| `proto`           | Protocol (TCP, UDP, ICMP)                         |
| `service`         | Detected service (HTTP, DNS, etc.)                |
| `duration`        | Connection duration                               |
| `orig_bytes`      | Bytes sent from origin                            |
| `resp_bytes`      | Bytes sent from responder                         |
| `conn_state`      | Connection state (S0, SF, REJ, etc.)              |
| `missed_bytes`    | Bytes missed in the connection                    |
| `history`         | Connection history (SYN, FIN, etc.)               |
| `orig_pkts`       | Packets sent from origin                          |
| `orig_ip_bytes`   | IP bytes sent from origin                         |
| `resp_pkts`       | Packets sent from responder                       |
| `resp_ip_bytes`   | IP bytes sent from responder                      |

---

## 2. `http.log` (HTTP Traffic)
| Field             | Description                                       |
|-------------------|---------------------------------------------------|
| `ts`              | HTTP request timestamp                            |
| `uid`             | Unique HTTP connection ID                         |
| `id.orig_h`       | Client IP                                         |
| `id.orig_p`       | Client port                                       |
| `id.resp_h`       | Server IP                                         |
| `id.resp_p`       | Server port                                       |
| `method`          | HTTP method (GET, POST, etc.)                     |
| `host`            | Hostname                                          |
| `uri`             | Requested URI                                     |
| `referrer`        | HTTP referrer                                     |
| `user_agent`      | Client user-agent                                 |
| `status_code`     | HTTP status code (200, 404, etc.)                 |
| `status_msg`      | Status message                                    |
| `info_code`       | Additional informational code                     |
| `info_msg`        | Additional informational message                  |
| `tags`            | HTTP tags (if anomalies present)                  |
| `username`        | Authenticated username                            |
| `password`        | Plain-text password (if transmitted)              |
| `proxied`         | Involved proxy servers                            |
| `orig_fuids`      | Uploaded file IDs                                 |
| `orig_mime_types` | MIME types of uploaded files                      |
| `resp_fuids`      | Downloaded file IDs                               |
| `resp_mime_types` | MIME types of downloaded files                    |

---

## 3. `dns.log` (DNS Traffic)
| Field             | Description                                       |
|-------------------|---------------------------------------------------|
| `ts`              | DNS request timestamp                             |
| `uid`             | Unique DNS connection ID                          |
| `id.orig_h`       | Client IP                                         |
| `id.orig_p`       | Client port                                       |
| `id.resp_h`       | DNS server IP                                     |
| `id.resp_p`       | DNS server port                                   |
| `proto`           | Protocol (TCP/UDP)                                |
| `trans_id`        | DNS transaction ID                                |
| `query`           | Queried domain name                               |
| `qclass`          | Query class (default 1 for IN)                    |
| `qclass_name`     | Query class name                                  |
| `qtype`           | Query type (A, AAAA, MX, etc.)                    |
| `qtype_name`      | Query type name                                   |
| `rcode`           | Response code                                     |
| `rcode_name`      | Response code name                                |
| `AA`              | Authoritative Answer flag                         |
| `TC`              | Truncated flag                                    |
| `RD`              | Recursion Desired flag                            |
| `RA`              | Recursion Available flag                          |
| `Z`               | Reserved for future use                           |
| `answers`         | DNS answers                                       |
| `TTLs`            | List of TTLs for answers                          |
| `rejected`        | Query rejected                                    |

---

## 4. `ssl.log` (SSL/TLS Traffic)
| Field             | Description                                       |
|-------------------|---------------------------------------------------|
| `ts`              | SSL connection timestamp                          |
| `uid`             | Unique SSL connection ID                          |
| `id.orig_h`       | Client IP                                         |
| `id.orig_p`       | Client port                                       |
| `id.resp_h`       | Server IP                                         |
| `id.resp_p`       | Server port                                       |
| `version`         | SSL/TLS version                                   |
| `cipher`          | Cipher used                                       |
| `curve`           | Curve used (ECDH)                                 |
| `server_name`     | Server name (SNI)                                 |
| `resumed`         | Session resumed (True/False)                      |
| `last_alert`      | Last SSL alert                                    |
| `next_protocol`   | Negotiated next protocol                          |
| `established`     | Connection established                            |
| `cert_chain_fuids`| File IDs of certificate chain                     |
| `client_cert_chain_fuids` | Client certificate chain file IDs         |
| `subject`         | Certificate subject                               |
| `issuer`          | Certificate issuer                                |
| `validation_status` | Certificate validation status                   |

---

## 5. `x509.log` (X.509 Certificates)
| Field             | Description                                       |
|-------------------|---------------------------------------------------|
| `ts`              | Certificate timestamp                             |
| `id`              | Unique certificate ID                             |
| `certificate`     | Certificate content                               |
| `certificate_fuid` | Certificate file ID                              |
| `serial`          | Certificate serial number                         |
| `subject`         | Certificate subject                               |
| `issuer`          | Certificate issuer                                |
| `valid_from`      | Validity start date                               |
| `valid_until`     | Validity end date                                 |
| `key_alg`         | Key algorithm                                     |
| `sig_alg`         | Signature algorithm                               |
| `key_type`        | Key type (RSA, DSA, etc.)                         |

---

## 6. `files.log` (File Activity)
| Field             | Description                                       |
|-------------------|---------------------------------------------------|
| `ts`              | File activity timestamp                           |
| `fuid`            | Unique file ID                                    |
| `tx_hosts`        | Transmitter hosts list                            |
| `rx_hosts`        | Receiver hosts list                               |
| `conn_uids`       | Associated connection IDs                         |
| `source`          | File source (HTTP, SMTP, etc.)                    |
| `depth`           | File depth in the connection                      |
| `analyzers`       | Analysis performed on the file                    |
| `mime_type`       | MIME type of the file                             |
| `filename`        | Filename (if available)                           |
| `duration`        | File transfer duration                            |
| `local_orig`      | Local origin indicator (True/False)               |
| `is_orig`         | Origin indicator                                  |
| `seen_bytes`      | Bytes seen of the file                            |
| `total_bytes`     | Total bytes of the file                           |
| `missing_bytes`   | Missing bytes                                     |
| `overflow_bytes`  | Overflow bytes                                    |
| `timedout`        | Timeout indicator                                 |
| `parent_fuid`     | Parent file ID                                    |
| `md5`, `sha1`, `sha256` | File hashes                                |

---

## 7. `dce_rpc.log` (DCE/RPC Traffic)
| Field             | Description                                       |
|-------------------|---------------------------------------------------|
| `ts`              | DCE/RPC connection timestamp                      |
| `uid`             | Unique DCE/RPC connection ID                      |
| `id.orig_h`       | Origin IP                                         |
| `id.orig_p`       | Origin port                                       |
| `id.resp_h`       | Destination IP                                    |
| `id.resp_p`       | Destination port                                  |
| `rtt`             | Response time for the call                        |
| `named_pipe`      | Named pipe used                                   |
| `endpoint`        | Call endpoint                                     |
| `operation`       | DCE/RPC operation performed                       |

---

## 8. `smb_files.log` (SMB Files)
| Field             | Description                                       |
|-------------------|---------------------------------------------------|
| `ts`              | SMB operation timestamp                           |
| `uid`             | Unique SMB connection ID                          |
| `id.orig_h`       | Client IP                                         |
| `id.orig_p`       | Client port                                       |
| `id.resp_h`       | Server IP                                         |
| `id.resp_p`       | Server port                                       |
| `action`          | Action performed (open, read, write, etc.)        |
| `path`            | Accessed file path                                |
| `name`            | File name                                         |
| `size`            | File size                                         |
| `prev_name`       | Previous name (if renamed)                        |
| `times`           | Access, modification, and creation times          |
