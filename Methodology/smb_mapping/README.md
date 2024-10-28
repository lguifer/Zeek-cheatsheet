
## 1. View All SMB Operations
This query retrieves all SMB operations logged in the `smb_mapping.log`.

```bash
cat smb_mapping.log | zeek-cut -d '\t' ts uid id.orig_h id.orig_p id.resp_h id.resp_p connection_id operation
```

## 2. Count SMB Operations by Source IP
This query counts how many SMB operations each source IP performed.

```bash
cat smb_mapping.log | zeek-cut -d '\t' id.orig_h operation | sort | uniq -c | sort -nr
```

## 3. Identify Unique Connections
To identify unique SMB connections and their respective operations, you can use:

```bash
cat smb_mapping.log | zeek-cut -d '\t' id.orig_h id.orig_p id.resp_h id.resp_p connection_id operation | sort -u
```

## 4. Filter for Specific SMB Operations (e.g., Create, Delete)
If you want to filter for specific operations such as `Create` and `Delete`, use:

```bash
cat smb_mapping.log | zeek-cut -d '\t' ts id.orig_h id.orig_p id.resp_h id.resp_p connection_id operation | grep -E "Create|Delete"
```

## 5. Count Operations Per Connection
This query counts how many operations each SMB connection has performed.

```bash
cat smb_mapping.log | zeek-cut -d '\t' connection_id operation | sort | uniq -c | sort -nr
```

## 6. Identify Suspicious Source IPs
To identify source IPs that are performing an unusually high number of SMB operations, you can combine sorting and counting:

```bash
cat smb_mapping.log | zeek-cut -d '\t' id.orig_h | sort | uniq -c | sort -nr | head -n 10
```

## 7. Track Operations Over Time
If you want to track SMB operations over a specific time range, for example, within the last hour, you can adjust the `ts` filtering accordingly.

```bash
cat smb_mapping.log | zeek-cut -d '\t' ts id.orig_h operation | awk -v date="$(date -d '1 hour ago' '+%Y-%m-%d %H:%M:%S')" '$1 > date'
```

## 8. List All Operations to a Specific Destination
To see all SMB operations directed at a specific destination IP, replace `DEST_IP` with the actual IP address:

```bash
cat smb_mapping.log | zeek-cut -d '\t' ts id.orig_h id.orig_p operation | grep 'DEST_IP'
```
