
## 1. View All DCE RPC Operations
This query retrieves all DCE RPC operations logged in the `dce_rpc.log`.

```bash
cat dce_rpc.log | zeek-cut -d '\t' ts uid id.orig_h id.orig_p id.resp_h id.resp_p rtt named_pipe endpoint operation
```

## 2. Count DCE RPC Operations by Source IP
This query counts how many DCE RPC operations each source IP performed.

```bash
cat dce_rpc.log | zeek-cut -d '\t' id.orig_h operation | sort | uniq -c | sort -nr
```

## 3. Identify Unique DCE RPC Connections
To identify unique DCE RPC connections and their respective operations, you can use:

```bash
cat dce_rpc.log | zeek-cut -d '\t' id.orig_h id.orig_p id.resp_h id.resp_p named_pipe operation | sort -u
```

## 4. Filter for Specific DCE RPC Operations (e.g., OpenSCManagerW, CreateService)
If you want to filter for specific operations such as `OpenSCManagerW` and `CreateService`, use:

```bash
cat dce_rpc.log | zeek-cut -d '\t' ts id.orig_h id.orig_p id.resp_h id.resp_p named_pipe operation | grep -E "OpenSCManagerW|CreateService"
```

## 5. Count Operations Per Named Pipe
This query counts how many operations each named pipe has performed.

```bash
cat dce_rpc.log | zeek-cut -d '\t' named_pipe operation | sort | uniq -c | sort -nr
```

## 6. Identify Suspicious Source IPs
To identify source IPs that are performing an unusually high number of DCE RPC operations, you can combine sorting and counting:

```bash
cat dce_rpc.log | zeek-cut -d '\t' id.orig_h | sort | uniq -c | sort -nr | head -n 10
```

## 7. Track Operations Over Time
If you want to track DCE RPC operations over a specific time range, for example, within the last hour, you can adjust the `ts` filtering accordingly.

```bash
cat dce_rpc.log | zeek-cut -d '\t' ts id.orig_h operation | awk -v date="$(date -d '1 hour ago' '+%Y-%m-%d %H:%M:%S')" '$1 > date'
```

## 8. List All Operations to a Specific Named Pipe
To see all DCE RPC operations directed at a specific named pipe, replace `PIPE_NAME` with the actual named pipe:

```bash
cat dce_rpc.log | zeek-cut -d '\t' ts id.orig_h id.orig_p operation | grep 'PIPE_NAME'
```
