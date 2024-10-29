# Analyzing Suricata Fast Log for Unique Connections Between Two IPs

This repository contains a Bash command that analyzes Suricata's Fast Log to identify unique connections between two specified IP addresses.

## Command Overview

The following command extracts and highlights unique connections between two IP addresses (for this example, 10.8.15.133 and 72.5.43.29) from the Suricata Fast Log file named `fast.log`.

```bash
cat fast.log | sort -t'[' -k3,3 -u | awk -F '\\[1:[0-9]+:[0-9]+\\]' '{print $1, $2, $3}' | grep -E '10.8.15.133.*72.5.43.29|72.5.43.29.*10.8.15.133' | sort -k1,1 -u | bcat
```


