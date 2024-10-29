### 1. **Get unique AD users, excluding machine accounts**

This lists unique users from `kerberos.log` and excludes entries that look like machine accounts (ending in `$` or containing `-`).

```bash
cat kerberos.log | zeek-cut client | grep -vE '\$|-' | awk -F '/' '{print $1}' | sort -u
```

### 2. **Get unique machine accounts (by name)**

This query identifies machine accounts, which often end with `$` in Active Directory environments. This can be useful to monitor machine activity separately.

```bash
cat kerberos.log | zeek-cut client | grep '\$' | sort -u
```

### 3. **List machine names and their associated IP addresses**

This query extracts the `client` and `id.orig_h` fields to show each machine's name and its corresponding IP address. Filtering machine accounts with `$` helps in isolating machines specifically.

```bash
cat kerberos.log | zeek-cut client id.orig_h | grep '\$' | sort -u
```

### 4. **Identify unique client-server pairs in Kerberos traffic**

Useful for tracking which users or machines are communicating with specific servers.

```bash
cat kerberos.log | zeek-cut client server | sort -u
```

### 5. **List all TGT (Ticket Granting Ticket) requests**

This query identifies TGT requests, as they may reveal logins or re-authentications. The `AS-REQ` message type usually indicates TGT requests.

```bash
cat kerberos.log | zeek-cut msg_type client | grep 'AS-REQ' | sort -u
```

### 6. **Identify unusual service ticket requests (TGS-REQ)**

Service tickets requested for privileged services (like Domain Controllers) might indicate attempts to access sensitive resources.

```bash
cat kerberos.log | zeek-cut msg_type service client | grep 'TGS-REQ' | grep -i 'krbtgt' | sort -u
```

### 7. **Monitor failed authentication attempts**

Failed logins can indicate brute force attacks or unauthorized access attempts. Filtering on the result shows only failed authentications.

```bash
cat kerberos.log | zeek-cut client result | grep -v 'SUCCESS' | sort -u
```

### 8. **Identify clients using specific encryption types (e.g., weak types)**

This query helps identify clients using encryption types that might be less secure, such as RC4 or DES.

```bash
cat kerberos.log | zeek-cut client encryption_type | grep -E 'rc4|des' | sort -u
```

### 9. **List Kerberos logins with elevated permissions**

Requests for administrative service tickets can indicate privilege escalation attempts.

```bash
cat kerberos.log | zeek-cut client service | grep -E 'admin|administrator|domain' | sort -u
```

### 10. **Identify possible golden ticket attacks**

Repeated TGT requests for the `krbtgt` account may indicate a golden ticket attack.

```bash
cat kerberos.log | zeek-cut client service | grep -i 'krbtgt' | sort -u
```