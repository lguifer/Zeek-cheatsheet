
### Cheat Sheet for DCE/RPC Calls Used by Attackers

| RPC Call                          | Description                                                                                       | Expected Use Case                      | Potential Malicious Activity                                      |
|-----------------------------------|---------------------------------------------------------------------------------------------------|----------------------------------------|------------------------------------------------------------------|
| **NetShareEnum**                  | Enumerates shared resources on a server.                                                        | Normal administrative tasks.           | Attackers enumerating shares for sensitive information.          |
| **NetSessionEnum**                | Retrieves sessions connected to shared resources.                                                | Normal monitoring of sessions.         | Gathering active session details for further exploitation.       |
| **SamrLookupNamesInDomain**       | Looks up user names in a domain.                                                                  | User management.                       | Reconnaissance for user accounts to facilitate attacks.          |
| **SamrEnumerateDomainsInSam**     | Enumerates domains in a security account manager (SAM).                                          | Domain management.                     | Identifying domains for lateral movement.                        |
| **SetSecurityObject**             | Modifies security descriptors on objects.                                                         | Administering permissions.             | Unauthorized changes to security settings.                       |
| **DcomCreate**                    | Creates a DCOM object on the remote machine.                                                    | Application initialization.            | Malicious application launches or remote execution.              |
| **ServiceControl**                | Sends commands to control services on the remote system.                                        | Service management.                    | Stopping critical services or malicious service installation.    |
| **NetUserEnum**                   | Enumerates users on a server.                                                                    | User management.                       | Gathering user information for targeted attacks.                 |
| **RpcMgmtStopServer**            | Stops the RPC server for a specified interface.                                                 | Server maintenance.                    | Disabling services to hide malicious activity.                   |
| **DcomConnect**                   | Establishes a DCOM connection to a remote service.                                              | Remote procedure calls.                | Establishing backdoor access.                                    |
| **NetRemoteTOD**                  | Retrieves time of day information from a remote server.                                          | Normal synchronization tasks.          | Time manipulation for log evasion.                               |
| **NetrFileEnum**                  | Enumerates files on a shared resource.                                                            | Normal file sharing.                   | Scanning for sensitive files to exfiltrate.                     |
| **NetrUserGetInfo**               | Retrieves detailed information about a user.                                                     | Normal user account management.        | Gathering detailed user account information for attacks.         |
| **NetrServerReqChallenge**        | Used for authentication to servers and can be leveraged to gain unauthorized access.            | Server authentication and validation.  | Attackers attempting to authenticate without proper credentials.  |
| **RExec**                         | Remote execution of commands.                                                                    | Running commands on remote machines.   | Attackers executing malicious commands remotely.                 |
| **NetrLogonSamLogon**             | Authenticates users and can be exploited for credential harvesting.                             | User login processes.                  | Credential theft or replay attacks.                             |
| **Remote Command Invocation**      | General method for executing commands on remote systems.                                        | Remote administration.                 | Executing unauthorized commands or scripts.                     |
| **DcomExecute**                   | Executes a DCOM method on a remote server.                                                      | Remote management of applications.     | Malicious command execution through DCOM interfaces.            |
| **NetrRemoteAdmin**               | Establishes a remote administration session.                                                     | Legitimate remote management.          | Unauthorized access to admin sessions.                          |
| **NetExec**                       | Executes a command on a remote system.                                                           | Administrative tasks.                  | Attackers executing commands to compromise systems.             |

### Zeek-Cut Queries for Monitoring Malicious RPC Calls

1. **Monitoring for NetShareEnum Calls**
   ```bash
   cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'NetShareEnum'
   ```

2. **Session Enumeration Attempts**
   ```bash
   cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'NetSessionEnum'
   ```

3. **User Lookup Monitoring**
   ```bash
   cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'SamrLookupNamesInDomain'
   ```

4. **Domain Enumeration**
   ```bash
   cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'SamrEnumerateDomainsInSam'
   ```

5. **Unauthorized Security Descriptor Changes**
   ```bash
   cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'SetSecurityObject'
   ```

6. **Service Control Commands**
   ```bash
   cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'ServiceControl'
   ```

7. **User Enumeration Monitoring**
   ```bash
   cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'NetUserEnum'
   ```

8. **File Enumeration Activities**
   ```bash
   cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'NetrFileEnum'
   ```

9. **DCOM Connection Attempts**
   ```bash
   cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'DcomConnect'
   ```

10. **Monitor for Remote Command Execution Attempts**
    ```bash
    cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'RExec'
    ```

11. **Authentication Challenges from Unusual Hosts**
    ```bash
    cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'NetrServerReqChallenge'
    ```

12. **Monitoring User Logon Attempts**
    ```bash
    cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'NetrLogonSamLogon'
    ```

13. **Monitoring for DCOM Command Execution**
    ```bash
    cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'DcomExecute'
    ```

14. **Remote Administration Session Monitoring**
    ```bash
    cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'NetrRemoteAdmin'
    ```

15. **Execution of Remote Commands via NetExec**
    ```bash
    cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'NetExec'
    ```

16. **Abnormal Patterns in Command Executions**
    ```bash
    cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep -E 'RExec|NetExec|DcomExecute'
    ```

17. **Audit Commands for Multiple Users**
    ```bash
    cat dce_rpc.log | zeek-cut id.orig_h id.resp_h rpc_call | grep 'Remote Command Invocation'
    ```