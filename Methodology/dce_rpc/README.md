
### DCE/RPC Cheat Sheet

#### 1. **Service Control Operations**
These operations manage Windows services through the Service Control Manager (SCM).

| **Operation**                      | **Description**                                                          |
|------------------------------------|--------------------------------------------------------------------------|
| `OpenSCManagerW`                  | Opens a handle to the service control manager.                         |
| `CreateServiceWOW64A`             | Creates a new service.                                                  |
| `StartServiceA`                   | Starts a service that has been created but is not running.             |
| `StopService`                      | Stops a running service.                                                |
| `DeleteService`                    | Deletes a service from the service control manager.                    |
| `QueryServiceStatus`               | Queries the status of a service.                                       |
| `ChangeServiceConfig`             | Changes the configuration of an existing service.                      |
| `CloseServiceHandle`               | Closes a handle to a service.                                          |

#### 2. **Registry Operations**
These operations manipulate the Windows Registry.

| **Operation**                      | **Description**                                                          |
|------------------------------------|--------------------------------------------------------------------------|
| `BaseRegCreateKey`                | Creates a new registry key.                                            |
| `BaseRegSetValue`                 | Sets the value of a registry key.                                      |
| `BaseRegDeleteValue`              | Deletes a value from a registry key.                                   |
| `BaseRegOpenKey`                  | Opens an existing registry key.                                        |
| `BaseRegQueryValue`               | Retrieves the value of a registry key.                                 |
| `BaseRegDeleteKey`                | Deletes a registry key.                                                |
| `BaseRegEnumKey`                  | Enumerates subkeys of a specified registry key.                        |

#### 3. **Authentication and Security Operations**
These operations deal with authentication mechanisms in Windows.

| **Operation**                      | **Description**                                                          |
|------------------------------------|--------------------------------------------------------------------------|
| `ImpersonateNamedPipeClient`       | Allows a server to impersonate a client.                               |
| `RevertToSelf`                    | Reverts the impersonation back to the original security context.       |
| `SetSecurityObject`               | Sets the security descriptor for a specified object.                   |
| `GetSecurityObject`               | Retrieves the security descriptor for a specified object.              |

#### 4. **File Operations**
These operations manage file access and manipulation.

| **Operation**                      | **Description**                                                          |
|------------------------------------|--------------------------------------------------------------------------|
| `NtCreateFile`                    | Creates or opens a file.                                               |
| `NtReadFile`                      | Reads data from a file.                                               |
| `NtWriteFile`                     | Writes data to a file.                                                |
| `NtDeleteFile`                    | Deletes a file.                                                       |

#### 5. **Process and Thread Operations**
These operations manage processes and threads in the system.

| **Operation**                      | **Description**                                                          |
|------------------------------------|--------------------------------------------------------------------------|
| `CreateProcess`                   | Creates a new process and its primary thread.                          |
| `OpenProcess`                     | Opens an existing local process.                                       |
| `TerminateProcess`                | Ends the specified process.                                            |
| `CreateRemoteThread`              | Creates a thread that runs in the virtual address space of another process. |

#### 6. **Network Operations**
These operations manage network connections and configurations.

| **Operation**                      | **Description**                                                          |
|------------------------------------|--------------------------------------------------------------------------|
| `NetrServerConnect`               | Establishes a connection to a server.                                  |
| `NetrShareAdd`                    | Adds a new share on the server.                                       |
| `NetrShareDel`                    | Deletes a share on the server.                                        |

### Tips for Usage
- **Understanding Context**: Most of these operations are used in the context of exploitation and lateral movement in Windows environments.
- **Mitre ATT&CK Mapping**: Many of these RPC calls relate to MITRE ATT&CK techniques, particularly in the execution and persistence tactics.
- **Security Monitoring**: Monitor the usage of these calls in your environment as they may indicate suspicious activities.

