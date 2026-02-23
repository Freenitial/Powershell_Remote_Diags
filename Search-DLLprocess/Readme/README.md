# Search-DLLprocess 🔎🧩

Scanner to identify **which running processes have loaded specific DLLs**, locally or on remote Windows machines.

Works both ways:
- Entering a  .DLL displays the processes using it
- Entering an .EXE displays the DLLs launched by it

It is recommended to **copy-paste only the function** in PowerShell console, then call it when needed. 

**Alias to call faster : `SDLL`**

Also available as .ps1 or .bat

---

## ✨ Features

* ⚡ **Fast module enumeration** using native Win32 APIs  
* 🧠 **Flexible matching**
  * Filename only: `ntdll.dll`,`chrome.exe`
  * Full path with wildcards: `C:\Windows\System32\msp*.dll`
* 🖥️ **Local and remote scanning**
  * PowerShell Remoting for execution
  * Fast reachability check via **TCP 445 (SMB)** before connecting
* 🧵 **Parallel execution**
* 🗂️ **Sorted output**, readable directly in console
* 🧱 **Single file**: runnable as `.bat`, `.cmd`, or `.ps1`

---

## 🧾 Output

<img width="979" height="512" alt="image" src="https://github.com/user-attachments/assets/01173c0d-dfdc-46d3-9c9f-3be0a0374a54" />

---

## 🔧 Parameters

### `-Patterns <string[]>` (mandatory)
One or more wildcard patterns describing DLLs to search for.

Accepted forms:
* Filename only  
  `bcrypt.dll`,`chrome.exe`
* Full or partial path with wildcards  
  `C:\Windows\System32\api-ms-win-*.dll`

Matching logic automatically switches between filename-only and full-path mode.

---

### `-ComputerNames <string[]>` (optional)
List of computers to scan.

* Defaults to the **local machine**
* Supports hostnames and IP addresses
* Each target is first tested on **TCP port 445**

---

### `-Credential <PSCredential>` (optional)
Credentials used for remote execution.

* Automatically prompted if needed (if one target is an IP address)
* Reused across hosts
* Reset automatically if access is denied on a remote system

---

### `-MaxThreads <int>` (optional, default: `10`)
Maximum number of parallel runspaces.

* Controls how many computers are scanned simultaneously
* Higher values increase speed but also CPU and memory usage
* Safe default for mixed local / remote environments

---

### `-SortingTimeout <int>` (optional, default: `6`)
Maximum time (in seconds) to wait before forcing ordered output.

* If some hosts are slow, output continues once the timeout is reached
* Prevents the console from blocking on long-running machines

---

## 🧪 Examples

**Search multiple DLL patterns locally**
```powershell
Search-DLLprocess dbghelp*.dll,api-ms-win-*.dll
````

**Scan multiple remote computers**

```powershell
Search-DLLprocess bcrypt.dll PC01,PC02
```

**Limit concurrency**

```powershell
Search-DLLprocess ntdll.dll -MaxThreads 4
```

---

## 📦 Requirements

* PowerShell 2.0+
* Windows XP+
* **Remote scans** require WinRM / PowerShell Remoting enabled
* Should run **as Administrator**

---
