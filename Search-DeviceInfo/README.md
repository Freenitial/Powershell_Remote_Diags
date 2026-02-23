# Search-DeviceInfo 🔎💻

Gather **system information and logged-on user sessions** from local or remote Windows machines in a single call.

It is recommended to **copy-paste only the function** in PowerShell console, then call it when needed.

**Alias to call faster : `SDEV`**

Also available as .ps1 or .bat

---

## ✨ Features

* 📋 **System overview**
  * OS name and version
  * PowerShell version
  * Uptime
  * Pending reboot detection (multiple sources)
  * Free disk space on C:
* 👥 **Logged-on user sessions** via WTS API
  * Session name, state, idle time, session duration
  * Active Directory display name resolution when domain-joined
* 🖥️ **Local and remote scanning**
  * PowerShell Remoting for execution
  * Fast reachability check via **TCP 445 (SMB)** before connecting
* 🧵 **Parallel execution**
* 🗂️ **Sorted output**, readable directly in console
* 🧱 **Single file**: runnable as `.bat`, `.cmd`, or `.ps1`

---

## 🧾 Output

<img width="577" height="288" alt="image" src="https://github.com/user-attachments/assets/155e108c-493b-488f-a3b3-14dae277eb14" />

Displays for each computer:
- **System properties** (OS, build, uptime, pending reboot, free disk space)
- **User session table** (color-coded: green for Active, dark yellow for Disconnected)

### Pending Reboot Sources

The following potential sources are checked:
- `CCM_RebootRequired`
- `WindowsUpdate`
- `ComponentBasedServicing`
- `PendingFileRenameOperations`
- `UpdateExeVolatile`
- `WMI RebootPending`

---

## 🔧 Parameters

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

**Get info for the local machine**
```powershell
Search-DeviceInfo
```

**Scan multiple remote computers**
```powershell
Search-DeviceInfo PC01,PC02,PC03
```

**Scan with explicit credentials and limited threads**
```powershell
Search-DeviceInfo PC-01,192.168.1.10,PC-02,192.168.1.11 -MaxThreads 2
```

---

## 📦 Requirements

* PowerShell 2.0+
* Windows XP+
* **Remote scans** require WinRM / PowerShell Remoting enabled
* Should run **as Administrator**

---
