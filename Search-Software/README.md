# Search-Software 🔎📦

Scanner to find **installed software by display name** in the Windows registry, locally or on remote Windows machines.

It is recommended to **copy-paste only the function** in PowerShell console, then call it when needed.

**Alias to call faster : `SSFT`**

Also available as .ps1 or .bat

---

## ✨ Features

* ⚡ **Fast registry enumeration** using .NET registry API
* 🧠 **Flexible matching**
  * Wildcards are automatically wrapped around each search pattern
  * Multiple patterns supported in a single call
* 📂 **Enumerates both registry paths HKLM\HKCU**
  * Native 64-bit (`Uninstall`)
  * WOW6432Node 32-bit (`WOW6432Node\Uninstall`)
* 🖥️ **Local and remote scanning**
  * PowerShell Remoting for execution
  * Fast reachability check via **TCP 445 (SMB)** before connecting
* 🧵 **Parallel execution**
* 🗂️ **Sorted output** grouped by display name, readable directly in console
* 🧱 **Single file**: runnable as `.bat`, `.cmd`, or `.ps1`

---

## 🧾 Output

<img width="802" height="301" alt="image" src="https://github.com/user-attachments/assets/1c0fb652-6cb6-477b-8cc6-660afcde433c" />

Displays for each match:
- **Display name** (highlighted)
- **Registry key path** (color-coded: green for 64-bit, cyan for 32-bit)
- **Version**
- **Uninstall string**, quiet uninstall string, or ModifyPath fallback

---

## 🔧 Parameters

### `-DisplayNames <string[]>` (mandatory)
One or more search strings to match against installed software display names.

Wildcards are automatically added around each pattern, so `7-Zip` matches any entry containing `7-Zip`.

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

**Search for a single software locally**
```powershell
Search-Software  7-Zip
```

**Search multiple patterns on remote computers**
```powershell
Search-Software  "Visual C++",Chrome  PC01,PC02
```

**Limit concurrency**
```powershell
Search-Software  Office  -MaxThreads 4
```

---

## 📦 Requirements

* PowerShell 2.0+
* Windows XP+
* **Remote scans** require WinRM / PowerShell Remoting enabled
* Should run **as Administrator** for remote scan

---
