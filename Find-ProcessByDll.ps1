[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,Position=0)][string[]]$DllPatterns,
    [Parameter(Mandatory=$false,Position=1)][string[]]$ComputerNames = @($env:COMPUTERNAME),
    [System.Management.Automation.PSCredential]$Credential = $null,
    [int]$MaxThreads = 10,
    [int]$SortingTimeout = 6
)

function Find-ProcessByDll {
    <#
    .SYNOPSIS
        Author  : Leo Gillet / Freenitial on GitHub
        Version : v1.1
        Scan local or remote computers to detect running processes 
        that have loaded DLLs matching specified patterns.
    .PARAMETER DllPatterns
        One or more wildcard patterns representing DLL paths or filenames
        Example: -DllPatterns mspmsnsv.dll,"C:\Windows\System32\*.dll"
    .PARAMETER TargetComputerNames
        Optional. Array of computer names to scan. Defaults to the 
        current machine. Uses port 445 (SMB) to test connectivity 
        before attempting remote execution.
    .NOTES
        - Uses low-level API calls for performance (EnumProcesses, EnumProcessModulesEx).
        - Requires administrative rights on target machines for full results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)][string[]]$DllPatterns,
        [Parameter(Mandatory=$false,Position=1)][string[]]$ComputerNames = @($env:COMPUTERNAME),
        [System.Management.Automation.PSCredential]$Credential = $null,
        [int]$MaxThreads = 10,
        [int]$SortingTimeout = 6
    )
    # Fast connectivity test via TCP 445
    function Test-ComputerAvailable {
        param([string]$Computer,[int]$Timeout=500)
        $TcpClient = New-Object Net.Sockets.TcpClient
        try {
            $AsyncResult = $TcpClient.BeginConnect($Computer,445,$null,$null)
            if (-not $AsyncResult.AsyncWaitHandle.WaitOne($Timeout,$false)) { $TcpClient.Close(); return $false }
            $TcpClient.EndConnect($AsyncResult) | Out-Null; $TcpClient.Close(); return $true
        } catch { $TcpClient.Close(); return $false }
    }
    if (-not $DllPatterns) { return }
    # Auto-credential prompt when IP addresses are detected
    if (-not $Credential) {
        foreach ($ComputerName in $ComputerNames) {
            $ParsedIp = $null
            if ([System.Net.IPAddress]::TryParse($ComputerName,[ref]$ParsedIp)) {
                if (-not $script:Credentials) { $script:Credentials = Get-Credential -Message "Search by IP needs credentials" }
                $Credential = $script:Credentials; break
            }
        }
    }
    # C# P/Invoke definitions for process and module enumeration
    $CSharpCode = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Win32Api {
    [Flags] public enum ProcessAccessFlags : uint { PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_VM_READ = 0x0010 }
    [Flags] public enum ListModulesOptions : uint { LIST_MODULES_ALL = 0x03 }
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("psapi.dll", SetLastError = true)] public static extern bool EnumProcesses([MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] int[] processIds, int size, [MarshalAs(UnmanagedType.U4)] out int bytesReturned);
    [DllImport("psapi.dll", SetLastError = true)] public static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, ListModulesOptions dwFilterFlag);
    [DllImport("psapi.dll", CharSet = CharSet.Auto, SetLastError = true)] public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, uint nSize);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)] public static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);
}
"@
    if (-not ([System.Management.Automation.PSTypeName]'Win32Api').Type) {
        try { Add-Type -TypeDefinition $CSharpCode -ReferencedAssemblies 'System','System.Core' -ErrorAction Stop } catch { return }
    }
    # Build list of reachable computers while tracking unreachable ones in order
    $ReachableComputers   = @()
    $UnreachableComputers = @{}
    foreach ($Computer in $ComputerNames) {
        $IsLocalComputer = ($Computer -eq $env:COMPUTERNAME -or $Computer -eq 'localhost' -or $Computer -eq '.')
        if ($IsLocalComputer -or (Test-ComputerAvailable $Computer)) { $ReachableComputers += $Computer }
        else { $UnreachableComputers[$Computer] = $true }
    }
    if ($ReachableComputers.Count -eq 0 -and $UnreachableComputers.Count -eq 0) { Write-Host "`n"; return }
    # Create RunspacePool for parallel execution
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
    $RunspacePool.Open()
    # Launch all parallel jobs
    $RunningJobs = @()
    foreach ($Computer in $ReachableComputers) {
        $PowerShellInstance = [PowerShell]::Create().AddScript({
            param($TargetComputer, $CredentialObject, $Patterns, $CSharpSource)
            # ScriptBlock containing the actual DLL scan logic
            $ScanScriptBlock = {
                param([string[]]$DllPatternsLocal, [string]$CSharpSourceLocal)
                # Ensure Win32Api type is loaded in remote session
                if (-not ([System.Management.Automation.PSTypeName]'Win32Api').Type) {
                    Add-Type -TypeDefinition $CSharpSourceLocal -ReferencedAssemblies 'System','System.Core' -ErrorAction Stop
                }
                # Build pattern info list with filename-only detection
                $PatternInfoList = @()
                foreach ($Pattern in $DllPatternsLocal) {
                    if ($Pattern) {
                        $Trimmed = $Pattern.Trim()
                        if ($Trimmed) {
                            $PatternInfoList += [pscustomobject]@{
                                PatternLower    = $Trimmed.ToLowerInvariant()
                                UseFileNameOnly = (-not ($Trimmed -match '[\\/]'))
                            }
                        }
                    }
                }
                if (-not $PatternInfoList) { return @() }
                # Reusable buffers for performance
                $ModulePathBuilder  = New-Object System.Text.StringBuilder 1024
                $ProcessPathBuilder = New-Object System.Text.StringBuilder 1024
                $PointerSize        = [IntPtr]::Size
                $ModuleHandles      = New-Object IntPtr[] 256
                $ProcessPathCache   = @{}
                $ProcessIdArray     = New-Object int[] 2048
                $BytesReturned      = 0
                # Get all process IDs from system
                if (-not [Win32Api]::EnumProcesses($ProcessIdArray, $ProcessIdArray.Length * 4, [ref]$BytesReturned)) { return @() }
                $ProcessCount     = [int]($BytesReturned / 4)
                $CollectedResults = @()
                # Iterate through all processes
                for ($ProcessIndex = 0; $ProcessIndex -lt $ProcessCount; $ProcessIndex++) {
                    $CurrentProcessId = $ProcessIdArray[$ProcessIndex]
                    if ($CurrentProcessId -eq 0) { continue }
                    $ProcessHandle = [IntPtr]::Zero
                    try {
                        # Open process with query and VM read rights
                        $AccessRights  = [Win32Api+ProcessAccessFlags]::PROCESS_QUERY_INFORMATION -bor [Win32Api+ProcessAccessFlags]::PROCESS_VM_READ
                        $ProcessHandle = [Win32Api]::OpenProcess($AccessRights, $false, $CurrentProcessId)
                        if ($ProcessHandle -eq [IntPtr]::Zero) { continue }
                        # Enumerate loaded modules
                        $RequiredBytes = 0
                        $FilterOption  = [Win32Api+ListModulesOptions]::LIST_MODULES_ALL
                        $BufferSize    = $ModuleHandles.Length * $PointerSize
                        if (-not [Win32Api]::EnumProcessModulesEx($ProcessHandle, $ModuleHandles, $BufferSize, [ref]$RequiredBytes, $FilterOption)) { continue }
                        # Resize buffer if needed
                        if ($RequiredBytes -gt $BufferSize) {
                            $ModuleHandles = New-Object IntPtr[] ([int][math]::Ceiling($RequiredBytes / [double]$PointerSize))
                            $BufferSize    = $ModuleHandles.Length * $PointerSize
                            if (-not [Win32Api]::EnumProcessModulesEx($ProcessHandle, $ModuleHandles, $BufferSize, [ref]$RequiredBytes, $FilterOption)) { continue }
                        }
                        $ModuleCount = [int]($RequiredBytes / $PointerSize)
                        # Iterate through all modules of this process
                        for ($ModuleIndex = 0; $ModuleIndex -lt $ModuleCount; $ModuleIndex++) {
                            $CurrentModuleHandle = $ModuleHandles[$ModuleIndex]
                            [void]$ModulePathBuilder.Remove(0, $ModulePathBuilder.Length)
                            [void][Win32Api]::GetModuleFileNameEx($ProcessHandle, $CurrentModuleHandle, $ModulePathBuilder, [uint32]$ModulePathBuilder.Capacity)
                            $ModuleFullPath = $ModulePathBuilder.ToString()
                            if ([string]::IsNullOrEmpty($ModuleFullPath)) { continue }
                            $ModulePathLower = $ModuleFullPath.ToLowerInvariant()
                            $ModuleFileLower = [System.IO.Path]::GetFileName($ModulePathLower)
                            # Pattern matching
                            $IsMatch = $false
                            foreach ($PatternInfo in $PatternInfoList) {
                                if ($PatternInfo.UseFileNameOnly) {
                                    if ($ModuleFileLower -like $PatternInfo.PatternLower) { $IsMatch = $true; break }
                                } else {
                                    if ($ModulePathLower -like $PatternInfo.PatternLower) { $IsMatch = $true; break }
                                }
                            }
                            if (-not $IsMatch) { continue }
                            # Retrieve process path from cache or API
                            $ProcessFullPath = $ProcessPathCache[$CurrentProcessId]
                            if (-not $ProcessFullPath) {
                                [void]$ProcessPathBuilder.Remove(0, $ProcessPathBuilder.Length)
                                $PathLength = $ProcessPathBuilder.Capacity
                                if ([Environment]::OSVersion.Version.Major -ge 6 -and [Win32Api]::QueryFullProcessImageName($ProcessHandle, 0, $ProcessPathBuilder, [ref]$PathLength)) {
                                    $ProcessFullPath = $ProcessPathBuilder.ToString()
                                } else {
                                    try {
                                        $WmiProcess = Get-WmiObject -Class Win32_Process -Filter "ProcessId=$CurrentProcessId" -ErrorAction Stop
                                        $ProcessFullPath = if ($WmiProcess.ExecutablePath) { $WmiProcess.ExecutablePath } else { $WmiProcess.Name }
                                    } catch { $ProcessFullPath = 'N/A' }
                                }
                                $ProcessPathCache[$CurrentProcessId] = $ProcessFullPath
                            }
                            $CollectedResults += [pscustomobject]@{ ProcessFullPath = $ProcessFullPath; DllFullPath = $ModuleFullPath }
                        }
                    } finally {
                        if ($ProcessHandle -ne [IntPtr]::Zero) { [void][Win32Api]::CloseHandle($ProcessHandle) }
                    }
                }
                $CollectedResults
            }
            # Execute locally or remotely
            $IsLocalComputer = ($TargetComputer -eq $env:COMPUTERNAME -or $TargetComputer -eq 'localhost' -or $TargetComputer -eq '.')
            if ($IsLocalComputer) { return & $ScanScriptBlock -DllPatternsLocal $Patterns -CSharpSourceLocal $CSharpSource }
            $InvokeArgs = @{ ComputerName = $TargetComputer; ErrorAction = 'Stop'; ScriptBlock = $ScanScriptBlock; ArgumentList = @(,$Patterns), $CSharpSource }
            if ($CredentialObject) { $InvokeArgs['Credential'] = $CredentialObject }
            Invoke-Command @InvokeArgs
        }).AddArgument($Computer).AddArgument($Credential).AddArgument($DllPatterns).AddArgument($CSharpCode)
        $PowerShellInstance.RunspacePool = $RunspacePool
        $RunningJobs += @{ Computer = $Computer; PowerShell = $PowerShellInstance; AsyncHandle = $PowerShellInstance.BeginInvoke() }
    }
    # Tracking structures for ordered display with timeout
    $PollingStartTime     = Get-Date
    $CompletedResults     = @{}
    $DisplayedComputers   = @{}
    $TimeoutReached       = $false
    # Polling loop with ordered display until timeout
    while ($RunningJobs.Count -gt 0 -or ($CompletedResults.Count - $DisplayedComputers.Count) -gt 0) {
        $ElapsedSeconds = ((Get-Date) - $PollingStartTime).TotalSeconds
        # Collect completed jobs without displaying yet
        $StillRunningJobs = @()
        foreach ($Job in $RunningJobs) {
            if ($Job.AsyncHandle.IsCompleted) {
                $Computer = $Job.Computer
                try {
                    $ResultData = @($Job.PowerShell.EndInvoke($Job.AsyncHandle))
                    $CompletedResults[$Computer] = @{ Success = $true; Data = $ResultData; Error = $null }
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    if ($_.Exception.InnerException) { $ErrorMessage += " :: " + $_.Exception.InnerException.Message }
                    # Detect access denied by finding PSRemotingTransportException.ErrorCode = 5
                    $IsAccessDenied = $false
                    $CurrentException = $_.Exception
                    while ($CurrentException -and -not $IsAccessDenied) {
                        if ($CurrentException.PSObject.Properties['ErrorRecord'] -and $CurrentException.ErrorRecord.Exception) {
                            $EmbeddedException = $CurrentException.ErrorRecord.Exception
                            if ($EmbeddedException.GetType().Name -eq 'PSRemotingTransportException' -and $EmbeddedException.ErrorCode -eq 5) {
                                $IsAccessDenied = $true
                            }
                        }
                        $CurrentException = $CurrentException.InnerException
                    }
                    if ($IsAccessDenied) { $script:Credentials = $null } # Reset auto-credential if denied access
                    $CompletedResults[$Computer] = @{ Success = $false; Data = $null; Error = $ErrorMessage }
                }
                $Job.PowerShell.Dispose()
            } else { $StillRunningJobs += $Job }
        }
        $RunningJobs = $StillRunningJobs
        # Check if timeout reached
        if (-not $TimeoutReached -and $ElapsedSeconds -ge $SortingTimeout) { $TimeoutReached = $true }
        # Display results respecting original order
        foreach ($Computer in $ComputerNames) {
            if ($DisplayedComputers.ContainsKey($Computer)) { continue }
            # Handle unreachable computers in sequence
            if ($UnreachableComputers.ContainsKey($Computer)) {
                if ($TimeoutReached -or $CompletedResults.ContainsKey($ComputerNames[([Array]::IndexOf($ComputerNames,$Computer)+1) % $ComputerNames.Count]) -or $RunningJobs.Count -eq 0) {
                    Write-Host "`n`n==========  $Computer  =========="
                    Write-Host ("  Host {0} not reachable (skipping)." -f $Computer) -ForegroundColor DarkGray
                    $DisplayedComputers[$Computer] = $true
                } elseif (-not $TimeoutReached) { break }
                continue
            }
            # Handle completed results
            if ($CompletedResults.ContainsKey($Computer)) {
                Write-Host "`n`n==========  $Computer  =========="
                $StoredResult = $CompletedResults[$Computer]
                if ($StoredResult.Success) {
                    $ResultData = $StoredResult.Data
                    if ($ResultData.Count -gt 0) {
                        $DisplayIndex = 0
                        foreach ($Result in ($ResultData | Sort-Object ProcessFullPath, DllFullPath -Unique)) {
                            if ($DisplayIndex -gt 0) { Write-Host "  -------" }
                            Write-Host ("  DLL     = {0}" -f $Result.DllFullPath) -ForegroundColor Yellow
                            Write-Host ("  Process = {0}" -f $Result.ProcessFullPath) -ForegroundColor Cyan
                            $DisplayIndex++
                        }
                    } else { Write-Host ("  No matching DLL found on {0}." -f $Computer) -ForegroundColor Gray }
                } else { Write-Host ("  Error on {0} : {1}" -f $Computer, $StoredResult.Error) -ForegroundColor Red }
                $DisplayedComputers[$Computer] = $true
            } elseif (-not $TimeoutReached) { break }
        }
        if ($RunningJobs.Count -gt 0) { Start-Sleep -Milliseconds 100 }
    }
    # Cleanup resources
    $RunspacePool.Close()
    $RunspacePool.Dispose()
    Write-Host "`n"
}


Find-ProcessByDll -DllPatterns $DllPatterns -ComputerNames $ComputerNames -Credential $Credential -MaxThreads $MaxThreads -SortingTimeout $SortingTimeout
Read-Host
