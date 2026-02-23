[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,Position=0)][string[]]$Patterns,
    [Parameter(Mandatory=$false,Position=1)][string[]]$ComputerNames = @($env:COMPUTERNAME),
    [System.Management.Automation.PSCredential]$Credential = $null,
    [int]$MaxThreads = 10,
    [int]$SortingTimeout = 6
)

function Search-DLLprocess {
    <#
    .SYNOPSIS
        Author  : Leo Gillet / Freenitial on GitHub
        Version : v1.2 
        Scan local or remote computers to find which processes loaded
        specific DLLs, or which DLLs a specific process has loaded.
    .PARAMETER Patterns
        One or more processName.exe, or DLL paths/filenames
        Example: -Patterns mspmsnsv.dll,"C:\Windows\System32\*.dll",chrome.exe
    .PARAMETER TargetComputerNames
        Optional. Array of computer names to scan. Defaults to the
        current machine. Uses port 445 (SMB) to test connectivity
        before attempting remote execution.
    .NOTES
        - Uses low-level API calls for performance
        - Requires administrative rights on target machines for full results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)][string[]]$Patterns,
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
    if (-not $Patterns) { return }
    # Validate that every pattern explicitly ends with .dll or .exe
    foreach ($RawPattern in $Patterns) {
        if ($RawPattern) {
            $TrimmedPattern = $RawPattern.Trim()
            if ($TrimmedPattern) {
                $LowerValidation = $TrimmedPattern.ToLowerInvariant()
                if (-not ($LowerValidation.EndsWith('.dll') -or $LowerValidation.EndsWith('.exe'))) {
                    Write-Host ("Error : Pattern '{0}' must end with .dll or .exe" -f $TrimmedPattern) -ForegroundColor Red
                    return
                }
            }
        }
    }
    # Auto-credential prompt when IP addresses are detected
    if (-not $Credential) {
        foreach ($ComputerName in $ComputerNames) {
            $ParsedIp = $null
            if ([System.Net.IPAddress]::TryParse($ComputerName,[ref]$ParsedIp)) {
                if (-not $script:Credentials) { $script:Credentials = Get-Credential -Message "Search by IP needs credentials" }
                $Credential = $script:Credentials
                break
            }
        }
    }
    # C# P/Invoke definitions for process and module enumeration
    $CSharpCode = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Win32Api {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcesses([MarshalAs(UnmanagedType.LPArray)] int[] processIds, int size, out int bytesReturned);
    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, out int lpcbNeeded);
    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, out int lpcbNeeded, uint dwFilterFlag);
    [DllImport("psapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpBaseName, uint nSize);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);
}
"@
    if (-not ([System.Management.Automation.PSTypeName]'Win32Api').Type) {
        try { Add-Type -TypeDefinition $CSharpCode } catch { return }
    }
    # Determine search mode flags for display messages
    $HasExeSearch = $false
    $HasDllSearch = $false
    foreach ($PatternCheck in $Patterns) {
        if ($PatternCheck) {
            $LowerCheck = $PatternCheck.Trim().ToLowerInvariant()
            if ($LowerCheck.EndsWith('.exe')) { $HasExeSearch = $true }
            elseif ($LowerCheck.EndsWith('.dll')) { $HasDllSearch = $true }
        }
    }
    # Build list of reachable computers while tracking unreachable ones in order
    $ReachableComputers   = New-Object System.Collections.ArrayList
    $UnreachableComputers = @{}
    foreach ($Computer in $ComputerNames) {
        $IsLocalComputer = ($Computer -eq $env:COMPUTERNAME -or $Computer -eq 'localhost' -or $Computer -eq '.')
        if ($IsLocalComputer -or (Test-ComputerAvailable $Computer)) { [void]$ReachableComputers.Add($Computer) }
        else                                                         { $UnreachableComputers[$Computer] = $true }
    }
    if ($ReachableComputers.Count -eq 0 -and $UnreachableComputers.Count -eq 0) { Write-Host "`n"; return }
    # Create RunspacePool for parallel execution
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
    $RunspacePool.Open()
    # Launch all parallel jobs
    $RunningJobs = New-Object System.Collections.ArrayList
    foreach ($Computer in $ReachableComputers) {
        $PowerShellInstance = [PowerShell]::Create().AddScript({
            param($TargetComputer, $CredentialObject, $InputPatterns, $CSharpSource)
            # ScriptBlock containing the actual scan logic (DLL and EXE modes)
            $ScanScriptBlock = {
                param([string[]]$PatternsLocal, [string]$CSharpSourceLocal)
                # Ensure Win32Api type is loaded via Add-Type in remote session
                if (-not ([System.Management.Automation.PSTypeName]'Win32Api').Type) {
                    Add-Type -TypeDefinition $CSharpSourceLocal
                }
                # Classify patterns into EXE search and DLL search lists
                $ExePatternInfoList = New-Object System.Collections.ArrayList
                $DllPatternInfoList = New-Object System.Collections.ArrayList
                foreach ($Pattern in $PatternsLocal) {
                    if ($Pattern) {
                        $Trimmed = $Pattern.Trim()
                        if ($Trimmed) {
                            $LowerPattern = $Trimmed.ToLowerInvariant()
                            $HasWildcard  = ($LowerPattern.IndexOf('*') -ge 0 -or $LowerPattern.IndexOf('?') -ge 0)
                            $PatternInfoObject = [pscustomobject]@{
                                PatternLower    = $LowerPattern
                                UseFileNameOnly = (-not ($Trimmed -match '[\\/]'))
                                IsExactMatch    = (-not $HasWildcard)
                            }
                            if ($LowerPattern.EndsWith('.exe')) { [void]$ExePatternInfoList.Add($PatternInfoObject) }
                            else                                { [void]$DllPatternInfoList.Add($PatternInfoObject) }
                        }
                    }
                }
                if ($ExePatternInfoList.Count -eq 0 -and $DllPatternInfoList.Count -eq 0) { return @() }
                # Detect Vista+ for API selection (XP fallback support)
                $IsVistaOrLater = ([Environment]::OSVersion.Version.Major -ge 6)
                # Process access rights and module enumeration constants
                $AccessQueryAndRead = [uint32]0x0410
                $ListModulesAll     = [uint32]0x03
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
                $CollectedResults = New-Object System.Collections.ArrayList
                # Iterate through all processes
                for ($ProcessIndex = 0; $ProcessIndex -lt $ProcessCount; $ProcessIndex++) {
                    $CurrentProcessId = $ProcessIdArray[$ProcessIndex]
                    if ($CurrentProcessId -eq 0) { continue }
                    $ProcessHandle = [IntPtr]::Zero
                    try {
                        # Open process with query and VM read rights
                        $ProcessHandle = [Win32Api]::OpenProcess($AccessQueryAndRead, $false, $CurrentProcessId)
                        if ($ProcessHandle -eq [IntPtr]::Zero) { continue }
                        # Resolve process path early only when EXE patterns require it
                        $ProcessFullPath  = $null
                        $ProcessPathLower = $null
                        $ProcessFileLower = $null
                        $IsExeMatch       = $false
                        if ($ExePatternInfoList.Count -gt 0) {
                            $ProcessFullPath = $ProcessPathCache[$CurrentProcessId]
                            if (-not $ProcessFullPath) {
                                if ($IsVistaOrLater) {
                                    $ProcessPathBuilder.Length = 0
                                    $PathLength = $ProcessPathBuilder.Capacity
                                    if ([Win32Api]::QueryFullProcessImageName($ProcessHandle, 0, $ProcessPathBuilder, [ref]$PathLength)) { $ProcessFullPath = $ProcessPathBuilder.ToString() }
                                }
                                if (-not $ProcessFullPath) {
                                    $ProcessPathBuilder.Length = 0
                                    $CharsCopied = [Win32Api]::GetModuleFileNameEx($ProcessHandle, [IntPtr]::Zero, $ProcessPathBuilder, [uint32]$ProcessPathBuilder.Capacity)
                                    if ($CharsCopied -gt 0) { $ProcessFullPath = $ProcessPathBuilder.ToString() }
                                }
                                if (-not $ProcessFullPath) {
                                    try {
                                        $WmiProcess = Get-WmiObject -Class Win32_Process -Filter "ProcessId=$CurrentProcessId" -ErrorAction Stop
                                        $ProcessFullPath = if ($WmiProcess.ExecutablePath) { $WmiProcess.ExecutablePath } else { $WmiProcess.Name }
                                    } catch { $ProcessFullPath = 'N/A' }
                                }
                                $ProcessPathCache[$CurrentProcessId] = $ProcessFullPath
                            }
                            # Match process path against EXE patterns
                            if ($ProcessFullPath -ne 'N/A') {
                                $ProcessPathLower     = $ProcessFullPath.ToLowerInvariant()
                                $ProcessLastSeparator = $ProcessPathLower.LastIndexOf('\')
                                $ProcessFileLower     = if ($ProcessLastSeparator -ge 0) { $ProcessPathLower.Substring($ProcessLastSeparator + 1) } else { $ProcessPathLower }
                                foreach ($PatternInfo in $ExePatternInfoList) {
                                    if ($PatternInfo.UseFileNameOnly) {
                                        if ($PatternInfo.IsExactMatch) { if ($ProcessFileLower -eq $PatternInfo.PatternLower)   { $IsExeMatch = $true; break } }
                                        else                           { if ($ProcessFileLower -like $PatternInfo.PatternLower) { $IsExeMatch = $true; break } }
                                    } else {
                                        if ($PatternInfo.IsExactMatch) { if ($ProcessPathLower -eq $PatternInfo.PatternLower)   { $IsExeMatch = $true; break } }
                                        else                           { if ($ProcessPathLower -like $PatternInfo.PatternLower) { $IsExeMatch = $true; break } }
                                    }
                                }
                            }
                            # Skip module enumeration entirely when no EXE match and no DLL patterns
                            if (-not $IsExeMatch -and $DllPatternInfoList.Count -eq 0) { continue }
                        }
                        # Enumerate loaded modules with OS-appropriate API
                        $RequiredBytes = 0
                        $BufferSize    = $ModuleHandles.Length * $PointerSize
                        if ($IsVistaOrLater) { $EnumSuccess = [Win32Api]::EnumProcessModulesEx($ProcessHandle, $ModuleHandles, $BufferSize, [ref]$RequiredBytes, $ListModulesAll) }
                        else                 { $EnumSuccess = [Win32Api]::EnumProcessModules($ProcessHandle, $ModuleHandles, $BufferSize, [ref]$RequiredBytes) }
                        if (-not $EnumSuccess) { continue }
                        # Resize buffer if needed
                        if ($RequiredBytes -gt $BufferSize) {
                            $ModuleHandles = New-Object IntPtr[] ([int][math]::Ceiling($RequiredBytes / [double]$PointerSize))
                            $BufferSize    = $ModuleHandles.Length * $PointerSize
                            if ($IsVistaOrLater) { $EnumSuccess = [Win32Api]::EnumProcessModulesEx($ProcessHandle, $ModuleHandles, $BufferSize, [ref]$RequiredBytes, $ListModulesAll) }
                            else                 { $EnumSuccess = [Win32Api]::EnumProcessModules($ProcessHandle, $ModuleHandles, $BufferSize, [ref]$RequiredBytes) }
                            if (-not $EnumSuccess) { continue }
                        }
                        $ModuleCount = [int]($RequiredBytes / $PointerSize)
                        # Single pass through all modules for both EXE and DLL modes
                        for ($ModuleIndex = 0; $ModuleIndex -lt $ModuleCount; $ModuleIndex++) {
                            $CurrentModuleHandle = $ModuleHandles[$ModuleIndex]
                            $ModulePathBuilder.Length = 0
                            [void][Win32Api]::GetModuleFileNameEx($ProcessHandle, $CurrentModuleHandle, $ModulePathBuilder, [uint32]$ModulePathBuilder.Capacity)
                            $ModuleFullPath = $ModulePathBuilder.ToString()
                            if ([string]::IsNullOrEmpty($ModuleFullPath)) { continue }
                            $ModulePathLower = $ModuleFullPath.ToLowerInvariant()
                            # EXE mode : collect all loaded modules for matched process
                            if ($IsExeMatch) {
                                if ($ModulePathLower -ne $ProcessPathLower) {
                                    [void]$CollectedResults.Add(@($ProcessFullPath, $ModuleFullPath, 'exe'))
                                }
                            }
                            # DLL mode : match module against DLL patterns
                            if ($DllPatternInfoList.Count -gt 0) {
                                $LastSeparatorIndex = $ModulePathLower.LastIndexOf('\')
                                $ModuleFileLower    = if ($LastSeparatorIndex -ge 0) { $ModulePathLower.Substring($LastSeparatorIndex + 1) } else { $ModulePathLower }
                                $IsDllMatch = $false
                                foreach ($PatternInfo in $DllPatternInfoList) {
                                    if ($PatternInfo.UseFileNameOnly) {
                                        if ($PatternInfo.IsExactMatch) { if ($ModuleFileLower -eq $PatternInfo.PatternLower)   { $IsDllMatch = $true; break } }
                                        else                           { if ($ModuleFileLower -like $PatternInfo.PatternLower) { $IsDllMatch = $true; break } }
                                    } else {
                                        if ($PatternInfo.IsExactMatch) { if ($ModulePathLower -eq $PatternInfo.PatternLower)   { $IsDllMatch = $true; break } }
                                        else                           { if ($ModulePathLower -like $PatternInfo.PatternLower) { $IsDllMatch = $true; break } }
                                    }
                                }
                                if ($IsDllMatch) {
                                    # Lazy process path resolution for DLL mode
                                    if (-not $ProcessFullPath) {
                                        $ProcessFullPath = $ProcessPathCache[$CurrentProcessId]
                                        if (-not $ProcessFullPath) {
                                            if ($IsVistaOrLater) {
                                                $ProcessPathBuilder.Length = 0
                                                $PathLength = $ProcessPathBuilder.Capacity
                                                if ([Win32Api]::QueryFullProcessImageName($ProcessHandle, 0, $ProcessPathBuilder, [ref]$PathLength)) { $ProcessFullPath = $ProcessPathBuilder.ToString() }
                                            }
                                            if (-not $ProcessFullPath) {
                                                $ProcessPathBuilder.Length = 0
                                                $CharsCopied = [Win32Api]::GetModuleFileNameEx($ProcessHandle, [IntPtr]::Zero, $ProcessPathBuilder, [uint32]$ProcessPathBuilder.Capacity)
                                                if ($CharsCopied -gt 0) { $ProcessFullPath = $ProcessPathBuilder.ToString() }
                                            }
                                            if (-not $ProcessFullPath) {
                                                try {
                                                    $WmiProcess = Get-WmiObject -Class Win32_Process -Filter "ProcessId=$CurrentProcessId" -ErrorAction Stop
                                                    $ProcessFullPath = if ($WmiProcess.ExecutablePath) { $WmiProcess.ExecutablePath } else { $WmiProcess.Name }
                                                } catch { $ProcessFullPath = 'N/A' }
                                            }
                                            $ProcessPathCache[$CurrentProcessId] = $ProcessFullPath
                                        }
                                    }
                                    [void]$CollectedResults.Add(@($ProcessFullPath, $ModuleFullPath, 'dll'))
                                }
                            }
                        }
                    } finally { if ($ProcessHandle -ne [IntPtr]::Zero) { [void][Win32Api]::CloseHandle($ProcessHandle) } }
                }
                $CollectedResults
            }
            # Execute locally or remotely
            $IsLocalComputer = ($TargetComputer -eq $env:COMPUTERNAME -or $TargetComputer -eq 'localhost' -or $TargetComputer -eq '.')
            if ($IsLocalComputer) { return & $ScanScriptBlock -PatternsLocal $InputPatterns -CSharpSourceLocal $CSharpSource }
            $InvokeArgs = @{ ComputerName = $TargetComputer; ErrorAction = 'Stop'; ScriptBlock = $ScanScriptBlock; ArgumentList = @(,$InputPatterns), $CSharpSource }
            if ($CredentialObject) { $InvokeArgs['Credential'] = $CredentialObject }
            Invoke-Command @InvokeArgs
        }).AddArgument($Computer).AddArgument($Credential).AddArgument($Patterns).AddArgument($CSharpCode)
        $PowerShellInstance.RunspacePool = $RunspacePool
        [void]$RunningJobs.Add(@{ Computer = $Computer; PowerShell = $PowerShellInstance; AsyncHandle = $PowerShellInstance.BeginInvoke() })
    }
    # Tracking structures for ordered display with timeout
    $PollingStartTime     = Get-Date
    $CompletedResults     = @{}
    $DisplayedComputers   = @{}
    $TimeoutReached       = $false
    # Polling loop with ordered display until timeout
    while ($DisplayedComputers.Count -lt $ComputerNames.Count) {
        $ElapsedSeconds = ((Get-Date) - $PollingStartTime).TotalSeconds
        # Collect completed jobs without displaying yet
        $StillRunningJobs = New-Object System.Collections.ArrayList
        foreach ($Job in $RunningJobs) {
            if ($Job.AsyncHandle.IsCompleted) {
                $Computer = $Job.Computer
                try {
                    $EndInvokeOutput = $Job.PowerShell.EndInvoke($Job.AsyncHandle)
                    $ResultData = New-Object System.Collections.ArrayList
                    if ($EndInvokeOutput) { foreach ($SingleItem in $EndInvokeOutput) { [void]$ResultData.Add($SingleItem) } }
                    $CompletedResults[$Computer] = @{ Success = $true; Data = $ResultData; Error = $null }
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    if ($_.Exception.InnerException) { $ErrorMessage += " :: " + $_.Exception.InnerException.Message }
                    # Walk exception chain to detect PSRemotingTransportException
                    $IsAccessDenied = $false
                    $IsWinRMFailure = $false
                    $CurrentException = $_.Exception
                    while ($CurrentException) {
                        if ($CurrentException.PSObject.Properties['ErrorRecord'] -and $CurrentException.ErrorRecord.Exception) {
                            $EmbeddedException = $CurrentException.ErrorRecord.Exception
                            if ($EmbeddedException.GetType().Name -eq 'PSRemotingTransportException') {
                                if ($EmbeddedException.ErrorCode -eq 5) { $IsAccessDenied = $true }
                                else { $IsWinRMFailure = $true }
                                break
                            }
                        }
                        if ($CurrentException.GetType().Name -eq 'PSRemotingTransportException') {
                            if ($CurrentException.PSObject.Properties['ErrorCode'] -and $CurrentException.ErrorCode -eq 5) { $IsAccessDenied = $true }
                            else { $IsWinRMFailure = $true }
                            break
                        }
                        $CurrentException = $CurrentException.InnerException
                    }
                    # Determine failure category and store appropriate message
                    if ($IsAccessDenied) {
                        $script:Credentials = $null
                        $CompletedResults[$Computer] = @{ Success = $false; Data = $null; Error = 'Access Denied' }
                    } elseif ($IsWinRMFailure) {
                        $CompletedResults[$Computer] = @{ Success = $false; Data = $null; Error = 'WinRM Failed' }
                    } else {
                        $CompletedResults[$Computer] = @{ Success = $false; Data = $null; Error = $ErrorMessage }
                    }
                }
                $Job.PowerShell.Dispose()
            } else { [void]$StillRunningJobs.Add($Job) }
        }
        $RunningJobs = $StillRunningJobs
        # Check if timeout reached
        if (-not $TimeoutReached -and $ElapsedSeconds -ge $SortingTimeout) { $TimeoutReached = $true }
        # Display results respecting original order
        foreach ($Computer in $ComputerNames) {
            if ($DisplayedComputers.ContainsKey($Computer)) { continue }
            # Handle unreachable computers in sequence
            if ($UnreachableComputers.ContainsKey($Computer)) {
                # Find next reachable computer to determine display readiness
                $NextReachableComputer = $null
                $ComputerIndex = [Array]::IndexOf($ComputerNames, $Computer)
                for ($SearchIndex = $ComputerIndex + 1; $SearchIndex -lt $ComputerNames.Count; $SearchIndex++) {
                    if (-not $UnreachableComputers.ContainsKey($ComputerNames[$SearchIndex])) {
                        $NextReachableComputer = $ComputerNames[$SearchIndex]
                        break
                    }
                }
                $CanDisplayUnreachable = $TimeoutReached -or $RunningJobs.Count -eq 0 -or ($NextReachableComputer -and $CompletedResults.ContainsKey($NextReachableComputer))
                if ($CanDisplayUnreachable) {
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
                        # Dedup and separate results by search mode (PS 2.0 compatible)
                        $SeenEntries    = @{}
                        $ExeModeResults = New-Object System.Collections.ArrayList
                        $DllModeResults = New-Object System.Collections.ArrayList
                        foreach ($RawResult in $ResultData) {
                            $SearchMode = if ($RawResult.Count -ge 3) { $RawResult[2] } else { 'dll' }
                            $DedupeKey  = '{0}|{1}|{2}' -f $RawResult[0], $RawResult[1], $SearchMode
                            if (-not $SeenEntries.ContainsKey($DedupeKey)) {
                                $SeenEntries[$DedupeKey] = $true
                                if ($SearchMode -eq 'exe') { [void]$ExeModeResults.Add($RawResult) }
                                else                       { [void]$DllModeResults.Add($RawResult) }
                            }
                        }
                        $DisplayIndex = 0
                        # EXE mode display : group loaded modules by process
                        if ($ExeModeResults.Count -gt 0) {
                            $GroupedByProcess = @{}
                            $ProcessDisplayOrder = New-Object System.Collections.ArrayList
                            foreach ($ExeResult in $ExeModeResults) {
                                $ProcPath = $ExeResult[0]
                                if (-not $GroupedByProcess.ContainsKey($ProcPath)) {
                                    $GroupedByProcess[$ProcPath] = New-Object System.Collections.ArrayList
                                    [void]$ProcessDisplayOrder.Add($ProcPath)
                                }
                                [void]$GroupedByProcess[$ProcPath].Add($ExeResult[1])
                            }
                            foreach ($ProcPath in ($ProcessDisplayOrder | Sort-Object)) {
                                if ($DisplayIndex -gt 0) { Write-Host "  -------" }
                                Write-Host ("  Process = {0}" -f $ProcPath) -ForegroundColor Cyan
                                foreach ($LoadedModule in ($GroupedByProcess[$ProcPath] | Sort-Object)) {
                                    Write-Host ("  DLL     = {0}" -f $LoadedModule) -ForegroundColor Yellow
                                }
                                $DisplayIndex++
                            }
                        }
                        # DLL mode display : show matching dll-process pairs
                        if ($DllModeResults.Count -gt 0) {
                            $SortedDllResults = $DllModeResults | Sort-Object { $_[0] }, { $_[1] }
                            # Prevent single-result unrolling by foreach
                            if ($DllModeResults.Count -eq 1) { $SortedDllResults = @(,$SortedDllResults) }
                            foreach ($DllResult in $SortedDllResults) {
                                if ($DisplayIndex -gt 0) { Write-Host "  -------" }
                                Write-Host ("  DLL     = {0}" -f $DllResult[1]) -ForegroundColor Yellow
                                Write-Host ("  Process = {0}" -f $DllResult[0]) -ForegroundColor Cyan
                                $DisplayIndex++
                            }
                        }
                    } else {
                        # Context-aware empty result message
                        if     ($HasExeSearch -and -not $HasDllSearch) { Write-Host ("  No matching process found on {0}." -f $Computer) -ForegroundColor Gray }
                        elseif ($HasDllSearch -and -not $HasExeSearch) { Write-Host ("  No matching DLL found on {0}." -f $Computer) -ForegroundColor Gray }
                        else                                           { Write-Host ("  No match found on {0}." -f $Computer) -ForegroundColor Gray }
                    }
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
Set-Alias -Name sdll -Value Search-DLLprocess

Search-DLLprocess -Patterns $Patterns -ComputerNames $ComputerNames -Credential $Credential -MaxThreads $MaxThreads -SortingTimeout $SortingTimeout
$message = "Search Complete. Press Any Key to Exit."
Write-Host $message -NoNewline
$null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ("`r" + (" " * $message.Length) + "`r") -NoNewline
