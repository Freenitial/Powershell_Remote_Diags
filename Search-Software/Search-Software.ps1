[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,Position=0)][string[]]$DisplayNames,
    [Parameter(Mandatory=$false,Position=1)][string[]]$ComputerNames = @($env:COMPUTERNAME),
    [System.Management.Automation.PSCredential]$Credential = $null,
    [int]$MaxThreads = 10,
    [int]$SortingTimeout = 6
)

function Search-Software {
    <#
    .SYNOPSIS
        Author  : Leo Gillet / Freenitial on GitHub
        Version : v1.0
        Search local or remote computers for installed software
        by matching display names in the Windows registry.
    .PARAMETER DisplayNames
        One or more search strings to match against software display names.
        Wildcards are automatically wrapped around each pattern.
        Example: -DisplayNames "Visual C++",Chrome
    .PARAMETER ComputerNames
        Optional. Array of computer names to scan. Defaults to the
        current machine. Uses port 445 (SMB) to test connectivity
        before attempting remote execution.
    .NOTES
        - Enumerates both 64-bit and WOW6432Node registry paths
        - Returns display name, version, bitness, and uninstall strings
        - Requires administrative rights on target machines for remote results
    #>
    param(
        [Parameter(Mandatory=$true)][string[]]$DisplayNames,
        [string[]]$ComputerNames = @($env:COMPUTERNAME),
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
    # Build list of reachable computers while tracking unreachable ones in order
    $ReachableComputers   = New-Object System.Collections.ArrayList
    $UnreachableComputers = @{}
    foreach ($Computer in $ComputerNames) {
        $IsLocalComputer = ($Computer -eq $env:COMPUTERNAME -or $Computer -eq 'localhost' -or $Computer -eq '.')
        if ($IsLocalComputer -or (Test-ComputerAvailable $Computer)) { [void]$ReachableComputers.Add($Computer) }
        else { $UnreachableComputers[$Computer] = $true }
    }
    if ($ReachableComputers.Count -eq 0 -and $UnreachableComputers.Count -eq 0) { Write-Host "`n"; return }
    # Create RunspacePool for parallel execution
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
    $RunspacePool.Open()
    # Launch all parallel jobs
    $RunningJobs = New-Object System.Collections.ArrayList
    foreach ($Computer in $ReachableComputers) {
        $PowerShellInstance = [PowerShell]::Create().AddScript({
            param($TargetComputer, $CredentialObject, $Patterns)
            # ScriptBlock containing the actual scan logic
            $ScanScriptBlock = {
                param([string[]]$SearchPatterns)
                $WildcardPatterns = New-Object System.Collections.ArrayList
                foreach ($Pattern in $SearchPatterns) { if ($Pattern) { $Trimmed = $Pattern.Trim(); if ($Trimmed) { [void]$WildcardPatterns.Add('*'+$Trimmed+'*') } } }
                if ($WildcardPatterns.Count -eq 0) { return @() }
                # Registry base paths with bitness metadata
                $RegistryBases = @(
                    @{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';              IsWow = $false }
                    @{ Path = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall';  IsWow = $true }
                )
                $LocalMachine     = [Microsoft.Win32.Registry]::LocalMachine
                $CollectedEntries = New-Object System.Collections.ArrayList
                # Enumerate registry keys via .NET for performance
                foreach ($Base in $RegistryBases) {
                    $ParentKey = $null
                    try { $ParentKey = $LocalMachine.OpenSubKey($Base.Path) } catch {}
                    if (-not $ParentKey) { continue }
                    try {
                        foreach ($SubKeyName in $ParentKey.GetSubKeyNames()) {
                            $SubKey = $null
                            try { $SubKey = $ParentKey.OpenSubKey($SubKeyName) } catch {}
                            if (-not $SubKey) { continue }
                            try {
                                $EntryDisplayName = $SubKey.GetValue('DisplayName')
                                if (-not $EntryDisplayName) { continue }
                                # Pattern matching against display name
                                $IsMatch = $false
                                foreach ($Pat in $WildcardPatterns) { if ($EntryDisplayName -like $Pat) { $IsMatch = $true; break } }
                                if (-not $IsMatch) { continue }
                                $EntryUninstallString      = $SubKey.GetValue('UninstallString')
                                $EntryQuietUninstall       = $SubKey.GetValue('QuietUninstallString')
                                $EntryModifyPath           = $SubKey.GetValue('ModifyPath')
                                if (-not $EntryUninstallString -and -not $EntryQuietUninstall -and -not $EntryModifyPath) { continue }
                                $Bitness  = if ($Base.IsWow) { '32-bit' } else { '64-bit' }
                                $BitOrder = if ($Base.IsWow) { 1 } else { 0 }
                                [void]$CollectedEntries.Add((New-Object PSObject -Property @{
                                    DisplayName          = $EntryDisplayName
                                    DisplayVersion       = ($SubKey.GetValue('DisplayVersion') -as [string])
                                    RegistryKeyPath      = "HKLM\$($Base.Path)\$SubKeyName"
                                    Bitness              = $Bitness
                                    BitOrder             = $BitOrder
                                    UninstallString      = $EntryUninstallString
                                    QuietUninstallString = $EntryQuietUninstall
                                    ModifyPath           = $EntryModifyPath
                                }))
                            } finally { $SubKey.Close() }
                        }
                    } finally { $ParentKey.Close() }
                }
                $CollectedEntries
            }
            # Execute locally or remotely
            $IsLocalComputer = ($TargetComputer -eq $env:COMPUTERNAME -or $TargetComputer -eq 'localhost' -or $TargetComputer -eq '.')
            if ($IsLocalComputer) { return & $ScanScriptBlock -SearchPatterns $Patterns }
            $InvokeArgs = @{ ComputerName = $TargetComputer; ErrorAction = 'Stop'; ScriptBlock = $ScanScriptBlock; ArgumentList = @(,$Patterns) }
            if ($CredentialObject) { $InvokeArgs['Credential'] = $CredentialObject }
            Invoke-Command @InvokeArgs
        }).AddArgument($Computer).AddArgument($Credential).AddArgument($DisplayNames)
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
                    $ResultData = @($Job.PowerShell.EndInvoke($Job.AsyncHandle))
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
                        # Group results by DisplayName
                        $GroupedByName = @{}
                        foreach ($Entry in $ResultData) {
                            $Name = $Entry.DisplayName
                            if (-not $GroupedByName.ContainsKey($Name)) { $GroupedByName[$Name] = New-Object System.Collections.ArrayList }
                            [void]$GroupedByName[$Name].Add($Entry)
                        }
                        $SortedNames = @($GroupedByName.Keys)
                        [Array]::Sort($SortedNames, [StringComparer]::InvariantCultureIgnoreCase)
                        foreach ($Name in $SortedNames) {
                            Write-Host ""; Write-Host ("> " + $Name) -ForegroundColor White -BackgroundColor Black
                            foreach ($BitValue in 0,1) {
                                foreach ($Entry in $GroupedByName[$Name]) {
                                    if ($Entry.BitOrder -ne $BitValue) { continue }
                                    $PathColor = if ($Entry.Bitness -eq '64-bit') { 'Green' } else { 'Cyan' }
                                    Write-Host ("  " + $Entry.RegistryKeyPath) -ForegroundColor $PathColor
                                    $VersionDisplay = if ($Entry.DisplayVersion) { $Entry.DisplayVersion } else { '-' }
                                    Write-Host ("  " + $VersionDisplay) -ForegroundColor Yellow
                                    # Display uninstall commands with ModifyPath fallback
                                    if ($Entry.UninstallString -or $Entry.QuietUninstallString) {
                                        if ($Entry.UninstallString)      { Write-Host ("  "              + $Entry.UninstallString)      -ForegroundColor DarkYellow }
                                        if ($Entry.QuietUninstallString) { Write-Host ("  "              + $Entry.QuietUninstallString) -ForegroundColor Magenta }
                                    } elseif ($Entry.ModifyPath)         { Write-Host ("  [ModifyPath] " + $Entry.ModifyPath)           -ForegroundColor DarkYellow
                                    } else                               { Write-Host  "  No uninstall command provided"                -ForegroundColor DarkGray }
                                }
                            }
                        }
                    } else { Write-Host ("  No matching software found on {0}." -f $Computer) -ForegroundColor Gray }
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
Set-Alias -Name ssft -Value Search-Software

Search-Software -DisplayNames $DisplayNames -ComputerNames $ComputerNames -Credential $Credential -MaxThreads $MaxThreads -SortingTimeout $SortingTimeout
Read-Host
