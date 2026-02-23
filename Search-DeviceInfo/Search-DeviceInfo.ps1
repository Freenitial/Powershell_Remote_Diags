[CmdletBinding()]
param(
    [Parameter(Mandatory=$false,Position=0)][string[]]$ComputerNames = @($env:COMPUTERNAME),
    [System.Management.Automation.PSCredential]$Credential = $null,
    [int]$MaxThreads = 10,
    [int]$SortingTimeout = 6
)

function Search-DeviceInfo {
    <#
    .SYNOPSIS
        Author  : Leo Gillet / Freenitial on GitHub
        Version : v1.0
        Gather system information and logged-on user sessions, local or remote.
    .PARAMETER ComputerNames
        Optional. Array of computer names to scan. Defaults to the
        current machine. Uses port 445 (SMB) to test connectivity
        before attempting remote execution.
    .NOTES
        - Reports OS version, build, uptime, free disk space, and pending reboot status
        - Enumerates user sessions via WTS API
        - Resolves Active Directory display names when domain-joined
        - Requires administrative rights on target machines for remote results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,Position=0)][string[]]$ComputerNames = @($env:COMPUTERNAME),
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
    # Resolve display name from Active Directory via local ADSI
    function Resolve-UserDisplayName {
        param([string]$UserName, [hashtable]$Cache)
        if ($Cache.ContainsKey($UserName)) { return $Cache[$UserName] }
        $DisplayName = ''
        try {
            $AdSearcher = [adsisearcher]"(samaccountname=$UserName)"
            $AdSearcher.PropertiesToLoad.Add('displayname') | Out-Null
            $AdResult = $AdSearcher.FindOne()
            if ($AdResult -and $AdResult.Properties['displayname']) {
                $DisplayName = $AdResult.Properties['displayname'][0]
            }
        } catch {}
        $Cache[$UserName] = $DisplayName
        return $DisplayName
    }
    # C# P/Invoke definitions for WTS session enumeration
    $WtsCSharpCode = @"
using System;
using System.Runtime.InteropServices;
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WtsSessionInfo {
    public int SessionId;
    [MarshalAs(UnmanagedType.LPTStr)]
    public string WinStationName;
    public int State;
}
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WtsInfoData {
    public int State;
    public int SessionId;
    public int IncomingBytes;
    public int OutgoingBytes;
    public int IncomingFrames;
    public int OutgoingFrames;
    public int IncomingCompressedBytes;
    public int OutgoingCompressedBytes;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string WinStationName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)]
    public string Domain;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)]
    public string UserName;
    public long ConnectTime;
    public long DisconnectTime;
    public long LastInputTime;
    public long LogonTime;
    public long CurrentTime;
}
public static class WtsNativeApi {
    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, ref IntPtr ppSessionInfo, ref int pCount);
    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, int wtsInfoClass, ref IntPtr ppBuffer, ref int pBytesReturned);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern void WTSFreeMemory(IntPtr pMemory);
}
"@
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
    # Ensure WTS types are loaded locally via Add-Type
    if (-not ([System.Management.Automation.PSTypeName]'WtsNativeApi').Type) {
        try { Add-Type -TypeDefinition $WtsCSharpCode } catch { return }
    }
    # Build list of reachable computers while tracking unreachable ones in order
    $ReachableComputers   = New-Object System.Collections.ArrayList
    $UnreachableComputers = @{}
    foreach ($Computer in $ComputerNames) {
        $IsLocalComputer = ($Computer -eq $env:COMPUTERNAME -or $Computer -eq 'localhost' -or $Computer -eq '.')
        if ($IsLocalComputer) {
            [void]$ReachableComputers.Add($Computer)
        } elseif (Test-ComputerAvailable $Computer) {
            [void]$ReachableComputers.Add($Computer)
        } else {
            $UnreachableComputers[$Computer] = $true
        }
    }
    if ($ReachableComputers.Count -eq 0 -and $UnreachableComputers.Count -eq 0) { Write-Host "`n"; return }
    # Check if local machine is domain-joined for display name resolution
    $IsDomainJoined = [bool]$env:USERDNSDOMAIN
    $DisplayNameCache = @{}
    # Create RunspacePool for parallel execution
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
    $RunspacePool.Open()
    # Launch all parallel jobs
    $RunningJobs = New-Object System.Collections.ArrayList
    foreach ($Computer in $ReachableComputers) {
        $PowerShellInstance = [PowerShell]::Create().AddScript({
            param($TargetComputer, $CredentialObject, $WtsCSharpSource)
            # ScriptBlock containing the actual info gathering logic
            $InfoScriptBlock = {
                param([string]$WtsCSharpSourceLocal)
                # Ensure WTS types are loaded via Add-Type in remote session
                if (-not ([System.Management.Automation.PSTypeName]'WtsNativeApi').Type) {
                    Add-Type -TypeDefinition $WtsCSharpSourceLocal
                }
                $IsVistaOrLater = ([Environment]::OSVersion.Version.Major -ge 6)
                # Check if a registry key exists via .NET
                function Test-RegistryKeyPresent {
                    param([string]$SubPath)
                    $RegistryKey = $null
                    try { $RegistryKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubPath) } catch {}
                    $KeyExists = ($RegistryKey -ne $null)
                    if ($RegistryKey) { $RegistryKey.Close() }
                    return $KeyExists
                }
                # Read a single value from a registry key via .NET
                function Get-RegistryKeyValue {
                    param([string]$SubPath, [string]$ValueName)
                    $RegistryKey = $null
                    try { $RegistryKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubPath) } catch {}
                    if (-not $RegistryKey) { return $null }
                    $Value = $null
                    try { $Value = $RegistryKey.GetValue($ValueName) } catch {}
                    $RegistryKey.Close()
                    return $Value
                }
                # Duration formatter (keeps only significant units)
                function Format-Duration {
                    param([TimeSpan]$Duration)
                    if ($Duration.TotalSeconds -lt 1) { return '-' }
                    $TotalDays = [int][math]::Floor($Duration.TotalDays)
                    $Hours = $Duration.Hours ; $Minutes = $Duration.Minutes ; $Seconds = $Duration.Seconds
                    $Components = @(
                        @{ Value = $TotalDays; Label = 'd' }
                        @{ Value = $Hours;     Label = 'h' }
                        @{ Value = $Minutes;   Label = 'm' }
                        @{ Value = $Seconds;   Label = 's' }
                    )
                    $FirstIndex = -1; $LastIndex = -1
                    for ($i = 0; $i -lt $Components.Count; $i++) {
                        if ($Components[$i].Value -gt 0) { if ($FirstIndex -eq -1) { $FirstIndex = $i } ; $LastIndex = $i }
                    }
                    if ($FirstIndex -eq -1) { return '-' }
                    # Drop seconds when duration includes days to keep output compact
                    if ($TotalDays -gt 0 -and $LastIndex -eq 3) { $LastIndex = 2 }
                    $Parts = New-Object System.Collections.ArrayList
                    for ($i = $FirstIndex; $i -le $LastIndex; $i++) {
                        $ValuePart = if ($i -eq $FirstIndex) { $Components[$i].Value } else { '{0:00}' -f $Components[$i].Value }
                        [void]$Parts.Add("$ValuePart$($Components[$i].Label)")
                    }
                    return ($Parts -join ' ')
                }
                # Pending reboot detection from multiple sources via .NET registry access
                function Get-PendingReboot {
                    $RebootReasons = @{}
                    $RebootReasons['CCM_RebootRequired']      = Test-RegistryKeyPresent 'SOFTWARE\Microsoft\CCM\RebootRequired'
                    $RebootReasons['WindowsUpdate']           = Test-RegistryKeyPresent 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
                    $RebootReasons['ComponentBasedServicing'] = Test-RegistryKeyPresent 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
                    $RebootReasons['PendingFileRenameOps']    = [bool](Get-RegistryKeyValue 'SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations')
                    $VolatileValue                            = Get-RegistryKeyValue 'SOFTWARE\Microsoft\Updates' 'UpdateExeVolatile'
                    $RebootReasons['UpdateExeVolatile']       = ($VolatileValue -ne $null -and $VolatileValue -ne 0)
                    try { $RebootReasons['WMI_RebootPending'] = (Get-WmiObject Win32_OperatingSystem).RebootPending } catch { $RebootReasons['WMI_RebootPending'] = $false }
                    $ActiveReasons = $RebootReasons.GetEnumerator() | Where-Object { $_.Value } | Select-Object -ExpandProperty Key
                    [pscustomobject]@{
                        PendingReboot = [bool]$ActiveReasons
                        Reasons       = $ActiveReasons
                        Display       = if ($ActiveReasons) { "YES ($($ActiveReasons -join ', '))" } else { "NO" }
                    }
                }
                # Enumerate logged-on users via WTS API
                function Get-WtsUserSessions {
                    param([bool]$VistaOrLater)
                    # Build WMI logon time cache for XP fallback (class 24 not available pre-Vista)
                    $WmiLogonTimeCache = @{}
                    if (-not $VistaOrLater) {
                        try {
                            $InteractiveLogonSessions = Get-WmiObject -Query "SELECT * FROM Win32_LogonSession WHERE LogonType=2 OR LogonType=10"
                            foreach ($LogonSession in $InteractiveLogonSessions) {
                                if (-not $LogonSession.StartTime) { continue }
                                try {
                                    $AssociatedAccounts = Get-WmiObject -Query "ASSOCIATORS OF {Win32_LogonSession.LogonId='$($LogonSession.LogonId)'} WHERE AssocClass=Win32_LoggedOnUser Role=Dependent"
                                    foreach ($Account in $AssociatedAccounts) {
                                        if ($Account.Name) {
                                            $WmiLogonTimeCache[$Account.Name] = [System.Management.ManagementDateTimeConverter]::ToDateTime($LogonSession.StartTime)
                                        }
                                    }
                                } catch {}
                            }
                        } catch {}
                    }
                    $StateNames      = @('Active','Connected','ConnectQuery','Shadow','Disconnected','Idle','Listen','Reset','Down','Init')
                    $ServerHandle    = [IntPtr]::Zero
                    $SessionInfoPtr  = [IntPtr]::Zero
                    $SessionCount    = 0
                    $SessionInfoSize = [Runtime.InteropServices.Marshal]::SizeOf([type][WtsSessionInfo])
                    $CollectedUsers  = New-Object System.Collections.ArrayList
                    if (-not [WtsNativeApi]::WTSEnumerateSessions($ServerHandle, 0, 1, [ref]$SessionInfoPtr, [ref]$SessionCount)) {
                        return @()
                    }
                    try {
                        $CurrentPtr = $SessionInfoPtr
                        for ($i = 0; $i -lt $SessionCount; $i++) {
                            $SessionInfo   = [Runtime.InteropServices.Marshal]::PtrToStructure($CurrentPtr, [type][WtsSessionInfo])
                            $CurrentPtr    = [IntPtr]($CurrentPtr.ToInt64() + $SessionInfoSize)
                            $UserName      = $null
                            $SessionName   = '-'
                            $StateName     = 'Unknown'
                            $IdleDisplay   = '-'
                            $OpenedDisplay = '-'
                            if ($VistaOrLater) {
                                # Vista+ : query WTSINFO struct (class 24) for full session details
                                $InfoBuffer    = [IntPtr]::Zero
                                $BytesReturned = 0
                                if (-not [WtsNativeApi]::WTSQuerySessionInformation($ServerHandle, $SessionInfo.SessionId, 24, [ref]$InfoBuffer, [ref]$BytesReturned)) { continue }
                                try {
                                    $WtsInfo = [Runtime.InteropServices.Marshal]::PtrToStructure($InfoBuffer, [type][WtsInfoData])
                                } finally { [WtsNativeApi]::WTSFreeMemory($InfoBuffer) }
                                if ($WtsInfo.UserName) { $UserName = $WtsInfo.UserName.Trim() }
                                if ($WtsInfo.WinStationName -and $WtsInfo.WinStationName.Trim()) { $SessionName = $WtsInfo.WinStationName.Trim() }
                                if ($WtsInfo.State -ge 0 -and $WtsInfo.State -lt $StateNames.Count) { $StateName = $StateNames[$WtsInfo.State] }
                                if ($WtsInfo.LastInputTime -gt 0 -and $WtsInfo.CurrentTime -gt 0 -and $WtsInfo.CurrentTime -gt $WtsInfo.LastInputTime) {
                                    $IdleTicks   = $WtsInfo.CurrentTime - $WtsInfo.LastInputTime
                                    $SessionTicks = if ($WtsInfo.LogonTime -gt 0 -and $WtsInfo.CurrentTime -gt $WtsInfo.LogonTime) { $WtsInfo.CurrentTime - $WtsInfo.LogonTime } else { 0 }
                                    # Idle cannot logically exceed session duration. Sometimes WTS API reports wrong IDLE values.
                                    if ($SessionTicks -gt 0 -and $IdleTicks -gt $SessionTicks) { $IdleDisplay = '-' }
                                    else { $IdleDisplay = Format-Duration -Duration ([TimeSpan]::FromTicks($IdleTicks)) }
                                }
                                if ($WtsInfo.LogonTime -gt 0 -and $WtsInfo.CurrentTime -gt 0 -and $WtsInfo.CurrentTime -gt $WtsInfo.LogonTime) {
                                    $OpenedDisplay = Format-Duration -Duration ([TimeSpan]::FromTicks($WtsInfo.CurrentTime - $WtsInfo.LogonTime))
                                }
                            } else {
                                # XP fallback : query individual WTS properties (class 5/6/8)
                                $InfoBuffer = [IntPtr]::Zero ; $BytesReturned = 0
                                if (-not [WtsNativeApi]::WTSQuerySessionInformation($ServerHandle, $SessionInfo.SessionId, 5, [ref]$InfoBuffer, [ref]$BytesReturned)) { continue }
                                $UserName = [Runtime.InteropServices.Marshal]::PtrToStringUni($InfoBuffer)
                                [WtsNativeApi]::WTSFreeMemory($InfoBuffer)
                                if ($UserName) { $UserName = $UserName.Trim() }
                                $InfoBuffer = [IntPtr]::Zero ; $BytesReturned = 0
                                if ([WtsNativeApi]::WTSQuerySessionInformation($ServerHandle, $SessionInfo.SessionId, 6, [ref]$InfoBuffer, [ref]$BytesReturned)) {
                                    $RawStationName = [Runtime.InteropServices.Marshal]::PtrToStringUni($InfoBuffer)
                                    [WtsNativeApi]::WTSFreeMemory($InfoBuffer)
                                    if ($RawStationName -and $RawStationName.Trim()) { $SessionName = $RawStationName.Trim() }
                                }
                                $InfoBuffer = [IntPtr]::Zero ; $BytesReturned = 0
                                if ([WtsNativeApi]::WTSQuerySessionInformation($ServerHandle, $SessionInfo.SessionId, 8, [ref]$InfoBuffer, [ref]$BytesReturned)) {
                                    $StateValue = [Runtime.InteropServices.Marshal]::ReadInt32($InfoBuffer)
                                    [WtsNativeApi]::WTSFreeMemory($InfoBuffer)
                                    if ($StateValue -ge 0 -and $StateValue -lt $StateNames.Count) { $StateName = $StateNames[$StateValue] }
                                }
                                # Session duration from WMI logon time cache (idle not available pre-Vista)
                                if ($UserName -and $WmiLogonTimeCache.ContainsKey($UserName)) {
                                    $LogonDuration = (Get-Date) - $WmiLogonTimeCache[$UserName]
                                    if ($LogonDuration.TotalSeconds -ge 1) { $OpenedDisplay = Format-Duration -Duration $LogonDuration }
                                }
                            }
                            # Skip empty users, collect result
                            if (-not $UserName) { continue }
                            [void]$CollectedUsers.Add([pscustomobject]@{
                                UserName = $UserName
                                Session  = $SessionName
                                State    = $StateName
                                Idle     = $IdleDisplay
                                Opened   = $OpenedDisplay
                            })
                        }
                    } finally { [WtsNativeApi]::WTSFreeMemory($SessionInfoPtr) }
                    return $CollectedUsers
                }
                # Read OS information from registry via .NET
                $NtVersionKey = $null
                try { $NtVersionKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion') } catch {}
                $ProductName      = if ($NtVersionKey) { $NtVersionKey.GetValue('ProductName') }       else { 'N/A' }
                $DisplayVersion   = if ($NtVersionKey) { $NtVersionKey.GetValue('DisplayVersion') }    else { $null }
                $CurrentBuildNum  = if ($NtVersionKey) { $NtVersionKey.GetValue('CurrentBuildNumber') } else { $null }
                $CurrentVersion   = if ($NtVersionKey) { $NtVersionKey.GetValue('CurrentVersion') }    else { $null }
                $UBR              = if ($NtVersionKey) { $NtVersionKey.GetValue('UBR') }                else { $null }
                $CSDVersion       = if ($NtVersionKey) { $NtVersionKey.GetValue('CSDVersion') }        else { $null }
                $BuildLabEx       = if ($NtVersionKey) { $NtVersionKey.GetValue('BuildLabEx') }        else { $null }
                $BuildLab         = if ($NtVersionKey) { $NtVersionKey.GetValue('BuildLab') }          else { $null }
                if ($NtVersionKey) { $NtVersionKey.Close() }
                $BuildNumber = 0
                if ($CurrentBuildNum) { [int]::TryParse($CurrentBuildNum, [ref]$BuildNumber) | Out-Null }
                if ($BuildNumber -ge 22000) { $ProductName = $ProductName -replace "Windows 10","Windows 11" }
                # Compose OSName with version suffix (DisplayVersion for Win10+, CSDVersion for older)
                $OsNameDisplay = $ProductName
                if ($DisplayVersion) { $OsNameDisplay = "$OsNameDisplay $DisplayVersion" }
                elseif ($CSDVersion) { $OsNameDisplay = "$OsNameDisplay $CSDVersion" }
                # BuildLab : prefer BuildLabEx, fallback to BuildLab
                $BuildLabDisplay = if ($BuildLabEx) { $BuildLabEx } elseif ($BuildLab) { $BuildLab } else { 'N/A' }
                # Build : Win10+ uses CurrentBuildNumber.UBR, older uses CurrentVersion.CurrentBuildNumber
                if ($UBR -ne $null -and $CurrentBuildNum)      { $BuildDisplay = "$CurrentBuildNum.$UBR" }
                elseif ($CurrentVersion -and $CurrentBuildNum) { $BuildDisplay = "$CurrentVersion.$CurrentBuildNum" }
                elseif ($CurrentBuildNum)                      { $BuildDisplay = $CurrentBuildNum }
                else                                           { $BuildDisplay = 'N/A' }
                # Compute uptime via WMI
                $OperatingSystem = Get-WmiObject Win32_OperatingSystem
                $LastBootTime    = [System.Management.ManagementDateTimeConverter]::ToDateTime($OperatingSystem.LastBootUpTime)
                $UptimeSpan      = (Get-Date) - $LastBootTime
                # Pending reboot check
                $PendingReboot   = Get-PendingReboot
                # Free disk space via .NET DriveInfo
                $DriveC          = New-Object System.IO.DriveInfo("C")
                $FreeDiskDisplay = "{0:N2} GB" -f ($DriveC.AvailableFreeSpace / 1GB)
                # WTS user session enumeration
                $UserSessions = @(Get-WtsUserSessions -VistaOrLater $IsVistaOrLater)
                # Return as flat array to avoid PS 2.0 member enumeration issue
                @(
                    $env:COMPUTERNAME,
                    $OsNameDisplay, $BuildLabDisplay, $BuildDisplay,
                    [string]$PSVersionTable.PSVersion,
                    "$($UptimeSpan.Days) days, $($UptimeSpan.Hours) hours, $($UptimeSpan.Minutes) minutes",
                    $PendingReboot.Display,
                    $FreeDiskDisplay,
                    $UserSessions
                )
            }
            # Execute locally or remotely
            $IsLocalComputer = ($TargetComputer -eq $env:COMPUTERNAME -or $TargetComputer -eq 'localhost' -or $TargetComputer -eq '.')
            if ($IsLocalComputer) { return & $InfoScriptBlock -WtsCSharpSourceLocal $WtsCSharpSource }
            $InvokeArgs = @{ ComputerName = $TargetComputer; ErrorAction = 'Stop'; ScriptBlock = $InfoScriptBlock; ArgumentList = $WtsCSharpSource }
            if ($CredentialObject) { $InvokeArgs['Credential'] = $CredentialObject }
            Invoke-Command @InvokeArgs
        }).AddArgument($Computer).AddArgument($Credential).AddArgument($WtsCSharpCode)
        $PowerShellInstance.RunspacePool = $RunspacePool
        [void]$RunningJobs.Add(@{ Computer = $Computer; PowerShell = $PowerShellInstance; AsyncHandle = $PowerShellInstance.BeginInvoke() })
    }
    # Property display order (indices 0-7 match the flat array from scriptblock)
    $PropertyNames      = @('ComputerName','OSName','BuildLab','Build','Powershell','LastReboot','PendingReboot','FreeDiskSpace')
    $MaxPropertyLength  = ($PropertyNames | Measure-Object -Property Length -Maximum).Maximum
    # Tracking structures for ordered display with timeout
    $PollingStartTime   = Get-Date
    $CompletedResults   = @{}
    $DisplayedComputers = @{}
    $TimeoutReached     = $false
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
                    if ($ResultData -and $ResultData.Count -ge 9) {
                        # Display system properties by index
                        for ($PropIndex = 0; $PropIndex -lt $PropertyNames.Count; $PropIndex++) {
                            Write-Host ("  {0,-$MaxPropertyLength} = {1}" -f $PropertyNames[$PropIndex], $ResultData[$PropIndex]) -ForegroundColor White
                        }
                        # Display logged-on user sessions as a table
                        $UserSessions = @($ResultData[8])
                        $ValidSessions = New-Object System.Collections.ArrayList
                        foreach ($UserSession in $UserSessions) { if ($UserSession) { [void]$ValidSessions.Add($UserSession) } }
                        if ($ValidSessions.Count -gt 0) {
                            # Pre-resolve display names and compute max user column width
                            $ResolvedSessions = New-Object System.Collections.ArrayList
                            foreach ($UserSession in $ValidSessions) {
                                $UserDisplay = [string]$UserSession.UserName
                                if ($IsDomainJoined -and $UserSession.UserName) {
                                    $FullName = Resolve-UserDisplayName -UserName $UserSession.UserName -Cache $DisplayNameCache
                                    if ($FullName) { $UserDisplay = "$($UserSession.UserName) ($FullName)" }
                                }
                                [void]$ResolvedSessions.Add(@{ Display = $UserDisplay; Session = $UserSession })
                            }
                            $UserColumnWidth = [math]::Max(6, ($ResolvedSessions | ForEach-Object { $_.Display.Length } | Measure-Object -Maximum).Maximum + 2)
                            # Column definitions with dynamic user width
                            $DynamicColumns = @(
                                @{ Header = 'User';    Width = $UserColumnWidth }
                                @{ Header = 'Session'; Width = 14 }
                                @{ Header = 'State';   Width = 12 }
                                @{ Header = 'Idle';    Width = 13 }
                                @{ Header = 'Opened';  Width = 13 }
                            )
                            $RowFormatString = "  {0,-$($DynamicColumns[0].Width)}{1,-$($DynamicColumns[1].Width)}{2,-$($DynamicColumns[2].Width)}{3,-$($DynamicColumns[3].Width)}{4,-$($DynamicColumns[4].Width)}"
                            Write-Host ($RowFormatString -f $DynamicColumns[0].Header, $DynamicColumns[1].Header, $DynamicColumns[2].Header, $DynamicColumns[3].Header, $DynamicColumns[4].Header) -ForegroundColor DarkCyan
                            $SeparatorLine = '  '
                            foreach ($Column in $DynamicColumns) { $SeparatorLine += ('-' * ($Column.Width - 2)) + '  ' }
                            Write-Host $SeparatorLine -ForegroundColor DarkGray
                            foreach ($Resolved in $ResolvedSessions) {
                                $StateColor = if ($Resolved.Session.State -eq 'Active') { 'Green' } elseif ($Resolved.Session.State -eq 'Disconnected') { 'DarkYellow' } else { 'Gray' }
                                Write-Host ($RowFormatString -f $Resolved.Display, $Resolved.Session.Session, $Resolved.Session.State, $Resolved.Session.Idle, $Resolved.Session.Opened) -ForegroundColor $StateColor
                            }
                        } else { Write-Host "  No logged-on users." -ForegroundColor DarkGray }
                    } else { Write-Host ("  No data retrieved from {0}." -f $Computer) -ForegroundColor Gray }
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
Set-Alias -Name sdev -Value Search-DeviceInfo

Search-DeviceInfo -ComputerNames $ComputerNames -Credential $Credential -MaxThreads $MaxThreads -SortingTimeout $SortingTimeout
$message = "Search Complete. Press Any Key to Exit."
Write-Host $message -NoNewline
$null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ("`r" + (" " * $message.Length) + "`r") -NoNewline
