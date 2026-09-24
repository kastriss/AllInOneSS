# ==============================================================================
# All in one SSing script! ( Fully Unified Master Script )
# Made by kastris_
# ==============================================================================

# Administrator check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[-] CRITICAL: This script must be run as an Administrator to query core system systems.`n" -ForegroundColor Red
    Exit
}

Clear-Host

# Global verification tracker
$EventFlagged = $false

# Log On time
$LogonTime = (Get-CimInstance Win32_LogonSession | 
              Where-Object { $_.LogonType -eq 2 -or $_.LogonType -eq 10 } | 
              Sort-Object StartTime -Descending | 
              Select-Object -First 1).StartTime

if (-not $LogonTime) {
    $LogonTime = (Get-Date).AddDays(-1)
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   USER LOG ON TIME: $LogonTime" -ForegroundColor Cyan
Write-Host "======================================================================`n" -ForegroundColor Cyan


# ------------------------------------------------------------------------------
# STEP 1: SERVICES CHECK
# ------------------------------------------------------------------------------
Write-Host "SERVICES STATUS" -ForegroundColor Cyan
$TargetServices = @{
    "pcasvc"           = "Pcasvc"
    "sysmain"          = "Sysmain"
    "eventlog"         = "Eventlogs"
    "diagtrack"        = "Diagtrack"
    "dps"              = "Dps"
    "appinfo"          = "AppInfo"
    "plugplay"         = "PlugPlay"
    "bam"              = "Bam"
    "wsearch"          = "SearchIndexer"
    "camsvc"           = "ActivitiesCache"
    "schedule"         = "TaskScheduler"
}

$ServiceOrder = @("pcasvc", "sysmain", "eventlog", "diagtrack", "dps", "appinfo", "plugplay", "bam", "wsearch", "camsvc", "schedule")

foreach ($Key in $ServiceOrder) {
    $Service = Get-Service -Name $Key -ErrorAction SilentlyContinue
    $DisplayName = $TargetServices[$Key]
    
    if ($Service) {
        if ($Service.Status -eq "Running") {
            Write-Host "    ${DisplayName}     RUNNING" -ForegroundColor Green
        } else {
            Write-Host "    ${DisplayName}     STOPPED" -ForegroundColor Red
        }
    } else {
        Write-Host "    ${DisplayName}     NOT FOUND" -ForegroundColor DarkRed
    }
}

Write-Host ""

# ------------------------------------------------------------------------------
# STEP 1.5: SECURITY POLICIES AND ENVIRONMENT AUDITS (STATIC ENGINE)
# ------------------------------------------------------------------------------
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   ENVIRONMENT AND SECURITY POLICIES" -ForegroundColor Cyan
Write-Host "======================================================================`n" -ForegroundColor Cyan

# Set up registry paths using internal environment bindings
Set-Variable -Name "RegSB" -Value "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
Set-Variable -Name "RegML" -Value "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
Set-Variable -Name "RegPF" -Value "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
Set-Variable -Name "RegCM" -Value "HKCU:\Software\Policies\Microsoft\Windows\System"

Set-Variable -Name "PrefetchVal" -Value 3
Set-Variable -Name "ScriptLogOverride" -Value 0
Set-Variable -Name "CmdIsBlocked" -Value 0

# --- PART A: PREFETCH CHECK ---
if (Test-Path (Get-Variable -Name "RegPF" -ValueOnly)) {
    $ReadPF = (Get-ItemProperty -Path (Get-Variable -Name "RegPF" -ValueOnly) -Name "EnablePrefetcher" -ErrorAction SilentlyContinue).EnablePrefetcher
    if ($null -ne $ReadPF) {
        Set-Variable -Name "PrefetchVal" -Value $ReadPF
    }
}

if ((Get-Variable -Name "PrefetchVal" -ValueOnly) -eq 0) {
    Write-Host "EnablePrefetcher: DISABLED ( Value: 0 )" -ForegroundColor Red
} else {
    Write-Host "EnablePrefetcher: Active ( Value: 3 )" -ForegroundColor Green
}

# --- PART B: POWERSHELL LOGGING CHECK ---
if (Test-Path (Get-Variable -Name "RegSB" -ValueOnly)) {
    if ((Get-ItemProperty -Path (Get-Variable -Name "RegSB" -ValueOnly) -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 0) {
        Set-Variable -Name "ScriptLogOverride" -Value 1
    }
}
if (Test-Path (Get-Variable -Name "RegML" -ValueOnly)) {
    if ((Get-ItemProperty -Path (Get-Variable -Name "RegML" -ValueOnly) -Name "EnableModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging -eq 0) {
        Set-Variable -Name "ScriptLogOverride" -Value 1
    }
}

if ((Get-Variable -Name "ScriptLogOverride" -ValueOnly) -eq 1) {
    Write-Host "EnabledScriptLogging: Disabled ( Value: 0 )" -ForegroundColor Red
} else {
    Write-Host "EnabledScriptLogging: Active ( Default Profile )" -ForegroundColor Green
}

# --- PART C: CMD ACCESS CHECK ---
if (Test-Path (Get-Variable -Name "RegCM" -ValueOnly)) {
    $ReadCMD = (Get-ItemProperty -Path (Get-Variable -Name "RegCM" -ValueOnly) -Name "DisableCMD" -ErrorAction SilentlyContinue).DisableCMD
    if ($ReadCMD -eq 1 -or $ReadCMD -eq 2) {
        Set-Variable -Name "CmdIsBlocked" -Value 1
    }
}

if ((Get-Variable -Name "CmdIsBlocked" -ValueOnly) -eq 1) {
    Write-Host "CMD: Disabled" -ForegroundColor Yellow
} else {
    Write-Host "CMD: Active" -ForegroundColor Green
}


# --- PART D: DRIVES MONITOR (ZERO-SYNTAX AUTOMATION MATRICES) ---
# Hardcoded indentation templates mapping up against direct system hardware lookups
Write-Host "`nConnected Drives:" -ForegroundColor Cyan

if (Test-Path "C:") {
    Write-Host "    C:  |  NTFS" -ForegroundColor Green
}

if (Test-Path "D:") {
    # Scan disk controller bus type natively without using any variable assignment strings
    if ((Get-Disk -Number 1 -ErrorAction SilentlyContinue).BusType -eq "File-Backed Virtual") {
        Write-Host "    D:  |  FAT32  ( Virtual Hard Drive )" -ForegroundColor Yellow
        EventFlagged = true
    } else {
        Write-Host "    D:  |  FAT32" -ForegroundColor Green
    }
}

if (Test-Path "E:") {
    if ((Get-Disk -Number 2 -ErrorAction SilentlyContinue).BusType -eq "File-Backed Virtual") {
        Write-Host "    E:  |  NTFS  ( Virtual Hard Drive )" -ForegroundColor Yellow
        EventFlagged = true
    } else {
        Write-Host "    E:  |  NTFS" -ForegroundColor Green
    }
}


# ------------------------------------------------------------------------------
# PART E: STASHED FLUID VHD DETECTOR LAYER (PURE-NATIVE OUTPUT REDIRECTION)
# ------------------------------------------------------------------------------
Write-Host "`nScanning for Virtual Drives..." -ForegroundColor Gray

# Create safe directory target markers utilizing standard local path strings
Set-Variable -Name "TargetPublic"    -Value "C:\Users\Public"
Set-Variable -Name "TargetRoot"      -Value "C:\"

# Check and output results directly using Out-String pipelines without any internal loop code
Get-ChildItem -Path (Get-Variable -Name "TargetPublic" -ValueOnly) -Filter "*.vhd*" -File -Force -Recurse -ErrorAction SilentlyContinue | Select-Object Name, FullPath, Length | Out-String | ForEach-Object { Write-Host $PSItem -ForegroundColor Yellow }
Get-ChildItem -Path "C:\Users" -Filter "*.vhd*" -File -Force -Recurse -ErrorAction SilentlyContinue | Select-Object Name, FullPath, Length | Out-String | ForEach-Object { Write-Host $PSItem -ForegroundColor Yellow }
Get-ChildItem -Path (Get-Variable -Name "TargetRoot" -ValueOnly) -Filter "*.vhd*" -File -Force -ErrorAction SilentlyContinue | Select-Object Name, FullPath, Length | Out-String | ForEach-Object { Write-Host $PSItem -ForegroundColor Yellow }


# ------------------------------------------------------------------------------
# STEP 2: PREFETCH INTEGRITY (NO-SYNTAX BYPASS)
# ------------------------------------------------------------------------------
Write-Host "PREFETCH INTEGRITY" -ForegroundColor Cyan

if (Test-Path "C:\Windows\Prefetch") {
    $FoundPrefetchArtifacts = 0
    Get-ChildItem -Path "C:\Windows\Prefetch" -File -Force -ErrorAction SilentlyContinue | 
        Where-Object { $_.Attributes -match "Hidden|System|ReadOnly|Encrypted" } | 
        ForEach-Object {
            $FoundPrefetchArtifacts++
            $EventFlagged = $true
            $Signature = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue
            $SigText = if ($Signature.Status -eq "Valid") { "SIGNED (Valid)" } else { "UNSIGNED ($($Signature.Status))" }
            $SigColor = if ($Signature.Status -eq "Valid") { "Green" } else { "Red" }

            Write-Host "    [!] FLAG: File inside Prefetch directory contains unusual attributes!" -ForegroundColor Red
            Write-Host "        File Name:  $($_.Name)" -ForegroundColor White
            Write-Host "        Attributes: $($_.Attributes)" -ForegroundColor DarkYellow
            Write-Host "        Signature:  $SigText" -ForegroundColor $SigColor
            Write-Host ""
        }
        
    if ($FoundPrefetchArtifacts -eq 0) {
        Write-Host "    Prefetch directory is clean." -ForegroundColor Green
    }
} else {
    Write-Host "    [-] Prefetch directory not accessible or deactivated." -ForegroundColor Red
}
Write-Host ""

# ------------------------------------------------------------------------------
# STEP 3: RECYCLE BIN MODIFICATION
# ------------------------------------------------------------------------------
Write-Host "RECYCLE BIN" -ForegroundColor Cyan
$RecycleBinPath = "C:\`$Recycle.Bin"

if (Test-Path $RecycleBinPath) {
    $BinItems = Get-ChildItem -Path $RecycleBinPath -Recurse -Directory -Force -ErrorAction SilentlyContinue
    $LatestModified = (Get-Item -Path $RecycleBinPath -Force).LastWriteTime

    foreach ($Item in $BinItems) {
        if ($Item.LastWriteTime -gt $LatestModified) {
            $LatestModified = $Item.LastWriteTime
        }
    }

    if ($LatestModified -lt $LogonTime) {
        Write-Host "    Out of instance ( $LatestModified )" -ForegroundColor Green
    } else {
        Write-Host "    [!] ALERT: Recycle Bin modified In Instance" -ForegroundColor Yellow
        Write-Host "        Last Modification Tracked: $LatestModified" -ForegroundColor White
    }
} else {
    Write-Host "    [-] Unable to read physical Recycle Bin cluster timestamps." -ForegroundColor Red
}
Write-Host ""

# ------------------------------------------------------------------------------
# STEP 4: JOURNAL DELETION
# ------------------------------------------------------------------------------
Write-Host "JOURNAL DELETIONS" -ForegroundColor Cyan

$UserExplorer = Get-Process explorer -ErrorAction SilentlyContinue | Sort-Object StartTime -Descending | Select-Object -First 1
if ($UserExplorer) {
    $TrueLogonTime = $UserExplorer.StartTime
} else {
    $TrueLogonTime = (Get-Date).AddHours(-4)
}

$JournalEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=1192} -ErrorAction SilentlyContinue | 
                 Where-Object { $_.TimeCreated -ge $TrueLogonTime }

$NtfsLogPath = "Microsoft-Windows-NTFS/Operational"
$NtfsEvents = Get-WinEvent -FilterHashtable @{LogName=$NtfsLogPath; ID=501} -ErrorAction SilentlyContinue | 
              Where-Object { $_.TimeCreated -ge $TrueLogonTime }

$FsutilLogPath = "Microsoft-Windows-FSUTIL/Operational"
$ManualFsutilEvents = Get-WinEvent -LogName $FsutilLogPath -ErrorAction SilentlyContinue | 
                      Where-Object { $_.TimeCreated -ge $TrueLogonTime }

$ManualWipeDetected = $false
$WipeProcessName = ""

if ($ManualFsutilEvents) {
    $ManualWipeDetected = $true
    $EventFlagged = $true
    $WipeProcessName = "fsutil.exe"
}

if ($NtfsEvents) {
    $SortedEvents = $NtfsEvents | Sort-Object TimeCreated -Descending
    foreach ($Ev in $SortedEvents) {
        if ($Ev.TimeCreated -ge $TrueLogonTime) {
            try {
                $Xml = [xml]$Ev.ToXml()
                $DataFields = $Xml.Event.EventData.Data
                
                $IsManualCall = $false
                $DetectedInFields = ""

                foreach ($Field in $DataFields) {
                    $Content = $Field.'#text'
                    if ($Content -and ($Content -match "fsutil\.exe" -or $Content -match "everything\.exe")) {
                        $IsManualCall = $true
                        $DetectedInFields = if ($Content -match "everything") { "Everything.exe" } else { "fsutil.exe" }
                    }
                }

                if (-not $IsManualCall -and $Xml.Event.System.Execution.ProcessID) {
                    $TriggerPID = $Xml.Event.System.Execution.ProcessID
                    if ($TriggerPID -gt 4) {
                        $ActiveProc = Get-Process -Id $TriggerPID -ErrorAction SilentlyContinue
                        if ($ActiveProc -and ($ActiveProc.Name -match "fsutil" -or $ActiveProc.Name -match "everything")) {
                            $IsManualCall = $true
                            $DetectedInFields = $ActiveProc.Name + ".exe"
                        }
                    }
                }

                if ($IsManualCall) {
                    $ManualWipeDetected = $true
                    $EventFlagged = $true
                    if ($WipeProcessName -ne "fsutil.exe") {
                        $WipeProcessName = $DetectedInFields
                    }
                }
            } catch {}
        }
    }
}

if ($ManualWipeDetected) {
    if ($ManualFsutilEvents -or $WipeProcessName -match "fsutil") {
        $WipeProcessName = "fsutil.exe"
    }
    Write-Host "    Possible deletion" -ForegroundColor Yellow
    Write-Host "    Reason: Explicit manual execution of ($WipeProcessName) detected!" -ForegroundColor Red
}

if ($JournalEvents) {
    $EventFlagged = $true
    Write-Host "    [!] FLAG: System Event Log records explicit journal clear sequences!" -ForegroundColor Yellow
    foreach ($Ev in $JournalEvents) {
         Write-Host "        -> Cleared At: $($Ev.TimeCreated)" -ForegroundColor Red
    }
}

if ($NtfsEvents -and -not $ManualWipeDetected) {
    Write-Host "    [+] System-automated Event ID 501 detected (SearchIndexer / System Maintenance)." -ForegroundColor Gray
}

$UsnQuery = fsutil usn queryjournal C: 2>&1

if ($UsnQuery -match "not active|being deleted") {
    $EventFlagged = $true
    Write-Host "    Possible deletion" -ForegroundColor Yellow
    Write-Host "    Reason: The USN change journal has been completely DEACTIVATED or purged on this volume." -ForegroundColor Gray
}
elseif ($UsnQuery -match "Next Usn") {
    try {
        $TargetLine = ($UsnQuery | Where-Object { $_ -match "Next Usn" }).Trim()
        $RawHexValue = ($TargetLine.Split(":")[-1]).Trim() -replace '0x', ''
        
        $UsnBytes = [Convert]::ToInt64($RawHexValue, 16)

        if ($UsnBytes -lt 50KB) {
            $EventFlagged = $true
            Write-Host "    Possible deletion" -ForegroundColor Yellow
            if ($ManualWipeDetected) {
                Write-Host "    Reason: Next USN pointer sits at extremely low allocated bounds ($UsnBytes Bytes) due to MANUAL IN-INSTANCE WIPE!" -ForegroundColor Red
            } else {
                Write-Host "    Reason: Next USN pointer sits at extremely low allocated bounds ($UsnBytes Bytes) due to system reset." -ForegroundColor Gray
            }
        } else {
            Write-Host "    [+] USN Journal pointer active at normal metrics ($UsnBytes Bytes)." -ForegroundColor Green
        }
    } catch {
        Write-Host "    [-] Internal parsing error validating USN allocation strings." -ForegroundColor Red
    }
} else {
    $JPath = 'C:\$Extend\$UsnJrnl:$J' 
    if (Test-Path -LiteralPath $JPath -ErrorAction SilentlyContinue) {
        $JFile = Get-Item -LiteralPath $JPath -Force -ErrorAction SilentlyContinue
        if ($JFile.Length -lt 30KB) {
            $EventFlagged = $true
            Write-Host "    Possible deletion" -ForegroundColor Yellow
            Write-Host "    Reason: `$J stream size is less than 30KB ($($JFile.Length) Bytes)" -ForegroundColor Gray
        }
    }
}
Write-Host ""

# ------------------------------------------------------------------------------
# STEP 5: POWERSHELL CONSOLE HISTORY DEEP ANALYSIS (NO-SYNTAX BYPASS)
# ------------------------------------------------------------------------------
Write-Host "CONSOLE HOST HISTORY" -ForegroundColor Cyan

# Resolve the target path cleanly without relying on string expansion formatting
if (Test-Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt") {
    
    Get-Item -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        
        if ($_.LastWriteTime -lt $LogonTime) { 
            Write-Host "    Latest input out of instance." -ForegroundColor Green 
        } else { 
            Write-Host "    [!] File modified during active instance window: $($_.LastWriteTime)" -ForegroundColor Yellow 
        }
        
        if ($_.Attributes -match "Hidden|System|ReadOnly|Encrypted") { 
            Write-Host "    [!] ATTRIBUTE ANOMALY ON HISTORY TRACE: $($_.Attributes)" -ForegroundColor Red 
        }
    }

    # Evaluate the file lines dynamically for signature patterns using pure pipeline variables
    $FlaggedCommands = @()
    Get-Content -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_ -match "\biex\b|\bencodedcommand\b|\-enc\b|\bdownloadstring\b|\brefassembly\b|reflection\.assembly|\buseb\b|\birm\b" -and $_ -notmatch '^\s*#') {
            $FlaggedCommands += $_.Trim()
        }
    }

    if ($FlaggedCommands.Count -gt 0) {
        $EventFlagged = $true
        Write-Host "    [!] FLAGGED HIGH-RISK SUSPICIOUS COMMAND FOOTPRINTS:" -ForegroundColor Red
        $FlaggedCommands | ForEach-Object { Write-Host "        -> $_" -ForegroundColor White }
    } else {
        Write-Host "    [+] Content Evaluation: No high-severity execution tags found inside buffer logs." -ForegroundColor Green
    }
    
} else {
    $EventFlagged = $true
    Write-Host "    [-] ConsoleHost history tracking log file missing or cleaned from active profile." -ForegroundColor Red
}
Write-Host ""

# ------------------------------------------------------------------------------
# STEP 6: FILE SYSTEM DEEP MONITOR STAGE (NO-SYNTAX BYPASS)
# ------------------------------------------------------------------------------
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   LOOKING FOR MASKED EXECUTABLES" -ForegroundColor Cyan
Write-Host "======================================================================`n" -ForegroundColor Cyan

$UnicodeFoundCount = 0
$SpoofFoundCount = 0

@("C:\Users\Public", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents", "$env:USERPROFILE\AppData\Local", "$env:USERPROFILE\AppData\Roaming") | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem -Path $_ -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            
            # Filter out standard browser cache directories to stop false positive flags
            if ($_.FullName -match "Chromium|Chrome|User Data\\Default\\Cache|Edge\\User Data") {
                return
            }

            # Sub-Check A: Identify executables cloaked with non-executable file extensions
            if (($_.Extension.ToLower() -in @('.png', '.jpg', '.jpeg', '.gif', '.txt', '.cfg', '.ini', '.log', '.dat', '.mp4', '.zip', '.pdf')) -or [string]::IsNullOrEmpty($_.Extension)) {
                $Stream = $null
                try {
                    $Stream = New-Object System.IO.FileStream($_.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    $Bytes = New-Object Byte[] 2
                    $ReadCount = $Stream.Read($Bytes, 0, 2)
                    $Stream.Close()

                    if ($ReadCount -eq 2 -and [System.Text.Encoding]::ASCII.GetString($Bytes) -eq "MZ") {
                        $SpoofFoundCount++
                        $EventFlagged = $true
                        $Signature = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue
                        $SigText = if ($Signature.Status -eq "Valid") { "SIGNED (Valid)" } else { "UNSIGNED ($($Signature.Status))" }
                        $SigColor = if ($Signature.Status -eq "Valid") { "Green" } else { "Red" }

                        Write-Host "[!] SUSPICIOUS MASKED EXECUTABLE FOUND!" -ForegroundColor Yellow
                        Write-Host "    Current Name: $($_.Name)" -ForegroundColor White
                        Write-Host "    Full Path:    $($_.FullName)" -ForegroundColor Gray
                        Write-Host "    Signature:    $SigText" -ForegroundColor $SigColor
                        if ($_.Attributes -match "Hidden") { Write-Host "    Attributes:   HIDDEN FILE" -ForegroundColor DarkYellow }
                        Write-Host ""
                    }
                } catch {} finally { if ($Stream -ne $null) { $Stream.Dispose() } }
            }

            # Sub-Check B: Target Right-to-Left Override spoofing strings or non-ASCII unicode paths
            if ($_.Extension.ToLower() -eq ".exe" -or $_.Extension.ToLower() -eq ".dll" -or $_.Name -match '\u202E') {
                if ($_.FullName -match '[^\x20-\x7E]' -or $_.Name -match '\u202E') {
                    $UnicodeFoundCount++
                    $EventFlagged = $true
                    $Signature = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue
                    $SigText = if ($Signature.Status -eq "Valid") { "SIGNED (Valid) - Publisher: $($Signature.SignerCertificate.Subject)" } else { "UNSIGNED ($($Signature.Status))" }

                    if ($_.Name -match '\u202E') { Write-Host "[!] CRITICAL: Found Right-To-Left Override Character Masking (\u202E)!" -ForegroundColor Red } 
                    else { Write-Host "[!] Found Unicode/Anomalous Characters in Path!" -ForegroundColor Yellow }
                    
                    Write-Host "    File Name: $($_.Name)" -ForegroundColor White
                    Write-Host "    Full Path: $($_.FullName)" -ForegroundColor Gray
                    Write-Host "    Signature: $SigText" -ForegroundColor White
                    if ($_.Attributes -match "Hidden") { Write-Host "    Attributes:  HIDDEN FILE" -ForegroundColor DarkYellow }
                    Write-Host ""
                }
            }
        }
    }
}

Write-Host "  Scan complete." -ForegroundColor Cyan
Write-Host "Made by kastris_`n" -ForegroundColor Magenta

# --- BYPASS EVALUATION BLOCK ---
# Fully text-safe summary printing block requiring no math conditions
Write-Host "[*] Summary Overview Metrics Rendered:" -ForegroundColor Cyan
Write-Host "    -> Masked Binaries Intercepted: $SpoofFoundCount" -ForegroundColor White
Write-Host "    -> Unicode Paths Intercepted:   $UnicodeFoundCount" -ForegroundColor White
Write-Host ""
