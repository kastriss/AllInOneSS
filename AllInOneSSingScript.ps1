# ==============================================================================
# All in one SSing script! ( This is a prototype may be shitty )
# Made by kastris_
# ==============================================================================

# Administrator or script wont run
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[-] CRITICAL: This script must be run as an Administrator to query core system systems.`n" -ForegroundColor Red
    Exit
}

Clear-Host

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
# STEP 2: PREFETCH INTEGRITY
# ------------------------------------------------------------------------------
Write-Host "PREFETCH INTEGRITY" -ForegroundColor Cyan
$PrefetchPath = "C:\Windows\Prefetch"
$FoundPrefetchArtifacts = 0

if (Test-Path $PrefetchPath) {
    $PrefetchFiles = Get-ChildItem -Path $PrefetchPath -File -Force -ErrorAction SilentlyContinue

    foreach ($File in $PrefetchFiles) {
        if ($File.Attributes -match "Hidden|System|ReadOnly|Encrypted") {
            $FoundPrefetchArtifacts++
            $Signature = Get-AuthenticodeSignature -FilePath $File.FullName -ErrorAction SilentlyContinue
            $SigText = if ($Signature.Status -eq "Valid") { "SIGNED (Valid)" } else { "UNSIGNED ($($Signature.Status))" }
            $SigColor = if ($Signature.Status -eq "Valid") { "Green" } else { "Red" }

            Write-Host "    [!] FLAG: File inside Prefetch directory contains unusual attributes!" -ForegroundColor Red
            Write-Host "        File Name:  $($File.Name)" -ForegroundColor White
            Write-Host "        Attributes: $($File.Attributes)" -ForegroundColor DarkYellow
            Write-Host "        Signature:  $SigText" -ForegroundColor $SigColor
            Write-Host ""
        }
    }
    
    if ($FoundPrefetchArtifacts -eq 0) {
        Write-Host "    Prefetch directory is clean.`n" -ForegroundColor Green
    }
} else {
    Write-Host "    [-] Prefetch directory not accessible or deactivated.`n" -ForegroundColor Red
}


# ------------------------------------------------------------------------------
# STEP 3: RECYCLE BIN MODIFICATION
# ------------------------------------------------------------------------------
Write-Host "RECYCLE BIN" -ForegroundColor Cyan
$RecycleBinPath = "C:\`$Recycle.Bin"

if (Test-Path $RecycleBinPath) {
    # Recursively queries the inner security subfolders inside the Bin
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
# STEP 4: Journal Deletion ( This took a WHILE to make )
# ------------------------------------------------------------------------------
Write-Host "JOURNAL DELETIONS" -ForegroundColor Cyan

$UserExplorer = Get-Process explorer -ErrorAction SilentlyContinue | Sort-Object StartTime -Descending | Select-Object -First 1
if ($UserExplorer) {
    $TrueLogonTime = $UserExplorer.StartTime
} else {
    $TrueLogonTime = (Get-Date).AddHours(-4) # Aggressive fallback if process boundaries break
}

# Check for traditional administrative event footprints (Event ID 1192) inside our strict instance window
$JournalEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=1192} -ErrorAction SilentlyContinue | 
                 Where-Object { $_.TimeCreated -ge $TrueLogonTime }

# Target the NTFS Operational Log path for Event ID 501 inside our strict instance window
$NtfsLogPath = "Microsoft-Windows-NTFS/Operational"
$NtfsEvents = Get-WinEvent -FilterHashtable @{LogName=$NtfsLogPath; ID=501} -ErrorAction SilentlyContinue | 
              Where-Object { $_.TimeCreated -ge $TrueLogonTime }

# Queries the specialized FSUTIL operational engine logs.
$FsutilLogPath = "Microsoft-Windows-FSUTIL/Operational"
$ManualFsutilEvents = Get-WinEvent -LogName $FsutilLogPath -ErrorAction SilentlyContinue | 
                      Where-Object { $_.TimeCreated -ge $TrueLogonTime }

$EventFlagged = $false
$ManualWipeDetected = $false
$WipeProcessName = ""

# If ANY entry landed in the FSUTIL log channel during this session, a manual command has been entered
if ($ManualFsutilEvents) {
    $ManualWipeDetected = $true
    $EventFlagged = $true
    $WipeProcessName = "fsutil.exe"
}

# Verification
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
                        # Assign temporary name to evaluate prioritization rules later
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
                    
                    # FIX: PRIORITY OVERRIDE FILTER
                    # If the script previously assigned "Everything.exe" but we know fsutil was also active or called,
                    # or if we want to make sure fsutil is never masked by a background indexer, stick to fsutil.exe
                    if ($WipeProcessName -ne "fsutil.exe") {
                        $WipeProcessName = $DetectedInFields
                    }
                }
            } catch {}
        }
    }
}

# ------------------------------------------------------------------------------
# CONSOLE OUTPUT RENDERING ENGINE
# ------------------------------------------------------------------------------

# If a manual tool interaction was confirmed by either channel during the active session window
if ($ManualWipeDetected) {
    # FINAL CORRECTION: If fsutil telemetry triggered anywhere in the log sequence, force the name display to fsutil.exe
    if ($ManualFsutilEvents -or $WipeProcessName -match "fsutil") {
        $WipeProcessName = "fsutil.exe"
    }

    Write-Host "    Possible deletion" -ForegroundColor Yellow
    Write-Host "    Reason: Explicit manual execution of ($WipeProcessName) detected IN-INSTANCE!" -ForegroundColor Red
}

# Evaluate traditional administrative commands if present
if ($JournalEvents) {
    $EventFlagged = $true
    Write-Host "    [!] FLAG: System Event Log records explicit journal clear sequences!" -ForegroundColor Yellow
    foreach ($Ev in $JournalEvents) {
         Write-Host "        -> Cleared At: $($Ev.TimeCreated)" -ForegroundColor Red
    }
}

# If background system tasks triggered updates but no manual intervention occurred
if ($NtfsEvents -and -not $ManualWipeDetected) {
    Write-Host "    [+] System-automated Event ID 501 detected (SearchIndexer / System Maintenance)." -ForegroundColor Gray
}

# Run the live query against the storage volume
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
        
        # If its under 50kb
        if ($UsnBytes -lt 50KB) {
            $EventFlagged = $true
            Write-Host "    Possible deletion" -ForegroundColor Yellow
            if ($ManualWipeDetected) {
                Write-Host "    Reason: Next USN pointer sits at extremely low allocated bounds ($UsnBytes Bytes) due to MANUAL IN-INSTANCE WIPE!" -ForegroundColor Red
            } else {
                Write-Host "    Reason: Next USN pointer sits at extremely low allocated bounds ($UsnBytes Bytes) due to system reset." -ForegroundColor Gray
            }
        } else {
            # Display current live size state while keeping any operational flags active
            if (-not $EventFlagged) {
                Write-Host "    [+] USN Journal pointer active at normal metrics ($UsnBytes Bytes)." -ForegroundColor Green
            } else {
                Write-Host "    [!] Current Live Size recovered to: $UsnBytes Bytes" -ForegroundColor DarkYellow
            }
        }
    } catch {
        Write-Host "    [-] Internal parsing error validating USN allocation strings." -ForegroundColor Red
    }
} else {
    # File layer check just in case permissions block the native command utility tool
    $JPath = "C:\`$Extend\`$UsnJrnl:`$J"
    if (Test-Path $JPath -ErrorAction SilentlyContinue) {
        $JFile = Get-Item -Path $JPath -Force -ErrorAction SilentlyContinue
        if ($JFile.Length -lt 30KB) {
            $EventFlagged = $true
            Write-Host "    Possible deletion" -ForegroundColor Yellow
            Write-Host "    Reason: `$J stream size is less than 30KB ($($JFile.Length) Bytes)" -ForegroundColor Gray
        }
    }
}

if (-not $EventFlagged -and -not $NtfsEvents) {
    Write-Host "    [+] Logs indicate no recent administrative or manual USN wipe commands." -ForegroundColor Green
}
Write-Host ""


# ------------------------------------------------------------------------------
# STEP 5: POWERSHELL CONSOLE HISTORY DEEP ANALYSIS
# ------------------------------------------------------------------------------
Write-Host "CONSOLE HOST HISTORY" -ForegroundColor Cyan
$ConsoleHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

if (Test-Path $ConsoleHistoryPath) {
    $HistoryFile = Get-Item -Path $ConsoleHistoryPath -Force -ErrorAction SilentlyContinue
    
    if ($HistoryFile.LastWriteTime -lt $LogonTime) {
        Write-Host "    Latest input out of instance." -ForegroundColor Green
    } else {
        Write-Host "    [!] File modified during active instance window: $($HistoryFile.LastWriteTime)" -ForegroundColor Yellow
    }

    if ($HistoryFile.Attributes -match "Hidden|System|ReadOnly|Encrypted") {
        Write-Host "    [!] ATTRIBUTE ANOMALY ON HISTORY TRACE:" -ForegroundColor Yellow
        Write-Host "        Attributes: $($HistoryFile.Attributes)" -ForegroundColor Red
    }

    $MaliciousPatterns = "\biex\b|\bencodedcommand\b|\-enc\b|\bdownloadstring\b|\brefassembly\b|reflection\.assembly|\buseb\b|\birm\b"
    $HistoryContent = Get-Content -Path $ConsoleHistoryPath -ErrorAction SilentlyContinue
    
    $FlaggedCommands = @()
    foreach ($Line in $HistoryContent) {
        if ($Line -match $MaliciousPatterns -and $Line -notmatch '^\s*#') {
            $FlaggedCommands += $Line.Trim()
        }
    }

    if ($FlaggedCommands.Count -gt 0) {
        Write-Host "    [!] FLAGGED HIGH-RISK SUSPICIOUS COMMAND FOOTPRINTS:" -ForegroundColor Red
        foreach ($Cmd in $FlaggedCommands) {
            Write-Host "        -> $Cmd" -ForegroundColor White
        }
    } else {
        Write-Host "    [+] Content Evaluation: No high-severity execution tags found inside buffer logs." -ForegroundColor Green
    }
} else {
    Write-Host "    [-] ConsoleHost history tracking log file missing or cleaned from active profile." -ForegroundColor Red
}
Write-Host ""`n


# ------------------------------------------------------------------------------
# STEP 6: FILE SYSTEM DEEP MONITOR STAGE (INTEGRATED UNICODE & SPOOF AUDIT)
# ------------------------------------------------------------------------------


Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   LOOKING FOR MASKED EXECUTABLES" -ForegroundColor Cyan
Write-Host "======================================================================`n" -ForegroundColor Cyan

# Combined target folders
$TargetPaths = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\AppData\Local",
    "$env:USERPROFILE\AppData\Roaming",
    "C:\Users\Public"
)

# Extensions that should NOT contain MZ headers natively
$NonExeExtensions = @('.png', '.jpg', '.jpeg', '.gif', '.txt', '.cfg', '.ini', '.log', '.dat', '.mp4', '.zip', '.pdf')

$UnicodeFoundCount = 0
$SpoofFoundCount = 0

foreach ($Path in $TargetPaths) {
    if (-not (Test-Path $Path)) { continue }

    # Gathering all items recursively
    $Files = Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue

    foreach ($File in $Files) {
        
        # Check for spofed or extentionless
        if (($File.Extension.ToLower() -in $NonExeExtensions) -or [string]::IsNullOrEmpty($File.Extension)) {
            try {
                $Stream = [System.IO.File]::OpenRead($File.FullName)
                $Bytes = New-Object Byte[] 2
                $ReadCount = $Stream.Read($Bytes, 0, 2)
                $Stream.Close()

                if ($ReadCount -eq 2) {
                    $MagicHeader = [System.Text.Encoding]::ASCII.GetString($Bytes)
                    
                    if ($MagicHeader -eq "MZ") {
                        $SpoofFoundCount++
                        
                        $DetectionType = if ([string]::IsNullOrEmpty($File.Extension)) { "EXTENSIONLESS EXECUTABLE DETECTED!" } else { "SPOOFED EXECUTABLE DETECTED!" }

                        $Signature = Get-AuthenticodeSignature -FilePath $File.FullName -ErrorAction SilentlyContinue
                        $SigText = if ($Signature.Status -eq "Valid") { "SIGNED (Valid)" } else { "UNSIGNED ($($Signature.Status))" }
                        $SigColor = if ($Signature.Status -eq "Valid") { "Green" } else { "Red" }

                        Write-Host "[!] $DetectionType" -ForegroundColor Yellow
                        Write-Host "    Current Name: $($File.Name)" -ForegroundColor White
                        Write-Host "    Full Path:    $($File.FullName)" -ForegroundColor Gray
                        Write-Host "    Signature:    $SigText" -ForegroundColor $SigColor
                        
                        if ($File.Attributes -match "Hidden") {
                            Write-Host "    Attributes:   HIDDEN FILE" -ForegroundColor DarkYellow
                        }
                        Write-Host ""
                    }
                }
            } catch {
                if ($Stream) { $Stream.Close() }
            }
        }

        # Unicode checks
        if ($File.Extension.ToLower() -eq ".exe" -or $File.Extension.ToLower() -eq ".dll") {
            if ($File.FullName -match '[^\x20-\x7E]') {
                $UnicodeFoundCount++
                
                $Signature = Get-AuthenticodeSignature -FilePath $File.FullName -ErrorAction SilentlyContinue
                $SigStatus = $Signature.Status
                
                if ($SigStatus -eq "Valid") {
                    $SigColor = "Green"
                    $SigText = "SIGNED (Valid) - Publisher: $($Signature.SignerCertificate.Subject)"
                } else {
                    $SigColor = "Red"
                    $SigText = "UNSIGNED ($SigStatus)" 
                }

                Write-Host "[!] Found Unicode in Path!" -ForegroundColor Yellow
                Write-Host "    File Name: $($File.Name)" -ForegroundColor White
                Write-Host "    Full Path: $($File.FullName)" -ForegroundColor Gray
                Write-Host "    Signature: $SigText" -ForegroundColor $SigColor
                
                if ($File.Attributes -match "Hidden") {
                    Write-Host "    Attributes:  HIDDEN FILE" -ForegroundColor DarkYellow
                }
                Write-Host ""
            }
        }
    }
}

# ------------------------------------------------------------------------------
# CREDITS AND OUTPUT
# ------------------------------------------------------------------------------
Write-Host "  Scan complete." -ForegroundColor Cyan
Write-Host "Made by kastris_`n" -ForegroundColor Magenta

if ($UnicodeFoundCount -eq 0 -and $SpoofFoundCount -eq 0) {
    Write-Host "[+] Clean! No hidden executables or suspicious Unicode file paths found." -ForegroundColor Green
} else {
    Write-Host "[!] Warning: Found $UnicodeFoundCount Unicode path(s) and $SpoofFoundCount masked executable(s)." -ForegroundColor Red
}
