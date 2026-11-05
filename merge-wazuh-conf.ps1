#
# merge-wazuh-conf.ps1
# version 2.0
# by Kevin Branch (Branch Network Consulting, LLC)
#
# This builds and applies a fresh ossec-agent/ossec.conf from a merge of all ossec-agent/conf.d/*.conf files, with automatic revertion to the previous ossec.conf in the event that Wazuh Agent fails to restart or reconnect with the newer merged version of ossec.conf.
# It is intended to be run automatically by Wazuh Agent itself via a locally defined command-type localfile section invoking it at ossec-agent scripts/merge-wazuh-conf.ps1.
# This is part of accomodating the use of custom WPKs to securely distribute and/or invoke new scripts and to distribute and apply new config sections to be merged into ossec.conf, especially ones involving formerly "remote" commands.
#
# This script should be located and executed in ossec-agent\scripts\merge-wazuh-conf.ps1.  
# The following must be part of ossec-agent\ossec.conf to ensure this script is run daily and at each agent restart.
#
# <ossec_config>
#   <localfile>
#      <log_format>command</log_format>
#      <alias>merge-wazuh-conf</alias>
#      <command>PowerShell.exe -ExecutionPolicy Bypass -File scripts/merge-wazuh-conf.ps1</command>
#      <frequency>86400</frequency>
#   </localfile>  
# </ossec_config>
#
# EventLog entries written to Application log with source Wazuh-Modular:
#
# 10000 - Info  - "merge-wazuh-conf: applying new merged ossec.conf and restarting Wazuh agent..."
# 10001 - Error - "merge-wazuh-conf: new ossec.conf appears to prevent Wazuh Agent from starting.  Reverting and restarting..."
# 10002 - Info  - "merge-wazuh-conf: reverted ossec.conf and Wazuh agent successfully restarted..."
# 10003 - Error - "merge-wazuh-conf: reverted ossec.conf and Wazuh agent still failed to start"
# 10004 - Info  - "merge-wazuh-conf: exited due to a previous failed ossec.conf remerge attempt less than an hour ago"
# 10005 - Info  - "merge-wazuh-conf: ossec.conf is already up to date"
#

# Create EventLog Source "Wazuh-Modular" in the "Application" log if missing so logging is possible if needed.
New-EventLog -LogName 'Application' -Source "Wazuh-Modular" -ErrorAction 'silentlycontinue'

# As a safeguard, ensure that the Windows Wazuh Agent service is set to autorecover if it fails.
& sc.exe failure wazuhsvc reset=86400 actions=restart/900000 | out-null
& sc.exe failureflag wazuhsvc 1 | out-null

# Discover which Program Files directory would contain Wazuh's program directory, with a 64bit vs 32bit check.
If ([Environment]::Is64BitOperatingSystem) {
    $PFPATH="C:\Program Files (x86)"
} else {
    $PFPATH="C:\Program Files"
}

# Prevent concurrent merge executions before modifying configuration files.
# Windows automatically releases the lock if the owning process exits.
try {
    $MergeMutex = New-Object System.Threading.Mutex($false, 'Global\BNC-WazuhConfigMerge')
    $MergeLockAcquired = $false

    try {
        $MergeLockAcquired = $MergeMutex.WaitOne(0)
    } catch [System.Threading.AbandonedMutexException] {
        $MergeLockAcquired = $true
    }

    if (-not $MergeLockAcquired) {
        Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10007 -EntryType Information -Message "merge-wazuh-conf: skipped due to script already running" -Category 0
        $MergeMutex.Dispose()
        exit 2
    }
} catch {
    Write-Output "merge-wazuh-conf: failed to acquire merge lock: $_"
    exit 2
}

# If Wazuh agent conf.d directory is not yet present, then create it and populate it with a 000-base.conf copied from current ossec.conf file.
if ( -not (Test-Path -LiteralPath "$PFPATH\ossec-agent\conf.d" -PathType Container ) ) {
    New-Item -ItemType "directory" -Path "$PFPATH\ossec-agent\conf.d" | out-null
    while ( -not ( Test-Path "$PFPATH\ossec-agent\conf.d" -PathType Container ) ) {
	sleep 1
 	Write-Output "directory missing, pausing..."
    }
    Copy-Item "$PFPATH\ossec-agent\ossec.conf" "$PFPATH\ossec-agent\conf.d\000-base.conf"
    # If the newly generated 000-base.conf (from old ossec.conf) is missing the merge-wazuh-conf command section, then append it now.    
	$baseFile = Get-Content "$PFPATH\ossec-agent\conf.d\000-base.conf" -Raw
    if ($baseFile -notmatch 'merge-wazuh-conf\.ps1') {
        $mergeCommand = @"
    <localfile>
        <log_format>command</log_format>
        <alias>merge-wazuh-conf</alias>
        <command>PowerShell.exe -ExecutionPolicy Bypass -File scripts/merge-wazuh-conf.ps1</command>
        <frequency>86400</frequency>
    </localfile>
"@
        $closingTag = '</ossec_config>'
        $position = $baseFile.LastIndexOf($closingTag, [System.StringComparison]::OrdinalIgnoreCase)
        if ($position -lt 0) {
            throw "Cannot add merge command: 000-base.conf has no closing ossec_config tag."
        }
        $baseFile = $baseFile.Insert($position, "$mergeCommand`r`n")
        Set-Content "$PFPATH\ossec-agent\conf.d\000-base.conf" -Value $baseFile
    }
}
# If there was a failed ossec.conf remerge attempt less than an hour ago then bail out (failed as in Wazuh agent would not start using latest merged ossec.conf)
# This is to prevent an infinite loop of remerging, restarting, failing, reverting, and restarting again, caused by bad material in a conf.d file.
if ( ( Test-Path -LiteralPath "$PFPATH\ossec-agent\ossec.conf-BAD" ) -and ( ( (Get-Date) - (Get-Item "$PFPATH\ossec-agent\ossec.conf-BAD").LastWriteTime ).totalhours -lt 1 ) ) {
    Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10004 -EntryType Error -Message "merge-wazuh-conf: exited due to a previous failed ossec.conf remerge attempt less than an hour ago" -Category 0
    exit 2
}
# Merge conf.d/*.conf into conf.d/config.merged
$files = Get-ChildItem "$PFPATH\ossec-agent\conf.d\*.conf"
Remove-Item -Path "$PFPATH\ossec-agent\conf.d\config.merged" -erroraction 'silentlycontinue'
foreach ($f in $files) {
    $fname = $f.Name
    $content = Get-Content $f.FullName
    Add-Content -Path "$PFPATH\ossec-agent\conf.d\config.merged" -Value "<!--`nFrom conf.d/$fname`n-->"
    Add-Content -Path "$PFPATH\ossec-agent\conf.d\config.merged" -Value $content
    Add-Content -Path "$PFPATH\ossec-agent\conf.d\config.merged" -Value ""
}
# If the rebuilt config.merged file is the same (by MD5 hash) as the main ossec.conf then there is nothing more to do.
$hash1 = (Get-FileHash "$PFPATH\ossec-agent\conf.d\config.merged" -Algorithm MD5).Hash
$hash2 = (Get-FileHash "$PFPATH\ossec-agent\ossec.conf" -Algorithm MD5).Hash
if ($hash1 -eq $hash2) {
    Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10005 -EntryType Information -Message "merge-wazuh-conf: ossec.conf is already up to date" -Category 0

    # Initial deployment invokes the merge while WazuhSvc is stopped.
    # Otherwise, an unchanged configuration requires no service action.
    $Service = Get-Service WazuhSvc -ErrorAction Stop

    if ($Service.Status -eq 'Stopped') {
        Start-Service WazuhSvc -ErrorAction Stop

        $Connected = $false
        $Deadline = (Get-Date).AddSeconds(90)

        do {
            if ( ((Get-Service WazuhSvc -ErrorAction SilentlyContinue).Status -eq 'Running') -and ( (netstat -nat) -match ':1514[^\d]+ESTABLISHED' ) ) {
                $Connected = $true
                break
            }
            Start-Sleep -Seconds 5
        } while ((Get-Date) -lt $Deadline)

        if (-not $Connected) {
            Write-Output "merge-wazuh-conf: agent failed to reconnect during initial startup."
            exit 2
        }
    }

# However if config.merged is different than ossec.conf, then back up ossec.conf, replace it with config.merged, and restart Wazuh Agent service
} else {
    Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10000 -EntryType Information -Message "merge-wazuh-conf: applying new merged ossec.conf and restarting Wazuh agent..." -Category 0
    # Pause to give time for above log message to be transmitted to Wazuh manager.  The upcoming agent restart will otherwise cause this log to be lost.
    Start-Sleep 10
    # Preserve the current configuration before applying the merged version.
    # The merge lock ensures another instance cannot overwrite this backup.
    Copy-Item "$PFPATH\ossec-agent\ossec.conf" "$PFPATH\ossec-agent\ossec.conf-BACKUP" -Force -ErrorAction Stop
    Copy-Item "$PFPATH\ossec-agent\conf.d\config.merged" "$PFPATH\ossec-agent\ossec.conf" -Force
    $Service = Get-Service WazuhSvc -ErrorAction Stop

    if ($Service.Status -ne 'Stopped') {
        Stop-Service WazuhSvc -ErrorAction Stop
        $Service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }

    Start-Service WazuhSvc -ErrorAction Stop

    # Wait up to 60 seconds for Wazuh Agent to restart and reconnect.
    $Connected = $false
    $Deadline = (Get-Date).AddSeconds(60)

    do {
        if ( ((Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue).Status -eq "Running") -and ( (netstat -nat) -match ':1514[^\d]+ESTABLISHED' ) ) {
            $Connected = $true
            break
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $Deadline)

    # If the agent failed to reconnect, restore the previous configuration.
    if (-not $Connected) {
        Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10001 -EntryType Error -Message "merge-wazuh-conf: new ossec.conf appears to prevent Wazuh Agent from starting.  Reverting and restarting..." -Category 0
        Move-Item "$PFPATH\ossec-agent\ossec.conf" "$PFPATH\ossec-agent\ossec.conf-BAD" -Force
        Move-Item "$PFPATH\ossec-agent\ossec.conf-BACKUP" "$PFPATH\ossec-agent\ossec.conf" -Force
        Stop-Service WazuhSvc
        Start-Service WazuhSvc

        # Wait up to 60 seconds for the restored configuration to reconnect.
        $Recovered = $false
        $Deadline = (Get-Date).AddSeconds(60)

        do {
            if ( ((Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue).Status -eq "Running") -and ( (netstat -nat) -match ':1514[^\d]+ESTABLISHED' ) ) {
                $Recovered = $true
                break
            }
            Start-Sleep -Seconds 5
        } while ((Get-Date) -lt $Deadline)

        if ($Recovered) {
            Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10002 -EntryType Information -Message "merge-wazuh-conf: reverted ossec.conf and Wazuh agent successfully restarted..." -Category 0
        } else {
            Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10003 -EntryType Error -Message "merge-wazuh-conf: reverted ossec.conf and Wazuh agent still failed to start" -Category 0
        }
        exit 2
    }
}
