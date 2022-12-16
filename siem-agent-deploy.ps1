#
# siem-agent-deploy.ps1
#
# This script is for checking and/or installing the Wazuh agent on Windows systems.  It can directly install or uninstall it, conditionally install it, or simply check to see if installation/reinstallation is needed.
# The Wazuh agent for Windows presently includes Wazuh agent integrated for centralized configuration and reporting via the Wazuh manager.  
# It also defaults to signalling to the Wazuh manager to push the Sysmon and/or Osquery management WPKs to this agent, which can be optionally excluded.
#
# Depending on the use case, this script can be called singly on a one time or periodic basis to conditionally install/reinstall the agent.  
# Alternatively, a higher level configuration management system like Puppet could first call this script just to check if installation/reinstallation is called for, and based on the exit code it receives, 
# conditionally call this script a second time to explicitly install/reinstall the agent.
#
# Deployment will install Wazuh agent on Ubuntu, CentOS, and Amazon Linux systems.
# After preserving the working Wazuh agent registration key if present, Wazuh/OSSEC agent is completely purged and then reinstalled.
#
# The Wazuh agent self registration process is included, but will be skipped if an existing working registration can be recycled.
# Agent name and group names must match exactly for registration to be recycled. This will keep the same agent id associated with the agent.
#
# If any of the listed test families fail, the Wazuh agent will be (re)installed.
#
# If the call to this script is deemed broken, or either the Wazuh Manager connect port or registration port are unresponsive to a probe, an exit code of 2 will be returned.
#
# The default exit code is 0.
#
# Is the agent presently really connected to the Wazuh manager?
# Is the agent connected to the right manager?
# Is the agent currently a member of all intended Wazuh agent groups?
# Is the target version of Wazuh agent installed?
#
# Required Parameters:
#
# -WazuhVer         Full version of Wazuh agent to confirm and/or install, like "4.1.4". 
# -WazuhMgr         IP or FQDN of the Wazuh manager for ongoing agent connections. 
# -WazuhRegPass     Password for registration with Wazuh manager (put in quotes).
#
# Optional Parameters:
#
# -WazuhRegMgr      IP or FQDN of the Wazuh manager for agent registration connection (defaults to $WazuhMgr if not specified)
# -WazuhAgentName   Name under which to register this agent in place of locally detected Windows host name.
# -WazuhGroups      Comma separated list of optional extra Wazuh agent groups to member this agent.  No spaces.  Put whole list in quotes.  Groups must already exist.
#                   Use "" to expect zero extra groups.
#                   If not specified, agent group membership will not be checked at all.
#                   Do not include "windows" or "windows-local"group as these are autodetected and will dynamically be inserted as groups.
#                   Do not include "osquery" or "osquery-local" as these will automatically be included unless -SkipOsquery is in the command call
#					Do not include "sysmon" or "sysmon-local" as these will automatically be included unless -SkipSysmon is in the command call
# -WazuhSrc         Static download path to fetch Wazuh agent installer.  Overrides WazuhVer value.
# -SkipSysmon		Flag to not signal the Wazuh manager to push managed Sysmon WPK to this system. (Default is to not skip this.)
# -SkipOsquery      Flag to not signal the Wazuh manager to push managed Osquery WPK to this system. (Default is to not skip this.)
# -Install          Skip all checks and force installation
# -Uninstall        Uninstall Wazuh agent and sub-agents
# -CheckOnly        Only run checks to see if installation is current or in need of deployment
# -LBprobe          Additionally check for manager connectivity with an agent-auth probe to avoid being fooled by a load balancer that handshakes even when service down.
# -Debug            Show debug output
# -help             Show command syntax
#
# Sample command line:
#
# PowerShell.exe -ExecutionPolicy Bypass -File .\siem-agent-deploy.ps1 -WazuhVer "4.3.9" -WazuhMgr "{Manager DNS or IP}" -WazuhRegPass "{Your_Password}" -WazuhGroups "{Your_comma_separated_group_list}" -Debug
#
# Please note that the following groups are built into the script and should be added to the Wazuh Manager PRIOR to any use of this script.
#
# "windows,windows-local,sysmon,sysmon-local,osquery,osquery-local".
#

# All possible parameters that may be specified for check-only, conditional install, forced install or forced uninstall purposes.
param ( $WazuhVer, 
	$WazuhMgr, 
	$WazuhRegMgr, 
	$WazuhRegPass, 
	$WazuhAgentName = $env:computername, 
	$WazuhGroups = "#NOGROUP#", 
	$WazuhSrc, 
	[switch]$SkipSysmon=$false, 
	[switch]$SkipOsquery=$false,
	[switch]$Local=$false,
	[switch]$Debug=$false,
	[switch]$CheckOnly=$false,
	[switch]$Install=$false,
	[switch]$Uninstall=$false,
	[switch]$LBprobe=$false
);

# 
# Probe a target FQDN/IP on a target tcp port and if no response is received or the FQDN cannot be resolved, then fail and bail with an exit code of 2.
#
function tprobe {
	$tp_host = $args[0]
	$tp_port = $args[1]
	if ($Debug) { Write-Output "Probing $tp_host on port $tp_port..." }
	if ( -not ( $tp_host -as [IPAddress] -as [Bool] ) ) {
		$IPBIG=""
		$IPBIG=([System.Net.Dns]::GetHostEntry($tp_host)).AddressList.IPAddressToString
		if ( $IPBIG -eq "" ) {	
			if ($Debug) { Write-Output "Failed to resolve IP for $tp_host" }
			exit 2
		}
	}
	$tcpClient = New-Object System.Net.Sockets.TcpClient
	$connection = $tcpClient.ConnectAsync($tp_host, $tp_port).Wait(1000)
	if ($connection) {
		if ($Debug) { Write-Output "Success!" }
	}
	else {
		if ($Debug) { Write-Output "Probe failed!" }
		exit 2
	}
}

function writePEMfile {
$PEMtoWrite = @"
-----BEGIN CERTIFICATE-----
MIIDNzCCAh+gAwIBAgIURDCxvmgAH12XqdEdQH/CKgy0+CIwDQYJKoZIhvcNAQEL
BQAwKzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAklOMQ8wDQYDVQQKDAZCTkMgQ0Ew
HhcNMjIxMDAzMjExNzU5WhcNMzIwOTMwMjExNzU5WjArMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCSU4xDzANBgNVBAoMBkJOQyBDQTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBANpnhmd+2mUHCjzqvwHx6KeYSaQa2IFNXoQHlj70vMSBm7dH
GebtQSCF1W3XlRwCW6lK6MitSnPSx8D9ct8QvI7cWYvcjZ1OcY3Vv69rfM5akqi4
J1wlWn2HkLmoEdoMwNAQD9c+3XCS9KRC6VcIW7XH+029iTisPNP+X1vFeFCyjz68
SxpL7Ili5GrcDaCWD7Rw7fZjkyTIOrm80vAVGPuXMpSYbdFCwk12j0TQuVovg9bG
b0ykvZBuNrhzfw/KVoxNmsnagZ1gZgMyRJFaje2RmwQu719lu+qoVunzoMZnt/bj
WlLvPENSrYvjhO7+LEVE+uHPgZb5IhAM3GTXpQECAwEAAaNTMFEwHQYDVR0OBBYE
FPT8KA/lCLNFutMi+d3RVX8gCpBzMB8GA1UdIwQYMBaAFPT8KA/lCLNFutMi+d3R
VX8gCpBzMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEdHaQzB
4t6ICDqaoClIlukZPnPOBX3vIaXSTucdX5s0bX0wGNngG+FKM7Ka/jY51YyfCFOr
6J6v0GSIFmTeOX/G4zoy+daxd1sIkMq16urBHxWepanhKmM2UnIrVEqaD2Jjgt30
yuIVJyENaCrXhdH82HndaVEUR8aGnEVUmgPpg+9pRAh8sQUu7LCENI+HP+uaa29c
e1A3jj1X98UOy+58chxEHtyaZy06v3vz4UNWgJf/LGBMT7wO3c8TsTT5KmgHR460
zraxbhmzb4JAji0bZuYlldSjhizRCpJjroFjWHluDUa9Oqi5La52o+rpRVwT53bY
O7bM4haWNBQkxEU=
-----END CERTIFICATE-----
"@
	$PEMtoWrite | Out-File -FilePath "$PFPATH\ossec-agent\bnc_wpk_root.pem" -Encoding ASCII
}

#
# Write merge-wazuh-conf.ps1 to scripts directory
#
function writeMergeScript {
	
$ScriptToWrite = @'
#
# merge-wazuh-conf.ps1
# version 1.1
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
# 10000 - Info  - "merge-wazuh-conf.ps1 applying new merged ossec.conf and restarting Wazuh agent..."
# 10001 - Error - "merge-wazuh-conf.ps1 new ossec.conf appears to prevent Wazuh Agent from starting.  Reverting and restarting..."
# 10002 - Info  - "merge-wazuh-conf.ps1 reverted ossec.conf and Wazuh agent successfully restarted..."
# 10003 - Error - "merge-wazuh-conf.ps1 reverted ossec.conf and Wazuh agent still failed to start."
# 10004 - Info  - "merge-wazuh-conf.ps1 exited due to a previous failed ossec.conf remerge attempt less than an hour ago."
# 10005 - Info  - "merge-wazuh-conf.ps1 found ossec.conf up to date with conf.d."
#

# Create EventLog Source "Wazuh-Modular" in the "Application" log if missing so logging is possible if needed.
New-EventLog -LogName 'Application' -Source "Wazuh-Modular" -ErrorAction 'silentlycontinue'

# Discover which Program Files directory would contain Wazuh's program directory, with a 64bit vs 32bit check.
If ([Environment]::Is64BitOperatingSystem) {
    $PFPATH="C:\Program Files (x86)"
} else {
    $PFPATH="C:\Program Files"
}

# If Wazuh agent conf.d directory is not yet present, then create it and populate it with a 000-base.conf copied from current ossec.conf file.
if ( -not (Test-Path -LiteralPath "$PFPATH\ossec-agent\conf.d" -PathType Container ) ) {
    New-Item -ItemType "directory" -Path "$PFPATH\ossec-agent\conf.d" | out-null
    Copy-Item "$PFPATH\ossec-agent\ossec.conf" "$PFPATH\ossec-agent\conf.d\000-base.conf"
    # If the newly generated 000-base.conf (from old ossec.conf) is missing the merge-wazuh-conf command section, then append it now.
    $baseFile = Get-Content "$PFPATH/ossec-agent/conf.d/000-base.conf" -erroraction 'silentlycontinue'
}

# If there was a failed ossec.conf remerge attempt less than an hour ago then bail out (failed as in Wazuh agent would not start using latest merged ossec.conf)
# This is to prevent an infinite loop of remerging, restarting, failing, reverting, and restarting again, caused by bad material in a conf.d file.
if ( ( Test-Path -LiteralPath "$PFPATH\ossec-agent\ossec.conf-BAD" ) -and ( ( (Get-Date) - (Get-Item "$PFPATH\ossec-agent\ossec.conf-BAD").LastWriteTime ).totalhours -lt 1 ) ) {
    Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10004 -EntryType Information -Message "merge-wazuh-conf.ps1 exited due to a previous failed ossec.conf remerge attempt less than an hour ago." -Category 0
    exit
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
    Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10005 -EntryType Information -Message "merge-wazuh-conf.ps1 found ossec.conf up to date with conf.d." -Category 0
# However if config.merged is different than ossec.conf, then back up ossec.conf, replace it with config.merged, and restart Wazuh Agent service
} else {
    Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10000 -EntryType Information -Message "merge-wazuh-conf.ps1 applying new merged ossec.conf and restarting Wazuh agent..." -Category 0
    Copy-Item "$PFPATH\ossec-agent\ossec.conf" "$PFPATH\ossec-agent\ossec.conf-BACKUP" -Force
    Copy-Item "$PFPATH\ossec-agent\conf.d\config.merged" "$PFPATH\ossec-agent\ossec.conf" -Force
    Stop-Service WazuhSvc
    Start-Service WazuhSvc
    Start-Sleep -s 5
    # If after replacing ossec.conf and restarting, the Wazuh Agent fails to start, then revert to the backed up ossec.conf, restart, and hopefully recovering the service.
    if ( ( -not ( (Get-Service -Name "WazuhSvc").Status -eq "Running" ) ) -or ( -not ( ( netstat -nat ) -match ':1514[^\d]+ESTABLISHED' ) ) ) {
        Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10001 -EntryType Error -Message "merge-wazuh-conf.ps1 new ossec.conf appears to prevent Wazuh Agent from starting.  Reverting and restarting..." -Category 0
        Move-Item "$PFPATH\ossec-agent\ossec.conf" "$PFPATH\ossec-agent\ossec.conf-BAD" -Force
        Move-Item "$PFPATH\ossec-agent\ossec.conf-BACKUP" "$PFPATH\ossec-agent\ossec.conf" -Force
        Stop-Service WazuhSvc
        Start-Service WazuhSvc
        Start-Sleep -s 5
        # Indicate if the service was successfully recovered by reverting ossec.conf.
        if ( ( (Get-Service -Name "WazuhSvc").Status -eq "Running" ) -and ( ( netstat -nat ) -match ':1514[^\d]+ESTABLISHED' ) ) {
            Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10002 -EntryType Information -Message "merge-wazuh-conf.ps1 reverted ossec.conf and Wazuh agent successfully restarted..." -Category 0
        } else {
            Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10003 -EntryType Error -Message "merge-wazuh-conf.ps1 reverted ossec.conf and Wazuh agent still failed to start." -Category 0
        }
    }
}
'@
New-Item -ItemType "directory" -Path "$PFPATH\ossec-agent\scripts" -erroraction 'silentlycontinue' | out-null
$ScriptToWrite | Out-File -FilePath "$PFPATH\ossec-agent\scripts\merge-wazuh-conf.ps1" -Encoding "UTF8"
}

#
# Check if Wazuh agent deployment is in the target state.  If this cannot be determined due to an invalid call on failed probe of the Wazuh manager, fail and bail with exit code 2.
# If no install/reinstall appears to be needed, then bail with an exit code of 0.
# If a installation/reinstallation is called for, then simply return.
#
function checkAgent {

	# Relevant script parameters
	#		
	# -WazuhMgr			IP or FQDN of the Wazuh manager for ongoing agent connections. (Required)
	# -WazuhRegMgr		IP or FQDN of the Wazuh manager for agent registration connection (defaults to $WazuhMgr if not specified)
	# -WazuhVer			Full Wazuh agent version number to confirm, like "3.12.2". (Required)
	# -WazuhGroups		Comma separated list of custom Wazuh agent groups. No spaces. Put whole list in quotes. (Optional)
	#					If intentionally specifying an empty set of custom groups, then your must use the syntax -WazuhGroups '""'
	# -SkipSysmon		Flag to not expect Sysmon default group membership. (Optional)
	# -SkipOsquery		Flag to not expect Osquery default group membership. (Optional)
	# -LBprobe			Additionally check for manager connectivity with an agent-auth probe to avoid being fooled by a load balancer that handshakes even when service down.

	if ($WazuhMgr -eq $null) { 
		if ($Debug) { Write-Output "Must use '-WazuhMgr' to specify the FQDN or IP of the Wazuh manager to which the agent shall retain a connection." }
		exit 2
	}
	# If WazuhRegMgr not listed, assume it is the same as WazuhMgr.
	if ($WazuhRegMgr -eq $null) { 
		$WazuhRegMgr = $WazuhMgr
	}
	if ($WazuhVer -eq $null) { 
		if ($Debug) { Write-Output "Must use '-WazuhVer' to specify the version of Wazuh agent to check for." }
		exit 2
	}

	$StateFile = Get-Item -Path "$PFPATH\ossec-agent\wazuh-agent.state" -erroraction SilentlyContinue
	if ( (($StateFile.LastWriteTime) -gt (Get-Date).AddMinutes(-10)) -and (Get-Content -Path "$PFPATH\ossec-agent\wazuh-agent.state" | Select-String -Pattern "status='connected'").Matches.Success ) {
		if ($Debug) { Write-Output "Agent is connected to a manager." }	
	} else {
		if ($Debug) { Write-Output "Agent is not connected to a manager, so will probe next." }	
		# Confirm the self registration and agent connection ports on the manager(s) are responsive.  
		# If either are not, then (re)deployment is not feasible, so return an exit code of 2 so as to not trigger the attempt of such.
		tprobe $WazuhMgr 1514
		tprobe $WazuhRegMgr 1515
		# If -LBprobe flag set, then additionally confirm the manager is reachable by intentionally attempting an agent-auth with a bad password
		# to see if "Invalid password" is in the output, which would probe a real Wazuh registration service is reachable on port 1515.
		if ( ( $LBprobe ) -and ( Test-Path -LiteralPath "$PFPATH\ossec-agent\agent-auth.exe") ) {
			if ($Debug) { Write-Output "Performing a load-balancer-aware check via an agent-auth.exe call to confirm manager is truly reachable..." }
			Remove-Item -Path "agent-auth-test-probe" -erroraction 'silentlycontinue'
			Start-Process -FilePath "$PFPATH\ossec-agent\agent-auth.exe" -ArgumentList "-m", "$WazuhRegMgr", "-P", "badpass" -Wait -WindowStyle 'Hidden' -redirectstandarderror "agent-auth-test-probe"
			if (  ( -not ( Test-Path -LiteralPath "agent-auth-test-probe" ) ) -or ( -not ( Get-Content "agent-auth-test-probe" | select-String "Invalid password" ) ) ) {
				Remove-Item -Path "agent-auth-test-probe" -erroraction 'silentlycontinue'
				if ($Debug) { Write-Output "LBprobe check failed.  Manager is not truly reachable." }
				exit 2
			}
			Remove-Item -Path "agent-auth-test-probe" -erroraction 'silentlycontinue'
			if ($Debug) { Write-Output "LBprobe check succeeded.  Manager is truly reachable." }
		}
	}

	#
	# Is the agent presently really connected to a Wazuh manager?
	#
	if ( (($StateFile.LastWriteTime) -gt (Get-Date).AddMinutes(-10)) -and (Get-Content -Path "$PFPATH\ossec-agent\wazuh-agent.state" | Select-String -Pattern "status='connected'").Matches.Success ) {
		if ($Debug) { Write-Output "The Wazuh agent is connected to a Wazuh manager." }
	} else {
		if ( $StateFile.LastWriteTime -gt (Get-Date).AddMinutes(-10) ) {
			if ($Debug) { Write-Output "Waiting 70 seconds to see if Wazuh agent is only temporarily disconnected from manager." }
			Start-Sleep -Seconds 70
			$StateFile = Get-Item -Path "$PFPATH\ossec-agent\wazuh-agent.state" -erroraction SilentlyContinue
			if ( (($StateFile.LastWriteTime) -gt (Get-Date).AddMinutes(-10)) -and (Get-Content -Path "$PFPATH\ossec-agent\wazuh-agent.state" | Select-String -Pattern "status='connected'").Matches.Success ) {
				if ($Debug) { Write-Output "The Wazuh agent is now connected to a Wazuh manager." }
			} else {
				if ($Debug) { Write-Output "The Wazuh agent is still not connected to a Wazuh manager." }
				return
			}
		} else {
			if ($Debug) { Write-Output "The Wazuh agent is not connected to a Wazuh manager." }
			return
		}
	}

        #
        # Connected to the right manager?
        #
        if ( -not ( $CurrentManager -eq $WazuhMgr ) ) {
            if ($Debug) { Write-Output "The Wazuh agent is connected to a different manager than the target manager." }
	    return
        }

	#
	# Is the agent currently a member of all intended Wazuh agent groups?
	#
	if ( -not ( $WazuhGroups -eq "#NOGROUP#" ) ) {
		If (Test-Path "$PFPATH\ossec-agent\shared\merged.mg") {	
			$file2 = Get-Content "$PFPATH\ossec-agent\shared\merged.mg" -erroraction 'silentlycontinue'	
			if ($file2 -match "Source\sfile:") {
				$CurrentGroups=((((Select-String -Path "$PFPATH\ossec-agent\shared\merged.mg" -Pattern "Source file:") | Select-Object -ExpandProperty Line).Replace("<!-- Source file: ","")).Replace("/agent.conf -->","")) -join ','
			} else {
				# If the agent is presently a member of only one agent group, then pull that group name into current group variable.
				$CurrentGroups=((((Select-String -Path "$PFPATH\ossec-agent\shared\merged.mg" -Pattern "#") | Select-Object -ExpandProperty Line).Replace("#","")))
			}
		} else {
			$CurrentGroups="#NONE#"
		}
		if ($Debug) { Write-Output "Current agent group membership: $CurrentGroups" }
		# Blend standard/dynamic groups with custom groups
		$WazuhGroupsPrefix = "windows,windows-local,"
		if ( $SkipOsquery -eq $false ) {
			$WazuhGroupsPrefix = $WazuhGroupsPrefix+"osquery,osquery-local,"
		}
		if ( $SkipSysmon -eq $false ) {
			$WazuhGroupsPrefix = $WazuhGroupsPrefix+"sysmon,sysmon-local,"
		}
		$WazuhGroups = $WazuhGroupsPrefix+$WazuhGroups
		$WazuhGroups = $WazuhGroups.TrimEnd(",")
		if ($Debug) { Write-Output "Target agent group membership:  $WazuhGroups" }
		if ( -not ( $CurrentGroups -eq $WazuhGroups ) ) {
			if ($Debug) { Write-Output "Current and expected agent group membership differ." }
			return
		}
	} else {
		if ($Debug) { Write-Output "Ignoring agent group membership since -WazuhGroups not specified." }
	}

	#
	# Is the target version of Wazuh agent installed?
	#
	$version = [IO.File]::ReadAllText("$PFPATH\ossec-agent\VERSION").trim().split("v")[1]
	if ($Debug) { Write-Output "Current Wazuh agent version is: $version" }
	if ($Debug) { Write-Output "Target Wazuh agent version is:  $WazuhVer" }
	if ( -not ( $WazuhVer.Trim() -eq $version.Trim() ) ) {
		if ($Debug) { Write-Output "Current and expected Wazuh agent version differ." }
		return
	}

	# All relevant tests passed, so return a success code.
	if ($Debug) { Write-Output "No deployment/redeployment appears to be needed." }
	exit 0
}

# 
# Uninstall Wazuh Agent, and unless skipped
# As part of the Wazuh Agent uninstall process, ascertain if we might be in a position to recycle the agent registration, and set the flag and preserve information accordingly.
#
function uninstallAgent {

	# Relevant script parameters
	#		
	# -WazuhMgr			IP or FQDN of the Wazuh manager for ongoing agent connections.  Required.
	# -WazuhAgentName	Name under which to register this agent in place of locally detected Windows host name
	# -Uninstall		Uninstall without checking and without installing thereafter

	if ($Debug) { Write-Output "Uninstalling the Wazuh agent." }
	
	if (Test-Path "$PFPATH\ossec-agent\ossec.log" -PathType leaf) {
		Copy-Item "$PFPATH\ossec-agent\ossec.log" -Destination "$Env:SystemDrive\Windows\Temp\"
	}
	
	# NuGet Dependency
	if ( -not (Test-Path -LiteralPath "C:\Program Files\PackageManagement\ProviderAssemblies\nuget" -PathType Container) ) {
		if ($Debug) { Write-Output "Installing dependency (NuGet) to be able to uninstall other packages..." }
		if ( $Local -eq $false ) {
			cd c:\
			$count = 0
			$success = $false;
			do{
				try{
					Install-PackageProvider -Name NuGet -Force
					$success = $true
				}
				catch{
					if ($count -lt 5) {
						if ($Debug) { Write-Output "Download attempt failed.  Will retry 10 seconds." }
					} else {
						if ($Debug) { Write-Output "Download attempt still failed.  Giving up and aborting the installation..." }
						exit 1
					}
					Start-sleep -Seconds 10
				}  
				$count++    
			}until($count -eq 6 -or $success)
		} else {
			if ( -not (Test-Path -LiteralPath "C:\Program Files\PackageManagement\ProviderAssemblies" -PathType Container ) ) {
				New-Item -ItemType "directory" -Path "C:\Program Files\PackageManagement\ProviderAssemblies"
			}
			Microsoft.PowerShell.Archive\Expand-Archive "nuget.zip" -DestinationPath "C:\Program Files\PackageManagement\ProviderAssemblies\"
			Import-PackageProvider -Name NuGet
		}
	}
	
	# If Wazuh agent is already installed and registered, and this is not an explicit uninstallation call, then note if registration may be recyclable,
	# and if so, preserve client.keys and the agent groups list to accomodate that, plus set the $MightRecycleRegistration flag.
	$RegFileName = "$PFPATH\ossec-agent\client.keys"
	if ( ( -not ($Uninstall) ) -and (Test-Path $RegFileName -PathType leaf) -and ((Get-Item $RegFileName).length -gt 0)  ) {
		# The existing registration will be recyled if:
		#	- the agent is already connected
		#	- the current and target manager are the same
		#	- the current and target agent name are the same
		#	- the agent group list is exactly the same (unless ignored by ommittance of -WazuhGroups)
		$StateFile = Get-Content "$PFPATH\ossec-agent\wazuh-agent.state" -erroraction 'silentlycontinue'
		$MergedFile = Get-Content "$PFPATH\ossec-agent\shared\merged.mg" -erroraction 'silentlycontinue'
		$MergedFileName = "$PFPATH\ossec-agent\shared\merged.mg"
		$CurrentAgentName=(Get-Content "$PFPATH\ossec-agent\client.keys").Split(" ")[1]
		if ( ($StateFile | Select-String -Pattern "'connected'" -quiet) -and ($WazuhMgr -eq $CurrentManager) -and ($CurrentAgentName -eq $WazuhAgentName) ) {
			if ($Debug) { Write-Output "Registration will be recycled unless there is an agent group mismatch." }
			$MightRecycleRegistration=$true
			if ($file2 -match "Source\sfile:") {
				$CurrentGroups=((((Select-String -Path $MergedFileName -Pattern "Source file:") | Select-Object -ExpandProperty Line).Replace("<!-- Source file: ","")).Replace("/agent.conf -->","")) -join ','
			} else {
				# If the agent is presently a member of only one agent group, then pull that group name into current group variable.
				$CurrentGroups=((((Select-String -Path $MergedFileName -Pattern "#") | Select-Object -ExpandProperty Line).Replace("#","")))
			}
			Remove-Item -Path "$env:TEMP\client.keys.bnc" -erroraction 'silentlycontinue' | out-null
			Copy-Item $RegFileName -Destination "$env:TEMP\client.keys.bnc"
		} else {
			if ($Debug) { Write-Output "Registration will not be recycled." }
			$MightRecycleRegistration=$false
		}
	}

	# If Wazuh agent service is running, stop it.  Otherwise uninstall will fail.
	if ( Get-Service | findstr -i " Wazuh " | findstr -i "Running" ) {
		if ($Debug) { Write-Output "Stopping current Wazuh Agent service..." }
		Stop-Service WazuhSvc
	}

	# If Wazuh agent already installed, blow it away
	if ( (Test-Path "$PFPATH\ossec-agent\wazuh-agent.exe" -PathType leaf) -or (Test-Path '$PFPATH\ossec-agent\ossec-agent.exe' -PathType leaf) ) {
		if ($Debug) { Write-Output "Uninstalling existing Wazuh Agent..." }
		Uninstall-Package -Name "Wazuh Agent" -erroraction 'silentlycontinue' | out-null
		Remove-Item "$PFPATH\ossec-agent" -recurse
	}   
	if (Test-Path "$PFPATH\ossec-agent" -PathType Container) {
		Remove-Item "$PFPATH\ossec-agent" -recurse -force
	}
	
}

#
# Install Wazuh Agent, recycling an existing registration if possible and otherwise re-registering it.
#
function installAgent {

	# Relevant script parameters
	#		
	# -WazuhVer			Full version of Wazuh agent to install, like "3.12.2"
	# -WazuhMgr			IP or FQDN of the Wazuh manager for ongoing agent connections.  Required.
	# -WazuhRegMgr		IP or FQDN of the Wazuh manager for agent registration connection (defaults to $WazuhMgr if not specified)
	# -WazuhRegPass		Password for registration with Wazuh manager (put in quotes).  Required.
	# -WazuhAgentName	Name under which to register this agent in place of locally detected Windows host name
	# -WazuhGroups		Comma separated list of Wazuh groups to member this agent.  No spaces.  Put whole list in quotes.  Groups must already exist.
	# -WazuhSrc			Static download path to fetch Wazuh agent installer.  Overrides $WazVer
	# -SkipSysmon		Do not signal to Wazuh manager for Sysmon wpk deployment.
	# -SkipOsquery		Do not signal to Wazuh manager for Osquery wpk deployment.
	
	if ($WazuhMgr -eq $null) { 
		write-host "Must use '-WazuhMgr' to specify the FQDN or IP of the Wazuh manager to which the agent shall retain a connection."
		exit 1
	}
	if ($WazuhRegPass -eq $null) { 
		write-host "Must use '-WazuhRegPass' to specify the password to use for agent registration."
		exit 1
	}
	if ($WazuhVer -eq $null) { 
		write-host "Must use '-WazuhVer' to specify the target version of Wazuh agent, like 3.13.1."
		exit 1
	}
	# Force skip Sysmon and Osquery if Windows is older then Win 10 or Win Svr 2012
	if ( [int]((Get-CimInstance Win32_OperatingSystem).BuildNumber) -lt 9200 ) {
	     Write-Output "Windows older than 10/2012, so skipping Sysmon and Osquery..."
	     $SkipSysmon=$true
	     $SkipOsquery=$true
	}
	# Force skip Osquery if Windows is 32bit
	If ( -not ([Environment]::Is64BitOperatingSystem) ) {
	     Write-Output "Windows is 32bit, so skipping Osquery..."
	     $SkipOsquery=$true
	}

	if ($WazuhRegMgr -eq $null) { 
		$WazuhRegMgr = $WazuhMgr
	}
	if ($WazuhSrc -eq $null) { 
		$WazuhMajorVer = $WazuhVer.ToCharArray()[0]
		$WazuhSrc = "https://packages.wazuh.com/$WazuhMajorVer.x/windows/wazuh-agent-$WazuhVer-1.msi"
	}
	if ( !($PSVersionTable.PSVersion.Major) -ge 5 ) {
		if ($Debug) { write-host "PowerShell 5.0 or higher is required by this script." }
		exit 1
	}

	if ( $WazuhGroups -eq "#NOGROUP#" ) {
		$SkippedGroups = $true
		$WazuhGroups = ""
	} else {
		$SkippedGroups = $false
	}

	# Blend standard/dynamic groups with custom groups
	$WazuhGroupsPrefix = "windows,windows-local,"
	if ( $SkipOsquery -eq $false ) {
		$WazuhGroupsPrefix = $WazuhGroupsPrefix+"osquery,osquery-local,"
	}
	if ( $SkipSysmon -eq $false ) {
		$WazuhGroupsPrefix = $WazuhGroupsPrefix+"sysmon,sysmon-local,"
	}
	$WazuhGroups = $WazuhGroupsPrefix+$WazuhGroups
	$WazuhGroups = $WazuhGroups.TrimEnd(",")

	# If "-Local" option selected, confirm the bnc-deploy.zip is present, unzip it, and confirm all required files were extracted from it.
	if ($Local) {
		if ( -not (Test-Path -LiteralPath "bnc-deploy.zip") ) {
		    if ($Debug) { Write-Output "Option '-Local' specified but no 'bnc-deploy.zip' file was found in current directory.  Giving up and aborting the installation..." }
			exit 1
		}
		Microsoft.PowerShell.Archive\Expand-Archive "bnc-deploy.zip" -Force -DestinationPath .
		if ( -not (Test-Path -LiteralPath "nuget.zip") ) {
			if ($Debug) { Write-Output "Option '-Local' specified but no 'nuget.zip' file was found in current directory.  Giving up and aborting the installation..." }
			exit 1
		}
		if ( -not (Test-Path -LiteralPath "wazuh-agent.msi") ) {
			if ($Debug) { Write-Output "Option '-Local' specified but no 'wazuh-agent.msi' file was found in current directory.  Giving up and aborting the installation..." }
			exit 1
		}
	}

    # If -Local not specified, then confirm that web requests to the Internet are allowed for this host before proceeding
    if ( -not ($Local) ) {
	    $ErrorActionPreference= 'silentlycontinue'
	    $connection = $false
	    $tcpClient = New-Object System.Net.Sockets.TcpClient
	    $connection = $tcpClient.ConnectAsync("www.google.com", 443).Wait(1000)
	    Remove-Variable tcpClient
	    if ( -not $connection ) {
		    if ($Debug) { Write-Output "Unable to open web connections to the Internet according to test against https://www.google.com`nYou may need to use the -Local option." }
		    exit 2
	    }
    }

	#
	# Wazuh Agent 
	#

	# Download Wazuh Agent installer or confirm it is already locally present if "-Local" option specified.
	if ( $Local -eq $false ) {
		# Download the correct version of the Wazuh installer MSI
		if ($Debug) {  Write-Output "Downloading $WazuhSrc" }
		$count = 0
		$success = $false;
		do{
			try{
				Invoke-WebRequest -Uri $WazuhSrc -OutFile wazuh-agent.msi
				$success = $true
			}
			catch{
				if ($count -lt 5) {
					if ($Debug) { Write-Output "Download attempt failed.  Will retry 10 seconds." }
				} else {
					if ($Debug) { Write-Output "Download attempt still failed.  Giving up and aborting the installation..." }
					exit 1
				}
				Start-sleep -Seconds 10
			}  
			$count++    
		}until($count -eq 6 -or $success)
	}

	# Install Wazuh Agent and then remove the installer file
	if ($Debug) {  Write-Output "Installing Wazuh Agent" }
	Start-Process -FilePath wazuh-agent.msi -ArgumentList "/q" -Wait -WindowStyle 'Hidden'
	if ( $Local -eq $false ) {
		rm .\wazuh-agent.msi
	}

	# Create ossec-agent\scripts and write the merge-wazuh-conf.ps1 file to it, and write the bnc_wpk_root.pem file
	writePEMfile
	writeMergeScript

	# If we can safely skip self registration and just restore the backed up client.keys file, then do so. Otherwise, self-register.
	if ( ($MightRecycleRegistration) -and ( ($CurrentGroups -eq $WazuhGroups) -or ($SkippedGroups) ) ) { 
		Copy-Item "$env:TEMP\client.keys.bnc" -Destination "$PFPATH\ossec-agent\client.keys"
	} else {
		# Register the agent with the manager
		# TODO: Keep existing groups if agent connected and -WazuhGroups not specified.
		Remove-Item -Path "$PFPATH\ossec-agent\client.keys"
		if ($Debug) {  
			Write-Output "Registering Wazuh Agent with $WazuhRegMgr..."
			Start-Process -NoNewWindow -FilePath "$PFPATH\ossec-agent\agent-auth.exe" -ArgumentList "-m", "$WazuhRegMgr", "-P", "$WazuhRegPass", "-G", "$WazuhGroups", "-A", "$WazuhAgentName" -Wait
		} else 	{
			Start-Process -FilePath "$PFPATH\ossec-agent\agent-auth.exe" -ArgumentList "-m", "$WazuhRegMgr", "-P", "$WazuhRegPass", "-G", "$WazuhGroups", "-A", "$WazuhAgentName" -Wait -WindowStyle 'Hidden'
		}
		if ( -not (Test-Path "$PFPATH\ossec-agent\client.keys" -PathType leaf) ) {
			if ($Debug) {  Write-Output "Wazuh Agent self-registration failed." }
			exit 1
		}
	}

	# Detect Windows version for use in configprofile line of ossec.conf
	switch ((Get-CimInstance Win32_OperatingSystem).BuildNumber)
	{
		6001 {$OS = "Win2008"}
		6002 {$OS = "Win2008"}
		6003 {$OS = "Win2008"}
		7600 {$OS = "Win2008, Win2008R2"}
		7601 {$OS = "Win2008, Win2008R2"}    
		9200 {$OS = "Win2012"}
		9600 {$OS = "Win2012, Win2012R2"}
		14393 {$OS = "Win2016"}
		16299 {$OS = "Win2016"}
		10240 {$OS = "Win10or2019"}
		10586 {$OS = "Win10or2019"}
		14393 {$OS = "Win10or2019"}
		15063 {$OS = "Win10or2019"}
		16299 {$OS = "Win10or2019"}
		17134 {$OS = "Win10or2019"}
		17763 {$OS = "Win10or2019"}
		18362 {$OS = "Win10or2019"}
		18363 {$OS = "Win10or2019"}
		{$_ -gt 22000} {$OS = "Win11"}
		{$_ -gt 20000} {$OS = "Win2022"}
		{$_ -gt 10240} {$OS = "Win10or2019"}
		default { $OS = "WindowsUnknown"}
	}

	if ($Debug) {  Write-Output "Writing ossec.conf" }
	# Write the ossec.conf file
$ConfigToWrite = @"
<!-- Wazuh Modular version 1.0 -->
<ossec_config>
	<client>
		<server>
			<address>$WazuhMgr</address>
		</server>
		<config-profile>$OS</config-profile>
		<enrollment>
			<enabled>no</enabled>
		</enrollment>
	</client>
	<agent-upgrade>
		<ca_verification>
			<enabled>yes</enabled>
			<ca_store>wpk_root.pem</ca_store>
			<ca_store>bnc_wpk_root.pem</ca_store>
		</ca_verification>
	</agent-upgrade>
	<localfile>
		<log_format>command</log_format>
		<alias>merge-wazuh-conf</alias>
		<command>PowerShell.exe -ExecutionPolicy Bypass -File scripts/merge-wazuh-conf.ps1</command>
		<frequency>86400</frequency>
	</localfile>  
</ossec_config>
"@
	$ConfigToWrite | Out-File -FilePath "$PFPATH/ossec-agent/ossec.conf" -Encoding ASCII

	#
	# Last Wazuh Agent steps
	#

	# Start up the Wazuh agent service
	if ($Debug) { Write-Output "Starting up the Wazuh agent..." }
	Start-Service WazuhSvc

	if ($Debug) { write-output "Configuring WazuhSvc Windows service to auto-restart after a 15 minute delay if the service fails." }
	& sc.exe failure wazuhsvc reset=86400 actions=restart/900000 | out-null
	& sc.exe failureflag wazuhsvc 1 | out-null

	# Do first-time execution of conf.d merge script to build a merged ossec.conf from conf.d files
	& "$PFPATH\ossec-agent\scripts\merge-wazuh-conf.ps1"

	# After 15 seconds confirm agent connected to manager
	if ($Debug) { Write-Output "Pausing for 15 seconds to allow agent to connect to manager..." }
	Start-Sleep -s 15 
	$file = Get-Content "$PFPATH\ossec-agent\ossec.log" -erroraction 'silentlycontinue'
	if ( -not ($file -match "Connected to the server ") ) {
		if ($Debug) { Write-Output "This agent FAILED to connect to the Wazuh manager." }
		exit 1
	}

	if ($Debug) { Write-Output "This agent has successfully connected to the Wazuh manager!" }
	if ( $Debug -and ( -not ( $SkipSysmon  ) ) ) { Write-Output "Sysmon should be automatically provisioned/reprovisioned in an hour or less as needed." }
	if ( $Debug -and ( -not ( $SkipOsquery ) ) ) { Write-Output "Osquery should be automatically provisioned/reprovisioned in an hour or less as needed." }
	exit 0
}

#
# Main
#

New-EventLog -LogName 'Application' -Source "Wazuh-Modular" -ErrorAction 'silentlycontinue'

# Set https protocol defaults to try stronger TLS first and allow all three forms of TLS
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# These variables are set in one of the above functions and need to be seen in another one of the above functions, so make them global.
New-Variable MightRecycleRegistration -value $false -option AllScope
New-Variable SkippedGroups -value $false -option AllScope

#Set installation path based on 64 vs. 32-bit Windows OS
$PFPATH="C:\Program Files (x86)"
If ( -not ([Environment]::Is64BitOperatingSystem) ) {
	Write-Output "Changing path variable to C:\Program Files for detected 32-bit Windows OS..."
	$PFPATH="C:\Program Files"
}

if ( $CheckOnly -and $Install ) {
	Write-Output "Cannot use -Install in combination with -CheckOnly."
	exit 2
}

# Note currently configured Wazuh manager if Wazuh agent is installed.  Needed during check and uninstall phases.
$CurrentManager = ""

if (Test-Path "$PFPATH\ossec-agent\ossec.conf" -PathType leaf) {
	$ConfigFile = $null
	if ( [bool]((Get-Content "$PFPATH\ossec-agent\ossec.conf" ) -as [xml]) ) {	
		[XML]$ConfigFile = Get-Content "$PFPATH\ossec-agent\ossec.conf" -erroraction 'silentlycontinue'
	}
	# If XML parsing of ossec.conf fails, use string based approach for one last attempt
	if ( $ConfigFile.ossec_config.client.server.address -ne $null ) {
		$CurrentManager = $ConfigFile.ossec_config.client.server.address
	} else {
		$mresult = [string](Get-Content "$PFPATH\ossec-agent\ossec.conf" -erroraction 'silentlycontinue') -match '<server>[\s\n]+<address>([\w\d-\.]+)</address>'
		if ($mresult){
			$CurrentManager = $matches[1]
		}		
		else {
			$CurrentManager = "#UNKNOWN#"
		}
	}
}

# Check if install/reinstall is called for unless an install or uninstall is being forced with -Install or -Uninstall
# checkAgent will bail unless an install/reinstall is called for.
if ( -not ( ($Install) -or ($Uninstall) ) ) {
	checkAgent
}

# If all we are doing is a check, then the check must have indicated a install/reinstall was needed, so return an exit code of 1 now.
if ( $CheckOnly ) {
	exit 1
}

# Uninstall the Wazuh Agent whether or not a fresh installation is to follow.  Bail if it cannot uninstall everything satisfactorily (exit code 1)
uninstallAgent

# Continue to the installation phase unless this was just a -Uninstall call to the script.  Fail and bail with exit code 1 if cannot install/deploy completely
if ( -not ($Uninstall) ) {
	installAgent
}

# Uninstall or uninstall&install process must have succeeded, so close down with code 0.
exit 0
