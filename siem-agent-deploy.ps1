#
# siem-agent-deploy.ps1
# Version 10.1
# Changes in this Version
# -----------------------
# Default Wazuh Version Change
#
# -----------------------
# last material change 11/8/2023
#
# This script is for checking and/or installing the Wazuh agent on Windows systems.  It can directly install or uninstall it, conditionally 
# install it, or simply check to see if installation/reinstallation is needed.  The Wazuh agent for Windows presently includes Wazuh agent 
# integrated for centralized configuration and reporting via the Wazuh manager.  It also defaults to signalling to the Wazuh manager to push 
# the Sysmon and/or Osquery management WPKs to this agent, which can be optionally excluded.
#
# Depending on the use case, this script can be called singly on a one time or periodic basis to conditionally install/reinstall the agent.  
# Alternatively, a higher level configuration management system like Puppet could first call this script just to check if 
# installation/reinstallation is called for, and based on the exit code it receives, conditionally call this script a second time to  
# explicitly install/reinstall the agent.
#
# After preserving the working Wazuh agent registration key if present, if the -Install flag is used, the Wazuh agent is completely purged and 
# then reinstalled.  The Wazuh agent self-registration process is included, but will be skipped if an existing working registration can be recycled.
# If the -Install flag is not set and 1) the agent is connected to a manager and 2) the target groups appear at the beginning of the list of 
# current groups, the checkAgent function will find no deployment/re-deployment is needed and will bail with exit code 0. This will keep the same 
# agent id and agent name associated with the agent prior to the script being run. Groups that were manually added via the Wazuh interface will not 
# be used for comparison purposes, but will still be applied if the agent registration is recycled.  If the script-defined target group membership 
# list, including groups added by the -ExtraGroups parameter, are not listed in order at the beginning of the list of discovered current groups for
# the agent, but the agent is connected to a manager, the script will re-register without an uninstall and reinstall of Wazuh. 
#
# If the call to this script is deemed broken, or either the Wazuh Manager connect port or registration port are unresponsive to a probe, an 
# exit code of 2 will be returned.
#
# By default, the script will install a minimum default version of Wazuh as hard-coded in the script.  However, there are two optional ways to 
# override this hard-coded parameter; 1) add a txt record to a domain you control that includes the version number of the Wazuh agent you wish 
# to install or 2) specify a minimum version in the command call.  After the install, the intention is for the automated agent upgrade cron 
# call to upgrade all connected agents to the version of the Wazuh Manager it is connected to. 
#
# The default exit code is 0.
# Exit code of 1 from the checkAgent function indicates a redeploy/re-registeration is needed. This exit code is only used if the -CheckOnly flag 
# is set on the command line.
# Exit code of 2 indicates that an error occurred or there was a problem with the command line parameters.
# 
# Is the agent presently really connected to the Wazuh manager?
# Is the agent currently a member of all intended Wazuh agent groups?
#
# Required Parameters:
#
# -Mgr					The IP or FQDN of the Wazuh manager for ongoing agent connections.
# -RegPass     			Password for registration with Wazuh manager (put in quotes).
#
# Optional Parameters:
#
# -Mgr2		        	The IP or FQDN of an optional second Wazuh manager for agents to connect to.
# -AgentName   			Name under which to register this agent in place of locally detected Windows host name.
# -ExtraGroups  		Additional groups beyond the default groups that are applied by the script, which include: windows, windows-local, 
#						linux, linux-local, sysmon, sysmon-local, osquery, osquery-local. 
# -VerDiscAddr			The Version Discovery Address where a .txt record has been added with the target version of the Wazuh agent to install.
# -InstallVer			The version of the Wazuh Agent to install.
# -DefaultInstallVer 	Command line paramenter and a preset within the script that is used as a last resort.
# -DownloadSource		Static download path to fetch Wazuh agent installer.  Overrides WazuhVer value.
# -SkipSysmon			Flag to not signal the Wazuh manager to push managed Sysmon WPK to this system. (Default is to not skip this.)
# -SkipOsquery			Flag to not signal the Wazuh manager to push managed Osquery WPK to this system. (Default is to not skip this.)
# -Install				Flag to skip all checks and force installation
# -Uninstall			Flag to uninstall Wazuh agent only
# -CheckOnly			Flag to only run checks to see if installation is current or in need of deployment
# -LBprobe				Additionally check for manager connectivity with an agent-auth probe to avoid being fooled by a load balancer that 
#						handshakes even when service down.
# -Local				Flag used when a host is not allowed to reach the internet. 
# -Debug				Flag to show debug output
# -help					Flag to show command line options

#
# Sample command line:
#
# PowerShell.exe -ExecutionPolicy Bypass -File .\siem-agent-deploy.ps1 -InstallVer "4.5.4" -Mgr "{Manager DNS or IP}" -RegPass "{Your_Password}" -ExtraGroups "{Your_comma_separated_group_list}" -Debug
#

#
# Please note that the following groups are built into the script and should be added to the Wazuh Manager PRIOR to any use of this script.
#
# "windows,windows-local,sysmon,sysmon-local,osquery,osquery-local".
#

# All possible parameters that may be specified for check-only, conditional install, forced install or forced uninstall purposes.

param ( $Mgr,
	$RegMgr,
	$RegPass,	
	$Mgr2,  
	$AgentName = $env:computername, 
	$ExtraGroups, 
	$global:VerDiscAddr,
	$InstallVer,
	$global:DefaultInstallVer = "4.5.4",
	$DownloadSource,
	[switch]$SkipSysmon=$false, 
	[switch]$SkipOsquery=$false,
	[switch]$Install=$false,
	[switch]$Uninstall=$false,
	[switch]$CheckOnly=$false,
	[switch]$LBprobe=$false,
	[switch]$Local=$false,
	[switch]$Help,
	[switch]$Debug=$false
);

function show_usage {
     Write-Host "Command syntax:"
     Write-Host "    [-Mgr" -NoNewline; Write-Host "    WAZUH_MANAGER]" -ForegroundColor Green
     Write-Host "    [-RegMgr" -NoNewline; Write-Host "    WAZUH_REGISTRATION_MANAGER]" -ForegroundColor Green
     Write-Host "    [-RegPass" -NoNewline; Write-Host "    WAZUH_REGISTRATION_PASSWORD]" -ForegroundColor Green
     Write-Host "    [-DefaultInstallVer" -NoNewline; Write-Host "    DEFAULT_WAZUH_VERSION]" -ForegroundColor Green
     Write-Host "    [-DownloadSource" -NoNewline; Write-Host "    WAZUH_AGENT_DOWNLOAD_URL]" -ForegroundColor Green
     Write-Host "    [-AgentName" -NoNewline; Write-Host "    WAZUH_AGENT_NAME_OVERRIDE]" -ForegroundColor Green
     Write-Host "    [-ExtraGroups" -NoNewline; Write-Host "    LIST_OF_EXTRA_GROUPS]" -ForegroundColor Green
     Write-Host "    [-VerDiscAddr" -NoNewline; Write-Host "    VERSION_DISCOVERY_ADDRESS]" -ForegroundColor Green
     "    [-SkipSysmon]","    [-SkipOsquery]","    [-Install]","    [-Uninstall]","    [-CheckOnly]","    [-Local]","    [-Debug]" | Write-Host
     Write-Host "    ./siem-agent-deploy.sh -Mgr" -NoNewline;Write-Host -ForegroundColor Green ' "siem.company.org"' -NoNewline;Write-Host " -RegPass" -NoNewline; Write-Host -ForegroundColor Green ' "h58fg3FS###12"' -NoNewline; Write-Host " -DefaultInstallVer" -NoNewline; Write-Host -ForegroundColor Green ' "4.5.4"' -NoNewline; Write-Host " -ExtraGroups"  -NoNewline; Write-Host -ForegroundColor Green ' "server,office"'
}

# 
# Probe a target FQDN/IP on a target tcp port and if no response is received or the FQDN cannot be resolved, then fail and bail with an exit 
# code of 2.
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
			$global:result = "2"
			return
		}
	}
	$tcpClient = New-Object System.Net.Sockets.TcpClient
	$connection = $tcpClient.ConnectAsync($tp_host, $tp_port).Wait(1000)
	if ($connection) {
		if ($Debug) { Write-Output "Success!" }
		$global:result = "0"
	}
	else {
		if ($Debug) { Write-Output "Probe failed!" }
		$global:result = "2"
	}
}

#
# BNC's Custom pem
#
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

# If Wazuh agent conf.d directory is not yet present, then create it and populate it with a 000-base.conf copied from current ossec.conf file.
if ( -not (Test-Path -LiteralPath "$PFPATH\ossec-agent\conf.d" -PathType Container ) ) {
    New-Item -ItemType "directory" -Path "$PFPATH\ossec-agent\conf.d" | out-null
    while ( -not ( Test-Path "$PFPATH\ossec-agent\conf.d" -PathType Container ) ) {
	sleep 1
 	Write-Output "directory missing, pausing..."
    }
    Copy-Item "$PFPATH\ossec-agent\ossec.conf" "$PFPATH\ossec-agent\conf.d\000-base.conf"
    # If the newly generated 000-base.conf (from old ossec.conf) is missing the merge-wazuh-conf command section, then append it now.
    $baseFile = Get-Content "$PFPATH/ossec-agent/conf.d/000-base.conf" -erroraction 'silentlycontinue'
}
# If there was a failed ossec.conf remerge attempt less than an hour ago then bail out (failed as in Wazuh agent would not start using latest merged ossec.conf)
# This is to prevent an infinite loop of remerging, restarting, failing, reverting, and restarting again, caused by bad material in a conf.d file.
if ( ( Test-Path -LiteralPath "$PFPATH\ossec-agent\ossec.conf-BAD" ) -and ( ( (Get-Date) - (Get-Item "$PFPATH\ossec-agent\ossec.conf-BAD").LastWriteTime ).totalhours -lt 1 ) ) {
    Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10004 -EntryType Error -Message "merge-wazuh-conf: exited due to a previous failed ossec.conf remerge attempt less than an hour ago" -Category 0
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
    Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10005 -EntryType Information -Message "merge-wazuh-conf: ossec.conf is already up to date" -Category 0

# However if config.merged is different than ossec.conf, then back up ossec.conf, replace it with config.merged, and restart Wazuh Agent service
} else {
    # If another instance of this script is already running, then exit.
    # Since after a merge, this script restarts the Wazuh agent and then waits to confirm
    # the agent comes all the way back up, this will be a common occurrence.
    if ( -not ( (Get-WMIObject -Class Win32_Process -Filter "Name='PowerShell.EXE'" | Where-Object {$_.CommandLine -Like "*merge-wazuh-conf.ps1*"}).CommandLine.count -EQ 1 ) ) {
        Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10007 -EntryType Information -Message "merge-wazuh-conf: skipped due to script already running" -Category 0
        exit
    }
    Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10000 -EntryType Information -Message "merge-wazuh-conf: applying new merged ossec.conf and restarting Wazuh agent..." -Category 0
    # Pause to give time for above log message to be transmitted to Wazuh manager.  The upcoming agent restart will otherwise cause this log to be lost.
    Start-Sleep 10
    # If deploy-wazuh-modular is already running, then ossec.conf has already been backed up and we should not do it again here.
    if ( (Get-WMIObject -Class Win32_Process -Filter "Name='PowerShell.EXE'" | Where-Object {$_.CommandLine -Like "*deploy-wazuh-modular.ps1*"}).CommandLine.count -EQ 0 ) {
        Copy-Item "$PFPATH\ossec-agent\ossec.conf" "$PFPATH\ossec-agent\ossec.conf-BACKUP" -Force
    }
    Copy-Item "$PFPATH\ossec-agent\conf.d\config.merged" "$PFPATH\ossec-agent\ossec.conf" -Force
    Stop-Service WazuhSvc
    Start-Service WazuhSvc
    Start-Sleep 30
    # If after replacing ossec.conf and restarting, the Wazuh Agent fails to start, then revert to the backed up ossec.conf, restart, and hopefully recovering the service.
    if ( ( -not ( (Get-Service -Name "WazuhSvc").Status -eq "Running" ) ) -or ( -not ( ( netstat -nat ) -match ':1514[^\d]+ESTABLISHED' ) ) ) {
        Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10001 -EntryType Error -Message "merge-wazuh-conf: new ossec.conf appears to prevent Wazuh Agent from starting.  Reverting and restarting..." -Category 0
        Move-Item "$PFPATH\ossec-agent\ossec.conf" "$PFPATH\ossec-agent\ossec.conf-BAD" -Force
        Move-Item "$PFPATH\ossec-agent\ossec.conf-BACKUP" "$PFPATH\ossec-agent\ossec.conf" -Force
        Stop-Service WazuhSvc
        Start-Service WazuhSvc
        Start-Sleep 15
        # Indicate if the service was successfully recovered by reverting ossec.conf.
        if ( ( (Get-Service -Name "WazuhSvc").Status -eq "Running" ) -and ( ( netstat -nat ) -match ':1514[^\d]+ESTABLISHED' ) ) {
            Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10002 -EntryType Information -Message "merge-wazuh-conf: reverted ossec.conf and Wazuh agent successfully restarted..." -Category 0
        } else {
            Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10003 -EntryType Error -Message "merge-wazuh-conf: reverted ossec.conf and Wazuh agent still failed to start" -Category 0
        }
    }
}
'@
New-Item -ItemType "directory" -Path "$PFPATH\ossec-agent\scripts" -erroraction 'silentlycontinue' | out-null
while ( -not ( Test-Path "$PFPATH\ossec-agent\scripts" -PathType Container ) ) {
   sleep 1
   Write-Output "directory missing, pausing..."
}
$ScriptToWrite | Out-File -FilePath "$PFPATH\ossec-agent\scripts\merge-wazuh-conf.ps1" -Encoding "UTF8"
}

# Checks if agent is in desired state
# return values
#	0 - no failure, but pass back Connected flag and CorrectGroupPrefix value to inform next steps to be taken.  
#		Discovering a need to (re)deploy on account of lack of contact with managr or incorrect agent group membership, is a finding, not a failure.
#	2 - any failure like bad parms, probe failure, unsupported OS
function checkAgent {

	# Relevant script parameters
	#		
	# -Mgr				The IP or FQDN of the Wazuh manager for ongoing agent connections. (Required)
	# -RegPass			Password for registration with Wazuh manager (put in quotes). (Required)
	# -Mgr2		        The IP or FQDN of an optional second Wazuh manager for agents to connect to.
	# -AgentName   		Name under which to register this agent in place of locally detected Windows host name.
	# -ExtraGroups  	Additional groups beyond the default groups that are applied by the script, which include: windows, windows-local, 
	#					linux, linux-local, sysmon, sysmon-local, osquery, osquery-local. 
	# -SkipSysmon		Flag to not signal the Wazuh manager to push managed Sysmon WPK to this system. (Default is to not skip this.)
	# -SkipOsquery		Flag to not signal the Wazuh manager to push managed Osquery WPK to this system. (Default is to not skip this.)
	# -CheckOnly		Flag to only run checks to see if installation is current or in need of deployment
	# -LBprobe			Flag to additionally check for manager connectivity with an agent-auth probe to avoid being fooled by a load balancer 
	#					that handshakes even when service down.
	# -Debug			Flag to show debug output

	if ($Mgr -eq $null) { 
		if ($Debug) { Write-Output "Must use '-Mgr' to specify the FQDN or IP of the Wazuh manager to which the agent shall retain a connection." }
		show_usage
		$global:result = "2"
		return
	}
	
	if ($Debug) { Write-Output "Checking connection status of agent." }
	$global:Connected = $false
	
	# Probe manager ports to confirm it is really reachable.
	# If we are not forcing an install (-Install) and it is fully evident the agent is presently connected to a manager, then no manager probes are necessary.  Otherwise perform them.
	$StateFile = Get-Item -Path "$PFPATH\ossec-agent\wazuh-agent.state" -erroraction SilentlyContinue
	if ( ( -not ($Install) ) -and (($StateFile.LastWriteTime) -gt (Get-Date).AddMinutes(-10)) -and (Get-Content -Path "$PFPATH\ossec-agent\wazuh-agent.state" | Select-String -Pattern "status='connected'").Matches.Success ) {
		if ($Debug) { Write-Output "Agent is connected to a manager. Skipping probing of manager..." }
	} else {
		# Confirm the self registration and agent connection ports on the manager(s) are responsive.  
		# If either are not, then (re)deployment is not feasible, so return an exit code of 2 so as to not trigger the attempt of such.
		if ($Debug) { Write-Output "Probing to see if the manager is reachable..." }	
		tprobe $Mgr 1514 
		if ( "$result" -eq "2" ){
			$global:result = "2"
			return
		}
		tprobe $RegMgr 1515 
		if ( "$result" -eq "2" ){
			$global:result = "2"
			return
		}
		# If -LBprobe flag set, then additionally confirm the manager is reachable by intentionally attempting an agent-auth with a bad 
		# password to see if "Invalid password" is in the output, which would probe a real Wazuh registration service is reachable on port 
		# 1515.
		if ( ( $LBprobe ) -and ( Test-Path -LiteralPath "$PFPATH\ossec-agent\agent-auth.exe") ) {
			if ($Debug) { Write-Output "Performing a load-balancer-aware check via an agent-auth.exe call to confirm manager is truly reachable..." }
			Remove-Item -Path "agent-auth-test-probe" -erroraction 'silentlycontinue'
			Start-Process -FilePath "$PFPATH\ossec-agent\agent-auth.exe" -ArgumentList "-m", "$RegMgr", "-P", "badpass" -Wait -WindowStyle 'Hidden' -redirectstandarderror "agent-auth-test-probe"
			if ( ( Test-Path -LiteralPath "agent-auth-test-probe" ) -or ( Get-Content "agent-auth-test-probe" | select-String "Invalid password" ) ) {
				Remove-Item -Path "agent-auth-test-probe" -erroraction 'silentlycontinue'
				if ($Debug) { Write-Output "LBprobe check succeeded.  Manager is truly reachable." }
			} else {
				Remove-Item -Path "agent-auth-test-probe" -erroraction 'silentlycontinue'
				if ($Debug) { Write-Output "LBprobe check failed.  Manager is not truly reachable." }
				$global:result = "2"
				return
            }
		}
	}

	#
	# Is the agent presently really connected to a Wazuh manager?  If not, wait a little over a minute and check again.
	# Set the "Connected" flag if success at 1st or 2nd check.
	#
	if ( (($StateFile.LastWriteTime) -gt (Get-Date).AddMinutes(-10)) -and (Get-Content -Path "$PFPATH\ossec-agent\wazuh-agent.state" | Select-String -Pattern "status='connected'").Matches.Success ) {
		if ($Debug) { Write-Output "The Wazuh agent is connected to a Wazuh manager." }
		$global:Connected = $true
	} else {
		if ( $StateFile.LastWriteTime -gt (Get-Date).AddMinutes(-10) ) {
			if ($Debug) { Write-Output "*** Waiting 70 seconds to see if Wazuh agent is only temporarily disconnected from manager." }
			Start-Sleep -Seconds 70
			$StateFile = Get-Item -Path "$PFPATH\ossec-agent\wazuh-agent.state" -erroraction SilentlyContinue
			if ( (($StateFile.LastWriteTime) -gt (Get-Date).AddMinutes(-10)) -and (Get-Content -Path "$PFPATH\ossec-agent\wazuh-agent.state" | Select-String -Pattern "status='connected'").Matches.Success ) {
				if ($Debug) { Write-Output "The Wazuh agent is now connected to a Wazuh manager." }
				$global:Connected = $true
			} else {
				if ($Debug) { Write-Output "*** The Wazuh agent is still not connected to a Wazuh manager." }
			}
		} else {
			if ($Debug) { Write-Output "*** The Wazuh agent is not connected to a Wazuh manager." }
		}
	}
	
	#
	# Is the agent group prefix correct?
	# The prefix starts with dynamically determined group names followed by ExtraGroups if specified.  
	# The prefix must match, but additional agent groups found after the prefix in the actual membership list are fine.
	#
	
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

	# Establish target agent group list prefix
	$GroupsPrefix = "windows,windows-local,"
	if ( $SkipOsquery -eq $false ) {
		$GroupsPrefix = $GroupsPrefix+"osquery,osquery-local,"
	}
	if ( $SkipSysmon -eq $false ) {
		$GroupsPrefix = $GroupsPrefix+"sysmon,sysmon-local,"
	}
	$GroupsPrefix = $GroupsPrefix+$ExtraGroups
	$global:TargetGroups = $GroupsPrefix.TrimEnd(",")

	# Enumerate actual list of agent groups this agent is membered into based on section headers in merged.mg
	If (Test-Path "$PFPATH\ossec-agent\shared\merged.mg") {	
		$file2 = Get-Content "$PFPATH\ossec-agent\shared\merged.mg" -erroraction 'silentlycontinue'	
		if ($file2 -match "Source\sfile:") {
			$global:CurrentGroups=((((Select-String -Path "$PFPATH\ossec-agent\shared\merged.mg" -Pattern "Source file:") | Select-Object -ExpandProperty Line).Replace("<!-- Source file: ","")).Replace("/agent.conf -->","")) -join ','
		} else {
			# If the agent is presently a member of only one agent group, then pull that group name into current group variable.
			$global:CurrentGroups=((((Select-String -Path "$PFPATH\ossec-agent\shared\merged.mg" -Pattern "#") | Select-Object -ExpandProperty Line).Replace("#","")))
		}
	} else {
		$global:CurrentGroups="#NONE#"
	}
	
	# Set CorrectGroupPrefix flag if the actual agent group membership of this agent starts with the target prefix agent group list.
	if ( $CurrentGroups -like "$TargetGroups*" ) {
		if ($Debug) { Write-Output "Expected $TargetGroups matches the prefix in $CurrentGroups." }
		$global:CorrectGroupPrefix = $true
	} else {
		if ($Debug) { Write-Output "Expected $TargetGroups is not at the start of $CurrentGroups." }
		$global:CorrectGroupPrefix = $false
	}
	
	$global:result = "0"
	return
}

# 
# Uninstall Wazuh Agent. As part of the Wazuh Agent uninstall process, ascertain if we might be in a position to recycle the agent 
# registration, and set the flag and preserve information accordingly.
#
function uninstallAgent {
	# Relevant script parameters
	#		
	# -Uninstall		Uninstall without checking and without installing thereafter
	# -Local			Used when a host is not allowed to reach the internet.

	if (Test-Path "$PFPATH\ossec-agent\ossec.log" -PathType leaf) {
		Copy-Item "$PFPATH\ossec-agent\ossec.log" -Destination "$Env:SystemDrive\Windows\Temp\"
	}
	
	# NuGet Dependency if not -Local context
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
						$global:result = "2"
						return						
					}
					Start-sleep -Seconds 10
				}  
				$count++    
			}until($count -eq 6 -or $success)
		} 
	}
	
	# If Wazuh agent is already installed and registered, and this is not an explicit uninstallation call, then note if registration may be 
	# recyclable, and if so, preserve client.keys and the agent groups list to accomodate that, plus set the $MightRecycleRegistration flag.
	$CorrectAgentName = $false
	if ( ( -not ($Uninstall) ) -and (Test-Path $RegFileName -PathType leaf) -and ((Get-Item $RegFileName).length -gt 0)  ) {
		# The existing registration will be recyled if:
		#	- the agent is already connected
		#	- the current and target agent name are the same
		#	- the agent group prefix is exactly the same (unless ignored by ommittance of -ExtraGroups)
		$StateFile = Get-Content "$PFPATH\ossec-agent\wazuh-agent.state" -erroraction 'silentlycontinue'
		$MergedFile = Get-Content "$PFPATH\ossec-agent\shared\merged.mg" -erroraction 'silentlycontinue'
		$MergedFileName = "$PFPATH\ossec-agent\shared\merged.mg"
		$CurrentAgentName=(Get-Content "$PFPATH\ossec-agent\client.keys").Split(" ")[1]
		if ( ($StateFile | Select-String -Pattern "'connected'" -quiet) -and ($CurrentAgentName -eq $AgentName) ) {
			if ($Debug) { Write-Output "Registration will be recycled unless there is an agent group mismatch." }
			$CorrectAgentName = $true
			$global:MightRecycleRegistration=$true
			Remove-Item -Path "$env:TEMP\client.keys.bnc" -erroraction 'silentlycontinue' | out-null
			Remove-Item -Path "$env:TEMP\ossec.conf.bnc" -erroraction 'silentlycontinue' | out-null
			Copy-Item $RegFileName -Destination "$env:TEMP\client.keys.bnc"
			Copy-Item $ConfigFileName -Destination "$env:TEMP\ossec.conf.bnc"
		} else {
			if ($Debug) { Write-Output "Registration will not be recycled." }
			$global:MightRecycleRegistration=$false
		}
	}

	# If Wazuh agent service is running, stop it.  Otherwise uninstall will fail.
	if ($Debug) { Write-Output "Stopping current Wazuh Agent service..." }
	Stop-Service WazuhSvc -erroraction 'silentlycontinue'


	# If Wazuh agent already installed and the -Uninstall flag is set or Wazuh agent is not connected to a manager, blow it away.
	if ( ($Install) -or ($Uninstall) -or ($Connected -eq $false)) {
		if (Test-Path "$PFPATH\ossec-agent\wazuh-agent.exe" -PathType leaf) {
			if ($Debug) { Write-Output "Uninstalling existing Wazuh Agent..." }
			Uninstall-Package -Name "Wazuh Agent" -erroraction 'silentlycontinue' | out-null
			Remove-Item "$PFPATH\ossec-agent" -recurse
		} else {
			if ($Debug) { Write-Output "Wazuh Agent not present..." }
		}
		if (Test-Path "$PFPATH\ossec-agent" -PathType Container) {
		Remove-Item "$PFPATH\ossec-agent" -recurse -force
		}
		if ($Debug) { Write-Output "Uninstallation done..." }
	} else {
		if ($Debug) { Write-Output "Uninstallation not needed..." }
	}	
}

#
# Re-register agent and re-install/install Wazuh Agent if needed, recycling an existing registration if possible, otherwise re-registering it.
#
# Deploy function
function installAgent {

	# Relevant script parameters
	#		
	# -Mgr					IP or FQDN of the Wazuh manager for ongoing agent connections. (Required.)
	# -RegPass				Password for registration with Wazuh manager (put in quotes). (Required.)
	# -Mgr2					The IP or FQDN of an optional second Wazuh manager for agents to connect to.
	# -RegMgr  				The IP or FQDN of the Wazuh manager for agent registration connection (defaults to -Mgr if not specified)
	# -AgentName   			Name under which to register this agent in place of locally detected Windows host name.
	# -ExtraGroups  		Additional groups beyond the default groups that are applied by the script, which include: windows, windows-local, 
	# 						linux, linux-local, sysmon, sysmon-local, osquery, osquery-local. 
	# -VerDiscAddr			The Version Discover Address where a .txt record has been added with the target version of the Wazuh agent to
	#						install.
	# -InstallVer			The version of the Wazuh Agent to install.
	# -DefaultInstallVer 	Command line paramenter and a preset within the script that is used as a last resort.
	# -DownloadSource   	Static download path to fetch Wazuh agent installer.  Overrides WazuhVer value.
	# -SkipSysmon   		Flag to not signal the Wazuh manager to push managed Sysmon WPK to this system. (Default is to not skip this.)
	# -SkipOsquery  		Flag to not signal the Wazuh manager to push managed Osquery WPK to this system. (Default is to not skip this.)
	# -Install      		Flag to skip all checks and force installation
	# -Local				Flag used when a host is not allowed to reach the internet
	# -Debug        		Flag to show debug output
	
	if ( !($PSVersionTable.PSVersion.Major) -ge 5 ) {
		if ($Debug) { write-host "*** PowerShell 5.0 or higher is required by this script." }
		$global:result = "2"
		return
	}
	
	if ($Mgr -eq $null -or $RegPass -eq $null) { 
		if ( $Mgr -eq $null ) {
		write-host "*** Must use '-Mgr' to specify the FQDN or IP of the Wazuh manager to which the agent shall retain a connection"
		} else {
		write-host "*** Must use '-RegPass' to specify the password to use for agent registration."
		}
		show_usage
		$global:result = "2"
		return
	}

	if ( ($Install) -or ( -not ($Connected) ) ) {
		# If InstallVer is not discovered or set as a parameter, use the DefaultInstaller value either set on command line or is hard-coded in script.
		if ( -not ($VerDiscAddr -eq $null) ) {
			$InstallVer = (Resolve-DnsName -Type txt -name $global:VerDiscAddr -ErrorAction SilentlyContinue).Strings
		}
		if ($InstallVer -eq $null) { 
			if ($Debug) { Write-Output "InstallVer was null, so using DefaultInstallVer value, if present from command line" }
			$InstallVer = $DefaultInstallVer
		}
		
		if ($DownloadSource -eq $null) { 
			$MajorVer = $InstallVer.ToCharArray()[0]
			$DownloadSource = "https://packages.wazuh.com/$MajorVer.x/windows/wazuh-agent-$InstallVer-1.msi"
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
				$global:result = "2"
				return
			}
		}

		#
		# Wazuh Agent 
		#

		# Download Wazuh Agent installer or confirm it is already locally present if "-Local" option specified.
		if ( -not ($Local) ) {
			# Download the correct version of the Wazuh installer MSI
			if ($Debug) {  Write-Output "Downloading $DownloadSource" }
			$count = 0
			$success = $false;
			do{
				try{
					Invoke-WebRequest -Uri $DownloadSource -OutFile wazuh-agent.msi
					$success = $true
				}
				catch{
					if ($count -lt 5) {
						if ($Debug) { Write-Output "Download attempt failed.  Will retry 10 seconds." }
					} else {
						if ($Debug) { Write-Output "Download attempt still failed.  Giving up and aborting the installation..." }
						$global:result = "2"
						return
					}
					Start-sleep -Seconds 10
				}  
				$count++    
			}until($count -eq 6 -or $success)
		} else {
			if ($Debug) {  Write-Output "Using local source file because the -Local flag parameter was used..." }
		}
		
		# Install Wazuh Agent and then remove the installer file
		if ($Debug) {  Write-Output "Installing Wazuh Agent" }
		Start-Process -FilePath .\wazuh-agent.msi -ArgumentList "/q" -Wait -WindowStyle 'Hidden'
		if ( -not ($Local) ) {
			Remove-Item -Path .\wazuh-agent.msi -erroraction silentlycontinue
		}
	
		# Create ossec-agent\scripts and write the merge-wazuh-conf.ps1 file to it, and write bnc_wpk_root.pem file
		writePEMfile
		writeMergeScript
    }
	
	# If we can safely skip self registration and just restore the backed up client.keys file, then do so. Otherwise, self-register.
	if ($Debug) { Write-Output "Stopping Wazuh agent to register and adjust config..." }
	Stop-Service WazuhSvc
	Remove-Item -Path "$PFPATH\ossec-agent\ossec.log" -erroraction silentlycontinue
	if ( ( $MightRecycleRegistration ) -and ( $Connected ) -and ( $CorrectGroupPrefix ) ) { 
		Copy-Item "$env:TEMP\client.keys.bnc" -Destination "$RegFileName"
	} else {
		# Register the agent with the manager
		Remove-Item -Path "$RegFileName" -erroraction silentlycontinue
		if ($Debug) { Write-Output "Registering Wazuh Agent with $RegMgr..." }
		if ($CorrectGroupPrefix) {
			Start-Process -NoNewWindow -FilePath "$PFPATH\ossec-agent\agent-auth.exe" -ArgumentList "-m", "$RegMgr", "-P", "$RegPass", "-G", "$CurrentGroups", "-A", "$AgentName" -Wait -RedirectStandardError "$env:TEMP\reg.state"
	        } else {
			Start-Process -NoNewWindow -FilePath "$PFPATH\ossec-agent\agent-auth.exe" -ArgumentList "-m", "$RegMgr", "-P", "$RegPass", "-G", "$TargetGroups", "-A", "$AgentName" -Wait -RedirectStandardError "$env:TEMP\reg.state"
		}
		if ($Debug) { type "$env:TEMP\reg.state" }
		$file = Get-Content "$env:TEMP\reg.state" -erroraction 'silentlycontinue'
		if ($file -match "Duplicate agent name") {
			if ($Debug) { Write-Output "Waiting 45 seconds for Manager to discover agent is disconnected before retrying registration..." }
			Start-Sleep 45
			if ($CorrectGroupPrefix) {
			    Start-Process -NoNewWindow -FilePath "$PFPATH\ossec-agent\agent-auth.exe" -ArgumentList "-m", "$RegMgr", "-P", "$RegPass", "-G", "$CurrentGroups", "-A", "$AgentName" -Wait -RedirectStandardError "$env:TEMP\reg.state"
	                } else {
			    Start-Process -NoNewWindow -FilePath "$PFPATH\ossec-agent\agent-auth.exe" -ArgumentList "-m", "$RegMgr", "-P", "$RegPass", "-G", "$TargetGroups", "-A", "$AgentName" -Wait -RedirectStandardError "$env:TEMP\reg.state"
		        }
			if ($Debug) { type "$env:TEMP\reg.state" }
		}
		if ( ( -not (Test-Path "$PFPATH\ossec-agent\client.keys" -PathType leaf) )  -or ( -not (Get-Item $RegFileName).length -gt 0)   ) {
			Copy-Item "$env:TEMP\client.keys.bnc" -Destination "$RegFileName" -erroraction silentlycontinue
			Copy-Item "$env:TEMP\ossec.conf.bnc" -Destination "$ConfigFileName" -erroraction silentlycontinue
			Start-Service WazuhSvc
			if ($Debug) {  Write-Output "Registration failed.  Reverted to previous known working client.keys and restarted Wazuh..." }
			$global:result = "2"
			return
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

	if ($Debug) {  Write-Output "Dynamically generating ossec.conf" }
	#
	# Dynamically generate ossec.conf
	#
if ( -not ( $Mgr2 -eq $null ) ) {
$MgrAdd = @"
		<server>
            		<address>$Mgr2</address>
            		<port>1514</port>
            		<protocol>tcp</protocol>
        	</server>
"@
}
	
$ConfigToWrite = @"
<!-- Wazuh Modular version 1.0 -->
<ossec_config>
	<client>
		<server>
			<address>$Mgr</address>
			<port>1514</port>
			<protocol>tcp</protocol>
		</server>
$MgrAdd
		<config-profile>$OS</config-profile>
		<notify_time>10</notify_time>
		<time-reconnect>60</time-reconnect>
		<auto_restart>yes</auto_restart>
		<enrollment>
			<enabled>no</enabled>
		</enrollment>
	</client>
	<logging>
        	<log_format>plain</log_format>
	</logging>
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

	# After 30 seconds confirm agent connected to manager
	if ($Debug) { Write-Output "Pausing for 30 seconds to allow agent to connect to manager..." }
	Start-Sleep -s 30 
	$file = Get-Content "$PFPATH\ossec-agent\ossec.log" -erroraction 'silentlycontinue'
	if ( -not ($file -match "Connected to the server ") ) {
		Start-Sleep -s 15
		if ($Debug) { Write-Output "Pausing for an additional 15 seconds to allow agent to connect to manager..." }
		$file = Get-Content "$PFPATH\ossec-agent\ossec.log" -erroraction 'silentlycontinue'
		if ( -not ($file -match "Connected to the server ") ) {
			if ($Debug) { Write-Output "This agent FAILED to connect to the Wazuh manager." }
			$global:result = "2"
			return
		}
	}

	if ($Debug) { Write-Output "This agent has successfully connected to the Wazuh manager!" }
 	Write-EventLog -LogName "Application" -Source "Wazuh-Modular" -EventID 10994 -EntryType Information -Message "siem-agent-deploy.ps1: Deployed Wazuh agent using script version $DEPLOY_VERSION" -Category 0
	if ( $Debug -and ( -not ( $SkipSysmon  ) ) ) { Write-Output "Sysmon should be automatically provisioned/reprovisioned in an hour or less as needed." }
	if ( $Debug -and ( -not ( $SkipOsquery ) ) ) { Write-Output "Osquery should be automatically provisioned/reprovisioned in an hour or less as needed." }
		$global:result = "0"
		return
}

#
# Main
#

$DEPLOY_VERSION=10

If ( $Help -eq $true ) {
	show_usage
	exit 2
}

New-EventLog -LogName 'Application' -Source "Wazuh-Modular" -ErrorAction 'silentlycontinue'

# Set https protocol defaults to try stronger TLS first and allow all three forms of TLS
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

#Set installation path based on 64 vs. 32-bit Windows OS
$PFPATH="C:\Program Files (x86)"
If ( -not ([Environment]::Is64BitOperatingSystem) ) {
	Write-Output "Changing path variable to C:\Program Files for detected 32-bit Windows OS..."
	$PFPATH="C:\Program Files"
}

$RegFileName = "$PFPATH\ossec-agent\client.keys"
$ConfigFileName="$PFPATH\ossec-agent\ossec.conf"

Write-Output ""

# If RegMgr not listed, assume it is the same as Mgr.
if ($RegMgr -eq $null) { 
	if ($Debug) { Write-Output "RegMgr was null, so using Mgr for registration." }
	$RegMgr = $Mgr
}

if ( $CheckOnly -and $Install ) {
	Write-Output "Cannot use -Install in combination with -CheckOnly."
	exit 2
}

Remove-Item -Path C:\Windows\System32\wazuh-agent.msi -erroraction silentlycontinue

# If "-Local" option selected, confirm the agent-deploy.zip is present, unzip it, and confirm all required files were extracted from it.
if ($Local) {
	if ( -not (Test-Path -LiteralPath "agent-deploy.zip") ) {
		if ($Debug) { Write-Output "Option '-Local' specified but no 'agent-deploy.zip' file was found in current directory.  Giving up and aborting the installation..." }
		$global:result = "2"
		return
	}
	Microsoft.PowerShell.Archive\Expand-Archive "agent-deploy.zip" -Force -DestinationPath .
	if ( -not (Test-Path -LiteralPath "nuget.zip") ) {
		if ($Debug) { Write-Output "Option '-Local' specified but no 'nuget.zip' file was found in current directory.  Giving up and aborting the installation..." }
		$global:result = "2"
		return
	}
	if ( -not (Test-Path -LiteralPath "C:\Program Files\PackageManagement\ProviderAssemblies" -PathType Container ) ) {
		New-Item -ItemType "directory" -Path "C:\Program Files\PackageManagement\ProviderAssemblies"
	}
	Microsoft.PowerShell.Archive\Expand-Archive "nuget.zip" -DestinationPath "C:\Program Files\PackageManagement\ProviderAssemblies\" -erroraction silentlycontinue | Out-null
	Import-PackageProvider -Name NuGet 
	if ( -not (Test-Path -LiteralPath "wazuh-agent.msi") ) {
		if ($Debug) { Write-Output "Option '-Local' specified but no 'wazuh-agent.msi' file was found in current directory.  Giving up and aborting the installation..." }
		$global:result = "2"
		return
	}
}

# If forced uninstall (-Uninstall) then just do that end exit with the return code from the function called.
if ( $Uninstall ) {
	uninstallAgent
	exit $result
}

# Check if install/reinstall is called for unless an uninstall is being forced with -Uninstall checkAgent will bail unless an 
# install/reinstall is called for.
checkAgent
if ( "$result" -eq "2" ) {
	exit 2
}
if ($Debug) {
	Write-Output ""
	Write-Output "Mgr: $Mgr"
	Write-Output "Mgr2: $Mgr2"
	Write-Output "RegMgr: $RegMgr"
	Write-Output "RegPass: $RegPass"
	Write-Output "InstallVer: $InstallVer"
	Write-Output "AgentName: $AgentName"
	Write-Output "DownloadSource: $DownloadSource"
	Write-Output "SkipSysmon: $SkipSysmon"
	Write-Output "SkipOsquery: $SkipOsquery"
	Write-Output "Connected: $Connected"
	Write-Output "ExtraGroups: $ExtraGroups"
	Write-Output "CorrectGroupPrefix: $CorrectGroupPrefix"
	Write-Output "RegFileName: $RegFileName"
	Write-Output "ConfigFileName: $ConfigFileName"
	Write-Output ""
}


# Is a (re)deploy recommended?  If so, then if -CheckOnly, just exit 1 to indicate that.  Otherwise commence the uninstall and install sequence 
# and exit with a code indicating the results.
if ( $Install -or ( -not ($Connected ) ) -or ( -not ($CorrectGroupPrefix ) ) ) {
	# If all we are doing is a check, then the check must have indicated a install/reinstall was needed, so return an exit code of 1 now.
	if ( $CheckOnly ) {
		if ($Debug) { Write-Output "The checkAgent function has determined that deployment/redeployment is needed." }
		exit 1
	} else {
		uninstallAgent
		if ( "$result" -eq "2" ) {
			exit 2
		}
		installAgent
		if ( "result" -eq "2" ) {
			exit 2
		}
		exit 0
	}
}

Write-Output "No deployment/redeployment appears to be needed."
exit 0
