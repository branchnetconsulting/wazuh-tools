#
# check-wazuh-windows-agent-suite.ps1
#
# This script is to be used to determine if there is need to call the deploy-wazuh-windows-agent-suite.ps1 script.
# If any of the follwing test families fail, a return code of 1 will be returned.  Otherwise it will return a 0.
# If this script is unable to perform the test due to wrong parameters or the Wazuh manager does not respond to probes, it will exit with a 2, meaning "test not possible".
# If any of the tests of the agent system fail to show compliance with target state, a 1 is returned, meaning "failed -- should (re)deploy".
# Othersie a 0 will be returned, meaning "passed tests - no (re)deploy needed".
# The Sysmon tests will be skipped if -SkipSysmon is selected and the Osquery tests will be skipped if -SkipOsquery is selected.
#
# 1 - Is the agent presently really connected to the Wazuh manager?
# 2 - Is the agent currently a member of all intended Wazuh agent groups?
# 3 - Is the target version of Wazuh agent installed?
# 4 - Is the target version of Sysmon installed
# 5 - Is the target version of Osquery installed
#
# Parameters:
#
# -WazuhMgr		IP or FQDN of the Wazuh manager for ongoing agent connections. (Required)
# -WazuhRegMgr		IP or FQDN of the Wazuh manager for agent registration connection (defaults to $WazuhMgr if not specified)
# -WazuhVer		Full Wazuh agent version number to confirm, like "3.12.2". (Required)
# -OsqueryVer		Full version of Osquery to validate, like "4.2.0" (Always N.N.N format, required unless -SkipOsquery specified)
# -SysmonVer		Full version of Sysmon to validate, like "11.11" (Always N.N format, required unless -SkipSysmon specified)
# -WazuhGroups		Comma separated list of custom Wazuh agent groups. No spaces. Put whole list in quotes. (Optional)
#			If intentionally specifying an empty set of custom groups, then your must use the syntax -WazuhGroups '""'
# -SkipSysmon		Flag to not examine Sysmon. (Optional)
# -SkipOsquery		Flag not to examine Osquery. (Optional)
# -Debug		Flag to turn on debug output. (Optional)
#
# Sample way to fetch and use this script:
#
# Invoke-WebRequest -Uri https://raw.githubusercontent.com/branchnetconsulting/wazuh-tools/master/check-wazuh-windows-agent-suite.ps1 -OutFile check-wazuh-windows-agent-suite.ps1
# .\check-wazuh-windows-agent-suite.ps1 -WazuhMgr "siem.company.com" -WazuhVer "3.13.1" -OsqueryVer "4.4.0" -SysmonVer "11.11"
# echo "Exit code: $LASTEXITCODE."
#

param ( $WazuhMgr, 
		$WazuhRegMgr, 
		$WazuhVer, 
		$OsqueryVer, 
		$SysmonVer, 
		[switch]$SkipSysmon=$false, 
		[switch]$SkipOsquery=$false,
		$WazuhGroups = "#NOGROUP#",
		[switch]$Debug=$false
);

function tprobe {
	$tp_host = $args[0]
	$tp_port = $args[1]
	if ($Debug) { Write-Output "Probing $tp_host on port $tp_port..." }
	if ( -not ( $tp_host -as [IPAddress] -as [Bool] ) ) {
		#$IPBIG = (Resolve-DnsName -Name $tp_host -ErrorAction SilentlyContinue).IP4Address
		$IPBIG=([System.Net.Dns]::GetHostEntry($tp_host)).AddressList.IPAddressToString
		if ( $IPBIG -eq $null) {	
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
if ( ($OsqueryVer -eq $null) -and ($SkipOsquery -eq $false) ) { 
	if ($Debug) { Write-Output "If '-SkipOsquery' is not specified, then -OsqueryVer must be provided." }
	exit 2
}
if ( ($SysmonVer -eq $null) -and ($SkipSysmon -eq $false) ) { 
	if ($Debug) { Write-Output "If '-SkipSysmon' is not specified, then -SysmonVer must be provided." }
	exit 2
}
if ( $WazuhGroups -eq "#NOGROUP#" ) {
	if ( ($SkipSysmon -eq $true) -or ($SkipOsquery -eq $true) ) {
		write-host "-SkipSysmon and -SkipOsquery must always be accompanied with the use of -WazuhGroups."
		exit 1
	}
}

# Confirm the self registration and agent connection ports on the manager(s) are responsive.  
# If either are not, then (re)deployment is not feasible, so return an exit code of 2 so as to not trigger the attempt of such.
tprobe $WazuhMgr 1514
tprobe $WazuhRegMgr 1515

#
# 1 - Is the agent presently really connected to the Wazuh manager?
#
$file = Get-Content "C:\Program Files (x86)\ossec-agent\ossec-agent.state" -erroraction 'silentlycontinue'
if ( -not ($file -match "'connected'" ) ) {
	if ($Debug) { Write-Output "The Wazuh agent is not connected to the Wazuh manager." }
	exit 1
}

#
# 2 - Is the agent currently a member of all intended Wazuh agent groups?
#
if ( -not ( $WazuhGroups -eq "#NOGROUP#" ) ) {
	$file2 = Get-Content "C:\Program Files (x86)\ossec-agent\shared\merged.mg" -erroraction 'silentlycontinue'
	if ($file2 -match "Source\sfile:") {
		$CURR_GROUPS=((((Select-String -Path 'C:\Program Files (x86)\ossec-agent\shared\merged.mg' -Pattern "Source file:") | Select-Object -ExpandProperty Line).Replace("<!-- Source file: ","")).Replace("/agent.conf -->","")) -join ','
	} else {
		# If the agent is presently a member of only one agent group, then pull that group name into current group variable.
		$CURR_GROUPS=((((Select-String -Path 'C:\Program Files (x86)\ossec-agent\shared\merged.mg' -Pattern "#") | Select-Object -ExpandProperty Line).Replace("#","")))
	}
	if ($Debug) { Write-Output "Current agent group membership: $CURR_GROUPS" }

	# Blend standard/dynamic groups with custom groups
	$WazuhGroupsPrefix = "windows,windows-local,"
	if ( $SkipOsquery -eq $false ) {
		$WazuhGroupsPrefix = $WazuhGroupsPrefix+"osquery,osquery-local,"
	}
	if ( $SkipSysmon -eq $false ) {
		$WazuhGroupsPrefix = $WazuhGroupsPrefix+"sysmon,sysmon-local,"
	}
	$WazuhGroupsPrefix = $WazuhGroupsPrefix+"org,"
	$WazuhGroups = $WazuhGroupsPrefix+$WazuhGroups
	$WazuhGroups = $WazuhGroups.TrimEnd(",")
	if ($Debug) { Write-Output "Target agent group membership:  $WazuhGroups" }
	if ( -not ( $CURR_GROUPS -eq $WazuhGroups ) ) {
		if ($Debug) { Write-Output "Current and expected agent group membership differ." }
		exit 1
	}
} else {
	if ($Debug) { Write-Output "Ignoring agent group membership since -WazuhGroups not specified." }
}

#
# 3 - Is the target version of Wazuh agent installed?
#
$version = [IO.File]::ReadAllText("C:\Program Files (x86)\ossec-agent\VERSION").split("`n")[0].split("v")[1]
if ($Debug) { Write-Output "Current Wazuh agent version is: $version" }
if ($Debug) { Write-Output "Target Wazuh agent version is:  $WazuhVer" }
if ( -not ( $WazuhVer.Trim() -eq $version.Trim() ) ) {
	if ($Debug) { Write-Output "Current and expected Wazuh agent version differ." }
	exit 1
}

if ( -not ( $SkipSysmon -eq $true ) ) {
	#
	# 4 - Is the target version of Sysmon installed?
	#
	# Local Sysmon.exe file exists?
	if ( -not (Test-Path -LiteralPath "C:\Program Files (x86)\sysmon-wazuh\Sysmon.exe") ) {
		if ($Debug) { Write-Output "Sysmon.exe is missing." }
		exit 1
	}
	# Local SysmonDrv.sys file exists?
	if ( -not (Test-Path -LiteralPath "c:\windows\SysmonDrv.sys") ) {
		if ($Debug) { Write-Output "SysmonDrv.sys is missing." }
		exit 1
	}
	# Local Sysmon.exe file at target version?
	$smver=[System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\Program Files (x86)\sysmon-wazuh\Sysmon.exe").FileVersion
	if ($Debug) { Write-Output "Current Sysmon version is: $smver" }
	if ($Debug) { Write-Output "Target Sysmon version is:  $SysmonVer" }
	if ( -not ( $smver.Trim() -eq $SysmonVer.Trim() ) ) {
		if ($Debug) { Write-Output "Current and expected Sysmon.exe version differ." }
		exit 1
	}
	###
	### SKIPPING VERSION CHECK OF SYSMON DRIVER BECAUSE 12.0 PUBLISHED IT WITH WRONG VERSION METADATA
	### https://social.technet.microsoft.com/Forums/en-US/08b323e0-3b8e-4840-ad09-bbb08077c2b9/sysmon-120-appears-to-have-outdated-version-metadata-on-sysmondrvsys?forum=miscutils
	###
	## SysmonDrv.sys at target version?
	#$SysmonDrvVer = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("c:\windows\SysmonDrv.sys").FileVersion
	#if ($Debug) { Write-Output "Current SysmonDrv.sys version is: $SysmonDrvVer" }
	#if ( -not ( $SysmonDrvVer.Trim() -eq $SysmonVer.Trim() ) ) {
	#	if ($Debug) { Write-Output "Current and expected SysmonDrv.sys version differ." }
	#	exit 1
	#}
	# Sysmon driver loaded?
	$fltOut = (fltMC.exe) | Out-String
	if ( -not ( $fltOut -match 'SysmonDrv' ) ) {
		if ($Debug) { Write-Output "Sysmon driver is not loaded." }
		exit 1
	}
}

if ( -not ( $SkipOsquery -eq $true ) ) {
	#
	# 5 - Is the target version of Osquery installed?
	#
	# Local osqueryd.exe present?
	if ( -not (Test-Path -LiteralPath "C:\Program Files\osquery\osqueryd\osqueryd.exe") ) {
		if ($Debug) { Write-Output "Osquery executable appears to be missing." }
		exit 1
	}
	# Correct version?
	$osqver=[System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\Program Files\osquery\osqueryd\osqueryd.exe").FileVersion
	$osqver = $osqver -replace '\.\d+$',''
	if ($Debug) { Write-Output "Current Osquery version is: $osqver" }
	if ($Debug) { Write-Output "Target Osquery version is:  $OsqueryVer" }
	if ( -not ( $osqver.Trim() -eq $OsqueryVer.Trim() ) ) {
		if ($Debug) { Write-Output "Current and expected Osquery version differ." }
		exit 1
	}
	# Actually running?
	if ( -not ( Get-Process -Name "osqueryd" -erroraction 'silentlycontinue' ) ) {
		if ($Debug) { Write-Output "Osquery does not appear to be running." }
		exit 1
	}
}

# All relevant tests passed, so return a success code.
if ($Debug) { Write-Output "No deployment/redeployment appears to be needed." }
exit 0
