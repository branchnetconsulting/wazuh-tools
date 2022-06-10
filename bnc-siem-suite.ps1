#
# bnc-siem-suite.ps1
#
# This script is for checking and/or installing the BNC SIEM suite on Windows systems.  It can directly install or uninstall it, conditionally install it, or simply check to see if installation/reinstallation is needed.
# The BNC SIEM suite for Windows presently includes Wazuh agent, Sysmon, and Osquery, all integrated for centralized configuration and reporting via the Wazuh manager.  Sysmon and/or Osquery can optionally be excluded.
#
# Depending on the use case, this script can be called singly on a one time or periodic basis to conditionally install/reinstall the suite.  
# Alternatively, a higher level configuration management system like Puppet could first call this script just to check if installation/reinstallation is called for, and based on the exit code it receives, 
# conditionally call this script a second time to explicitly install/reinstall the suite.
#
# Deployment will install Wazuh agent and Wazuh-integrated Osquery on Ubuntu, CentOS, and Amazon Linux systems.
# After preserving the working Wazuh agent registration key if present,  Wazuh/OSSEC agent and/or Osquery are completely purged and then reinstalled,
# with an option to skip Osquery.
#
# The Wazuh agent self registration process is included, but will be skipped if an existing working registration can be recycled.
# Agent name and group names must match exactly for registration to be recycled. This will keep the same agent id associated with the agent.
#
# If any of the listed test families fail, the SIEM packages will be (re)installed.
#
# If the call to this script is deemed broken, or either the Wazuh Manager connect port or registration port are unresponsive to a probe, an exit code of 2 will be returned.
#
# The default exit code is 0.
#
# Is the agent presently really connected to the Wazuh manager?
# Is the agent connected to the right manager?
# Is the agent currently a member of all intended Wazuh agent groups?
# Is the target version of Wazuh agent installed?
# Is the target version of Osquery installed and running?
#
# Required Parameters:
#
# -WazuhVer         Full version of Wazuh agent to confirm and/or install, like "4.1.4". 
# -WazuhMgr         IP or FQDN of the Wazuh manager for ongoing agent connections. 
# -WazuhRegPass     Password for registration with Wazuh manager (put in quotes).
# -OsqueryVer       Full version of Osquery to validate and/or install, like "4.6.0" (always N.N.N format, required unless -SkipOsquery specified).
# -SysmonVer		Full version of Sysmon to validate, like "11.11" (Always N.N format, required unless -SkipSysmon specified)    
#
# Optional Parameters:
#
# -WazuhRegMgr      IP or FQDN of the Wazuh manager for agent registration connection (defaults to $WazuhMgr if not specified)
# -WazuhAgentName   Name under which to register this agent in place of locally detected Windows host name.
# -WazuhGroups      Comma separated list of optional extra Wazuh agent groups to member this agent.  No spaces.  Put whole list in quotes.  Groups must already exist.
#                   Use "" to expect zero extra groups.
#                   If not specified, agent group membership will not be checked at all.
#                   Do not include "windows" or "windows-local"group as these are autodetected and will dynamically be inserted as groups.
#                   Also, do not include "osquery" as this will automatically be included unless SkipOsquery is set to "1"
# -WazuhSrc         Static download path to fetch Wazuh agent installer.  Overrides WazuhVer value.
# -SysmonSrc        Static download path to fetch Sysmon installer for if you host your own Sysmon. 
# -SysmonDLuser     Download username for Sysmon, if authentication is required where you have the installer stored.
# -SysmonDLpass     Download password for Sysmon, if authentication is required where you have the installer stored.
# -SysmonDLhash     MD5 hash of the Sysmon installer you have at your download source. 
# -SysmonConfSrc    Location of your Sysmon config file. 
# -OsquerySrc       Static download path to fetch Osquery agent installer.  Overrides OsqueryVer value.
# -SkipSysmon		Flag to not examine Sysmon. (Optional)
# -SkipOsquery      Set this flag to skip examination and/or installation of Osquery.  If the script determines that installation is warranted, this flag will result in Osquery being removed if present.
#                   Osquery is installed by default.
# -Install          Skip all checks and force installation
# -Uninstall        Uninstall Wazuh agent and sub-agents
# -CheckOnly        Only run checks to see if installation is current or in need of deployment
# -LBprobe          Additionally check for manager connectivity with an agent-auth probe to avoid being fooled by a load balancer that handshakes even when service down.
# -Debug            Show debug output
# -help             Show command syntax
#
# Sample command line:
#
# PowerShell.exe -ExecutionPolicy Bypass -File .\bnc-siem-suite.ps1 -WazuhVer "4.1.4" -OsqueryVer "4.6.0" -WazuhMgr "{Manager DNS or IP}" -WazuhRegPass "{Your_Password}" -WazuhGroups "{Your_comma_separated_group_list}" -Debug
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
	$SysmonSrc, 
	$SysmonDLuser,
	$SysmonDLpass,
	$SysmonDLhash,
	$SysmonConfSrc = "https://raw.githubusercontent.com/branchnetconsulting/sysmon-config/master/sysmonconfig-export.xml", 
	$OsqueryVer, 
	$OsquerySrc, 
	$SysmonVer,
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

#
# Check if SIEM suite deployment is in the target state.  If this cannot be determined due to an invalid call on failed probe of the Wazuh manager, fail and bail with exit code 2.
# If no install/reinstall appears to be needed, then bail with an exit code of 0.
# If a installation/reinstallation is called for, then simply return.
#
function checkSuite {

	# Relevant script parameters
	#		
	# -WazuhMgr			IP or FQDN of the Wazuh manager for ongoing agent connections. (Required)
	# -WazuhRegMgr		IP or FQDN of the Wazuh manager for agent registration connection (defaults to $WazuhMgr if not specified)
	# -WazuhVer			Full Wazuh agent version number to confirm, like "3.12.2". (Required)
	# -OsqueryVer		Full version of Osquery to validate, like "4.2.0" (Always N.N.N format, required unless -SkipOsquery specified)
	# -SysmonVer		Full version of Sysmon to validate, like "11.11" (Always N.N format, required unless -SkipSysmon specified)
	# -WazuhGroups		Comma separated list of custom Wazuh agent groups. No spaces. Put whole list in quotes. (Optional)
	#					If intentionally specifying an empty set of custom groups, then your must use the syntax -WazuhGroups '""'
	# -SkipSysmon		Flag to not examine Sysmon. (Optional)
	# -SkipOsquery		Flag not to examine Osquery. (Optional)
	# -LBprobe		Additionally check for manager connectivity with an agent-auth probe to avoid being fooled by a load balancer that handshakes even when service down.

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
		if ($Debug) { Write-Output "If -SkipOsquery is not specified, then -OsqueryVer must be provided." }
		exit 2
	}
	# Force skip Sysmon and Osquery if Windows is older then Win 10 or Win Svr 2012
	if ( [int]((Get-CimInstance Win32_OperatingSystem).BuildNumber) -lt 9200 ) {
	     Write-Output "Windows older than 10/2012, so skipping Sysmon and Osquery..."
	     $SkipSysmon=$true
	     $SkipOsquery=$true
	}
	# Force skip Osquery if Windows is 32bit
	If ( -not ([Environment]::Is64BitProcess) ) {
	     Write-Output "Windows is 32bit, so skipping Osquery..."
	     $SkipOsquery=$true
	}
	if ( ($SysmonVer -eq $null) -and ($SkipSysmon -eq $false) ) { 
		if ($Debug) { Write-Output "If -SkipSysmon is not specified, then -SysmonVer must be provided." }
        	Write-Output "a:$SysmonVer"
        	Write-Output "b:$SkipSysmon"
		exit 2
	}
	if ( $WazuhGroups -eq "#NOGROUP#" ) {
		if ( ($SkipSysmon -eq $true) -or ($SkipOsquery -eq $true) ) {
			if ($Debug) { write-host "-SkipSysmon and -SkipOsquery must always be accompanied with the use of -WazuhGroups." }
			exit 2
		}
	}

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
			if ($Debug) { Write-Output "-LBprobe check failed.  Manager is not truly reachable." }
			exit 2
		}
		Remove-Item -Path "agent-auth-test-probe" -erroraction 'silentlycontinue'
		if ($Debug) { Write-Output "-LBprobe check succeeded.  Manager is truly reachable." }

	}

	#
	# Is the agent presently really connected to the Wazuh manager?
	#
	if (Test-Path "$PFPATH\ossec-agent\wazuh-agent.state" -PathType leaf) {
		$StateFile = Get-Content "$PFPATH\ossec-agent\wazuh-agent.state" -erroraction 'silentlycontinue'
	} else {
		$StateFile = Get-Content "$PFPATH\ossec-agent\ossec-agent.state" -erroraction 'silentlycontinue'
	}	
	if ( -not ($StateFile -match "'connected'" ) ) {
		if ($Debug) { Write-Output "The Wazuh agent is not connected to the Wazuh manager." }
		return
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

	if ( -not ($SkipSysmon) ) {
		#
		# 4 - Is the target version of Sysmon installed?
		#
		# Local Sysmon.exe file exists?
		if ( -not (Test-Path -LiteralPath "$PFPATH\sysmon-wazuh\Sysmon.exe") ) {
			if ($Debug) { Write-Output "Sysmon.exe is missing." }
			return
		}
		# Local SysmonDrv.sys file exists?
		if ( -not (Test-Path -LiteralPath "c:\windows\SysmonDrv.sys") ) {
			if ($Debug) { Write-Output "SysmonDrv.sys is missing." }
			return
		}
		# Local Sysmon.exe file at target version?  Both Sysmon.exe and Sysmon64.exe will exist in this directory at the same version, so checking the first one should always be fine.
		$smver=[String]([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$PFPATH\sysmon-wazuh\Sysmon.exe").FileVersion)
		if ($Debug) { Write-Output "Current Sysmon version is: $smver" }
		if ($Debug) { Write-Output "Target Sysmon version is:  $SysmonVer" }
		if ( -not ( $smver.Trim() -eq ([String]$SysmonVer).Trim() ) ) {
			if ($Debug) { Write-Output "Current and expected Sysmon.exe version differ." }
			return
		}
		###
		### SKIPPING VERSION CHECK OF SYSMON DRIVER BECAUSE 12.0 PUBLISHED IT WITH WRONG VERSION METADATA
		### https://social.technet.microsoft.com/Forums/en-US/08b323e0-3b8e-4840-ad09-bbb08077c2b9/sysmon-120-appears-to-have-outdated-version-metadata-on-sysmondrvsys?forum=miscutils
		### It appears this was cleared up with 12.01 but I am not sure I want to trust that file's version to stay aligned in the future with the real product version.
		###
		## SysmonDrv.sys at target version?
		#$SysmonDrvVer = [String]([System.Diagnostics.FileVersionInfo]::GetVersionInfo("c:\windows\SysmonDrv.sys").FileVersion)
		#if ($Debug) { Write-Output "Current SysmonDrv.sys version is: $SysmonDrvVer" }
		#if ( -not ( ([String]$SysmonDrvVer).Trim() -eq ([String]$SysmonVer).Trim() ) ) {
		#	if ($Debug) { Write-Output "Current and expected SysmonDrv.sys version differ." }
		#	return
		#}
		# Sysmon driver loaded?
		$fltOut = (fltMC.exe) | Out-String
		if ( -not ( $fltOut -match 'SysmonDrv' ) ) {
			if ($Debug) { Write-Output "Sysmon driver is not loaded." }
			return
		}
	}

	if ( -not ($SkipOsquery) ) {
		#
		# 5 - Is the target version of Osquery installed?
		#
		# Local osqueryd.exe present?
		if ( -not (Test-Path -LiteralPath "C:\Program Files\osquery\osqueryd\osqueryd.exe") ) {
			if ($Debug) { Write-Output "Osquery executable appears to be missing." }
			return
		}
		# Correct version?
		$osqver=[String]([System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\Program Files\osquery\osqueryd\osqueryd.exe").FileVersion)
		$osqver = $osqver -replace '\.\d+$',''
		if ($Debug) { Write-Output "Current Osquery version is: $osqver" }
		if ($Debug) { Write-Output "Target Osquery version is:  $OsqueryVer" }
		if ( -not ( $osqver.Trim() -eq $OsqueryVer.Trim() ) ) {
			if ($Debug) { Write-Output "Current and expected Osquery version differ." }
			return
		}
		# Actually running?
		if ( -not ( Get-Process -Name "osqueryd" -erroraction 'silentlycontinue' ) ) {
			if ($Debug) { Write-Output "Osquery does not appear to be running." }
			return
		}
	}

	# All relevant tests passed, so return a success code.
	if ($Debug) { Write-Output "No deployment/redeployment appears to be needed." }
	exit 0
}

# 
# Uninstall Wazuh Agent, and unless skipped, also uninstall Sysmon and Osquery.
# As part of the Wazuh Agent uninstall process, ascertain if we might be in a position to recycle the agent registration, and set the flag and preserve information accordingly.
#
function uninstallSuite {

	# Relevant script parameters
	#		
	# -WazuhMgr			IP or FQDN of the Wazuh manager for ongoing agent connections.  Required.
	# -WazuhAgentName	Name under which to register this agent in place of locally detected Windows host name
	# -Uninstall		Uninstall without checking and without installing thereafter

	if ($Debug) { Write-Output "Uninstalling the SIEM suite." }
	
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
		if (Test-Path "$PFPATH\ossec-agent\wazuh-agent.state" -PathType leaf) {
			$StateFile = Get-Content "$PFPATH\ossec-agent\wazuh-agent.state" -erroraction 'silentlycontinue'
		} else {
			$StateFile = Get-Content "$PFPATH\ossec-agent\ossec-agent.state" -erroraction 'silentlycontinue'
		}
		$MergedFile = Get-Content "$PFPATH\ossec-agent\shared\merged.mg" -erroraction 'silentlycontinue'
		$MergedFileName = "$PFPATH\ossec-agent\shared\merged.mg"
		$CurrentAgentName=(Get-Content "$PFPATH\ossec-agent\client.keys").Split(" ")[1]
		if ( ($StateFile -match "'connected'") -and ($WazuhMgr -eq $CurrentManager) -and ($CurrentAgentName -eq $WazuhAgentName) ) {
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
	
	# If Sysmon present (and no -SkipSysmon specified), then wipe it all out
	if ( -not ($SkipSysmon) ) {
		# Blow away Wazuh-integrated Sysmon directory (used for applying Sysmon config updates)
    	if ( Test-Path "$PFPATH\sysmon-wazuh" -PathType Container ) {
            Remove-Item "$PFPATH\sysmon-wazuh" -recurse	
        }
		# If Sysmon is partly or fully installed, attempt to remove it with the Sysmon.exe or Sysmon64.exe that it was actually installed with.
		if ( (Test-Path c:\windows\SysmonDrv.sys -PathType leaf) -or (Test-Path c:\windows\Sysmon.exe -PathType leaf) -or (Test-Path c:\windows\Sysmon64.exe -PathType leaf) ) {
			if ($Debug) { Write-Output "Removing presently installed Sysmon..." }
			if ( (Test-Path c:\windows\SysmonDrv.sys -PathType leaf) -and (Test-Path c:\windows\Sysmon.exe -PathType leaf) ) {
				Move-Item -Path "c:\windows\Sysmon.exe" -Destination "c:\Sysmon.exe" -Force 
				Start-Process -FilePath "C:\Sysmon.exe" -ArgumentList "-u" -Wait -WindowStyle 'Hidden'
				if (Test-Path c:\windows\SysmonDrv.sys -PathType leaf) {
					Start-Process -FilePath "C:\Sysmon.exe" -ArgumentList "-u", "force" -Wait -WindowStyle 'Hidden'
				}
				Remove-Item "c:\Sysmon.exe"
			}
			if ( (Test-Path c:\windows\SysmonDrv.sys -PathType leaf) -and (Test-Path c:\windows\Sysmon64.exe -PathType leaf) ) {
				Move-Item -Path "c:\windows\Sysmon64.exe" -Destination "c:\Sysmon64.exe" -Force
				Start-Process -FilePath "C:\Sysmon64.exe" -ArgumentList "-u" -Wait -WindowStyle 'Hidden'
				if (Test-Path c:\windows\SysmonDrv.sys -PathType leaf) {
					Start-Process -FilePath "C:\Sysmon64.exe" -ArgumentList "-u", "force" -Wait -WindowStyle 'Hidden'
				}
				Remove-Item "c:\Sysmon64.exe"
			}
			if ($Debug) { Write-Output "Waiting 10 more seconds to be sure Sysmon removal process is complete." }
			Start-Sleep -Seconds 10
			if ( (Test-Path c:\windows\SysmonDrv.sys -PathType leaf) -or (Test-Path c:\windows\Sysmon.exe -PathType leaf) -or (Test-Path c:\windows\Sysmon64.exe -PathType leaf) ) {
				if ($Debug) { Write-Output "Removal of Sysmon failed." }
				exit 1
			}
		}
	}
	
	# Remove osquery if present and -SkipOsquery not specified.
	If ( -not ($SkipOsquery) ) {
		if (Test-Path "c:\Program Files\osquery\osqueryd\osqueryd.exe" -PathType leaf)  {
			if ($Debug) { Write-Output "Removing Osquery..." }
			Uninstall-Package -Name "osquery" -erroraction 'silentlycontinue' | out-null
			Remove-Item "C:\Progra~1\osquery" -recurse -erroraction 'silentlycontinue'
		}
		if (Test-Path "c:\Program Files\osquery\osqueryd\osqueryd.exe" -PathType leaf)  {
			if ($Debug) { Write-Output "Failed to remove Osquery." }
			exit 1
		}
	}
}

#
# Install Wazuh Agent, recycling an existing registration if possible and otherwise re-registering it.
# Also if not skipped, install Sysmon and Osquery.
#
function installSuite {

	# Relevant script parameters
	#		
	# -WazuhVer		Full version of Wazuh agent to install, like "3.12.2"
	# -WazuhMgr		IP or FQDN of the Wazuh manager for ongoing agent connections.  Required.
	# -WazuhRegMgr		IP or FQDN of the Wazuh manager for agent registration connection (defaults to $WazuhMgr if not specified)
	# -WazuhRegPass		Password for registration with Wazuh manager (put in quotes).  Required.
	# -WazuhAgentName	Name under which to register this agent in place of locally detected Windows host name
	# -WazuhGroups		Comma separated list of Wazuh groups to member this agent.  No spaces.  Put whole list in quotes.  Groups must already exist.
	#			Cannot skip -WazuhGroups if using -SkipSysmon or -SkipOsquery
	# -WazuhSrc		Static download path to fetch Wazuh agent installer.  Overrides $WazVer
        # -SysmonVer		Full version of Sysmon to validate, like "11.11" (optional value to double check version of Sysmon after downloaded)	
        # -SysmonSrc		Static download path to fetch Sysmon installer zip file.  
	# -SysmonDLuser         Optional web credentials for downloading Sysmon from -SysmonSrc alternate source, used like "-SysmonDLuser myusername"
	# -SysmonDLpass         Optional web credentials for downloading Sysmon from -SysmonSrc alternate source, used like "-SysmonDLpass mypassword".  Ignored if -SysmonDLuser skipped.
	# -SysmonDLhash         SHA256 hash of the Sysmon download file for validation.  Required if -SysmonSrc is used.
	# -SysmonConfSrc	Static download path to fetch Sysmon configuration file.
	# -SkipSysmon		Do not install Sysmon.  Completely remove it if present.
	# -OsqueryVer		Full version of Osquery to install, like "4.2.0"
	# -OsquerySrc		Static download path to fetch Osquery agent installer.  Overrides $OsqVer
	# -SkipOsquery		Do not install Osquery.  Completely remove it if present.
	# -Local		Expect all download files already to be present in current directory.  Do not use any $...Src parameters with this.
	
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
	if ( ($OsqueryVer -eq $null) -and ( $SkipOsquery -eq $false ) -and ( $OsquerySrc -eq $null ) ) { 
		write-host "Must use '-OsqueryVer' to specify the password to use for agent registration."
		exit 1
	}
	# Force skip Sysmon and Osquery if Windows is older then Win 10 or Win Svr 2012
	if ( [int]((Get-CimInstance Win32_OperatingSystem).BuildNumber) -lt 9200 ) {
	     Write-Output "Windows older than 10/2012, so skipping Sysmon and Osquery..."
	     $SkipSysmon=$true
	     $SkipOsquery=$true
	}
	# Force skip Osquery if Windows is 32bit
	If ( -not ([Environment]::Is64BitProcess) ) {
	     Write-Output "Windows is 32bit, so skipping Osquery..."
	     $SkipOsquery=$true
	}

if ($SysmonSrc -eq $null) { 
		$SysmonSrc = "https://download.sysinternals.com/files/Sysmon.zip"
	} else {
		if ( $SysmonDLhash -eq $null ) {
			write-host "When specifying -SysmonSrc, the -SysmonDLhash option must also be used to specify the SHA256 hash to verify the Sysmon installer."
			exit 1
		}
	}
	if ( -not ($SysmonDLuser -eq $null) ) {
		if ($SysmonDLpass -eq $null) {
			if ($Debug) { write-host "When specifying -SysmonDLuser, you must also specify -SysmonDLpass." }
			exit 1
		}
		$pair = "$($SysmonDLuser):$($SysmonDLpass)"
		$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Pair))
		$headers = @{ Authorization = "Basic $encodedCredentials" }
	}
	if ($WazuhRegMgr -eq $null) { 
		$WazuhRegMgr = $WazuhMgr
	}
	if ($WazuhSrc -eq $null) { 
		$WazuhMajorVer = $WazuhVer.ToCharArray()[0]
		$WazuhSrc = "https://packages.wazuh.com/$WazuhMajorVer.x/windows/wazuh-agent-$WazuhVer-1.msi"
	}
	if ($OsquerySrc -eq $null) { 
		$OsquerySrc = "https://pkg.osquery.io/windows/osquery-$OsqueryVer.msi"
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

	if ( $SkippedGroups -eq $true ) {
		if ( ($SkipSysmon -eq $true) -or ($SkipOsquery -eq $true) ) {
			if ($Debug) { write-host "-SkipSysmon and -SkipOsquery must always be accompanied with the use of -WazuhGroups." }
			exit 1
		}
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
		if ( -not (Test-Path -LiteralPath "Sysmon.zip") ) {
			if ($Debug) { Write-Output "Option '-Local' specified but no 'Sysmon.zip' file was found in current directory.  Giving up and aborting the installation..." }
			exit 1
		}	
		if ( -not (Test-Path -LiteralPath "sysmonconfig.xml") ) {
			if ($Debug) { Write-Output "Option '-Local' specified but no 'sysmonconfig.xml' file was found in current directory.  Giving up and aborting the installation..." }
			exit 1
		}	
		if ( -not (Test-Path -LiteralPath "osquery.msi") ) {
			if ($Debug) { Write-Output "Option '-Local' specified but no 'osquery.msi' file was found in current directory.  Giving up and aborting the installation..." }
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

	# If we can safely skip self registration and just restore the backed up client.keys file, then do so. Otherwise, self-register.
	if ( ($MightRecycleRegistration) -and ( ($CurrentGroups -eq $WazuhGroups) -or ($SkippedGroups) ) ) { 
		Copy-Item "$env:TEMP\client.keys.bnc" -Destination "$PFPATH\ossec-agent\client.keys"
	} else {
		# Register the agent with the manager (keep existing groups if agent connected and -WazuhGroups not specified)
		if ($Debug) {  Write-Output "Registering Wazuh Agent with $WazuhRegMgr..." }
        Remove-Item -Path "$PFPATH\ossec-agent\client.keys"
		#if ($SkippedGroups) {         
        #    Start-Process -FilePath "$PFPATH\ossec-agent\agent-auth.exe" -ArgumentList "-m", "$WazuhRegMgr", "-P", "$WazuhRegPass", "-G", "$CurrentGroups", "-A", "$WazuhAgentName" -Wait -WindowStyle 'Hidden'
		#} else {
			Start-Process -FilePath "$PFPATH\ossec-agent\agent-auth.exe" -ArgumentList "-m", "$WazuhRegMgr", "-P", "$WazuhRegPass", "-G", "$WazuhGroups", "-A", "$WazuhAgentName" -Wait -WindowStyle 'Hidden'
		#}
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
		{$_ -gt 18362} {$OS = "Win10or2019"}
		default { $OS = "WindowsUnknown"}
	}

	if ($Debug) {  Write-Output "Writing ossec.conf" }
	# Write the ossec.conf file
$ConfigToWrite = @"
<ossec_config>
   <client>
	  <server>
		 <address>$WazuhMgr</address>
		 <port>1514</port>
		 <protocol>tcp</protocol>
	  </server>
	  <config-profile>$OS</config-profile>
	  <notify_time>10</notify_time>
	  <time-reconnect>60</time-reconnect>
	  <auto_restart>yes</auto_restart>
	  <enrollment>
                 <enabled>no</enabled>
          </enrollment>
   </client>
   <logging>
	  <log_format>plain,json</log_format>
   </logging>
</ossec_config>
"@
	$ConfigToWrite | Out-File -FilePath "$PFPATH/ossec-agent/ossec.conf" -Encoding ASCII

	# Write the local_internal_options.conf file
	if ($Debug) {  Write-Output "Writing local_internal_options.conf..." }
$ConfigToWrite = @"
logcollector.remote_commands=1
wazuh_command.remote_commands=1
sca.remote_commands=1
"@
	$ConfigToWrite | Out-File -FilePath "$PFPATH/ossec-agent/local_internal_options.conf" -Encoding ASCII

	#
	# Sysmon
	#

	# Create "$PFPATH\sysmon-wazuh" directory if missing
	if ( -not (Test-Path -LiteralPath "$PFPATH\sysmon-wazuh" -PathType Container) ) { New-Item -Path "$PFPATH\" -Name "sysmon-wazuh" -ItemType "directory" | out-null }

	# Download and unzip Sysmon.zip, or unzip it from local directory if "-Local" option specified.
	# Sysmon must be acquired locally or via download even if "-SkipSysmon" was specified, so that we can use Sysmon.exe to uninstall Sysmon.
	Remove-Item "$PFPATH\sysmon-wazuh\*" -Force
	if ( $Local -eq $false ) {
		if ($Debug) { Write-Output "Downloading and unpacking Sysmon installer..." }
		$count = 0
		$success = $false;
		do{
			try{
				if ( $SysmonDLhash -eq $null ) {
					Invoke-WebRequest -Uri $SysmonSrc -OutFile "$env:TEMP\Sysmon.zip"
				} else {
					Invoke-WebRequest -Uri $SysmonSrc -Method Get -Headers $headers -OutFile "$env:TEMP\Sysmon.zip"
				}
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
		# If a hash was provided then calculate the hash of the downloaded Sysmon.zip and if the hashes don't match then fail.
		if ( -not ( $SysmonDLhash -eq $null ) ) {
			$SysmonRealHash=(Get-FileHash "$env:TEMP\Sysmon.zip" -Algorithm SHA256).Hash
			if ( -not ( $SysmonDLhash -eq $SysmonRealHash ) ) {
				if ($Debug) { Write-Output "The Sysmon verification hash does not match the downloaded $SysmonSrc." }
				exit 1
			}
		}
		Microsoft.PowerShell.Archive\Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$PFPATH\sysmon-wazuh"
		Remove-Item "$env:TEMP\Sysmon.zip" -Force -erroraction 'silentlycontinue'
	} else {
		Microsoft.PowerShell.Archive\Expand-Archive "Sysmon.zip" -DestinationPath "$PFPATH\sysmon-wazuh\"
	}

	if ( $SkipSysmon -eq $false ) {
		# Download SwiftOnSecurity config file for Sysmon or confirm it is already locally present if "-Local" option specified.
		if ( $Local -eq $false ) {
			# Download the latest SwiftOnSecurityconfig file for Sysmon and write it to Wazuh agent shared directory.
			# This is only to seed it so that the install process works even if the official and perhaps localized file hasn't propagated down from Wazuh manager yet.
			if ($Debug) { Write-Output "Downloading $SysmonConfSrc as sysmonconfig.xml..." }
			$count = 0
			$success = $false;
			do{
				try{
					Invoke-WebRequest -Uri "$SysmonConfSrc" -OutFile "C:\sysmonconfig.xml"
					$success = $true
				}
				catch{
					if ($Debug) {  Write-Output "Next attempt in 10 seconds" }
					Start-sleep -Seconds 10
				}  
				$count++    
			} until($count -eq 6 -or $success)
			if(-not($success)){exit 1}
		} else {	
			Copy-Item "sysmonconfig.xml" -Destination "C:\"
		}
	}

    # If -SysmonVer was specified but the version downloaded or previously provided (-Local) to install does not match it, then fail and bail
    If ( -not ($SysmonVer -eq $null ) )  {
		$smver=[String]([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$PFPATH\sysmon-wazuh\Sysmon.exe").FileVersion)
		if ( -not ( $smver.Trim() -eq ([String]$SysmonVer).Trim() ) ) {
			if ($Debug) { Write-Output "Current version of Sysmon to be installed ($smver) differs from what was specified ($SysmonVer)." }
			exit 1
		}
    }

	if ( $SkipSysmon -eq $false ) {
		if ($Debug) {  Write-Output "Installing Sysmon..." }
		If ([Environment]::Is64BitProcess){
			if ($Debug) { Write-Output "Using 64 bit installer" }
			Start-Process -FilePath "$PFPATH\sysmon-wazuh\Sysmon64.exe" -ArgumentList "-i","c:\sysmonconfig.xml","-accepteula" -Wait -WindowStyle 'Hidden'
		}else{
			if ($Debug) { Write-Output "Using 32 bit installer" }
			Start-Process -FilePath "$PFPATH\sysmon-wazuh\Sysmon.exe" -ArgumentList "-i","c:\sysmonconfig.xml","-accepteula" -Wait -WindowStyle 'Hidden'
		}
	}

	# Confirm Sysmon driver is actually loaded
	if (-not ( fltmc | findstr -i SysmonDrv )) {
		if ($Debug) { Write-Output "Installation of Sysmon failed.  Driver not loaded." }
		exit 1
	}

	#
	# osquery
	#
	if ( $SkipOsquery -eq $false ) {
		# Download Osquery installer or confirm it is already locally present if "-Local" option specified.
		if ( $Local -eq $false ) {
			# Download the osquery MSI
			if ($Debug) { Write-Output "Downloading $OsquerySrc..." }
			$count = 0
			$success = $false;
			do{
				try{
					Invoke-WebRequest -Uri $OsquerySrc -OutFile osquery.msi
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

		# Install osquery
		if ($Debug) { Write-Output "Installing Osquery..." }
		Start-Process -FilePath osquery.msi -ArgumentList "/q" -Wait -WindowStyle 'Hidden'
		if ( $Local -eq $false ) {
			rm .\osquery.msi
		}
		# Remove the Windows service that the MSI installed which we do not want
		if ($Debug) { Write-Output "Removing the osquery Windows service so Wazuh agent can manage it instead..." }
		Start-Process -FilePath C:\Progra~1\osquery\osqueryd\osqueryd.exe -ArgumentList "--uninstall" -Wait -WindowStyle 'Hidden'
	}

	#
	# Last Wazuh Agent steps
	#

	# Start up the Wazuh agent service
	if ($Debug) { Write-Output "Starting up the Wazuh agent..." }
	Start-Service WazuhSvc

	# After 15 seconds confirm agent connected to manager
	if ($Debug) { Write-Output "Pausing for 15 seconds to allow agent to connect to manager..." }
	Start-Sleep -s 15 
	$file = Get-Content "$PFPATH\ossec-agent\ossec.log" -erroraction 'silentlycontinue'
	if ($file -match "Connected to the server " ) {
		if ($Debug) { Write-Output "This agent has successfully connected to the Wazuh manager!" }
		exit 0
	} else {
		if ($Debug) { Write-Output "This agent FAILED to connect to the Wazuh manager." }
		exit 1
	}
}

#
# Main
#

# Set https protocol defaults to try stronger TLS first and allow all three forms of TLS
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# These variables are set in one of the above functions and need to be seen in another one of the above functions, so make them global.
New-Variable MightRecycleRegistration -value $false -option AllScope
New-Variable SkippedGroups -value $false -option AllScope

#Set installation path based on 64 vs. 32-bit Windows OS
$PFPATH="C:\Program Files (x86)"
If ( -not ([Environment]::Is64BitProcess) ) {
     Write-Output "Changing path variable to C:\Program Files for detected 32-bit Windows OS..."
     $PFPATH="C:\Program Files"
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
# checkSuite will bail unless an install/reinstall is called for.
if ( -not ( ($Install) -or ($Uninstall) ) ) {
	checkSuite
}

# If all we are doing is a check, then the check must have indicated a install/reinstall was needed, so return an exit code of 1 now.
if ( $CheckOnly ) {
	exit 1
}

# Uninstall the SIEM suite whether or not a fresh installation is to follow.  Bail if it cannot uninstall everything satisfactorily (exit code 1)
uninstallSuite

# Continue to the installation phase unless this was just a -Uninstall call to the script.  Fail and bail with exit code 1 if cannot install/deploy completely
if ( -not ($Uninstall) ) {
	installSuite
}

# Uninstall or uninstall&install process must have succeeded, so close down with code 0.
exit 0
