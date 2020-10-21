#
# deploy-wazuh-windows-agent-suite.ps1
# by Kevin Branch (kevin@branchnetconsulting.com)
# with contributions by Ken Fredericksen (ken@branchnetconsulting.com)
#
# Deployment script for Wazuh agent and subagents (by default Sysmon and Osquery).  
#
# The Agent self registration process is included, but will be skipped if an existing working registration can be recycled.
#
# From command shell or PowerShell (Run as Administrator), run this script as follows:
# 	PowerShell.exe -ExecutionPolicy Bypass -File ./deploy-wazuh-windows-agent-suite.ps1 -WazuhMgr "10.20.30.40" -WazuhRegPass "theRegistrationPW"
#
# This script should work on Windows systems as old as Windows Server 2012 provided PowerShell 5.1 is present.  Likely Powershell 5.0 would be OK.
#
# -WazuhVer		Full version of Wazuh agent to install, like "3.12.2"
# -WazuhMgr		IP or FQDN of the Wazuh manager for ongoing agent connections.  Required.
# -WazuhRegMgr		IP or FQDN of the Wazuh manager for agent registration connection (defaults to $WazuhMgr if not specified)
# -WazuhRegPass		Password for registration with Wazuh manager (put in quotes).  Required.
# -WazuhAgentName	Name under which to register this agent in place of locally detected Windows host name
# -WazuhGroups		Comma separated list of Wazuh groups to member this agent.  No spaces.  Put whole list in quotes.  Groups must already exist.
#			Cannot skip -WazuhGroups if using -SkipSysmon or -SkipOsquery
# -WazuhSrc		Static download path to fetch Wazuh agent installer.  Overrides $WazVer
# -SysmonSrc		Static download path to fetch Sysmon installer zip file.  
# -SysmonDLuser     	Optional web credentials for downloading Sysmon from -SysmonSrc alternate source, used like "-SysmonDLuser myusername"
# -SysmonDLpass     	Optional web credentials for downloading Sysmon from -SysmonSrc alternate source, used like "-SysmonDLpass mypassword".  Ignored if -SysmonDLuser skipped.
# -SysmonDLhash     	SHA256 hash of the Sysmon download file for validation.  Required if -SysmonSrc is used.
# -SysmonConfSrc	Static download path to fetch Sysmon configuration file.
# -SkipSysmon		Do not install Sysmon.  Completely remove it if present.
# -OsqueryVer		Full version of Osquery to install, like "4.2.0"
# -OsquerySrc		Static download path to fetch Osquery agent installer.  Overrides $OsqVer
# -SkipOsquery		Do not install Osquery.  Completely remove it if present.
# -Local		Expect all download files already to be present in current directory.  Do not use any $...Src parameters with this.
#
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
	[switch]$SkipSysmon=$false, 
	$OsqueryVer, 
	$OsquerySrc, 
	[switch]$SkipOsquery=$false,
	[switch]$Local=$false
);

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
		write-host "When specifying -SysmonDLuser, you must also specify -SysmonDLpass."
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
    $WazuhSrc = "https://packages.wazuh.com/3.x/windows/wazuh-agent-$WazuhVer-1.msi"
}
if ($OsquerySrc -eq $null) { 
    $OsquerySrc = "https://pkg.osquery.io/windows/osquery-$OsqueryVer.msi"
}
if ( !($PSVersionTable.PSVersion.Major) -ge 5 ) {
	write-host "PowerShell 5.0 or higher is required by this script."
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
		write-host "-SkipSysmon and -SkipOsquery must always be accompanied with the use of -WazuhGroups."
		exit 1
	}
}

# Blend standard/dynamic groups with custom groups
$WazuhGroupsPrefix = "windows,"
if ( $SkipOsquery -eq $false ) {
	$WazuhGroupsPrefix = $WazuhGroupsPrefix+"osquery,"
}
if ( $SkipSysmon -eq $false ) {
	$WazuhGroupsPrefix = $WazuhGroupsPrefix+"sysmon,"
}
$WazuhGroups = $WazuhGroupsPrefix+$WazuhGroups
$WazuhGroups = $WazuhGroups.TrimEnd(",")

# If "-Local" option selected, confirm all required local files are present.
if ( $Local -eq $true ) {
	if ( -not (Test-Path -LiteralPath "nuget.zip") ) {
		Write-Output "Option '-Local' specified but no 'nuget.zip' file was found in current directory.  Giving up and aborting the installation..."
		exit 1
	}
	if ( -not (Test-Path -LiteralPath "wazuh-agent.msi") ) {
		Write-Output "Option '-Local' specified but no 'wazuh-agent.msi' file was found in current directory.  Giving up and aborting the installation..."
		exit 1
	}
	if ( -not (Test-Path -LiteralPath "Sysmon.zip") ) {
		Write-Output "Option '-Local' specified but no 'Sysmon.zip' file was found in current directory.  Giving up and aborting the installation..."
		exit 1
	}	
	if ( -not (Test-Path -LiteralPath "sysmonconfig.xml") ) {
		Write-Output "Option '-Local' specified but no 'sysmonconfig.xml' file was found in current directory.  Giving up and aborting the installation..."
		exit 1
	}	
	if ( -not (Test-Path -LiteralPath "osquery.msi") ) {
		Write-Output "Option '-Local' specified but no 'osquery.msi' file was found in current directory.  Giving up and aborting the installation..."
		exit 1
	}
}

# Set https protocol defaults to try stronger TLS first and allow all three forms of TLS
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Take note if agent is already connected to a Wazuh manager and collect relevant data
# If the agent is already connected to the same target manager, the agent name has not changed, and the agent group list is exactly the same,
# then the registration will be retained by backing up client.keys now and restoring it after reinstallation of the Wazuh agent, skipping self-registration. 
$file = Get-Content "C:\Program Files (x86)\ossec-agent\ossec-agent.state" -erroraction 'silentlycontinue'
$file2 = Get-Content "C:\Program Files (x86)\ossec-agent\shared\merged.mg" -erroraction 'silentlycontinue'
if ($file -match "'connected'" ) {
    Write-Output "Agent currently connected, so saving client.keys to $env:TEMP\client.keys.bnc"
    $ALREADY_CONNECTED=$true
    $OLDNAME=(type "C:\Program Files (x86)\ossec-agent\client.keys").Split(" ")[1]
    Remove-Item -Path "$env:TEMP\client.keys.bnc" -erroraction 'silentlycontinue' | out-null
    Copy-Item 'C:\Program Files (x86)\ossec-agent\client.keys' -Destination "$env:TEMP\client.keys.bnc"
    if ($file2 -match "Source\sfile:") {
        $CURR_GROUPS=((((Select-String -Path 'C:\Program Files (x86)\ossec-agent\shared\merged.mg' -Pattern "Source file:") | Select-Object -ExpandProperty Line).Replace("<!-- Source file: ","")).Replace("/agent.conf -->","")) -join ','
    } else {
        # If the agent is presently a member of only one agent group, then pull that group name into current group variable.
        $CURR_GROUPS=((((Select-String -Path 'C:\Program Files (x86)\ossec-agent\shared\merged.mg' -Pattern "#") | Select-Object -ExpandProperty Line).Replace("#","")))
    }
} else {
    $ALREADY_CONNECTED=$false
}

# NuGet Dependency

if ( -not (Test-Path -LiteralPath "C:\Program Files\PackageManagement\ProviderAssemblies\nuget" -PathType Container) ) {
	Write-Output "Installing dependency (NuGet) to be able to uninstall other packages..."
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
					Write-Output "Download attempt failed.  Will retry 10 seconds."
				} else {
					Write-Output "Download attempt still failed.  Giving up and aborting the installation..."
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

#
# Wazuh Agent 
#

# Download Wazuh Agent installer or confirm it is already locally present if "-Local" option specified.
if ( $Local -eq $false ) {
	# Download the correct version of the Wazuh installer MSI
	Write-Output "Downloading $WazuhSrc"
	$count = 0
	$success = $false;
	do{
		try{
			Invoke-WebRequest -Uri $WazuhSrc -OutFile wazuh-agent.msi
			$success = $true
		}
		catch{
			if ($count -lt 5) {
				Write-Output "Download attempt failed.  Will retry 10 seconds."
			} else {
				Write-Output "Download attempt still failed.  Giving up and aborting the installation..."
				exit 1
			}
			Start-sleep -Seconds 10
		}  
		$count++    
	}until($count -eq 6 -or $success)
}

# If Wazuh agent already installed, blow it away

if (Test-Path 'C:\Program Files (x86)\ossec-agent\ossec-agent.exe' -PathType leaf) {
	Write-Output "Uninstalling existing Wazuh Agent..."
	if ( Get-Service | findstr -i " Wazuh " | findstr -i "Running" ) {
		Write-Output "Stopping current Wazuh Agent service..."
		net stop wazuh
	}
	Uninstall-Package -Name "Wazuh Agent" -erroraction 'silentlycontinue' | out-null
}

# Install Wazuh Agent and then remove the installer file
Write-Output "Installing Wazuh Agent"
Start-Process -FilePath wazuh-agent.msi -ArgumentList "/q" -Wait -WindowStyle 'Hidden'
if ( $Local -eq $false ) {
	rm .\wazuh-agent.msi
}

# If we can safely skip self registration and just restore the backed up client.keys file, then do so. Otherwise, self-register.
# This should keep us from burning through so many agent ID numbers.
$SKIP_REG = $false
if ($ALREADY_CONNECTED -eq "yes") { 
	Write-Output "Agent is presently connected..."
	Write-Output "Current registered agent name is: $OLDNAME and new target name is: $WazuhAgentName"
	if ($WazuhAgentName -eq $OLDNAME) {
		Write-Output "Old and new agent registration names match." 
                Write-Output "Current group memberships are: $CURR_GROUPS and new target group memberships are: $WazuhGroups"
		if ($SkippedGroups -eq $false) {
			if ($CURR_GROUPS -eq $WazuhGroups) {
				Write-Output "Old and new agent group memberships match. Will skip self-registration and restore client.keys backup instead."
				$SKIP_REG = $true
			} else {
 			  	Write-Output "Current groups and new target groups do not match."
   				$SKIP_REG = $false
			}
		} else {
			Write-Output "Skipping group comparison."
			$SKIP_REG = $true
		}
	}
}

if  ($SKIP_REG -eq $false) {
    # Register the agent with the manager (keep existing groups if agent connected and -WazuhGroups not specified)
    Write-Output "Registering Wazuh Agent with $WazuhRegMgr..."
	if ( ($SkippedGroups -eq $true) -and ( $ALREADY_CONNECTED -eq "yes" ) ) {
		rm 'C:\Program Files (x86)\ossec-agent\client.keys'
		C:\Progra~2\ossec-agent\agent-auth.exe -m "$WazuhRegMgr" -P "$WazuhRegPass" -G "$CURR_GROUPS" -A "$WazuhAgentName"
	} else {
		rm 'C:\Program Files (x86)\ossec-agent\client.keys'
		C:\Progra~2\ossec-agent\agent-auth.exe -m "$WazuhRegMgr" -P "$WazuhRegPass" -G "$WazuhGroups" -A "$WazuhAgentName"
	}
	if ( -not (Test-Path 'C:\Program Files (x86)\ossec-agent\client.keys' -PathType leaf) ) {
		Write-Output "Wazuh Agent self-registration failed."
		exit 1
	}
} else {
	Copy-Item "$env:TEMP\client.keys.bnc" -Destination 'C:\Program Files (x86)\ossec-agent\client.keys'
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

Write-Output "Writing ossec.conf"
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
      <notify_time>60</notify_time>
      <time-reconnect>300</time-reconnect>
      <auto_restart>yes</auto_restart>
   </client>
   <logging>
      <log_format>plain,json</log_format>
   </logging>
</ossec_config>
"@
$ConfigToWrite | Out-File -FilePath C:/Progra~2/ossec-agent/ossec.conf -Encoding ASCII

# Write the local_internal_options.conf file
Write-Output "Writing local_internal_options.conf..."
$ConfigToWrite = @"
logcollector.remote_commands=1
wazuh_command.remote_commands=1
sca.remote_commands=1
"@
$ConfigToWrite | Out-File -FilePath C:/Progra~2/ossec-agent/local_internal_options.conf -Encoding ASCII

#
# Sysmon
#

# Create "C:\Program Files (x86)\sysmon-wazuh" directory if missing
if ( -not (Test-Path -LiteralPath "C:\Program Files (x86)\sysmon-wazuh" -PathType Container) ) { New-Item -Path "C:\Program Files (x86)\" -Name "sysmon-wazuh" -ItemType "directory" | out-null }

# Download and unzip Sysmon.zip, or unzip it from local directory if "-Local" option specified.
# Sysmon must be acquired locally or via download even if "-SkipSysmon" was specified, so that we can use Sysmon.exe to uninstall Sysmon.
Remove-Item "C:\Progra~2\sysmon-wazuh\*" -Force
if ( $Local -eq $false ) {
	Write-Output "Downloading and unpacking Sysmon installer..."
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
				Write-Output "Download attempt failed.  Will retry 10 seconds."
			} else {
				Write-Output "Download attempt still failed.  Giving up and aborting the installation..."
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
			Write-Output "The Sysmon verification hash does not match the downloaded $SysmonSrc."
			exit 1
		}
	}
	Microsoft.PowerShell.Archive\Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "C:\Program Files (x86)\sysmon-wazuh"
	Remove-Item "$env:TEMP\Sysmon.zip" -Force -erroraction 'silentlycontinue'
} else {
	Microsoft.PowerShell.Archive\Expand-Archive "Sysmon.zip" -DestinationPath "C:\Program Files (x86)\sysmon-wazuh\"
}

if ( $SkipSysmon -eq $false ) {
	# Download SwiftOnSecurity config file for Sysmon or confirm it is already locally present if "-Local" option specified.
	if ( $Local -eq $false ) {
		# Download the latest SwiftOnSecurity config file for Sysmon and write it to Wazuh agent shared directory.
		# This is only to seed it so that the install process works even if the official and perhaps localized file hasn't propagated down from Wazuh manager yet.
		Write-Output "Downloading $SysmonConfSrc as sysmonconfig.xml..."
		$count = 0
		$success = $false;
		do{
			try{
				Invoke-WebRequest -Uri "$SysmonConfSrc" -OutFile "C:\Program Files (x86)\ossec-agent\shared\sysmonconfig.xml"
				$success = $true
			}
			catch{
				Write-Output "Next attempt in 10 seconds"
				Start-sleep -Seconds 10
			}  
			$count++    
		}until($count -eq 6 -or $success)
		if(-not($success)){exit 1}
	} else {	
		Copy-Item "sysmonconfig.xml" -Destination "C:\Program Files (x86)\ossec-agent\shared\"
	}
}

#
# If Sysmon is present, attempt to remove it with the Sysmon.exe or Sysmon64.exe that it was actually installed with, moving the original installer to old-Sysmon.exe or old-Sysmon64.exe in c:\progra~2\sysmon-wazuh\
#
if ( (Test-Path c:\windows\SysmonDrv.sys -PathType leaf) -or (Test-Path c:\windows\Sysmon.exe -PathType leaf) -or (Test-Path c:\windows\Sysmon64.exe -PathType leaf) ) {
	Write-Output "Removing presently installed Sysmon..."
	if ( (Test-Path c:\windows\SysmonDrv.sys -PathType leaf) -and (Test-Path c:\windows\Sysmon.exe -PathType leaf) ) {
		Move-Item -Path "c:\windows\Sysmon.exe" -Destination "c:\Sysmon.exe" -Force 
		Start-Process -FilePath "C:\Sysmon.exe" -ArgumentList "-u" -Wait -WindowStyle 'Hidden'
		if (Test-Path c:\windows\SysmonDrv.sys -PathType leaf) {
			Start-Process -FilePath "C:\Sysmon.exe" -ArgumentList "-u", "force" -Wait -WindowStyle 'Hidden'
		}
		Move-Item -Path "c:\Sysmon.exe" -Destination "c:\progra~2\sysmon-wazuh\old-Sysmon.exe" -Force
	}
	if ( (Test-Path c:\windows\SysmonDrv.sys -PathType leaf) -and (Test-Path c:\windows\Sysmon64.exe -PathType leaf) ) {
		Move-Item -Path "c:\windows\Sysmon64.exe" -Destination "c:\Sysmon64.exe" -Force
		Start-Process -FilePath "C:\Sysmon64.exe" -ArgumentList "-u" -Wait -WindowStyle 'Hidden'
		if (Test-Path c:\windows\SysmonDrv.sys -PathType leaf) {
			Start-Process -FilePath "C:\Sysmon64.exe" -ArgumentList "-u", "force" -Wait -WindowStyle 'Hidden'
		}
		Move-Item -Path "c:\Sysmon64.exe" -Destination "c:\progra~2\sysmon-wazuh\old-Sysmon64.exe" -Force
	}
	if (Test-Path c:\windows\SysmonDrv.sys -PathType leaf) {
		Start-Process -FilePath "C:\Progra~2\sysmon-wazuh\Sysmon.exe" -ArgumentList "-u" -Wait -WindowStyle 'Hidden'
	}
	if (Test-Path c:\windows\SysmonDrv.sys -PathType leaf) {
		Start-Process -FilePath "C:\Progra~2\sysmon-wazuh\Sysmon.exe" -ArgumentList "-u", "force" -Wait -WindowStyle 'Hidden'
	}
	Write-Output "Waiting 10 more seconds to be sure Sysmon removal process is complete."
	Start-Sleep -Seconds 10
	if ( (Test-Path c:\windows\SysmonDrv.sys -PathType leaf) -or (Test-Path c:\windows\Sysmon.exe -PathType leaf) -or (Test-Path c:\windows\Sysmon64.exe -PathType leaf) ) {
		Write-Output "Removal of Sysmon failed."
		exit 1
	}
}

if ( $SkipSysmon -eq $true ) {
	Remove-Item "C:\Program Files (x86)\sysmon-wazuh" -recurse -erroraction 'silentlycontinue'
} else {
	Write-Output "Installing Sysmon..."
	If ([Environment]::Is64BitProcess){
		Start-Process -FilePath C:\Progra~2\sysmon-wazuh\Sysmon64.exe -ArgumentList "-i","c:\progra~2\ossec-agent\shared\sysmonconfig.xml","-accepteula" -Wait -WindowStyle 'Hidden'
	}else{
		Start-Process -FilePath C:\Progra~2\sysmon-wazuh\Sysmon.exe -ArgumentList "-i","c:\progra~2\ossec-agent\shared\sysmonconfig.xml","-accepteula" -Wait -WindowStyle 'Hidden'
	}
}

# Confirm Sysmon driver is actually loaded
if (-not ( fltmc | findstr -i SysmonDrv )) {
	Write-Output "Installation of Sysmon failed.  Driver not loaded."
	exit 1
}

#
# osquery
#

# Remove osquery if present (making sure wazuh agent is not running before blowing away osquery dir)
if (Test-Path "c:\Program Files\osquery\osqueryd\osqueryd.exe" -PathType leaf)  {
	Write-Output "Removing Osquery..."
	if ( Get-Service | findstr -i " Wazuh " | findstr -i "Running" ) {
		net stop wazuh
	}
	Uninstall-Package -Name "osquery" -erroraction 'silentlycontinue' | out-null
	Remove-Item "C:\Progra~1\osquery" -recurse -erroraction 'silentlycontinue'
}
if (Test-Path "c:\Program Files\osquery\osqueryd\osqueryd.exe" -PathType leaf)  {
	Write-Output "Failed to remove Osquery."
	exit 1
}

if ( $SkipOsquery -eq $false ) {
	# Download Osquery installer or confirm it is already locally present if "-Local" option specified.
	if ( $Local -eq $false ) {
		# Download the osquery MSI
		Write-Output "Downloading $OsquerySrc..."
		$count = 0
		$success = $false;
		do{
			try{
				Invoke-WebRequest -Uri $OsquerySrc -OutFile osquery.msi
				$success = $true
			}
			catch{
				if ($count -lt 5) {
					Write-Output "Download attempt failed.  Will retry 10 seconds."
				} else {
					Write-Output "Download attempt still failed.  Giving up and aborting the installation..."
					exit 1
				}
				Start-sleep -Seconds 10
			}  
			$count++    
		}until($count -eq 6 -or $success)
	} 	

	# Install osquery
	Write-Output "Installing Osquery..."
	Start-Process -FilePath osquery.msi -ArgumentList "/q" -Wait -WindowStyle 'Hidden'
	if ( $Local -eq $false ) {
		rm .\osquery.msi
	}
	# Remove the Windows service that the MSI installed which we do not want
	Write-Output "Removing the osquery Windows service so Wazuh agent can manage it instead..."
	Start-Process -FilePath C:\Progra~1\osquery\osqueryd\osqueryd.exe -ArgumentList "--uninstall" -Wait -WindowStyle 'Hidden'
}

#
# Last Wazuh Agent steps
#

# Start up the Wazuh agent service
Write-Output "Starting up the Wazuh agent..."
net start wazuh

# After 15 seconds confirm agent connected to manager
Write-Output "Pausing for 15 seconds to allow agent to connect to manager..."
Start-Sleep -s 15 
$file = Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -erroraction 'silentlycontinue'
if ($file -match "Connected to the server " ) {
	Write-Output "This agent has successfully connected to the Wazuh manager!"
	exit 0
} else {
	Write-Output "This agent FAILED to connect to the Wazuh manager."
	exit 1
}
