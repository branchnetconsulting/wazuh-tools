#
# gen-bnc-deploy-local.ps1
#
# This script is for downloading all of the necessary files for the installation of the BNC SIEM suite on Windows systems that are not connected to the Internet.  This can be run on another Windows system that is connected to the Internet, 
# creating a file called bnc-deploy.zip that can be placed, along with the bnc-siem-suite.ps1 script, into the working directory of the target Windows system. The -local option on the will unzip the bnc-deploy.zip file and use these unzipped files to deploy
# the BNC SIEM suite.
#
# examples:
#    .\gen-bnc-deploy-local.ps1 -WazuhVer "3.13.2" -OsqueryVer "4.5.1" -SysmonVer "12.02"
#    .\gen-bnc-deploy-local.ps1 -WazuhVer "3.13.2" -OsqueryVer "4.5.1" -SysmonVer "12.02" -SysmonSrc "http(s)://PATH-HERE/Sysmon_12.02.zip" -SysmonDLuser "USERNAME-HERE" -SysmonDLpass "PASSWOROD-HERE" -SysmonDLhash "SHA-256-HASH-HERE"
#

# All possible parameters that may be specified for check-only, conditional install, forced install or forced uninstall purposes.
param ( $WazuhVer, 
	$WazuhSrc, 
	$SysmonVer,
	$SysmonSrc, 
	$SysmonDLuser,
	$SysmonDLpass,
	$SysmonDLhash,
	$SysmonConfSrc = "https://raw.githubusercontent.com/branchnetconsulting/sysmon-config/master/sysmonconfig-export.xml", 
	$OsqueryVer, 
	[switch]$Debug=$true
);

#
# Download and stage all files into a temporary new directory. 
#
function DownloadFiles {

	# Relevant script parameters
	#		
	# -WazuhVer			Full version of Wazuh agent to install, like "3.12.2"
	# -WazuhSrc			Static download path to fetch Wazuh agent installer.  Overrides $WazVer
	# -SysmonVer		Full version of Sysmon to validate, like "11.11" (optional value to double check version of Sysmon after downloaded)	
	# -SysmonSrc		Static download path to fetch Sysmon installer zip file.  
	# -SysmonDLuser     Optional web credentials for downloading Sysmon from -SysmonSrc alternate source, used like "-SysmonDLuser myusername"
	# -SysmonDLpass     Optional web credentials for downloading Sysmon from -SysmonSrc alternate source, used like "-SysmonDLpass mypassword".  Ignored if -SysmonDLuser skipped.
	# -SysmonDLhash     SHA256 hash of the Sysmon download file for validation.  Required if -SysmonSrc is used.
	# -SysmonConfSrc	Static download path to fetch Sysmon configuration file.
	# -OsqueryVer		Full version of Osquery to install, like "4.2.0"
	
	if ($WazuhVer -eq $null) { 
		write-host "Must use '-WazuhVer' to specify the target version of Wazuh agent, like 3.13.1."
		exit 1
	}
	if ($OsqueryVer -eq $null) { 
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
			if ($Debug) { write-host "When specifying -SysmonDLuser, you must also specify -SysmonDLpass." }
			exit 1
		}
		$pair = "$($SysmonDLuser):$($SysmonDLpass)"
		$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Pair))
		$headers = @{ Authorization = "Basic $encodedCredentials" }
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

	# Set https protocol defaults to try stronger TLS first and allow all three forms of TLS
	[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
	
	Remove-Item "bnc-deploy.zip" -recurse -force -erroraction 'silentlycontinue'
	Remove-Item "$env:TEMP\generatebncdeploy" -recurse -force -erroraction 'silentlycontinue'
	New-Item -ItemType "directory" -Path "$env:TEMP\generatebncdeploy" | out-null

	# NuGet Dependency
	if ($Debug) { Write-Output "Fetching dependency (NuGet) to be able to uninstall other packages..." }
	$count = 0
	$success = $false;
	do{
		try{
			Install-PackageProvider -Name NuGet -Force | out-null
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
	} until($count -eq 6 -or $success)
	
	Compress-Archive -Path "C:\Program Files\PackageManagement\ProviderAssemblies\*" -DestinationPath "$env:TEMP\generatebncdeploy\nuget.zip"

	# Download the correct version of the Wazuh installer MSI
	if ($Debug) {  Write-Output "Downloading $WazuhSrc..." }
	$count = 0
	$success = $false;
	do{
		try{
			Invoke-WebRequest -Uri $WazuhSrc -OutFile "$env:TEMP\generatebncdeploy\wazuh-agent.msi"
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

	# Download Sysmon.zip.
	if ($Debug) { Write-Output "Downloading Sysmon installer..." }
	$count = 0
	$success = $false;
	do{
		try{
			if ( $SysmonDLhash -eq $null ) {
				Invoke-WebRequest -Uri $SysmonSrc -OutFile "$env:TEMP\generatebncdeploy\Sysmon.zip"
			} else {
				Invoke-WebRequest -Uri $SysmonSrc -Method Get -Headers $headers -OutFile "$env:TEMP\generatebncdeploy\Sysmon.zip"
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
		$SysmonRealHash=(Get-FileHash "$env:TEMP\generatebncdeploy\Sysmon.zip" -Algorithm SHA256).Hash
		if ( -not ( $SysmonDLhash -eq $SysmonRealHash ) ) {
			if ($Debug) { Write-Output "The Sysmon verification hash does not match the downloaded $SysmonSrc." }
			exit 1
		}
	}

	# Download SwiftOnSecurity config file for Sysmon or confirm it is already locally present if "-Local" option specified.
	# Download the latest SwiftOnSecurity config file for Sysmon and write it to Wazuh agent shared directory.
	# This is only to seed it so that the install process works even if the official and perhaps localized file hasn't propagated down from Wazuh manager yet.
	if ($Debug) { Write-Output "Downloading $SysmonConfSrc as sysmonconfig.xml..." }
	$count = 0
	$success = $false;
	do{
		try{
			Invoke-WebRequest -Uri "$SysmonConfSrc" -OutFile "$env:TEMP\generatebncdeploy\sysmonconfig.xml"
			$success = $true
		}
		catch{
			if ($Debug) {  Write-Output "Next attempt in 10 seconds" }
			Start-sleep -Seconds 10
		}  
		$count++    
	} until($count -eq 6 -or $success)
	if(-not($success)){exit 1}

	# If -SysmonVer was specified but the version downloaded to install does not match it, then fail and bail
	New-Item -ItemType "directory" -Path "$env:TEMP\generatebncdeploy\bncsysmon" | out-null
	Microsoft.PowerShell.Archive\Expand-Archive "$env:TEMP\generatebncdeploy\Sysmon.zip" -Force -DestinationPath "$env:TEMP\generatebncdeploy\bncsysmon\"
	If ( -not ($SysmonVer -eq $null ) )  {
		$smver=[System.Diagnostics.FileVersionInfo]::GetVersionInfo("$env:TEMP\generatebncdeploy\bncsysmon\Sysmon.exe").FileVersion
		if ( -not ( $smver.Trim() -eq $SysmonVer.Trim() ) ) {
			if ($Debug) { Write-Output "Current version of Sysmon that was downloaded ($smver) differs from what was specified ($SysmonVer)." }
			exit 1
		}
	}

	# Download the osquery MSI
	if ($Debug) { Write-Output "Downloading $OsquerySrc..." }
	$count = 0
	$success = $false;
	do{
		try{
			Invoke-WebRequest -Uri $OsquerySrc -OutFile "$env:TEMP\generatebncdeploy\osquery.msi"
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
	} until($count -eq 6 -or $success)
}

function CreateZip {

	# check for the existence of correct files
	if ( -not (Test-Path -LiteralPath "$env:TEMP\generatebncdeploy\nuget.zip") ) {
		if ($Debug) { Write-Output "The 'nuget.zip' file was found in current directory.  Giving up and aborting..." }
		exit 1
	}
	if ( -not (Test-Path -LiteralPath "$env:TEMP\generatebncdeploy\wazuh-agent.msi") ) {
		if ($Debug) { Write-Output "The 'wazuh-agent.msi' file was found in current directory.  Giving up and aborting..." }
		exit 1
	}
	if ( -not (Test-Path -LiteralPath "$env:TEMP\generatebncdeploy\Sysmon.zip") ) {
		if ($Debug) { Write-Output "The 'Sysmon.zip' file was found in current directory.  Giving up and aborting..." }
		exit 1
	}	
	if ( -not (Test-Path -LiteralPath "$env:TEMP\generatebncdeploy\sysmonconfig.xml") ) {
		if ($Debug) { Write-Output "The 'sysmonconfig.xml' file was found in current directory.  Giving up and aborting..." }
		exit 1
	}	
	if ( -not (Test-Path -LiteralPath "$env:TEMP\generatebncdeploy\osquery.msi") ) {
		if ($Debug) { Write-Output "The 'osquery.msi' file was found in current directory.  Giving up and aborting..." }
		exit 1
	}

	Remove-Item "$env:TEMP\generatebncdeploy\bncsysmon\" -recurse -force 

	# Create bnc-deploy.zip file in current working directory.
	Compress-Archive -Path "$env:TEMP\generatebncdeploy\*" -DestinationPath "bnc-deploy.zip"

	Remove-Item "$env:TEMP\generatebncdeploy" -recurse -force
}

#
# Main
#
DownloadFiles
CreateZip
# If the script didn't bail previously, exit assuming success.
Write-Output "The new bnc-deploy.zip file was created successfully."
exit 0
