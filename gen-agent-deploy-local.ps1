#
# gen-agent-deploy-local.ps1
#
# This script is for downloading the necessary files for the installation of the Wazuh on Windows systems that are not connected to the Internet.  This can be run on another Windows system that is connected to the Internet, 
# creating a file called agent-deploy.zip that can be placed, along with the siem-agent-deploy.ps1 script, into the working directory of the target Windows system. The -local option on the will unzip the agent-deploy.zip 
# file and use these unzipped files to deploy the Wazuh agent.  Additional custom BNC components will be downloaded and installed based through the secure agent connection to the Wazuh Manager based on the group membership of the agent. 
#
# examples:
#	PowerShell.exe -ExecutionPolicy Bypass .\gen-agent-deploy-local.ps1 # Will use the default version referenced in the script parameters
#	PowerShell.exe -ExecutionPolicy Bypass .\gen-agent-deploy-local.ps1 -InstallVer "4.3.9" # Used to specify a version to be installed.
#	PowerShell.exe -ExecutionPolicy Bypass .\gen-agent-deploy-local.ps1 -VerDiscAddr "siem.branchnetconsulting.com" -DefaultInstallVer "4.3.9" #used to install the version referenced in the .txt DNS response.  If no response is received, the specified -DefaultInstallVer will be used instead. 
#

# All possible parameters that may be specified for check-only, conditional install, forced install or forced uninstall purposes.
param ( $VerDiscAddr,
	$InstallVer,
	$DefaultInstallVer = "4.3.9",
	$DownloadSource, 
	[switch]$Debug=$true
);

#
# Download and stage all files into a temporary new directory. 
#
function DownloadFiles {

	# Relevant script parameters
	#		
	# -VerDiscAddr			The Version Discovery Address where a .txt record has been added with the target version of the Wazuh agent to install.
	# -InstallVer			The version of the Wazuh Agent to install.
	# -DefaultInstallVer	Command line paramenter and a preset within the script that is used as a last resort.
	# -DownloadSource		Static download path to fetch Wazuh agent installer.  Overrides WazuhVer value.

	if ( -not ($VerDiscAddr -eq $null) ) {
		$InstallVer = (Resolve-DnsName -Type txt -name $VerDiscAddr -ErrorAction SilentlyContinue).Strings
	}

	if ($InstallVer -eq $null) { 
		if ($Debug) { Write-Output "InstallVer was null, so using DefaultInstallVer value, if present from command line" }
		$InstallVer = $DefaultInstallVer
	}
		
	if ($DownloadSource -eq $null) { 
		$MajorVer = $InstallVer.ToCharArray()[0]
		$DownloadSource = "https://packages.wazuh.com/$MajorVer.x/windows/wazuh-agent-$InstallVer-1.msi"
	}

	# Set https protocol defaults to try stronger TLS first and allow all three forms of TLS
	[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
	
	Remove-Item "agent-deploy.zip" -recurse -force -erroraction 'silentlycontinue'
	Remove-Item "$env:TEMP\generateagentdeploy" -recurse -force -erroraction 'silentlycontinue'
	New-Item -ItemType "directory" -Path "$env:TEMP\generateagentdeploy" | out-null

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
				$global:result = "2"
			}
			Start-sleep -Seconds 10
		}  
		$count++    
	} until($count -eq 6 -or $success)
	
	Compress-Archive -Path "C:\Program Files\PackageManagement\ProviderAssemblies\*" -DestinationPath "$env:TEMP\generateagentdeploy\nuget.zip"

	# Download the correct version of the Wazuh installer MSI
	if ($Debug) {  Write-Output "Downloading $DownloadSource..." }
	$count = 0
	$success = $false;
	do{
		try{
			Invoke-WebRequest -Uri $DownloadSource -OutFile "$env:TEMP\generateagentdeploy\wazuh-agent.msi"
			$success = $true
		}
		catch{
			if ($count -lt 5) {
				if ($Debug) { Write-Output "Download attempt failed.  Will retry 10 seconds." }
			} else {
				$global:result = "2"
			}
			Start-sleep -Seconds 10
		}  
		$count++    
	}until($count -eq 6 -or $success)
}

function CreateZip {

	# check for the existence of correct files
	if ( -not (Test-Path -LiteralPath "$env:TEMP\generateagentdeploy\nuget.zip") ) {
		if ($Debug) { Write-Output "The 'nuget.zip' file was found in current directory.  Giving up and aborting..." }
		$global:result = "2"
	}
	if ( -not (Test-Path -LiteralPath "$env:TEMP\generateagentdeploy\wazuh-agent.msi") ) {
		if ($Debug) { Write-Output "The 'wazuh-agent.msi' file was found in current directory.  Giving up and aborting..." }
		$global:result = "2"
	}

	# Create deploy.zip file in current working directory.
	Compress-Archive -Path "$env:TEMP\generateagentdeploy\*" -DestinationPath "agent-deploy.zip"

	Remove-Item "$env:TEMP\generateagentdeploy" -recurse -force
}

#
# Main
#

if ( !($PSVersionTable.PSVersion.Major) -ge 5 ) {
	if ($Debug) { write-host "PowerShell 5.0 or higher is required by this script." }
	exit 2
}

DownloadFiles
if ( $result -eq "2" ) {
	if ($Debug) { Write-Output "Downloading of one of the required files still failed.  Giving up and aborting the installation..." }
	exit 2
}

CreateZip
if ( $result -eq "2" ) {
	exit 2
}

# If the script didn't bail previously, exit assuming success.
Write-Output "The new agent-deploy.zip file was created successfully."
exit 0
