#
# Deployment script for Wazuh agent and subagents (including Sysmon and Osquery).  Agent registration process included.
# From command shell or powershell (Run as Administrator), run this script as follows:
# PowerShell.exe -ExecutionPolicy Bypass -File ./deploy-wazuh-windows.ps1  
#
# Last updated by Kevin Branch 4/9/2020
#

#
# Site-specific settings
#
$WazuhVersion="3.12.2"
$OsqueryVersion="4.3.0"
$WazuhServer="***AUTHD_SERVER***"
$WazuhRegPass="***REGISTRATION_PASSWORD***"
$WazuhGroups="osquery,sysmon"
$WazuhDownloadSource="https://packages.wazuh.com/3.x/windows/wazuh-agent-$WazuhVersion-1.msi"
$SysmonSource="http://www.branchnetconsulting.com/wazuh/Sysmon.exe"
$SysmonConfSource="https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$OsquerySource="https://pkg.osquery.io/windows/osquery-$OsqueryVersion.msi"

# Set https protocol defaults to try stronger TLS first and allow all three forms of TLS
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Dependency
cd c:\
echo "Installing dependency (NuGet) to be able to uninstall other packages"
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
			exit
		}
		Start-sleep -Seconds 10
    }  
    $count++    
}until($count -eq 6 -or $success)

#
# Wazuh Agent 
#

# Download the correct version of the Wazuh installer MSI
echo "Downloading $WazuhDownloadSource"
$count = 0
$success = $false;
do{
    try{
        Invoke-WebRequest -Uri $WazuhDownloadSource -OutFile wazuh-agent.msi
        $success = $true
    }
    catch{
		if ($count -lt 5) {
			Write-Output "Download attempt failed.  Will retry 10 seconds."
		} else {
			Write-Output "Download attempt still failed.  Giving up and aborting the installation..."
			exit
		}
		Start-sleep -Seconds 10
    }  
    $count++    
}until($count -eq 6 -or $success)

# If Wazuh agent already present, blow it away
echo "Stopping old Wazuh Agent if present"
net stop wazuh
echo "Uninstalling old Wazuh Agent if present"
Uninstall-Package -Name "Wazuh Agent" -erroraction 'silentlycontinue' | out-null

# Install Wazuh Agent and then clean up the installer file
echo "Installing Wazuh Agent"
Start-Process -FilePath wazuh-agent.msi -ArgumentList "/q" -Wait -WindowStyle 'Hidden'
rm .\wazuh-agent.msi

# Register the agent with the manager
echo "Registering Wazuh Agent"
C:\Progra~2\ossec-agent\agent-auth.exe -m "$WazuhServer" -P "$WazuhRegPass" -G "windows,$WazuhGroups"

echo "Writing ossec.conf"
# Write the ossec.conf file
$ConfigToWrite = @"
<ossec_config>
  <client>
    <server>
      <address>$WazuhServer</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <notify_time>60</notify_time>
    <time-reconnect>300</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>
  <active-response>
    <disabled>no</disabled>
  </active-response>
</ossec_config>
"@
$ConfigToWrite | Out-File -FilePath C:/Progra~2/ossec-agent/ossec.conf -Encoding ASCII

# Write the local_internal_options.conf file
echo "Writing local_internal_options.conf"
$ConfigToWrite = @"
logcollector.remote_commands=1
"@
$ConfigToWrite | Out-File -FilePath C:/Progra~2/ossec-agent/local_internal_options.conf -Encoding ASCII


#
# Sysmon
#

# Create "C:\Program Files (x86)\sysmon-wazuh" directory if missing
if ( -not (Test-Path -LiteralPath "C:\Program Files (x86)\sysmon-wazuh" -PathType Container) ) { New-Item -Path "C:\Program Files (x86)\" -Name "sysmon-wazuh" -ItemType "directory" | out-null }

# Download Sysmon.exe 
echo "Downloading Sysmon.exe"
$count = 0
$success = $false;
do{
    try{
        Invoke-WebRequest -Uri $SysmonSource -OutFile "C:\Program Files (x86)\sysmon-wazuh\Sysmon.exe"
        $success = $true
    }
    catch{
		if ($count -lt 5) {
			Write-Output "Download attempt failed.  Will retry 10 seconds."
		} else {
			Write-Output "Download attempt still failed.  Giving up and aborting the installation..."
			exit
		}
		Start-sleep -Seconds 10
    }  
    $count++    
}until($count -eq 6 -or $success)

# Download the latest SwiftOnSecurity config file for Sysmon and write it to Wazuh agent shared directory.
# This is only to seed it so that the install process works even if the official and perhaps localized file hasn't propagated down from Wazuh manager yet.
echo "Downloading $SysmonConfSource as sysmonconfig.xml"
$count = 0
$success = $false;
do{
    try{
        Invoke-WebRequest -Uri "$SysmonConfSource" -OutFile "C:\Program Files (x86)\ossec-agent\shared\sysmonconfig.xml"
        $success = $true
    }
    catch{
        Write-Output "Next attempt in 10 seconds"
        Start-sleep -Seconds 10
    }  
    $count++    
}until($count -eq 6 -or $success)
if(-not($success)){exit}

# Wipe any former install of Sysmon and install the just-downloaded version, referencing the downloaded config file to be deployed.
echo "Removing old Sysmon if present"
Start-Process -FilePath C:\Progra~2\sysmon-wazuh\Sysmon.exe -ArgumentList "-u" -Wait -WindowStyle 'Hidden'
echo "Installing Sysmon"
Start-Process -FilePath C:\Progra~2\sysmon-wazuh\Sysmon.exe -ArgumentList "-i","c:\progra~2\ossec-agent\shared\sysmonconfig.xml","-accepteula" -Wait -WindowStyle 'Hidden'

# Write the active-response script reload-sysmon.cmd to the Wazuh AR directory so that it can be run when new Sysmon configs arrive to import them.
echo "Writing reload-sysmon.cmd"
$ScriptToWrite = @"
@ECHO OFF
FOR /F "TOKENS=1* DELIMS= " %%A IN ('DATE/T') DO SET DATE=%%B
FOR /F "TOKENS=1* DELIMS= " %%A IN ('TIME/T') DO SET TIME=%%A
ECHO %DATE% %TIME% %0 %1 %2 %3 %4 %5 %6 %7 %8 %9 >> C:\Progra~2\ossec-agent\active-response\active-responses.log
c:\progra~2\sysmon-wazuh\Sysmon.exe -c c:\progra~2\ossec-agent\shared\sysmonconfig.xml
ECHO. >> C:\Progra~2\ossec-agent\active-response\active-responses.log
"@
$ScriptToWrite | Out-File -FilePath C:\Progra~2\ossec-agent\active-response\bin\reload-sysmon.cmd -Encoding ASCII


#
# osquery
#

# Remove osquery if present
echo "Removing old osquery if present"
Uninstall-Package -Name "osquery" -erroraction 'silentlycontinue' | out-null

# Download the osquery MSI
echo "Downloading $OsquerySource"
$count = 0
$success = $false;
do{
    try{
        Invoke-WebRequest -Uri $OsquerySource -OutFile osquery.msi
        $success = $true
    }
    catch{
		if ($count -lt 5) {
			Write-Output "Download attempt failed.  Will retry 10 seconds."
		} else {
			Write-Output "Download attempt still failed.  Giving up and aborting the installation..."
			exit
		}
		Start-sleep -Seconds 10
    }  
    $count++    
}until($count -eq 6 -or $success)

# Install osquery
Start-Process -FilePath osquery.msi -ArgumentList "/q" -Wait -WindowStyle 'Hidden'
rm .\osquery.msi

# Remove the Windows service that the MSI installed which we do not want
echo "Removing the osquery Windows service so Wazuh agent can manage it instead"
Start-Process -FilePath C:\Progra~1\osquery\osqueryd\osqueryd.exe -ArgumentList "--uninstall" -Wait -WindowStyle 'Hidden'

#
# Last Wazuh Agent steps
#

# Start up the Wazuh agent service
echo "Starting up the Wazuh agent"
net start wazuh

# After 60 seconds confirm 
echo "Pausing for one minute to allow agent to connect to manager"
Start-Sleep -s 60 
echo "If you see status='connected' below then the agent is successfully in contact with the manager."
find `"status=`" C:\progra~2\ossec-agent\ossec-agent.state
echo ""
