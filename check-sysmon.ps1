#
# check-sysmon.ps1
# developed by Branch Network Consulting, LLC
#
# Determines if Sysmon needs to be installed/upgraded to the target version on a system.
# To be run on Windows agents in "sysmon" agent group from ossec-agent\custbin\ by a local "check-sysmon" Wazuh command on every agent restart
#
# <ossec_config>
#   <localfile>
#      <log_format>command</log_format>
#      <alias>check-sysmon</alias>
#      <command>PowerShell.exe -ExecutionPolicy Bypass -File custbin/check-sysmon.ps1</command>
#      <frequency>86400</frequency>
#   </localfile>  
# </ossec_config>
#
# Outputs "0" if no target sysmon version defined in sysmon-target-version.txt.
# Outputs "0" if Sysmon is already loaded and at the target version.
# Outputs the target version number to indicate Sysmon state needs to be remediated on this host.
#
# A Wazuh rule watching for non-zero "check-sysmon" command output should trip a custom Wazuh integration to push a custom WPK corresponding 
# to the reported target version, to install Sysmon and this script and the related Wazuh command to the agent.
#

# Is Sysmon or Sysmon64 expected for this OS environment?
If ([Environment]::Is64BitOperatingSystem) {
    $SysmonInstallerFile="Sysmon64.exe"
} else {
    $SysmonInstallerFile="Sysmon.exe"
}

# Discover which Program Files directory would contain Wazuh's program directory, with a 64bit vs 32bit check.
If ([Environment]::Is64BitOperatingSystem) {
    $PFPATH="C:\Program Files (x86)"
} else {
    $PFPATH="C:\Program Files"
}

if ( -not (Test-Path -LiteralPath "$PFPATH\ossec-agent\shared\sysmon-target-version.txt") ) {
    Write-Host "0"
    exit
}

$InstalledInstallerVersion = [String]([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$Env:windir\$SysmonInstallerFile").FileVersion)
$InstalledDriverVersion = [String]([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$Env:windir\SysmonDrv.sys").FileVersion)
$TargetSysmonVersion = (Get-Content "$PFPATH\ossec-agent\shared\sysmon-target-version.txt" -TotalCount 1).Trim()

# Write fail string and exit if fltmc.exe indicates Sysmon is not loadded under default name (SysmonDrv)
if ( -not ( ( (fltMC.exe) | Out-String) -match 'SysmonDrv' ) ) {
    Write-Host "$TargetSysmonVersion" -NoNewline
    exit
}

if ( ($InstalledInstallerVersion -ne $TargetSysmonVersion) -or ($InstalledDriverVersion -ne $TargetSysmonVersion) ) {
    Write-Host "$TargetSysmonVersion" -NoNewline
    exit
}

# If Sysmon run/version state is compliant, then before outputting success code of "0", re-hash shared sysmonconfig.xml and compared it to 
# locally stored hash file sysmonconfig.md5.  If the hash file is missing or does not match the re-hashed value, then make Sysmon reload
# the config and lastly write the re-hashed value to sysmonconfig.md5
if ( (Test-Path -LiteralPath "$PFPATH\ossec-agent\sysmonconfig.md5") ) {
	$hashInUse = (Get-Content "$PFPATH\ossec-agent\sysmonconfig.md5" -TotalCount 1).Trim()
} else {
	$hashInUse = "none"
}
$hashLatest = (Get-FileHash "$PFPATH\ossec-agent\shared\sysmonconfig.xml" -Algorithm MD5).Hash
if ( $hashInUse -ne $hashLatest ) {
	& $Env:windir\$SysmonInstallerFile -c "$PFPATH\ossec-agent\shared\sysmonconfig.xml"
	$hashLatest | Out-File -FilePath "$PFPATH\ossec-agent\sysmonconfig.md5" -Encoding ASCII
}

Write-Host "0"
exit
