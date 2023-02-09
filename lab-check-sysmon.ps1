#
# check-sysmon.ps1
#
# This script reports the current state of Sysmon on this system.
# If newer is available, it also makes Sysmon reload its config from the Wazuh shared file.
#

# Prepare to handle 32 and 64 bit OS environment differently.
If ([Environment]::Is64BitOperatingSystem) {
        $PFPATH="C:\Program Files (x86)"
        $SysmonFile="Sysmon64.exe"
} else {
        $PFPATH="C:\Program Files"
        $SysmonFile="Sysmon.exe"
}

# Detemine the installed version of the Sysmon (call it 0 if absent)
if ( Test-Path -LiteralPath "$Env:windir\SysmonDrv.sys" ) {
        $InstalledSysmonVersion = [String]([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$Env:windir\SysmonDrv.sys").FileVersion)
} else {
        $InstalledSysmonVersion = "0"
}

# Read shared target version number of Sysmon from agent group shared directory
$TargetSysmonVersion = (Get-Content "$PFPATH\ossec-agent\shared\sysmon-target-version.txt" -TotalCount 1).Trim()

# Re-hash shared sysmonconfig.xml and compare it to locally stored hash file sysmonconfig.md5.  
# If the hash file is missing or does not match the re-hashed value, then make Sysmon reload
# the config and  write the re-hashed value to sysmonconfig.md5.
if ( (Test-Path -LiteralPath "$PFPATH\ossec-agent\sysmonconfig.md5") ) {
        $hashInUse = (Get-Content "$PFPATH\ossec-agent\sysmonconfig.md5" -TotalCount 1).Trim()
} else {
        $hashInUse = "NA"
}
$hashLatest = (Get-FileHash "$PFPATH\ossec-agent\shared\sysmonconfig.xml" -Algorithm MD5).Hash
if ( $hashInUse -ne $hashLatest ) {
        & $Env:windir\$SysmonFile -c "$PFPATH\ossec-agent\shared\sysmonconfig.xml" | out-null
        $hashLatest | Out-File -FilePath "$PFPATH\ossec-agent\sysmonconfig.md5" -Encoding ASCII
        Write-Host "$TargetSysmonVersion,$InstalledSysmonVersion,CONFIG-RELOADED-$hashLatest"
} else {
        Write-Host "$TargetSysmonVersion,$InstalledSysmonVersion,CONFIG-CURRENT-$hashInUse"
}
