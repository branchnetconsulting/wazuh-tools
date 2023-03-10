#
# check-sysmon.ps1
#
# This script reports the installed version of Sysmon on this system, and makes Sysmon reload its config from the Wazuh shared file if a newer config is available.
#

# Detemine the installed version of the Sysmon (call it 0 if absent)
if ( Test-Path -LiteralPath "$Env:windir\SysmonDrv.sys" ) {
        $InstalledSysmonVersion = [String]([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$Env:windir\SysmonDrv.sys").FileVersion)
} else {
        $InstalledSysmonVersion = "0"
}

# Re-hash shared sysmonconfig.xml and compare it to locally stored hash file sysmonconfig.md5.  
# If the hash file is missing or does not match the re-hashed value, then make Sysmon reload
# the config and  write the re-hashed value to sysmonconfig.md5.
if ( (Test-Path -LiteralPath "C:\Program Files (x86)\ossec-agent\sysmonconfig.md5") ) {
        $hashInUse = (Get-Content "C:\Program Files (x86)\ossec-agent\sysmonconfig.md5" -TotalCount 1).Trim()
} else {
        $hashInUse = "NA"
}
$hashLatest = (Get-FileHash "C:\Program Files (x86)\ossec-agent\shared\sysmonconfig.xml" -Algorithm MD5).Hash
if ( $hashInUse -ne $hashLatest ) {
        & $Env:windir\Sysmon.exe -c "C:\Program Files (x86)\ossec-agent\shared\sysmonconfig.xml" | out-null
        $hashLatest | Out-File -FilePath "C:\Program Files (x86)\ossec-agent\sysmonconfig.md5" -Encoding ASCII
        Write-Host "$InstalledSysmonVersion,CONFIG-RELOADED,$hashLatest"
} else {
        Write-Host "$InstalledSysmonVersion,CONFIG-CURRENT,$hashInUse"
}
