# check-osquery.ps1
# developed by Branch Network Consulting, LLC
#
# Determines if Osquery needs to be installed/upgraded to the target version on a system.
# To be run on Windows agents in "osquery" agent group from ossec-agent\custbin\ by a local "check-osquery" Wazuh command on every agent restart
#
# <ossec_config>
#   <localfile>
#      <log_format>command</log_format>
#      <alias>check-osquery</alias>
#      <command>PowerShell.exe -ExecutionPolicy Bypass -File custbin/check-osquery.ps1</command>
#      <frequency>86400</frequency>
#   </localfile>  
# </ossec_config>
#
# Outputs "0" if no target Osquery version defined in osquery-target-version.txt.
# Outputs "0" if Osquery is already loaded and at the target version.
# Outputs "0" if this is a 32-bit Windows installation.  There is no 32-bit version of Osquery.
# Outputs the target version number to indicate Osquery state needs to be remediated on this host.
#
# A Wazuh rule watching for non-zero "check-osquery" command output should trip a custom Wazuh integration to push a custom WPK corresponding 
# to the reported target version, to install Osquery and this script and the related Wazuh command to the agent.
#
# Is Osquery expected for this OS environment?

$PFPATH="C:\Program Files (x86)"

if ( -not ([Environment]::Is64BitOperatingSystem) ) {
    echo "0"
    exit
}

if ( -not (Test-Path -LiteralPath "$PFPATH\ossec-agent\shared\osquery-target-version.txt") ) {
    echo "0"
    exit
}

$InstalledVersion = & 'C:\Program Files\osquery\osqueryi.exe' --csv 'select version from osquery_info;' | select -Last 1
$TargetOsqueryVersion = (Get-Content "$PFPATH\ossec-agent\shared\osquery-target-version.txt" -TotalCount 1).Trim()

if ($InstalledVersion -ne $TargetOsqueryVersion) {
    echo "$TargetOsqueryVersion"
    exit
}

Start-Sleep 10
if ((get-process "osqueryd" -ErrorAction SilentlyContinue) -eq $Null) {
    echo "$TargetOsqueryVersion"
    exit
}

echo "0"
exit
