#
#Script for the complete removal of Wazuh Suite installed by BNC
#

# Remove Wazuh agent
echo "Stopping Wazuh Agent"
net stop wazuh
echo "Uninstalling Wazuh Agent"
Uninstall-Package -Name "Wazuh Agent" -erroraction 'silentlycontinue' | out-null
Remove-Item "C:\Progra~2\ossec-agent" -recurse -erroraction 'silentlycontinue'

echo "Removing Sysmon if present..."
Start-Process -FilePath C:\Progra~2\sysmon-wazuh\Sysmon.exe -ArgumentList "-u" -Wait -WindowStyle 'Hidden'
Remove-Item "C:\Progra~2\sysmon-wazuh" -recurse -erroraction 'silentlycontinue'

# Removing all traces of osquery (making sure wazuh agent is not running before blowing away osquery dir)
echo "Removing Osquery if present..."
net stop wazuh
Uninstall-Package -Name "osquery" -erroraction 'silentlycontinue' | out-null
Remove-Item "C:\Progra~1\osquery" -recurse -erroraction 'silentlycontinue'

echo "checking for leftover files/folders"
if (-not (Test-Path -LiteralPath C:\Progra~2\ossec-agent)) {
  echo "Confirmed: All Wazuh files have been deleted"
} else {
  echo "Manual deletion of c:\Program Files (x86)\ossec-agent may be required."
}

if (-not (Test-Path -LiteralPath C:\Progra~2\sysmon-wazuh)) {
  echo "Confirmed: All Wazuh related Sysmon files have been deleted"
} else {
  echo "Manual deletion of c:\Program Files (x86)\sysmon-wazuh directory and files may be required."
}

if (-not (Test-Path -LiteralPath C:\Progra~1\osquery)) {
  echo "Confirmed: All Wazuh related Osquery files have been deleted"
} else {
  echo "Manual deletion of c:\Program Files\osquery directory and files may be required."
}

if (-not (Test-Path -LiteralPath C:\Progra~2\ossec-agent) -Or -not (Test-Path -LiteralPath C:\Progra~2\sysmon-wazuh) -Or (Test-Path -LiteralPath C:\Progra~1\osquery)) {
  echo "The BNC suite of Wazuh and sub-agents has been uninstalled and remnants have been cleaned up"
} else {
  echo "The BNC suite of Wazuh and sub-agents has been uninstalled but requires some manual cleanup"
}
  exit
