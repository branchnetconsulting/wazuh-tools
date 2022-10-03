# check-osquery.sh
# developed by Branch Network Consulting, LLC
#
# Determines if Osquery needs to be installed/upgraded to the target version on a system.
# To be run on Windows agents in "osquery" agent group from /var/ossec/custbin/ by a local "check-osquery" Wazuh command on every agent restart
#
# <ossec_config>
#   <localfile>
#      <log_format>command</log_format>
#      <alias>check-osquery</alias>
#      <command>custbin/check-osquery.sh</command>
#      <frequency>86400</frequency>
#   </localfile>  
# </ossec_config>
#
# Outputs "0" if no target Osquery version defined in osquery-target-version.txt.
# Outputs "0" if Osquery is already loaded and at the target version.
# Outputs the target version number to indicate Osquery state needs to be remediated on this host.
#
# A Wazuh rule watching for non-zero "check-osquery" command output should trip a custom Wazuh integration to push a custom WPK corresponding 
# to the reported target version, to install Osquery and this script and the related Wazuh command to the agent.
#
# Is Osquery expected for this OS environment?

if [[ $OSTYPE == 'darwin'* ]]; then
    OS=Darwin
else
    if [[ -f /etc/os-release && `grep -i debian /etc/os-release` ]]; then
        OS=Linux
        LinuxFamily="deb"
    else
        OS=Linux
        LinuxFamily="rpm"
    fi
fi

if [ ! -f /var/ossec/etc/shared/osquery-target-version ]; then
    echo "0"
	  exit
fi

InstalledVersion=`/usr/bin/osqueryi --csv "select version from osquery_info;" | tail -n1`
TargetOsqueryVersion=`cat /var/ossec/etc/shared/osquery-target-version`

if [ ! $InstalledVersion = $TargetOsqueryVersion ]; then
    echo "$TargetOsqueryVersion,$OS,$LinuxFamily"
    #exit
fi

echo "0"
exit
