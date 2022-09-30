#
# merge-wazuh-conf.ps1
# version 1.0
# by Kevin Branch (Branch Network Consulting, LLC)
#
# This builds and applies a fresh /var/ossec/etc/ossec.conf from a merge of all /var/ossec/etc/conf.d/*.conf files, with automatic revertion to the previous ossec.conf in the event that Wazuh Agent fails to restart or reconnect with the newer merged version of ossec.conf.
# It is intended to be run automatically by Wazuh Agent itself via a locally defined command-type localfile section invoking it at ossec-agent custbin/merge-wazuh-conf.sh.
# This is part of accomodating the use of custom WPKs to securely distribute and/or invoke new scripts and to distribute and apply new config sections to be merged into ossec.conf, especially ones involving formerly "remote" commands.
#
# This script should be located and executed in /var/ossec/etc/custbin/merge-wazuh-conf.sh.  
# The following must be part of /var/ossec/etc/ossec.conf to ensure this script is run daily and at each agent restart.
#
# <ossec_config>
#   <localfile>
#      <log_format>command</log_format>
#      <alias>merge-wazuh-conf</alias>
#      <command>custbin/merge-wazuh-conf.sh</command>
#      <frequency>86400</frequency>
#   </localfile>  
# </ossec_config>
#
# Log entries written to Application log with source BNC-SIEM-Instrumentation:
#
# "Info - merge-wazuh-conf.sh applying new merged ossec.conf and restarting Wazuh agent..."
# "Error - merge-wazuh-conf.sh new ossec.conf appears to prevent Wazuh Agent from starting.  Reverting and restarting..."
# "Info - merge-wazuh-conf.sh reverted ossec.conf and Wazuh agent successfully restarted..."
# "Error - merge-wazuh-conf.sh reverted ossec.conf and Wazuh agent still failed to start."
# "Info - merge-wazuh-conf.sh exited due to a previous failed ossec.conf remerge attempt less than an hour ago."
# "Info - merge-wazuh-conf.sh found ossec.conf up to date with conf.d."
#

# If Wazuh agent conf.d directory is not yet present, then create it and populate it with a 000-base.conf copied from current ossec.conf file.

if  [ ! -d /var/ossec/etc/conf.d ]; then
    mkdir /var/ossec/etc/conf.d
    cp /var/ossec/etc/ossec.conf" /var/ossec/etc/conf.d/000-base.conf"
    # If the newly generated 000-base.conf (from old ossec.conf) is missing the merge-wazuh-conf command section, then append it now.
    if [[ ! `grep merge-wazuh-conf /var/ossec/etc/conf.d/000-base.conf 2> /dev/null` ]]; then
        echo "
        <ossec_config>
            <localfile>
                <log_format>command</log_format>
                <alias>merge-wazuh-conf</alias>
                <command>PowerShell.exe -ExecutionPolicy Bypass -File custbin/merge-wazuh-conf.ps1</command>
                <frequency>86400</frequency>
            </localfile>  
        </ossec_config>
        " >> /var/ossec/etc/conf.d/000-base.conf
    fi    
fi

# If there was a failed ossec.conf remerge attempt less than an hour ago then bail out (failed as in Wazuh agent would not start using latest merged ossec.conf) 
# This is to prevent an infinite loop of remerging, restarting, failing, reverting, and restarting again, caused by bad material in a conf.d file.
if [ -f /var/ossec/etc/ossec.conf-BAD ] && [ $((`date +%s` - `stat -c %Y /var/ossec/etc/ossec.conf-BAD`)) -lt 3600 ];then
    logger -t "BNC-SIEM-Instrumentation" "Info - merge-wazuh-conf.ps1 exited due to a previous failed ossec.conf remerge attempt less than an hour ago."
    exit
fi

# Merge conf.d/*.conf into conf.d/config.merged
$files=`ls /var/ossec/etc/conf.d/*.conf`
rm /var/ossec/etc/conf.d/config.merged 2> /dev/null
cat $files > /var/ossec/etc/conf.d/config.merged

# If the rebuilt config.merged file is the same (by MD5 hash) as the main ossec.conf then there is nothing more to do.
hash1=`md5sum /var/ossec/etc/conf.d/config.merged | awk '{print $1}'`
hash2=`md5sum /var/ossec/etc/ossec.conf | awk '{print $1}'`
if [ "$hash1" = "$hash2" ]; then
    #echo "ossec.conf is up to date"
    logger -t "BNC-SIEM-Instrumentation" "Info - merge-wazuh-conf.ps1 found ossec.conf up to date with conf.d."

# However if config.merged is different than ossec.conf, then back up ossec.conf, replace it with config.merged, and restart Wazuh Agent service
else
    #echo "ossec.conf rebuilt from merge of conf.d files"
    logger -t "BNC-SIEM-Instrumentation" "Info - merge-wazuh-conf.ps1 applying new merged ossec.conf and restarting Wazuh agent..."
    cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf-BACKUP
    cp /var/ossec/etc/conf.d/config.merged /var/ossec/etc/ossec.conf
    systemctl stop wazuh-agent
    systemctl start wazuh-agent
    sleep 5
    # If after replacing ossec.conf and restarting, the Wazuh Agent fails to start, then revert to the backed up ossec.conf, restart, and hopefully recovering the service.
    if [[ ! `pgrep -x "wazuh-agent"` ]] || [[ `netstat -nat | grep 1514 | awk -F':' '{print $3}'` =~ ^1514[^\d]+ESTABLISHED ]]; then
        #echo "Wazuh Agent service failed to start with the newly merged ossec.conf!  Reverting to backed up ossec.conf..."
		logger -t "BNC-SIEM-Instrumentation" "Error - merge-wazuh-conf.ps1 new ossec.conf appears to prevent Wazuh Agent from starting.  Reverting and restarting..."
        mv /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf-BAD
        mv /var/ossec/etc/ossec.conf-BACKUP /var/ossec/etc/ossec.conf
		systemctl stop wazuh-agent
		systemctl start wazuh-agent
		sleep 5
        # Indicate if the service was successfully recovered by reverting ossec.conf.
		if [[ ! `pgrep -x "wazuh-agent"` ]] || [[ `netstat -nat | grep 1514 | awk -F':' '{print $3}'` =~ ^1514[^\d]+ESTABLISHED ]]; then
            #echo "Wazuh Agent successfully running with reverted ossec.conf."
			logger -t "BNC-SIEM-Instrumentation" "Info - merge-wazuh-conf.ps1 reverted ossec.conf and Wazuh agent successfully restarted..."
        else
            #echo "Wazuh Agent fails run start with reverted ossec.conf.  Manual intervention required."
			logger -t "BNC-SIEM-Instrumentation" "Error - merge-wazuh-conf.ps1 reverted ossec.conf and Wazuh agent still failed to start."
        fi
    fi
fi
