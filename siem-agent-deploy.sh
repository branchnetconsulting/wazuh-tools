#!/bin/bash

#
# siem-agent-deploy.sh
#
# Version 10.2
# Changes in this version
# -----------------------
#
# Updated default Wazuh Version to 4.11.2
# Adding gpg keys for rpm and apt
#
# -----------------------
# 
#
# This script is for checking and/or installing the Wazuh agent on Linux/MacOs systems.  It can directly install or uninstall it, conditionally 
# install it, or simply check to see if installation/reinstallation is needed.  The Wazuh agent for Linux/MacOS presently includes Wazuh agent 
# integrated for centralized configuration and reporting via the Wazuh manager.  It also defaults to signalling to the Wazuh manager to push 
# the Osquery management WPK to this agent, which can be optionally excluded.
#
# Depending on the use case, this script can be called singly on a one time or periodic basis to conditionally install/reinstall the agent.  
# Alternatively, a higher level configuration management system like Puppet could first call this script just to check if 
# installation/reinstallation is called for, and based on the exit code it receives, conditionally call this script a second time to  
# explicitly install/reinstall the agent.
#
# Deployment will install Wazuh agent on Debian-based and Redhat-based systems, as well as MacOS (tested on MacOS 13.2). 
#
# After preserving the working Wazuh agent registration key if present, if the -Install flag is used, the Wazuh agent is completely purged and 
# then reinstalled.  The Wazuh agent self-registration process is included, but will be skipped if an existing working registration can be recycled.
# If the -Install flag is not set and 1) the agent is connected to a manager and 2) the target groups appear at the beginning of the list of 
# current groups, the checkAgent function will find no deployment/re-deployment is needed and will bail with exit code 0. This will keep the same 
# agent id and agent name associated with the agent prior to the script being run. Groups that were manually added via the Wazuh interface will not 
# be used for comparison purposes, but will still be applied if the agent registration is recycled.  If the script-defined target group membership 
# list, including groups added by the -ExtraGroups parameter, are not listed in order at the beginning of the list of discovered current groups for
# the agent, but the agent is connected to a manager, the script will re-register without an uninstall and reinstall of Wazuh. 
#
# If the call to this script is deemed broken, or either the Wazuh Manager connect port or registration port are unresponsive to a probe, an 
# exit code of 2 will be returned.
#
# By default, the script will install a minimum default version of Wazuh as hard-coded in the script.  However, there are two optional ways to 
# override this hard-coded parameter; 1) add a txt record to a domain you control that includes the version number of the Wazuh agent you wish 
# to install or 2) specify a minimum version in the command call.  After the install, the intention is for the automated agent upgrade cron 
# call to upgrade all connected agents to the version of the Wazuh Manager it is connected to. 
#
# The default exit code is 0.
# Exit code of 1 from the checkAgent function indicates a redeploy/re-registeration is needed. This exit code is only used if the -CheckOnly flag is set
# on the command line.
# Exit code of 2 indicates that an error occurred or there was a problem with the command line parameters.
# 
# Is the agent presently really connected to the Wazuh manager?
# Is the agent currently a member of all intended Wazuh agent groups?
#
# Required Parameters:
#
# -Mgr				The IP or FQDN of the Wazuh manager for ongoing agent connections.
# -RegPass     			Password for registration with Wazuh manager (put in quotes).
#
# Optional Parameters:
#
# -Mgr2				The IP or FQDN of an optional second Wazuh manager for agents to connect to.
# -RegMgr			Specific manager to register with
# -AgentName			Name under which to register this agent in place of locally detected Windows host name.
# -ExtraGroups  		Additional groups beyond the default groups that are applied by the script, which include:  
#				linux, linux-local, osquery, osquery-local. 
# -VerDiscAddr			The Version Discovery Address where a .txt record has been added with the target version of the Wazuh agent to install.
# -InstallVer			The version of the Wazuh Agent to install.
# -DefaultInstallVer 		Command line paramenter and a preset within the script that is used as a last resort.
# -DownloadSource	 	Static download path to fetch Wazuh agent installer.  Overrides WazuhVer value.
# -SkipOsquery  		Flag to not signal the Wazuh manager to push managed Osquery WPK to this system. (Default is to not skip this.)
# -Install			Flag to skip all checks and force installation
# -Uninstall			Flag to uninstall Wazuh agent only 
# -CheckOnly			Flag to only run checks to see if installation is current or in need of deployment
# -LBprobe			Flag to additionally check for manager connectivity with an agent-auth probe to avoid being fooled by a load balancer that 
# 				handshakes even when service down.
# -Debug			Flag to show debug output
# -help				Show command line options

# Sample way to fetch and use this script:
#
# curl https://raw.githubusercontent.com/branchnetconsulting/wazuh-tools/master/siem-agent-deploy.sh > siem-agent-deploy.sh
# chmod 744 siem-agent-deploy.sh
# ./siem-agent-deploy.sh -Mgr "siem.company.com" -RegMgr "{Manager DNS or IP}" -RegPass "{Your_Password}" -ExtraGroups "{Your_comma_separated_group_list}" -Debug
#

#
# Please note that the following agent groups are assumed to exist by this script and should be added to the Wazuh Manager PRIOR to any use of this script.
#
# linux,linux-local,osquery,osquery-local
# 

function show_usage() {
	LBLU='\033[1;34m'
	NC='\033[0m'
	printf "\nCommand syntax:\n	$0 \n	[-Mgr ${LBLU}WAZUH_MANAGER${NC}]\n	[-RegMgr ${LBLU}WAZUH_REGISTRATION_MANAGER${NC}]\n	[-RegPass \"${LBLU}WAZUH_REGISTRATION_PASSWORD${NC}]\"\n	[-DefaultInstallVer ${LBLU}DEFAULT_WAZUH_VERSION${NC}]\n	[-DownloadSource ${LBLU}WAZUH_AGENT_DOWNLOAD_URL${NC}]\n	[-AgentName ${LBLU}WAZUH_AGENT_NAME_OVERRIDE${NC}]\n	[-ExtraGroups ${LBLU}LIST_OF_EXTRA_GROUPS${NC}]\n	[-VerDiscAddr ${LBLU}VERSION_DISCOVERY_ADDRESS${NC}]\n	[-SkipOsquery]\n	[-Install]\n	[-Uninstall]\n	[-CheckOnly]\n	[-Debug]\n	[-help]\n\n"
	printf "Example:\n	$0 -Mgr ${LBLU}siem.company.org${NC} -RegPass ${LBLU}\"h58fg3FS###12\"${NC} -DefaultInstallVer ${LBLU}4.5.4${NC} -ExtraGroups ${LBLU}server,office${NC}\n\n"
}

function check_value() {
	if [[ "$1" == "" || "$1" == "-"* ]]; then
		ParmFailure=1
	fi
}

# Function for probing the Wazuh agent connection and Wazuh agent self-registration ports on the manager(s).
# returns 0 if probe succeeds, 2 if probe fails for any reason
function tprobe() {
	if [[ "$OStype" == "linux" ]]; then
		if [ $Debug == 1 ]; then echo "Preparing to probe $1 on port $2..."; fi
		if [[ `echo $1 | grep -E "^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"` ]]; then
			if [ $Debug == 1 ]; then echo "$1 appears to be an IP number."; fi
			tpr_ip=$1
		else
			if [ $Debug == 1 ]; then echo "Looking up IP for host $1..."; fi
			tpr_ip=`getent ahostsv4 $1 | awk '{ print $1 }' | head -n1`
		fi
		if [ "$tpr_ip" == "" ]; then
			if [ $Debug == 1 ]; then echo "*** Failed to find IP for $1."; fi
			return 2
		fi
		if [ $Debug == 1 ]; then echo "Probing $tpr_ip:$2..."; fi
		echo > /dev/tcp/$tpr_ip/$2 &
		sleep 2
		if [[ `ps auxw | awk '{print $2}' | egrep "^$!"` ]]; then
			if [ $Debug = 1 ]; then echo "Probe failed!"; fi
			kill $!
			return 2
		fi
		if [ $Debug == 1 ]; then echo "Success!"; fi
		return 0
	elif [[ "$OStype" == "macos" ]]; then
		if [ $Debug == 1 ]; then echo "Probing $1 on port $2..."; fi
		if [[ `nc -z -G1 $1 $2 2>&1 | grep succeeded` ]]; then 
			if [ $Debug == 1 ]; then echo "Success!"; fi
		else
			if [ $Debug = 1 ]; then echo "Probe failed!"; fi
			return 2
		fi
		return 0
	else 
		if [ $Debug = 1 ]; then echo "Probe impossible for unknown/unsupported OS type!"; fi
		return 2
	fi
}

#
# Write BNC's Custom pem file
#
function writePEMfile() {
echo "-----BEGIN CERTIFICATE-----
MIIDNzCCAh+gAwIBAgIURDCxvmgAH12XqdEdQH/CKgy0+CIwDQYJKoZIhvcNAQEL
BQAwKzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAklOMQ8wDQYDVQQKDAZCTkMgQ0Ew
HhcNMjIxMDAzMjExNzU5WhcNMzIwOTMwMjExNzU5WjArMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCSU4xDzANBgNVBAoMBkJOQyBDQTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBANpnhmd+2mUHCjzqvwHx6KeYSaQa2IFNXoQHlj70vMSBm7dH
GebtQSCF1W3XlRwCW6lK6MitSnPSx8D9ct8QvI7cWYvcjZ1OcY3Vv69rfM5akqi4
J1wlWn2HkLmoEdoMwNAQD9c+3XCS9KRC6VcIW7XH+029iTisPNP+X1vFeFCyjz68
SxpL7Ili5GrcDaCWD7Rw7fZjkyTIOrm80vAVGPuXMpSYbdFCwk12j0TQuVovg9bG
b0ykvZBuNrhzfw/KVoxNmsnagZ1gZgMyRJFaje2RmwQu719lu+qoVunzoMZnt/bj
WlLvPENSrYvjhO7+LEVE+uHPgZb5IhAM3GTXpQECAwEAAaNTMFEwHQYDVR0OBBYE
FPT8KA/lCLNFutMi+d3RVX8gCpBzMB8GA1UdIwQYMBaAFPT8KA/lCLNFutMi+d3R
VX8gCpBzMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEdHaQzB
4t6ICDqaoClIlukZPnPOBX3vIaXSTucdX5s0bX0wGNngG+FKM7Ka/jY51YyfCFOr
6J6v0GSIFmTeOX/G4zoy+daxd1sIkMq16urBHxWepanhKmM2UnIrVEqaD2Jjgt30
yuIVJyENaCrXhdH82HndaVEUR8aGnEVUmgPpg+9pRAh8sQUu7LCENI+HP+uaa29c
e1A3jj1X98UOy+58chxEHtyaZy06v3vz4UNWgJf/LGBMT7wO3c8TsTT5KmgHR460
zraxbhmzb4JAji0bZuYlldSjhizRCpJjroFjWHluDUa9Oqi5La52o+rpRVwT53bY
O7bM4haWNBQkxEU=
-----END CERTIFICATE-----
" > $WazPath/etc/bnc_wpk_root.pem
chown root:wazuh $WazPath/etc/bnc_wpk_root.pem
}

#
# Write merge-wazuh-conf.sh to scripts directory
#
function writeMergeScript() {
mkdir $WazPath/scripts 2> /dev/null
chown root:wazuh $WazPath/scripts

IFS='' read -r -d '' Script <<"EOL"
#!/bin/bash
#
# merge-wazuh-conf:
# version 1.0
# by Kevin Branch (Branch Network Consulting, LLC)
#
# This builds and applies a fresh $WazPath/etc/ossec.conf from a merge of all $WazPath/etc/conf.d/*.conf files, with automatic revertion to the previous ossec.conf in the event that Wazuh Agent fails to restart or reconnect with the newer merged version of ossec.conf.
# It is intended to be run automatically by Wazuh Agent itself via a locally defined command-type localfile section invoking it at ossec-agent scripts/merge-wazuh-conf:.
# This is part of accomodating the use of custom WPKs to securely distribute and/or invoke new scripts and to distribute and apply new config sections to be merged into ossec.conf, especially ones involving formerly "remote" commands.
#
# This script should be located and executed in /var/scripts/merge-wazuh-conf:.
# The following must be part of $WazPath/etc/ossec.conf to ensure this script is run daily and at each agent restart.
#
# <ossec_config>
#	<localfile>
#	<log_format>command</log_format>
#	<alias>merge-wazuh-conf</alias>
#	<command>scripts/merge-wazuh-conf.sh</command>
#	<frequency>86400</frequency>
#	</localfile>
# </ossec_config>
#
# Log entries written to Application log with source Wazuh-Modular:
#
# "Information(10000)	- merge-wazuh-conf: applying new merged ossec.conf and restarting Wazuh agent..."
# "Error(10001)			- merge-wazuh-conf: New ossec.conf appears to prevent Wazuh Agent from starting.  Reverting and restarting..."
# "Information(10002)	- merge-wazuh-conf: reverted ossec.conf and Wazuh agent successfully restarted..."
# "Error(10003)			- merge-wazuh-conf: reverted ossec.conf and Wazuh agent still failed to start"
# "Information(10004)	- merge-wazuh-conf: exited due to a previous failed ossec.conf remerge attempt less than an hour ago"
# "Information(10005)	- merge-wazuh-conf: ossec.conf already up to date"
# "Information(10006)	- merge-wazuh-conf: skipped due to script already running"
#

# Determine type of OS (Linux vs MacOS)
if [[ -f /etc/os-release ]]; then
	OStype="linux"
	WazPath="/var/ossec"
	STATPARMS="-c%Y"
elif [[ "`sysctl kern.version 2> /dev/null | grep Darwin`" ]]; then
	OStype="macos"
	WazPath="/Library/Ossec"
	STATPARMS="-f%m"
else	
	echo "Unable to determine what OS is running on this system.  Only Linux and MacOS are supported."
	exit
fi

# If Wazuh agent conf.d directory is not yet present, then create it and populate it with a 000-base.conf copied from current ossec.conf file.
if  [ ! -d $WazPath/etc/conf.d ]; then
	mkdir $WazPath/etc/conf.d 2> /dev/null
	chown -R root:wazuh $WazPath/etc/conf.d 2> /dev/null
	cp $WazPath/etc/ossec.conf $WazPath/etc/conf.d/000-base.conf 2> /dev/null
	# If the newly generated 000-base.conf (from old ossec.conf) is missing the merge-wazuh-conf command section, then append it now.
	if [[ ! `grep merge-wazuh-conf $WazPath/etc/conf.d/000-base.conf 2> /dev/null` ]]; then
		echo "" >> $WazPath/etc/conf.d/000-base.conf
		echo "
<ossec_config>
	<localfile>
		<log_format>command</log_format>
		<alias>merge-wazuh-conf</alias>
		<command>scripts/merge-wazuh-conf:</command>
		<frequency>86400</frequency>
	</localfile>
</ossec_config>
		" >> $WazPath/etc/conf.d/000-base.conf
	fi
fi
# If there was a failed ossec.conf remerge attempt less than an hour ago then bail out (failed as in Wazuh agent would not start using latest merged ossec.conf)
# This is to prevent an infinite loop of remerging, restarting, failing, reverting, and restarting again, caused by bad material in a conf.d file.
if [ -f $WazPath/etc/ossec.conf-BAD ] && [ $((`date +%s` - `stat $STATPARMS $WazPath/etc/ossec.conf-BAD`)) -lt 3600 ];then
	logger -t "Wazuh-Modular" "Error(10004) - merge-wazuh-conf: exited due to a previous failed ossec.conf remerge attempt less than an hour ago"
	exit
fi
# Merge conf.d/*.conf into conf.d/config.merged
files=`cd $WazPath/etc/conf.d; ls *.conf`
rm $WazPath/etc/conf.d/config.merged 2> /dev/null
touch $WazPath/etc/conf.d/config.merged
for file in $files; do
	echo "" >> $WazPath/etc/conf.d/config.merged 2> /dev/null
	echo "<!--" >> $WazPath/etc/conf.d/config.merged 2> /dev/null
	echo "From conf.d/$file" >> $WazPath/etc/conf.d/config.merged 2> /dev/null
	echo "-->" >> $WazPath/etc/conf.d/config.merged 2> /dev/null
	cat $WazPath/etc/conf.d/$file >> $WazPath/etc/conf.d/config.merged 2> /dev/null
	echo "" >> $WazPath/etc/conf.d/config.merged 2> /dev/null
done
# If the rebuilt config.merged file is the same (by MD5 hash) as the main ossec.conf then there is nothing more to do.

if [[ $OStype == "linux" ]]; then
	hash1=`md5sum $WazPath/etc/conf.d/config.merged | awk '{print $1}'`
	hash2=`md5sum $WazPath/etc/ossec.conf | awk '{print $1}'`
elif [[ $OStype == "macos" ]]; then
	hash1=`md5 $WazPath/etc/conf.d/config.merged | awk '{print $4}'`
	hash2=`md5 $WazPath/etc/ossec.conf | awk '{print $4}'`
else
	logger -t "Wazuh-Modular" "Error(10099) - merge-wazuh-conf: unknown local OS"
	exit
fi

if [[ "$hash1" == "$hash2" ]]; then
	#echo "ossec.conf is up to date"
	logger -t "Wazuh-Modular" "Information(10005) - merge-wazuh-conf: ossec.conf already up to date"
# However if config.merged is different than ossec.conf, then back up ossec.conf, replace it with config.merged, and restart Wazuh Agent service
# (unless a previous instance of the merge-wazuh-conf script it already running)
else
	# If another instance of this script is already running, then exit.
	# Since after a merge, this script restarts the Wazuh agent and then waits to confirm
	# the agent comes all the way back up, this will be a common occurrence.
	if [[ "`ps auxw | egrep '/bin/bash \.?/?scripts/merge-wazuh-conf.sh' | grep -v grep | grep -v " sh -c " | wc -l`" -gt 2 ]]; then
		logger -t "Wazuh-Modular" "Information(10006) - merge-wazuh-conf: skipped due to script already running"
		exit
	fi
	# echo "ossec.conf rebuilt from merge of conf.d files"
	logger -t "Wazuh-Modular" "Information(10000) - merge-wazuh-conf: applying new merged ossec.conf and restarting Wazuh agent..."
	sleep 10
	# If deploy-wazuh-modular is already running, then ossec.conf has already been backed up and we should not do it again here.
	if [[ ! `ps auxw | grep '/bin/bash scripts/deploy-wazuh-modular.sh' | grep -v grep` ]]; then
		cp -pr $WazPath/etc/ossec.conf $WazPath/etc/ossec.conf-BACKUP 2> /dev/null
	fi
	cp -pr $WazPath/etc/conf.d/config.merged $WazPath/etc/ossec.conf 2> /dev/null
	chown root:wazuh $WazPath/etc/ossec.conf 2> /dev/null
	
	# Restart the Wazuh agent with separate stop and start steps (works around some bug).
	if [[ `which systemctl 2> /dev/null` ]]; then
		systemctl stop wazuh-agent 
		systemctl start wazuh-agent 
	elif [[ `which service 2> /dev/null` ]]; then
		service wazuh-agent stop
		service wazuh-agent start
	elif [[ "$OStype" == "macos" ]]; then
		$WazPath/bin/wazuh-control stop
		$WazPath/bin/wazuh-control start
	else
		echo "Confused about how to restart Wazuh agent service...  Failing..."
		return 2
	fi

	sleep 30

	if [[ "$OStype" == "linux" ]]; then
		WazEstab=`ss -pn | grep " ESTAB .*:1514 [^0-9]*wazuh-agentd" | wc -l`
	elif [[ "$OStype" == "macos" ]]; then
		WazEstab=`netstat -nat | egrep "[.:]1514\s+ESTABLISHED" | wc -l`
	else
		echo "Confused about how to restart Wazuh agent service...  Failing..."
	fi

	# If after replacing ossec.conf and restarting, the Wazuh Agent fails to start, then revert to the backed up ossec.conf, restart, and hopefully recovering the service.
	if [[ ! `pgrep -x "wazuh-agentd"` ]] || [[ "$WazEstab" -ne 1 ]]; then
		# echo "Wazuh Agent service failed to start with the newly merged ossec.conf!  Reverting to backed up ossec.conf..."
		logger -t "Wazuh-Modular" "Error(10001) - merge-wazuh-conf: New ossec.conf appears to prevent Wazuh Agent from starting.  Reverting and restarting..."
		mv $WazPath/etc/ossec.conf $WazPath/etc/ossec.conf-BAD 2> /dev/null
		mv $WazPath/etc/ossec.conf-BACKUP $WazPath/etc/ossec.conf 2> /dev/null
		chown root:wazuh $WazPath/etc/ossec.conf 2> /dev/null
		# Restart the Wazuh agent with separate stop and start steps (works around some bug).
		if [[ `which systemctl 2> /dev/null` ]]; then
			systemctl stop wazuh-agent 
			systemctl start wazuh-agent 
		elif [[ `which service 2> /dev/null` ]]; then
			service wazuh-agent stop
			service wazuh-agent start
		elif [[ "$OStype" == "macos" ]]; then
			$WazPath/bin/wazuh-control stop
			$WazPath/bin/wazuh-control start
		else
			echo "Confused about how to restart Wazuh agent service...  Failing..."
			return 2
		fi
		sleep 30
		if [[ "$OStype" == "linux" ]]; then
			WazEstab=`ss -pn | grep " ESTAB .*:1514 [^0-9]*wazuh-agentd" | wc -l`
		elif [[ "$OStype" == "macos" ]]; then
			WazEstab=`netstat -nat | egrep "[.:]1514\s+ESTABLISHED" | wc -l`
		else
			echo "Confused about how to restart Wazuh agent service...  Failing..."
		fi
		# Indicate if the service was successfully recovered by reverting ossec.conf.
		if [[ `pgrep -x "wazuh-agentd"` ]] && [[ "$WazEstab" != 1 ]]; then
				# echo "Wazuh Agent successfully running with reverted ossec.conf."
				logger -t "Wazuh-Modular" "Information(10002) - merge-wazuh-conf: reverted ossec.conf and Wazuh agent successfully restarted..."
		else
				# echo "Wazuh Agent fails to start with reverted ossec.conf.  Manual intervention required."
				logger -t "Wazuh-Modular" "Error(10003) - merge-wazuh-conf: reverted ossec.conf and Wazuh agent still failed to start"
		fi
	fi
fi
EOL

echo "$Script" > $WazPath/scripts/merge-wazuh-conf.sh
chown wazuh:wazuh $WazPath/scripts/merge-wazuh-conf.sh
chmod +x $WazPath/scripts/merge-wazuh-conf.sh

# As an interim measure, for MacOS, change the merge-wazuh-conf script to echo to stdout instead of log via logger.
# Once we work out how to have Wazuh collect just "Wazuh-Modular"-tagged logs, this sed step will be removed.
if [[ $OStype == "macos" ]]; then
	sed -imerge-fixup 's/logger -t/echo/g' $WazPath/scripts/merge-wazuh-conf.sh
fi

}

# Checks if agent is in desired state
# return values
#	0 - no failure, but pass back Connected flag and CorrectGroupPrefix value to inform next steps to be taken.  
#		Discovering a need to (re)deploy on account of lack of contact with managr or incorrect agent group membership, is a finding, not a failure.
#	2 - any failure like bad parms, probe failure, unsupported OS
function checkAgent() {

	# Relevant script parameters
	#		
	# -Mgr		The IP or FQDN of the Wazuh manager for ongoing agent connections. (Required)
	# -RegPass	Password for registration with Wazuh manager (put in quotes). (Required)
	# -Mgr2		The IP or FQDN of an optional second Wazuh manager for agents to connect to.
	# -RegMgr	The IP or FQDN of the Wazuh manager for agent registration connection (defaults to $Mgr if not specified)
	# -AgentName	Name under which to register this agent in place of locally detected Windows host name.
	# -ExtraGroups 	Additional groups beyond the default groups that are applied by the script, which include: 
	#		linux, linux-local, osquery, osquery-local. 
	# -SkipOsquery	Flag to not signal the Wazuh manager to push managed Osquery WPK to this system. (Default is to not skip this.)
	# -CheckOnly	Flag to only run checks to see if installation is current or in need of deployment
	# -LBprobe	Flag to additionally check for manager connectivity with an agent-auth probe to avoid being fooled by a load balancer 
	#		that handshakes even when service down.
	# -Debug	Flag to show debug output

	if [ "$Mgr" == "" ]; then
		echo ""; echo "*** Must use '-Mgr' to specify the FQDN or IP of the Wazuh manager to which the agent should be or shall be a connected.."
		show_usage
		return 2
	fi
	# If RegMgr not listed, assume it is the same as Mgr.
	if [ "$RegMgr" == "" ]; then
		if [ $Debug == 1 ]; then echo ""; echo "*** RegMgr was null, so using Mgr for registration."; fi
		RegMgr=$Mgr
	fi

	if [ $Debug == 1 ]; then echo ""; echo "*** Checking connection status of agent."; fi
	Connected=0

	# Determine when agent state file last modified ( 0 means absent ), and then calculate how old it is.
	mtime=`stat $STATPARMS $WazPath/var/run/wazuh-agentd.state 2> /dev/null`
	if [ "$mtime" == "" ]; then
		mtime=0
	fi
	sfage=$((`date +%s`-$mtime))

	# Probe manager ports to confirm it is really reachable.
	# If we are not forcing an install (-Install) and it is fully evident the agent is presently connected to a manager, then no manager probes are necessary.  Otherwise perform them.
	if [[ "$Install" == 0 && "$sfage" -lt 70 && -f $WazPath/var/run/wazuh-agentd.state && `grep "status='connected'" $WazPath/var/run/wazuh-agentd.state 2> /dev/null` ]]; then
		if [ $Debug == 1 ]; then echo "Agent is presently connected to a manager.  Skipping probing of manager..."; fi
	else
		# Confirm the agent checkin and self registration ports on the manager(s) are responsive.
		# If either are not, then (re)deployment is not feasible, so return an exit code 2.
		if [ $Debug == 1 ]; then echo "Probing to see if the manager is reachable..."; fi
		tprobe $Mgr 1514
		tp1_result=$?
		tprobe $RegMgr 1515
		tp2_result=$?
		if [[ "$tp1_result" == 2 || "$tp2_result" == 2 ]]; then
			return 2
		fi
		# If -LBprobe flag set, then additionally confirm the manager is reachable by intentionally attempting an agent-auth with a bad 
		# password to see if "Invalid password" is in the output, which would prove a real Wazuh registration service is reachable on port 1515.
		if [ "$LBprobe" == 1 ] && [ -e $WazPath/bin/agent-auth ]; then 
			if [ $Debug == 1 ]; then echo "Performing a load-balancer-aware check via an agent-auth call to confirm manager is truly reachable..."; fi
			rm /tmp/lbprobe 2> /dev/null
			$WazPath/bin/agent-auth -m $Mgr -p1515 -P bad &> /tmp/lbprobe & 2> /dev/null
			sleep 5
			kill `ps auxw | grep agent-auth | grep -v grep | awk '{print $2}'` 2>/dev/null
			if [[ `grep "Invalid password" /tmp/lbprobe` ]]; then
				if [ $Debug == 1 ]; then echo "LBprobe check succeeded.  Manager is truly reachable."; fi
				rm /tmp/lbprobe 2> /dev/null
			else
				if [ $Debug == 1 ]; then echo "LBprobe check failed.  Manager is not truly reachable..."; fi
				return 2
			fi
		fi
	fi

	#
	# Is the agent presently really connected to a Wazuh manager?  If not, wait a little over a minute and check again.
	# Set the "Connected" flag if success at 1st or 2nd check.
	#
	if [[ $sfage -lt 70 && `grep "status='connected'" $WazPath/var/run/wazuh-agentd.state 2> /dev/null` ]]; then
		if [ $Debug == 1 ]; then echo "The Wazuh agent is connected to a Wazuh manager."; fi
		Connected=1
	elif [ $sfage -lt 70 ]; then
		if [ $Debug == 1 ]; then echo "*** Waiting 70 seconds to see if Wazuh agent is only temporarily disconnected from manager."; fi
		sleep 70
		# Recalculate how old the state file is ( 0 means absent )
		mtime=`stat $STATPARMS $WazPath/var/run/wazuh-agentd.state 2> /dev/null`
		if [ "$mtime" == "" ]; then
			mtime=0
		fi
		sfage=$((`date +%s`-$mtime))		
		if [[ $sfage -lt 70 && `grep "status='connected'" $WazPath/var/run/wazuh-agentd.state 2> /dev/null` ]]; then
			if [ $Debug == 1 ]; then echo "The Wazuh agent is now connected to a Wazuh manager."; fi
			Connected=1
		else
			if [ $Debug == 1 ]; then echo "*** The Wazuh agent is still not connected to a Wazuh manager."; fi
		fi
	else
		if [ $Debug == 1 ]; then echo "*** The Wazuh agent is not connected to a Wazuh manager."; fi
	fi

	#
	# Is the agent group prefix correct?
	# The prefix starts with dynamically determined group names followed by ExtraGroups if specified.  
	# The prefix must match, but additional agent groups found after the prefix in the actual membership list are fine.
	#

	# Establish target agent group list prefix
	if [[ "$OStype" == "linux" ]]; then
		GroupsPrefix="linux,linux-local,"
	elif  [[ "$OStype" == "macos" ]]; then
		GroupsPrefix="macos,macos-local,"
	else
		if [ $Debug == 1 ]; then echo "Unsupported OStype"; fi
		return 2
	fi
	if [ "$SkipOsquery" == 0 ]; then
		GroupsPrefix="${GroupsPrefix}osquery,osquery-local,"
	fi
	GroupsPrefix="${GroupsPrefix}$ExtraGroups"
	TargetGroups=`echo $GroupsPrefix | sed 's/,$//'`

	# Enumerate actual list of agent groups this agent is membered into based on section headers in merged.mg
	if [ -f $WazPath/etc/shared/merged.mg ]; then
		CurrentGroups=`echo \`grep "<\!-- Source file: " $WazPath/etc/shared/merged.mg | cut -d" " -f4 | cut -d/ -f1 \` | sed 's/ /,/g'`
	else
		CurrentGroups="#NONE#"
	fi	

	# Set CorrectGroupPrefix flag is the the actual agent group membership of this agent starts with the target prefix agent group list.
	if [ $Debug == 1 ]; then echo ""; echo  "Current agent groups: $CurrentGroups"; echo "Target agent groups:  $TargetGroups"; fi
	if [[ "$CurrentGroups" =~ ^${TargetGroups}* ]]; then
		if [ $Debug == 1 ]; then echo "*** Expected $TargetGroups matches the prefix in $CurrentGroups."; fi
		CorrectGroupPrefix=1
	else
		if [ $Debug == 1 ]; then echo "Expected $TargetGroups is not at the start of $CurrentGroups."; fi
		CorrectGroupPrefix=0
	fi

	return 0
}

#
# Uninstall Wazuh Agent. As part of the Wazuh Agent uninstall process, ascertain if we might be in a position to recycle the agent
# registration, and set the flag and preserve information accordingly.
#
function uninstallAgent() {
	# Relevant script parameters
	#		
	# -Uninstall		Uninstall without checking and without installing thereafter
	#
	if [ -f $LogFileName ]; then
		cp -p $LogFileName /tmp/
	fi

	# If Wazuh agent is already installed and registered, and this is not an explicit uninstallation call, then note if registration may be
	# recyclable, and if so, preserve client.keys and the agent groups list to accomodate that, plus set the $MightRecycleRegistration flag.
	CorrectAgentName="0"
	if [ "$Uninstall" == "0" ] && [ -s "$RegFileName" ]; then
		# The existing registration will be recyled if:
		#	- the agent is already connected
		#	- the current and target agent name are the same
		#	- the agent group prefix is exactly the same (unless ignored by ommittance of -ExtraGroups)
		if [ $Debug == 1 ]; then echo "Checking for presence of valid registration that could be recycled"; fi
		StateFile="$WazPath/var/run/wazuh-agentd.state"
		MergedFile="$WazPath/etc/shared/merged.mg"
		CurrentAgentName=`cat $RegFileName | awk '{print $2}'`
		if [[ `grep "connected" "$StateFile"` ]] && [ "$CurrentAgentName" == "$AgentName" ]; then
			if [ $Debug == 1 ]; then echo "Registration will be recycled unless there is an agent group mismatch."; fi
			CorrectAgentName="1"
			MightRecycleRegistration="1"
			rm /tmp/client.keys.bnc 2> /dev/null
			rm /tmp/ossec.conf.bnc 2> /dev/null
			cp -p $RegFileName /tmp/client.keys.bnc
			cp -p $ConfigFileName /tmp/ossec.conf.bnc
		else
			if [ $Debug == 1 ]; then echo "Registration will not be recycled."; fi
			MightRecycleRegistration="0"
		fi
	fi  

	# Stop any previous wazuh agent
	systemctl stop wazuh-agent 2> /dev/null
	service wazuh-agent stop 2> /dev/null
	/Library/Ossec/bin/wazuh-control stop 2> /dev/null

	# If Wazuh agent already installed and the -Uninstall or the -Install flag is set or Wazuh agent is not connected to a manager, blow it away.
	if [ "$Install" == "1" ] || [ "$Uninstall" == "1" ] || [ "$Connected" == "0" ]; then
		if [ -f $WazPath/bin/wazuh-agentd ]; then
			if [ "$PkgType" == "deb" ]; then
				if [ $Debug == 1 ]; then echo "Using apt to uninstall existing Wazuh Agent..."; fi
				apt-get -qq purge wazuh-agent 2> /dev/null
			elif [ "$PkgType" == "rpm" ]; then
				if [ $Debug == 1 ]; then echo "Using yum to uninstall existing Wazuh Agent..."; fi
				yum -y erase wazuh-agent 2> /dev/null
			elif [ "$PkgType" == "pkg" ]; then
				if [ $Debug == 1 ]; then echo "Uninstall any existing Wazuh Agent from MacOS..."; fi			
				/bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist
				/bin/rm -f /Library/LaunchDaemons/com.wazuh.agent.plist
				/bin/rm -rf /Library/StartupItems/WAZUH
				/usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent
			fi
			kill -kill `ps auxw | grep "$WazPath/bin" | grep -v grep | awk '{print $2}'` 2> /dev/null
			rm -rf $WazPath 2> /dev/null
		else
			if [ $Debug == 1 ]; then echo "Wazuh Agent not present..."; fi
		fi
		if [ $Debug == 1 ]; then echo "Uninstallation done..."; fi
	else
		if [ $Debug == 1 ]; then echo "Uninstallation not needed..."; fi
	fi
}

#
# Re-register agent and re-install/install Wazuh Agent if needed, recycling an existing registration if possible, otherwise re-registering it.
#
# Deploy function
function installAgent() {
	#
	# Relevant script parameters
	#		
	# -Mgr			IP or FQDN of the Wazuh manager for ongoing agent connections. (Required.)
	# -RegPass		Password for registration with Wazuh manager (put in quotes). (Required.)
	# -Mgr2			The IP or FQDN of an optional second Wazuh manager for agents to connect to.
	# -RegMgr  		The IP or FQDN of the Wazuh manager for agent registration connection (defaults to $Mgr if not specified)
	# -AgentName		Name under which to register this agent in place of locally detected Windows host name.
	# -ExtraGroups  	Additional groups beyond the default groups that are applied by the script, which include:  
	# 			linux, linux-local, osquery, osquery-local. 
	# -VerDiscAddr		The Version Discover Address where a .txt record has been added with the target version of the Wazuh agent to install.
	# -InstallVer		The version of the Wazuh Agent to install.
	# -DefaultInstallVer	Command line paramenter and a preset within the script that is used as a last resort.
	# -DownloadSource	Static download path to fetch Wazuh agent installer.  Overrides WazuhVer value.
	# -SkipOsquery  	Flag to not signal the Wazuh manager to push managed Osquery WPK to this system. (Default is to not skip this.)
	# -Install		Flag to skip all checks and force installation
	# -Debug		Flag to show debug output

	if [ "$Mgr" == "" ]; then
		echo ""; echo "*** Mgr variable must be used to specify the FQDN or IP of the Wazuh manager to which the agent shall retain a connection."
		show_usage
		return 2
	fi

	if [ "$RegPass" == "" ]; then
		echo ""; echo "*** WazuhRegPass variable must be used to specify the password to use for agent registration."
		show_usage
		return 2
	fi

	if [ "$RegMgr" == "" ]; then
		RegMgr="$Mgr"
	fi

	# Attempt install only if forced or agent not connected.
	if [ "$Install" == "1" ] || [ "$Connected" == "0" ]; then
		# If InstallVer is not discovered or set as a parameter, use the DefaultInstaller value either set on command line or is hard-coded in script.
		if [ "$VerDiscAddr" != "" ]; then
			InstallVer=`dig -t txt $VerDiscAddr +short | sed 's/"//g'`
		fi
		if [ "$InstallVer" == "" ]; then
			if [ $Debug == 1 ]; then echo "InstallVer was null, so using DefaultInstallVer value, if present from command line"; fi
			InstallVer=$DefaultInstallVer
		fi

		if [ "$DownloadSource" == "" ]; then
			MajorVer=`echo $InstallVer | awk -F. '{print $1}'`
			if [ "$PkgType" == "deb" ]; then
				DownloadSource="https://packages.wazuh.com/$MajorVer.x/apt/pool/main/w/wazuh-agent/wazuh-agent_$InstallVer-1_amd64.deb"
			elif [ "$PkgType" == "rpm" ]; then
				DownloadSource="https://packages.wazuh.com/$MajorVer.x/yum/wazuh-agent-$InstallVer-1.x86_64.rpm"
			elif [ "$PkgType" == "pkg" ]; then
   				if [[ `uname -m | grep arm64` ]]; then
       					MacArch="arm64"
	   			else
       					MacArch="intel64"
	   			fi
				DownloadSource="https://packages.wazuh.com/$MajorVer.x/macos/wazuh-agent-$InstallVer-1.$MacArch.pkg"
			fi
		fi

		#
		# Wazuh Agent 
		#

		if [ "$PkgType" == "deb" ]; then
			# Wazuh Agent remove/download/install
			if [ $Debug == 1 ]; then echo "Installing Wazuh Agent for deb linux family"; fi
			if [[ ! `which wget 2> /dev/null` ]]; then 
				apt -qq install wget
			fi
			rm -f /tmp/wazuh-agent_$InstallVer-1_amd64.deb 2> /dev/null
			wget -O /tmp/wazuh-agent_$InstallVer-1_amd64.deb $DownloadSource 2> /dev/null
			if [ $Debug == 1 ]; then
				curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
				chmod 644 /usr/share/keyrings/wazuh.gpg
    				dpkg -i /tmp/wazuh-agent_$InstallVer-1_amd64.deb
			else
   				curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
				chmod 644 /usr/share/keyrings/wazuh.gpg 2> /dev/null
				dpkg -i /tmp/wazuh-agent_$InstallVer-1_amd64.deb 2> /dev/null
			fi
			rm -f /tmp/wazuh-agent_$InstallVer-1_amd64.deb 2> /dev/null
			CFG_PROFILE=`. /etc/os-release; echo $ID, $ID\`echo $VERSION_ID | cut -d. -f1\`, $ID\`echo $VERSION_ID\``
		elif [ "$PkgType" == "rpm" ]; then
			# Wazuh Agent remove/download/install
			if [ $Debug == 1 ]; then echo "Installing Wazuh Agent for rpm linux family"; fi
			if [[ ! `which wget 2> /dev/null` ]]; then 
				yum -y install wget
			fi
			rm -f /tmp/wazuh-agent-$InstallVer-1.x86_64.rpm 2> /dev/null
			wget -O /tmp/wazuh-agent-$InstallVer-1.x86_64.rpm $DownloadSource 2> /dev/null
			if [ $Debug == 1 ]; then
				rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    				yum -y install /tmp/wazuh-agent-$InstallVer-1.x86_64.rpm
			else
   				rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH 2> /dev/null
				yum -y install /tmp/wazuh-agent-$InstallVer-1.x86_64.rpm 2> /dev/null
			fi 
			rm -f /tmp/wazuh-agent-$InstallVer-1.x86_64.rpm 2> /dev/null
			CFG_PROFILE=`. /etc/os-release; echo $ID, $ID\`echo $VERSION_ID\``
			if [[ -f /etc/redhat-release && `grep "CentOS release 6" /etc/redhat-release` ]]; then
				CFG_PROFILE="centos, centos6, centos6.`cut -d. -f2 /etc/redhat-release | cut -d\" \" -f1`"
			fi
		elif [ "$PkgType" == "pkg" ]; then
			# Wazuh Agent remove/download/install
			if [ $Debug == 1 ]; then echo "Installing Wazuh Agent for MacOS"; fi
			rm -f /tmp/wazuh-agent-$InstallVer-1.pkg 2> /dev/null
			curl $DownloadSource > /tmp/wazuh-agent-$InstallVer-1.pkg 2> /dev/null
			installer -pkg /tmp/wazuh-agent-$InstallVer-1.pkg -target /
			rm -f /tmp/wazuh-agent-$InstallVer-1.pkg 2> /dev/null
			CFG_PROFILE="darwin`sysctl kern.version | cut -d" " -f5 | cut -d. -f1`"
		else
			if [ $Debug == 1 ]; then echo "Unsupported OStype"; fi
			return 2
		fi

		# Create $WazPath/scripts and write the merge-wazuh-conf.sh file to it, and write bnc_wpk_root.pem file
		writePEMfile
		writeMergeScript
	fi

	# If we can safely skip self registration and just restore the backed up client.keys file, then do so. Otherwise, self-register.
	if [ $Debug == 1 ]; then echo "Stopping Wazuh agent to register and adjust config..."; fi
	systemctl stop wazuh-agent 2> /dev/null
	service wazuh-agent stop 2> /dev/null
	/Library/Ossec/bin/wazuh-control stop 2> /dev/null
	if [ "$MightRecycleRegistration" == "1" ] && [ "$Connected" == "1" ] && [ "$CorrectGroupPrefix" == "1" ]; then
		if [ $Debug == 1 ]; then echo "Restoring backup of client.keys"; fi
		cp -p /tmp/client.keys.bnc $RegFileName 2> /dev/null
	else
		# Register the agent with the manager
		rm $RegFileName
		if [ $Debug == 1 ]; then echo "Registering Wazuh Agent with $RegMgr..."; fi
		if [ "$CorrectGroupPrefix" == "1" ]; then
			$WazPath/bin/agent-auth -m "$RegMgr" -P "$RegPass" -G "$CurrentGroups" -A "$AgentName" &> /tmp/reg.state
		else
			$WazPath/bin/agent-auth -m "$RegMgr" -P "$RegPass" -G "$TargetGroups" -A "$AgentName" &> /tmp/reg.state
		fi
		if [ $Debug == 1 ]; then 
			cat /tmp/reg.state 
		fi
	fi
	if [[ `grep "Duplicate agent" /tmp/reg.state` ]]; then 
		if [ $Debug == 1 ]; then echo "Waiting 45 seconds for Manager to discover agent is disconnected before retrying registration..."; fi
		sleep 45
		if [ "$CorrectGroupPrefix" == "1" ]; then
				$WazPath/bin/agent-auth -m "$RegMgr" -P "$RegPass" -G "$CurrentGroups" -A "$AgentName" &> /tmp/reg.state
		else
			$WazPath/bin/agent-auth -m "$RegMgr" -P "$RegPass" -G "$TargetGroups" -A "$AgentName" &> /tmp/reg.state
		fi
		if [ $Debug == 1 ]; then cat /tmp/reg.state; fi
		if [ ! -s "$RegFileName" ]; then
			cp -p /tmp/client.keys.bnc $RegFileName 2> /dev/null
			cp -p /tmp/ossec.conf.bnc $ConfigFileName 2> /dev/null
			if [[ `which systemctl 2> /dev/null` ]]; then
				systemctl daemon-reload 2> /dev/null
				systemctl enable wazuh-agent 2> /dev/null
				systemctl start wazuh-agent
			elif [[ `which service 2> /dev/null` ]]; then
				chkconfig wazuh-agent on 2> /dev/null
				service wazuh-agent start
			elif [[ "$OStype" == "macos" ]]; then
				$WazPath/bin/wazuh-control start
			else
				if [ $Debug == 1 ]; then echo "Confused about how to start Wazuh agent service...  Failing..."; fi
				return 2
			fi
			if [ $Debug == 1 ]; then echo "Registration failed.  Reverted to previous known working client.keys and restarted Wazuh..."; fi
			return 2	
		fi
	fi

	#
	# Dynamically generate ossec.conf
	#
	if [ "$Mgr2" != "" ]; then
		MgrAdd=`cat << EOF
		<server>
			<address>$Mgr2</address>
			<port>1514</port>
			<protocol>tcp</protocol>
		</server>
EOF`
	fi
	echo "
<!-- Wazuh Modular version 1.0 -->
<ossec_config>
	<client>
		<server>
			<address>$Mgr</address>
			<port>1514</port>
			<protocol>tcp</protocol>
		</server>
$MgrAdd
		<config-profile>$CFG_PROFILE</config-profile>
		<notify_time>10</notify_time>
		<time-reconnect>60</time-reconnect>
		<auto_restart>yes</auto_restart>
		<enrollment>
			<enabled>no</enabled>
		</enrollment>
	</client>
	<logging>
		<log_format>plain</log_format>
	</logging>
	<agent-upgrade>
		<ca_verification>
			<enabled>yes</enabled>
			<ca_store>etc/wpk_root.pem</ca_store>
			<ca_store>etc/bnc_wpk_root.pem</ca_store>
		</ca_verification>
	</agent-upgrade>
	<localfile>
		<log_format>command</log_format>
			<alias>merge-wazuh-conf</alias>
			<command>/bin/bash scripts/merge-wazuh-conf.sh</command>
			<frequency>86400</frequency>
	</localfile>  
</ossec_config>
" > $WazPath/etc/ossec.conf

	#
	# Last Wazuh Agent steps
	#

	# Start up the Wazuh agent service
	if [ $Debug == 1 ]; then echo "Starting up the Wazuh agent..."; fi
	# Restart the Wazuh agent
	if [[ `which systemctl 2> /dev/null` ]]; then
		systemctl daemon-reload 2> /dev/null
		systemctl enable wazuh-agent 2> /dev/null
		systemctl start wazuh-agent 
	elif [[ `which service 2> /dev/null` ]]; then
		chkconfig wazuh-agent on 2> /dev/null
		service wazuh-agent start 
	elif [[ "$OStype" == "macos" ]]; then
		$WazPath/bin/wazuh-control start
	else
		if [ $Debug == 1 ]; then echo "Confused about how to start Wazuh agent service...  Failing..."; fi
		return 2
	fi

	# Do first-time execution of conf.d merge script to build a merged ossec.conf from conf.d files
	$WazPath/scripts/merge-wazuh-conf.sh

	# After 30 seconds confirm agent connected to manager
	if [ $Debug == 1 ]; then echo "Pausing for 30 seconds to allow agent to connect to manager..."; fi
	sleep 30
	if [[ ! `cat $LogFileName | grep "Connected to the server "` ]]; then
		sleep 15
		if [ $Debug == 1 ]; then echo "Pausing for an additional 15 seconds to allow agent to connect to manager..."; fi
		if [[ ! `cat $LogFileName | grep "Connected to the server "` ]]; then
			if [ $Debug == 1 ]; then echo "This agent FAILED to connect to the Wazuh manager."; fi
			return 2
		fi
	fi

	if [ $Debug == 1 ]; then echo "This agent has successfully connected to the Wazuh manager!"; fi
	if [ $Debug == 1 ] && [ "$SkipOsquery" == "0" ]; then echo "Osquery should be automatically provisioned/reprovisioned in an hour or less as needed."; fi
	return 0
}



#
# Main
#

# Set default values for certain named parameters
AgentName=`hostname`
DefaultInstallVer="4.11.2"
SkipOsquery=0
Install=0
Uninstall=0
CheckOnly=0
LBprobe=0
Debug=0

# Process script parameters
ParmFailure=0
while [ "$1" != "" ]; do
	case $1 in
		-Mgr )					shift
								check_value $1
								Mgr=$1
								;;
		-RegMgr )				shift
								check_value $1
								RegMgr=$1
								;;
		-RegPass )				shift
								check_value $1
								RegPass=$1
								;;
		-Mgr2 )					shift
								check_value $1
								Mgr2=$1
								;;
		-AgentName )			shift
								check_value $1
								AgentName="$1"
								;;
		-ExtraGroups )			if [[ "$2" == "" ]]; then
									shift
									ExtraGroups=""
								elif [[ "$2" == "-"* ]]; then
									ExtraGroups=""
								else
									shift
									ExtraGroups="$1"
								fi
								;;
		-VerDiscAddr )			shift
								check_value $1
								VerDiscAddr="$1"
								;;
		-InstallVer )			shift
								check_value $1
								InstallVer="$1"
								;;
		-DefaultInstallVer )	shift
								check_value $1
								DefaultInstallVer="$1"
								;;
		-DownloadSource )		shift
								check_value $1
								DownloadSource="$1"
								;;
		-SkipOsquery )			# no shift
								SkipOsquery=1
								;;
		-Install )				# no shift
								Install=1
								;;
		-Uninstall )			# no shift
								Uninstall=1
								;;
		-CheckOnly )			# no shift
								CheckOnly=1
								;;
		-LBprobe )				# no shift
								LBprobe=1
								;;
		-Debug )				# no shift
								Debug=1
								;;
		-help )					show_usage
								exit 0
								;;
		* )						show_usage
								exit 2
	esac
	shift
done
if [[ "$ParmFailure" == 1 ]]; then
	exit 2
fi

# Determine type of OS (Linux vs MacOS)
if [[ -f /etc/os-release ]]; then
	OStype="linux"
	WazPath="/var/ossec"
	STATPARMS="-c%Y"
elif [[ "`sysctl kern.version 2> /dev/null | grep Darwin`" ]]; then
	OStype="macos"
	WazPath="/Library/Ossec"
	STATPARMS="-f%m"
else	
	if [ $Debug == 1 ]; then echo "Unable to determine what OS is running on this system.  Only Linux and MacOS are supported."; fi
	exit 2
fi

# Bail if Wazuh Manager is installed here.
if [ -f $WazPath/bin/agent_control ]; then
	echo ""; echo "*** This deploy script cannot be used on a system where Wazuh manager is already installed."
	show_usage
	exit 2
fi

# Determine if deb, rpm, or pkg binary package types are to be used here.  For Debian-based, Redhat-based, or MacOS systems, respectively.
if [[ "$OStype" == "linux" ]]; then
	if [[ -f /etc/os-release && `grep -i debian /etc/os-release` ]]; then
		PkgType="deb"
	elif [[ -f /etc/os-release && `egrep -i "(redhat|fedora|oracle|centos)" /etc/os-release` ]]; then
		PkgType="rpm"
	else	
		if [ $Debug == 1 ]; then echo "Unable to determine which Linux flavor is running on this system.  Only Redhat/Fedora and Debian/Ubuntu families are supported."; fi
		exit 2
	fi
elif [[ "$OStype" == "macos" ]]; then
	PkgType="pkg"
else	
	if [ $Debug == 1 ]; then echo "Unexpected failure during OS detection."; fi
	exit 2
fi

RegFileName="$WazPath/etc/client.keys"
ConfigFileName="$WazPath/etc/ossec.conf"
LogFileName="$WazPath/logs/ossec.log"
	
if [ "$CheckOnly" == "1" ] && [ "$Install" == "1" ]; then
	echo ""; echo "*** Cannot use -Install in combination with -CheckOnly."
	exit 2
fi

# If forced uninstall (-Uninstall) then just do that end exit with the return code from the function called.
if [ "$Uninstall" == "1" ]; then
	uninstallAgent
	exit $?
fi

# Otherwise do checkAgent and exit with code 2 if the same was received from the function called.
checkAgent
checkAgentResult="$?"
if [ $Debug == 1 ]; then
	echo ""
	echo "Mgr: $Mgr"
	echo "Mgr2: $Mgr2"
	echo "RegMgr: $RegMgr"
	echo "RegPass: $RegPass"
	echo "InstallVer: $InstallVer"
	echo "AgentName: $AgentName"
	echo "DownloadSource: $DownloadSource"
	echo "SkipOsquery: $SkipOsquery"
	echo "Connected: $Connected"
	echo "ExtraGroups: $ExtraGroups"
	echo "CorrectGroupPrefix: $CorrectGroupPrefix"
	echo "OStype: $OStype"
	echo "PkgType: $PkgType"
	echo "WazPath: $WazPath"
	echo "RegFileName: $RegFileName"
	echo "ConfigFileName: $ConfigFileName"
fi
if [[ "$checkAgentResult" == 2 ]]; then
	exit 2
fi

# Is a (re)deploy recommended?  If so, then if -CheckOnly, just exit 1 to indicate that.  Otherwise commence the uninstall and install sequence and exit with a code indicating the results.
if [ "$Install" == 1 ] || [ "$Connected" == 0 ] || [ "$CorrectGroupPrefix" == 0 ]; then
	# If all we are doing is a check, then the check must have indicated a install/reinstall was needed, so return an exit code of 1 now.
	if [ "$CheckOnly" == 1 ]; then
		if [ $Debug == 1 ]; then echo "The checkAgent function has determined that deployment/redeployment is needed."; fi
		exit 1
	else
		uninstallAgent
		if [[ "$?" == 2 ]]; then
			exit 2
		fi
		installAgent
		if [[ "$?" == 2 ]]; then
			exit 2
		fi
		exit 0
	fi
fi

if [ $Debug == 1 ]; then echo "No deployment/redeployment appears to be needed."; fi
exit 0
