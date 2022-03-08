#!/bin/bash

#
# wazadcounter.sh
# Accumulating counter of Wazuh manager analysisd event drops
#
# The /var/ossec/var/run/wazuh-analysisd.state file where wazuh-analysisd natively reports event drops only contains
# the count for the last 5 seconds.  This script polls that file every 5 seconds and maintains an accumulating counter
# which it updates to disk every minute replacing /var/spool/tot_anl_drops
# and also appends a timestamped hourly log line to /var/spool/tot_anl_drops_hourly represeting the accumulated count at that time.
#
# Invoke this script like this:
#    nohup ./wazadcounter.sh &
#

if [ ! -f /var/spool/tot_anl_drops ]; then
        echo 0 > /var/spool/tot_anl_drops
fi

TDROPS=`cat /var/spool/tot_anl_drops`
i=0

while true; do
        LDROPS=`cat /var/ossec/var/run/wazuh-analysisd.state | grep "_dropped" | cut -d\' -f2`
        ((TDROPS=$TDROPS+$LDROPS))
        #echo "latest $LDROPS total $TDROPS"
        sleep 5
        ((mod=$i%12))
        if [ $mod == 0 ]; then
                #echo "Write to file $TDROPS"
                echo $TDROPS > /var/spool/tot_anl_drops
        fi
        ((mod=$i%720))
        if [ $mod == 0 ]; then
                #echo "Write hourly to file $TDROPS"
                date +"%c - $TDROPS" > /var/spool/tot_anl_drops_hourly
        fi
        ((i=$i+1))
done
