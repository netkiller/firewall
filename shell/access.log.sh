#!/bin/bash
########################################  
# Homepage: http://netkiller.github.io  
# Author: neo <netkiller@msn.com>  
########################################  
PIPE=/tmp/pipe  
pidfile=/tmp/firewall.pid
  
ACCCESS_LOG=/tmp/access.log
TIMEPOINT='24/May/2012'
BLACKLIST=/var/tmp/black.lst
WHITELIST=/var/tmp/white.lst
########################################  

if [ -z "$( egrep "CentOS|Redhat" /etc/issue)" ]; then
	echo 'Only for Redhat or CentOS'
	exit
fi

if [ ! -f ${BLACKLIST} ]; then
    touch ${BLACKLIST}
fi

if [ ! -f ${WHITELIST} ]; then
    touch ${WHITELIST}
fi

for deny in $(grep ${TIMEPOINT} ${ACCCESS_LOG} | awk '{print $1}' | awk -F'.' '{print $1"."$2"."$3"."$4}' | sort | uniq -c | sort -r -n | head -n 30| awk '{print $2}')
do

    if [ $(grep -c $deny ${WHITELIST}) -ne 0 ]; then
        echo 'Allow IP:' $deny
	iptables -D INPUT -p tcp --dport 443 -s $deny -j DROP
	iptables -D INPUT -p tcp --dport 80 -s $deny -j DROP
	continue
    fi

    if [ $(grep -c $deny ${BLACKLIST}) -eq 0 ] ; then

	echo 'Deny IP:' $deny
        echo $deny >> ${BLACKLIST}
        iptables -I INPUT -p tcp --dport 443 -s $deny -j DROP
        iptables -I INPUT -p tcp --dport 80 -s $deny -j DROP
    fi
done
	
