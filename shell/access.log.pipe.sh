#!/bin/bash
########################################  
# Homepage: http://netkiller.github.io  
# Author: neo <netkiller@msn.com>  
########################################  
ACCESSLOG=/www/logs/www.example.com/access.$(date +'%Y-%m-%d').log  
TIMEPOINT='24/May/2012'
KEYWORD=send.php
BLACKLIST=/var/tmp/black.lst
WHITELIST=/var/tmp/white.lst
PIPE=/var/tmp/pipe
pidfile=/var/tmp/firewall.pid
logfile=/var/tmp/firewall.log
########################################  
if [ -z "$( egrep "CentOS|Redhat" /etc/issue)" ]; then
	echo 'Only for Redhat or CentOS'
	exit
fi

if [ -z $1 ]; then  
    echo "$0 clear|fw|collect|process|close"  
fi
  
if [ "$1" == "clear" ]; then  
    rm -rf $BLACKLIST  
    rm -rf $PIPE  
    echo "Clear OK!!!"  
fi
  
if [ "$1" == "close" ]; then
	killall tail
    kill `cat $pidfile`  
    echo > $pidfile
fi
 
if [ ! -e $PIPE ]; then  
    mkfifo $PIPE  
fi  
  
if [ "$1" == 'fw' ]; then 
    iptables -A OUTPUT -p tcp --dport 2049 -j REJECT  
    iptables -A OUTPUT -p tcp -m multiport --dports 22,21 -j REJECT 

	for ipaddr in ${WHITELIST}
	do
		if [ $(grep -c $ipaddr ${WHITELIST}) -ne 0 ]; then
			iptables -A INPUT -p tcp --dport 443 -s $ipaddr -j ACCEPT
			iptables -A INPUT -p tcp --dport 80 -s $ipaddr -j ACCEPT
			echo 'Allow IP:' $ipaddr >> $logfile
		fi
		if [ $(grep -c $ipaddr ${BLACKLIST}) -eq 0 ] ; then
			iptables -D INPUT -p tcp --dport 443 -s $ipaddr -j DROP
			iptables -D INPUT -p tcp --dport 80 -s $ipaddr -j DROP
			echo 'Deny IP:' $ipaddr
			
		fi
	done
		
fi  
  
if [ "$1" == "collect" ]; then  
    killall tail
    for (( ; ; ))  
    do  
        tail -f $ACCESSLOG | grep $KEYWORD | cut -d ' ' -f1 > $PIPE  
    done &  
    echo $! > $pidfile  
fi  
  
if [ "$1" == "process" ]; then  

	if [ ! -f $BLACKLIST ]; then  
		touch $BLACKLIST  
	fi  

	if [ ! -f ${WHITELIST} ]; then
		touch ${WHITELIST}
	fi	
	
	for (( ; ; ))  
	do  
		while read ipaddr   
		do  
			if [ $(grep -c $ipaddr ${WHITELIST}) -ne 0 ]; then
				echo 'Allow IP:' $ipaddr >> $logfile
				continue
			fi		
		
			grep $ipaddr ${BLACKLIST}
			if [ $? -eq 1 ] ; then  
				echo $ipaddr >> ${BLACKLIST}
				iptables -I INPUT -p tcp --dport 80 -s $ipaddr -j DROP      
				echo "Deny IP: $ipaddr" >> $logfile
			fi  
		done < $PIPE  
	done &  
	echo $! >> $pidfile  
fi
