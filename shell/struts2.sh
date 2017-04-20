#!/bin/bash
########################################  
# Homepage: http://netkiller.github.io  
# Author: neo <netkiller@msn.com>  
########################################
# http://struts.apache.org/docs/s2-046.html
# Struts S2-046, S2-045 Â©¶´·À»ðÇ½
########################################
keywords=( "bash" "cmd" "struts" "ognl" "os.name" "win" "opensymphony" "redirectErrorStream" "ProcessBuilder" "getOutputStream" "getInputStream" "start()" "copy(" "flush()")
for keyword in "${keywords[@]}"
do
	echo "Deny $keyword OK"
	iptables -I INPUT -p tcp --dport 80 -m string --algo bm --string $keyword -j DROP
done
