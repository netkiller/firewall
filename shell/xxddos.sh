#!/bin/bash
#!/bin/bash           
########################################  
# Homepage: http://netkiller.github.io  
# Author: neo <netkiller@msn.com>  
########################################  
BLACKLIST=/tmp/BLACKLIST.lst  
PIPE=/tmp/pipe  
pidfile=/tmp/firewall.pid  
KEYWORD=XXDD0S  
ACCESSLOG=/www/logs/www.example.com/access.$(date +'%Y-%m-%d').log  
########################################  
if [ -z $1 ]; then  
    echo "$0 clear|fw|collect|process|close"  
fi
  
if [ "$1" == "clear" ]; then  
    rm -rf $BLACKLIST  
    rm -rf $PIPE  
    echo "Clear OK!!!"  
fi
  
if [ "$1" == "close" ]; then  
        kill `cat $pidfile`  
    echo > $pidfile  
fi
  
if [ ! -f $BLACKLIST ]; then  
    touch $BLACKLIST  
fi  
  
if [ ! -e $PIPE ]; then  
    mkfifo $PIPE  
fi  
  
if [ "$1" == 'fw' ]; then  
    iptables -A OUTPUT -p tcp --dport 2049 -j REJECT  
    iptables -A OUTPUT -p tcp -m multiport --dports 22,21 -j REJECT  
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
for (( ; ; ))  
do  
    while read line   
    do  
        grep $line ${BLACKLIST}
        if [ $? -eq 1 ] ; then  
            echo $line >> ${BLACKLIST}
            iptables -I INPUT -p tcp --dport 80 -s $line -j DROP      
        fi  
    done < $PIPE  
done &  
echo $! >> $pidfile  
fi  

	
