#!/bin/sh
#
modprobe ipt_MASQUERADE
modprobe ip_conntrack_ftp
modprobe ip_nat_ftp
iptables -F
iptables -t nat -F
iptables -X
iptables -t nat -X
###########################INPUT键###################################

iptables -P INPUT DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 110,80,25 -j ACCEPT
iptables -A INPUT -p tcp -s 192.168.0.0/24 --dport 139 -j ACCEPT
#允许内网samba,smtp,pop3,连接
iptables -A INPUT -i eth1 -p udp -m multiport --dports 53 -j ACCEPT
#允许dns连接
iptables -A INPUT -p tcp --dport 1723 -j ACCEPT
iptables -A INPUT -p gre -j ACCEPT
#允许外网vpn连接
iptables -A INPUT -s 192.186.0.0/24 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i ppp0 -p tcp --syn -m connlimit --connlimit-above 15 -j DROP
#为了防止DOS太多连接进来,那么可以允许最多15个初始连接,超过的丢弃
iptables -A INPUT -s 192.186.0.0/24 -p tcp --syn -m connlimit --connlimit-above 15 -j DROP
#为了防止DOS太多连接进来,那么可以允许最多15个初始连接,超过的丢弃
iptables -A INPUT -p icmp -m limit --limit 3/s -j LOG --log-level INFO --log-prefix "ICMP packet IN: "
iptables -A INPUT -p icmp -j DROP
#禁止icmp通信-ping 不通
iptables -t nat -A POSTROUTING -o ppp0 -s 192.168.0.0/24 -j MASQUERADE
#内网转发
iptables -N syn-flood
iptables -A INPUT -p tcp --syn -j syn-flood
iptables -I syn-flood -p tcp -m limit --limit 3/s --limit-burst 6 -j RETURN
iptables -A syn-flood -j REJECT
#防止SYN攻击 轻量
#######################FORWARD链###########################
iptables -P FORWARD DROP
iptables -A FORWARD -p tcp -s 192.168.0.0/24 -m multiport --dports 80,110,21,25,1723 -j ACCEPT
iptables -A FORWARD -p udp -s 192.168.0.0/24 --dport 53 -j ACCEPT
iptables -A FORWARD -p gre -s 192.168.0.0/24 -j ACCEPT
iptables -A FORWARD -p icmp -s 192.168.0.0/24 -j ACCEPT
#允许 vpn客户走vpn网络连接外网
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -I FORWARD -p udp --dport 53 -m string --string "tencent" -m time --timestart 8:15 --timestop 12:30 --days Mon,Tue,Wed,Thu,Fri,Sat  -j DROP
#星期一到星期六的8:00-12:30禁止qq通信
iptables -I FORWARD -p udp --dport 53 -m string --string "TENCENT" -m time --timestart 8:15 --timestop 12:30 --days Mon,Tue,Wed,Thu,Fri,Sat  -j DROP
#星期一到星期六的8:00-12:30禁止qq通信
iptables -I FORWARD -p udp --dport 53 -m string --string "tencent" -m time --timestart 13:30 --timestop 20:30 --days Mon,Tue,Wed,Thu,Fri,Sat  -j DROP
iptables -I FORWARD -p udp --dport 53 -m string --string "TENCENT" -m time --timestart 13:30 --timestop 20:30 --days Mon,Tue,Wed,Thu,Fri,Sat  -j DROP
#星期一到星期六的13:30-20:30禁止QQ通信
iptables -I FORWARD -s 192.168.0.0/24 -m string --string "qq.com" -m time --timestart 8:15 --timestop 12:30 --days Mon,Tue,Wed,Thu,Fri,Sat  -j DROP
#星期一到星期六的8:00-12:30禁止qq网页
iptables -I FORWARD -s 192.168.0.0/24 -m string --string "qq.com" -m time --timestart 13:00 --timestop 20:30 --days Mon,Tue,Wed,Thu,Fri,Sat  -j DROP
#星期一到星期六的13:30-20:30禁止QQ网页
iptables -I FORWARD -s 192.168.0.0/24 -m string --string "ay2000.net" -j DROP
iptables -I FORWARD -d 192.168.0.0/24 -m string --string "宽频影院" -j DROP
iptables -I FORWARD -s 192.168.0.0/24 -m string --string "色情" -j DROP
iptables -I FORWARD -p tcp --sport 80 -m string --string "广告" -j DROP
#禁止ay2000.net，宽频影院，色情，广告网页连接 ！但中文 不是很理想
iptables -A FORWARD -m ipp2p --edk --kazaa --bit -j DROP
iptables -A FORWARD -p tcp -m ipp2p --ares -j DROP
iptables -A FORWARD -p udp -m ipp2p --kazaa -j DROP
#禁止BT连接
iptables -A FORWARD -p tcp --syn --dport 80 -m connlimit --connlimit-above 15 --connlimit-mask 24
#######################################################################
sysctl -w net.ipv4.ip_forward=1 &>/dev/null
#打开转发
#######################################################################
sysctl -w net.ipv4.tcp_syncookies=1 &>/dev/null
#打开 syncookie （轻量级预防 DOS 攻击）
sysctl -w net.ipv4.netfilter.ip_conntrack_tcp_timeout_established=3800 &>/dev/null
#设置默认 TCP 连接痴呆时长为 3800 秒（此选项可以大大降低连接数）
sysctl -w net.ipv4.ip_conntrack_max=300000 &>/dev/null
#设置支持最大连接树为 30W（这个根据你的内存和 iptables 版本来，每个 connection 需要 300 多个字节）
#######################################################################
iptables -I INPUT -s 192.168.0.50 -j ACCEPT
iptables -I FORWARD -s 192.168.0.50 -j ACCEPT
#192.168.0.50是我的机子，全部放行！
############################完#########################################
