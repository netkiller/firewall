firewall
========

Install
-------
	# cd /usr/local/src/
	# yum install -y git python39
	# git clone https://github.com/netkiller/firewall.git
	# cd firewall
	# bash install.sh

Demo
----
	$ sudo /etc/init.d/firewall 
	Usage: /etc/init.d/firewall {start|stop|status|restart}

	$ sudo /etc/init.d/firewall start
	
	$ sudo /etc/init.d/firewall status
	Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
	 pkts bytes target     prot opt in     out     source               destination         
	   44  6163 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
		0     0 ACCEPT     icmp --  *      *       0.0.0.0/0            0.0.0.0/0           
		0     0 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0           
		0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22 state NEW
		0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            multiport dports 443,80 state NEW
		2  2884 REJECT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            reject-with icmp-host-prohibited

	Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
	 pkts bytes target     prot opt in     out     source               destination         
		0     0 REJECT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            reject-with icmp-host-prohibited

	Chain OUTPUT (policy ACCEPT 45 packets, 6893 bytes)
	 pkts bytes target     prot opt in     out     source               destination         
		0     0 REJECT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            multiport dports 20,21 reject-with icmp-port-unreachable
	
	$ sudo /etc/init.d/firewall stop
	
Rule file
---------
	
	$ sudo cat /srv/firewall/libexec/www.py 
	#!/usr/bin/env python3
	# -*- coding: utf-8 -*-
	from firewall import * 

	######################################## 
	# Web Application
	######################################## 

	www = Firewall()
	www.flush()
	www.policy(www.INPUT,www.ACCEPT)
	www.policy(www.OUTPUT,www.ACCEPT)
	www.policy(www.FORWARD,www.ACCEPT)
	www.input().state(('RELATED','ESTABLISHED')).accept()
	www.input().protocol('icmp').accept()
	www.input().interface('-i','lo').accept()
	www.input().protocol('tcp').dport('22').state('NEW').accept()
	www.input().protocol('tcp').dport(('443','80')).state('NEW').accept()
	www.output().protocol('tcp').dport(('20','21')).reject()

	#www.input().protocol('tcp').inbound('eth0').dport('80').recent('HTTP',2,20).drop()
	#www.input().protocol('tcp').inbound('eth0').dport('80').connlimit(30).drop()
	#www.input().protocol('tcp').inbound('eth0').dport('80').recent('HTTP').accept()
	# DDOS
	#www.input().proto('tcp').dport("80").string('XXDD0S').drop()
	www.input().reject('--reject-with icmp-host-prohibited')
	www.forward().reject('--reject-with icmp-host-prohibited')

	def start():
		www.start()
	def stop():
		www.stop()
	def restart():
		www.stop()
		www.start()
	def show():
		www.show()
	def status():
		www.status()
	def main():
		show()
		return( 0 )

	if __name__ == '__main__':
		main()

Testing API
-----------
    #!/usr/bin/python3
    from firewall import Firewall    
    single = Firewall()
    single.policy(single.INPUT,single.DROP)
    single.policy(single.OUTPUT,single.ACCEPT)
    single.policy(single.FORWARD,single.DROP)
    single.input().protocol('icmp').drop()
    single.input().protocol('tcp').dport(('3389','5900')).accept()
    single.input().protocol('tcp').dport(('137','138','139','145')).accept()
    single.show()
    #single.run()
    #single.list()
	
Donations
---------
We accept PayPal through:

https://www.paypal.me/netkiller

Wechat (微信) / Alipay (支付宝) 打赏:

http://www.netkiller.cn/home/donations.html