#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from netkiller.firewall import * 

######################################## 
# Web Application
######################################## 

smtp = Firewall()
smtp.flush()
smtp.policy(smtp.INPUT,smtp.ACCEPT)
smtp.policy(smtp.OUTPUT,smtp.ACCEPT)
smtp.policy(smtp.FORWARD,smtp.ACCEPT)
smtp.policy(smtp.POSTROUTING,smtp.ACCEPT)
smtp.input().state(('RELATED','ESTABLISHED')).accept()
smtp.input().protocol('icmp').accept()
smtp.input().interface('-i','lo').accept()
smtp.input().protocol('tcp').state('NEW').dport('22').accept()
#smtp.input().protocol('tcp').dport(('443','80')).state('NEW').accept()
smtp.input().protocol('tcp').dport(('25','110')).reject()

#smtp.input().protocol('tcp').inbound('eth0').dport('80').recent('HTTP',2,20).drop()
#smtp.input().protocol('tcp').inbound('eth0').dport('80').connlimit(30).drop()
#smtp.input().protocol('tcp').inbound('eth0').dport('80').recent('HTTP').accept()
smtp.input().reject('--reject-with icmp-host-prohibited')
smtp.forward().reject('--reject-with icmp-host-prohibited')
for ip in range(10,100):
	smtp.postrouting().outbound('enp2s0').protocol('tcp').state('NEW').statistic('5').snat('--to-source 192.168.0.'+str(ip))

def start():
	smtp.start()
def stop():
	smtp.stop()
def restart():
	smtp.stop()
	smtp.start()
def show():
	smtp.show()
def status():
	smtp.status()
def main():
	show()
	return( 0 )

if __name__ == '__main__':
	main()

