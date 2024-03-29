#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from netkiller.firewall import * 

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

