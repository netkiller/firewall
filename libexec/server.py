#!/usr/bin/env python3
# -*- coding: utf-8 -*-
######################################## 
# Web Application
######################################## 
from netkiller.firewall import * 

server = Firewall()
server.flush()
server.policy(server.INPUT,server.ACCEPT)
server.policy(server.OUTPUT,server.ACCEPT)
server.policy(server.FORWARD,server.ACCEPT)
server.input().state(('RELATED','ESTABLISHED')).accept()
server.input().protocol('icmp').accept()
server.input().interface('-i','lo').accept()
server.input().protocol('tcp').dport('22').state('NEW').accept()
server.input().protocol('tcp').dport(('443','80')).state('NEW').accept()
server.input().reject('--reject-with icmp-host-prohibited')
server.forward().reject('--reject-with icmp-host-prohibited')

def start():
	server.start()
def stop():
	server.stop()
def restart():
	server.stop()
	server.start()
def show():
	server.show()
def status():
	server.status()
def main():
	show()
	return( 0 )

if __name__ == '__main__':
	main()