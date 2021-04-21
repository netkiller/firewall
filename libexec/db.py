#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from netkiller.firewall import *

########################################
# PostgreSQL Firewall
########################################

db = Firewall()
db.flush()
db.policy(db.INPUT,db.DROP)
db.policy(db.OUTPUT,db.DROP)
db.policy(db.FORWARD,db.DROP)
db.input().state(('RELATED','ESTABLISHED')).accept()
db.input().protocol('icmp').accept()
db.input().interface('-i','lo').accept()
db.input().protocol('tcp').source('172.16.1.10').dport('22').state('NEW').accept()
db.input().protocol('tcp').source('172.16.1.0/24').dport('5432').state('NEW').accept()
db.output().protocol('icmp').accept()
db.output().protocol('udp').dport('53').accept()
db.output().destination('172.16.1.0/24').accept()
db.output().destination('172.16.3.0/24').reject()
db.output().destination('172.16.1.5').proto('tcp').dport('3306').accept()
db.output().destination('172.16.1.6').proto('tcp').dport('3306').accept()


def start():
        db.start()
def stop():
        db.stop()
def restart():
        db.stop()
        db.start()
def show():
        db.show()
def status():
        db.status()

def main():
	db.show()
	#server.run()
	#db.list()
	print()
	return( 0 )

if __name__ == '__main__':
	main()

