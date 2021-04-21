#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  example.py
#  
#  Copyright 2013 neo <netkiller@msn.com>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  

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

