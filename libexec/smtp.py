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

from firewall import * 

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

