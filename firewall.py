#!/usr/bin/env python
# -*- coding: utf-8 -*- 
###########################################
# Linux Firewall Management Pkg
###########################################
# homepage: http://netkiller.github.com
# author:	neo chen <netkiller@msn.com>
# nickname:	netkiller
###########################################
import os, sys
import types

class Service():
	
	def __init__(self):
		pass
	def name(self):
		pass
	def protocol(self):
		pass
	def port(self, src, dst):
		pass
	def www(self):
		return '80'
		
class Address():
	def __init__(self):
		pass
	def name(self):
		pass

class Protocol():
	IMCP	= 'ICMP'
	TCP		= 'TCP'
	UDP		= 'UDP'
	def __init__(self):
		pass
class Firewall(Service, Address):
	INPUT 	= 'INPUT'
	OUTPUT	= 'OUTPUT'
	FORWARD	= 'FORWARD'
	PREROUTING	= 'PREROUTING'
	POSTROUTING	= 'POSTROUTING'

	ACCEPT	= 'ACCEPT'
	DROP	= 'DROP'
	REJECT	= 'REJECT'
	
	def __init__(self):
		self.accesslist = []
		self.match 		= []
		self.nic		= []
		self.iptables = 'iptables'
		self.A = ''
		self.p = ''
		self.src = ''
		self.dst = ''
		self.port = ''
		self.ip = ''
		self.m = ''
		self.err 	= True
		#self.clear()
	def clear(self):
		self.match 		= []
		self.nic		= []
		self.A = ''
		self.p = ''
		self.src = ''
		self.dst = ''
		self.port = ''
		self.ip = ''
		self.m = ''
		self.err 	= True
		pass
	def flush(self):
		self.accesslist.append('iptables -F')
		self.accesslist.append('iptables -F -t nat')
		self.accesslist.append('iptables -F -t filter')
		self.accesslist.append('iptables -t nat -P PREROUTING ACCEPT')
		self.accesslist.append('iptables -t nat -P POSTROUTING ACCEPT')
	def policy(self,chain = None, target = None):
		if chain and target:
			self.accesslist.append('iptables -P '+chain+' '+target)
		else:
			self.accesslist.append('iptables -P INPUT ACCEPT')
			self.accesslist.append('iptables -P OUTPUT ACCEPT')
			self.accesslist.append('iptables -P FORWARD ACCEPT')
		pass
	def chain(self,tmp):
		if tmp in ('INPUT', 'OUTPUT', 'FORWARD'):
			self.A = '-A ' + tmp
			self.err = False
		elif tmp in ('PREROUTING', 'POSTROUTING'):
			self.A = '-t nat -A ' + tmp
			self.err = False
		else:
			self.A = None
			self.err = True
		return( self )
	def input(self):
		return self.chain('INPUT')
	def output(self):
		return self.chain('OUTPUT')
	def forward(self):
		return self.chain('FORWARD')	
	def inside(self):
		return self.chain('OUTPUT')
	def outside(self):
		return self.chain('INPUT')
	def trust(self):
		return self.chain('OUTPUT')
	def untrust(self):
		return self.chain('INPUT')		
	def interface(self,inter, name):
		if inter and name:
			self.nic.append(inter + ' ' + name)
		return( self )	
	def inbound(self,tmp):
		if tmp:
			self.interface('-i', tmp)
		return( self )
	def outbound(self,tmp):
		if tmp:
			self.interface('-o', tmp)
		return( self )	
	def protocol(self,tmp):
		if tmp in ('tcp', 'udp', 'icmp','gre'):
			self.p = "-p " + tmp
		else:
			self.p = ''
		return( self )
	def proto(self,tmp):
		return self.protocol(tmp)
	def source(self, src):
		if src :
			self.src = "-s " + src
		else:
			self.src = ''
		return( self )
	def destination(self, dst):
		if dst:
			self.dst = "-d " + dst
		else:
			self.dst = ''
		return( self )
	def state(self, tmp):
		if type(tmp) == types.StringType:
			self.match.append('-m state --state ' + tmp)
		elif type(tmp) == types.TupleType:
			self.match.append('-m state --state ' + ','.join(tmp))
		else:
			pass
		return( self )
	def string(self, tmp):
		if tmp:
			self.match.append('-m string --string "' +tmp+'"')
		else:
			pass
		return( self )
	def time(self, start, stop, days):
		if start and stop and days:
			self.match.append('-m time --timestart '+start+' --timestop '+stop+' --days ' +days+' ')
		else:
			pass
		return( self )
	def connlimit(self, tmp):
		if tmp:
			self.match.append('-m connlimit --connlimit-above ' +str(tmp)+'') 
		else:
			pass
		return( self )
	def sport(self,tmp):			
		if type(tmp) == types.StringType:
			self.match.append('--sport ' + tmp)
		elif type(tmp) == types.TupleType:
			self.match.append('-m multiport --sports ' + ','.join(tmp))
		else:
			pass
		return( self )
	def dport(self,tmp):
		type(tmp)
		if type(tmp) == types.StringType:
			self.match.append('--dport ' + str(tmp))
		elif type(tmp) == types.TupleType:
			self.match.append('-m multiport --dports ' + ','.join(tmp))
		else:
			pass
		return( self )
	def recent(self,name, seconds = None, hitcount = None):
		if seconds and hitcount and name:
			self.match.append('-m state --state NEW -m recent --name '+name+' --update --seconds '+str(seconds)+' --hitcount '+str(hitcount)+' --rsource')
		elif name :
			self.match.append('-m recent --name '+name+' --set')
		else:
			pass
		return( self )
				
	def target(self, targetname, desc = None):
		if targetname in ('ACCEPT', 'DROP', 'REJECT', 'RETURN', 'QUEUE', 'MASQUERADE', 'DNAT', 'SNAT'):
			self.acl_line = []
			self.acl_line.append(self.iptables)
			if self.A: 		self.acl_line.append(self.A)
			if self.nic:	self.acl_line.append(' '.join(self.nic))
			if self.p: 		self.acl_line.append(self.p)
			if self.src: 	self.acl_line.append(self.src)
			if self.dst:	self.acl_line.append(self.dst)
			if self.match:		self.acl_line.append(' '.join(self.match))
			self.acl_line.append('-j ' + targetname)
		if desc:
			self.acl_line.append(desc)
			
		if self.err:
			acsess_list = '# ' + ' '.join(self.acl_line)
		else:
			acsess_list = ' '.join(self.acl_line)
		self.accesslist.append(acsess_list)
		self.clear()
		
	def accept(self,desc = None):
		self.target('ACCEPT', desc)

	def reject(self,desc = None):
		self.target('REJECT', desc)
	
	def drop(self,desc = None):
		self.target('DROP', desc)

	def masquerade(self):
		self.target('MASQUERADE')
	def dnat(self,desc = None):
		self.target('DNAT',desc)
	def snat(self,desc = None):
		self.target('SNAT',desc)
	def show(self):
		print('\n'.join(self.accesslist))
	def run(self):
		for line in self.accesslist:
			os.system(line)
	def save(self,filename):
		try:
			ipt = open(filename,'w')
			for line in self.accesslist:
				ipt.write(line)
				ipt.write("\n")
			ipt.close()
		except IOError as e:
			print(e)
	def list(self):
		os.system('sudo iptables -S')
		#os.system('sudo iptables -L --line-numbers')
		
########################################
# Test
########################################
test = Firewall()
test.flush()
test.policy()
test.policy(test.INPUT,test.DROP)
test.chain('INPUT').accept()
test.interface('-i',"eth0").accept('# error test')
test.chain('INPUT').interface('-i',"eth0").accept('# ok test')
test.chain('OUTPUT').interface('-o',"eth0").protocol('icmp').accept()
test.output().interface('-i',"eth0").protocol('tcp').accept('')
test.chain('OUTPUT').inbound("eth0").protocol('tcp').source('172.16.1.0/24').accept('')
test.chain('OUTPUT').outbound("eth0").protocol('tcp').destination('172.16.1.1').accept('')
test.chain('FORWARD').inbound("eth0").outbound("eth0").protocol('tcp').source('172.16.1.0/24').destination('172.16.1.1').accept()
test.input().interface('-i',"eth0").protocol('tcp').state('NEW').accept()
test.chain('INPUT').interface('-i',"eth0").protocol('tcp').state('NEW').dport('21').accept()
test.chain('INPUT').inbound("eth0").protocol('tcp').state('NEW').dport(('3306','1152','5432')).accept('multiport test')

test.forward().source("172.16.0.1/24").protocol('tcp').string('sex').accept()
test.forward().dport("53").protocol('udp').time('8:00','18:00','Mon,Tue,Wed,Thu,Fri,Sat').accept()
test.forward().proto('udp').dport("53").string('movie').time('8:00','18:00','Mon,Tue,Wed,Thu,Fri,Sat').accept()
test.input().inbound('ppp0').connlimit(20).drop()
test.forward().reject('--reject-with icmp-host-prohibited')

#test.show()
#test.save('/tmp/firewall.txt')

########################################
# Demo Desktop PC
########################################
single = Firewall()
single.policy(single.INPUT,single.DROP)
single.policy(single.OUTPUT,single.ACCEPT)
single.policy(single.FORWARD,single.DROP)
single.input().protocol('icmp').drop()
single.input().protocol('tcp').dport(('3389','5900')).accept()
single.input().protocol('tcp').dport(('137','138','139','145')).accept()
#single.show()
#single.run()
#single.list()

########################################
# Demo Office Server
########################################
office = Firewall()
office.flush()
office.policy(office.INPUT,office.DROP)
office.policy(office.OUTPUT,office.ACCEPT)
office.policy(office.FORWARD,office.DROP)
office.input().state(('RELATED','ESTABLISHED')).accept()
office.input().protocol('icmp').accept()
office.input().inbound('eth0').protocol('udp').dport(('53','1194')).accept()
office.input().inbound('eth0').protocol('udp').dport(('68','68')).accept()
office.input().protocol('tcp').dport(('20','21','22','80')).accept()
office.input().protocol('tcp').dport(('5800','5900')).accept()
office.input().protocol('tcp').dport(('137','138','139','145')).accept()

#office.show()
#office.run()
#office.list()
########################################
# Demo IDC Server
########################################
server = Firewall()
server.flush()
server.policy(server.INPUT,server.DROP)
server.policy(server.OUTPUT,server.DROP)
server.policy(server.FORWARD,server.DROP)
server.input().state(('RELATED','ESTABLISHED')).accept()
server.input().protocol('icmp').accept()
#server.input().destination('192.168.0.0/24').accept()
server.input().protocol('tcp').dport(('21','22','80')).state('NEW').accept()
server.input().protocol('udp').dport(('53','1194')).accept()
server.input().protocol('tcp').source('172.16.1.0/24').dport('3306').accept()
server.output().protocol('icmp').accept()
server.output().destination('192.168.0.0/24').accept()
server.output().destination('172.16.0.5').reject()
server.output().destination('172.16.0.0/24').accept()
server.output().protocol('udp').dport('53').accept()
server.output().protocol('tcp').dport(('80','21','20','22','8000')).accept()
server.chain('PREROUTING').inbound('eth0').proto('tcp').dport('80').dnat('--to-destination 192.168.0.1:3128')
server.output().destination('172.16.0.10').proto('tcp').dport('3306').accept()
#server.show()
#server.run()
#server.list()

www = Firewall()
#www.flush()
www.policy(www.INPUT,www.ACCEPT)
www.policy(www.OUTPUT,www.ACCEPT)
www.policy(www.FORWARD,www.DROP)
www.input().state(('RELATED','ESTABLISHED')).accept()
www.input().protocol('icmp').accept()
www.input().source('172.16.1.0/24').accept()
www.input().protocol('tcp').dport(('21','22','80')).state('NEW').accept()
www.input().protocol('udp').source('113.106.63.1').dport(('53','1194')).accept()
www.input().protocol('tcp').source('172.16.1.0/24').dport('22').recent('SSH',60,5).reject('--reject-with tcp-reset')
www.output().protocol('icmp').accept()
www.output().protocol('tcp').accept()
www.output().destination('172.16.1.0/24').accept()
www.output().destination('172.16.3.0/24').reject()
www.output().destination('172.16.1.5').proto('tcp').dport('3306').accept()
#www.output().destination('172.16.1.5').accept()
www.output().protocol('udp').dport('53').accept()
www.output().protocol('tcp').dport(('80','3306')).accept()
www.output().protocol('tcp').dport('2049').reject()
www.output().protocol('tcp').dport('22').reject()
www.output().protocol('tcp').dport(('20','21')).reject()
www.chain('PREROUTING').inbound('eth0').proto('tcp').dport('80').dnat('--to-destination 192.168.0.1:3128')
# HTTP CC 攻击
www.input().protocol('tcp').inbound('eth0').dport('80').recent('HTTP',2,20).drop()
www.input().protocol('tcp').inbound('eth0').dport('80').connlimit(30).drop()
www.input().protocol('tcp').inbound('eth0').dport('80').recent('HTTP').accept()
# DDOS
www.input().proto('tcp').dport("80").string('XXDD0S').drop()
www.show()
#server.run()
#server.list()

"""
#iptables -A INPUT -p tcp --dport 80 -m recent --name CC --update --seconds 2 --hitcount 20 -j DROP
#iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 30 -j DROP
#iptables -A INPUT -p tcp --dport 80 -m recent --name CC --set -j ACCEPT
"""
db = Firewall()
db.flush()
db.policy(db.INPUT,db.DROP)
db.policy(db.OUTPUT,db.DROP)
db.policy(db.FORWARD,db.DROP)
db.input().state(('RELATED','ESTABLISHED')).accept()
db.input().protocol('icmp').accept()
db.input().protocol('tcp').source('172.16.1.10').dport('22').state('NEW').accept()
db.input().protocol('tcp').source('172.16.1.0/24').dport('3306').state('NEW').accept()
db.output().protocol('icmp').accept()
db.output().protocol('udp').dport('53').accept()
db.output().destination('172.16.1.0/24').accept()
db.output().destination('172.16.3.0/24').reject()
db.output().destination('172.16.1.5').proto('tcp').dport('3306').accept()
db.output().destination('172.16.1.6').proto('tcp').dport('3306').accept()
#db.show()
#server.run()
#server.list()

########################################
# Linux Gateway via pppoe
########################################
gateway = Firewall()
gateway.input().drop()
gateway.output().accept()
gateway.inside().state(('RELATED','ESTABLISHED')).accept('# match test')
gateway.forward().destination('127.16.0.0/24').accept()
gateway.chain('POSTROUTING').inbound("ppp0").source('172.16.0.0/24').masquerade()
#gateway.show()

########################################
# Cisco ASA Style
########################################
gateway = Firewall()
gateway.inside().accept()
gateway.inside().state(('RELATED','ESTABLISHED')).accept('# match test')
gateway.outside().drop()
#gateway.show()

########################################
# Juniper JunOS Style
########################################
gateway = Firewall()
gateway.trust().accept()
gateway.untrust().drop()
#gateway.show()

