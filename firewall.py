# -*- coding: utf-8 -*- 
###########################################
# Linux Firewall Management Pkg
###########################################
# homepage: http://netkiller.github.com
# author:	neo chen <netkiller@msn.com>
# nickname:	netkiller
###########################################
import os, sys

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
class Policy():
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
		self.accesslist.append('iptables -X')
		self.accesslist.append('iptables -F -t nat')
		self.accesslist.append('iptables -F -t filter')
	def policy(self,chain = None, target = None):
		if chain and target:
			if chain in ('PREROUTING', 'POSTROUTING'):
				self.accesslist.append('iptables -t nat -P '+chain+' '+target)
			else:
				self.accesslist.append('iptables -P '+chain+' '+target)
		else:
			self.accesslist.append('iptables -P INPUT ACCEPT')
			self.accesslist.append('iptables -P OUTPUT ACCEPT')
			self.accesslist.append('iptables -P FORWARD ACCEPT')
			self.accesslist.append('iptables -t nat -P PREROUTING ACCEPT')
			self.accesslist.append('iptables -t nat -P POSTROUTING ACCEPT')
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
	def input(self, comment = None):
		return self.chain(self.INPUT)
	def output(self, comment = None):
		return self.chain(self.OUTPUT)
	def forward(self, comment = None):
		return self.chain(self.FORWARD)
	def inside(self):
		return self.chain('OUTPUT')
	def outside(self):
		return self.chain('INPUT')
	def trust(self):
		return self.chain('OUTPUT')
	def untrust(self):
		return self.chain('INPUT')	
	def prerouting(self):
		return self.chain('PREROUTING')
	def postrouting(self):
		return self.chain('POSTROUTING')		
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
		if type(src) == str:
			self.src = "-s " + src
		elif isinstance(src, tuple):
			self.src = "-s " + ','.join(src)
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
		if type(tmp) == str:
			self.match.append('-m state --state ' + tmp + ' -m tcp')
		elif isinstance(tmp, tuple):
			self.match.append('-m state --state ' + ','.join(tmp))
		else:
			pass
		return( self )
	def statistic(self, tmp):
		self.match.append('-m statistic --mode nth --every ' + tmp + ' --packet 0')
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
		if isinstance(tmp, str) :
			self.match.append('--sport ' + tmp)
		elif isinstance(tmp, tuple) :
			self.match.append('-m multiport --sports ' + ','.join(tmp))
		else:
			pass
		return( self )
	def dport(self,tmp):
		type(tmp)
		if isinstance(tmp, str) :
			self.match.append('--dport ' + str(tmp))
		elif isinstance(tmp, tuple) :
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
			if self.match:	self.acl_line.append(' '.join(self.match))
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
		
	def dnat(self,desc = None):
		self.target('DNAT', desc)
		
	def snat(self,desc = None):
		self.target('SNAT', desc)

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
	def start(self):
		self.run()
	def stop(self):
		self.flush()
		self.run()
	def status(self):
		os.system('iptables -L -vn')
