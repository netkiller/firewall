#!/usr/bin/env python3
# -*- coding: utf-8 -*- 
from netkiller.firewall import Firewall
test = Firewall()
test.flush()
test.policy(test.INPUT,test.DROP)
test.policy(test.OUTPUT,test.ACCEPT)
test.policy(test.FORWARD,test.DROP)
test.input().protocol('icmp').drop()
test.input().protocol('tcp').dport(('3389','5900')).accept()
test.input().protocol('tcp').dport(('137','138','139','145')).accept()
test.show()
#test.run()
#test.list()
