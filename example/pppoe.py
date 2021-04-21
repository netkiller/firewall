#!/usr/bin/env python3
# -*- coding: utf-8 -*- 
########################################
# Linux Gateway via pppoe
########################################
from netkiller.firewall import Firewall
gateway = Firewall()
gateway.input().drop()
gateway.output().accept()
gateway.inside().state(('RELATED','ESTABLISHED')).accept('# match test')
gateway.forward().destination('127.16.0.0/24').accept()
gateway.chain('POSTROUTING').inbound("ppp0").source('172.16.0.0/24').masquerade()
gateway.show()