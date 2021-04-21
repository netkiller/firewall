#!/usr/bin/env python3
# -*- coding: utf-8 -*- 
########################################
# Juniper JunOS Style
########################################
from netkiller.firewall import Firewall
gateway = Firewall()
gateway.trust().accept()
gateway.untrust().drop()
gateway.input().protocol('icmp').drop()
gateway.input().protocol('tcp').dport(('3389','5900')).accept()
gateway.show()