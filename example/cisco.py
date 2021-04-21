#!/usr/bin/env python3
# -*- coding: utf-8 -*- 
########################################
# Cisco ASA Style
########################################
from netkiller.firewall import Firewall
gateway = Firewall()
gateway.inside().accept()
gateway.inside().state(('RELATED','ESTABLISHED')).accept('# match test')
gateway.outside().drop()
gateway.show()