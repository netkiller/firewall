firewall
========

https://pypi.org/project/netkiller-firewall/

Example
-------

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
