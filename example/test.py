from firewall import Firewall

single = Firewall()
single.policy(single.INPUT,single.DROP)
single.policy(single.OUTPUT,single.ACCEPT)
single.policy(single.FORWARD,single.DROP)
single.input().protocol('icmp').drop()
single.input().protocol('tcp').dport(('3389','5900')).accept()
single.input().protocol('tcp').dport(('137','138','139','145')).accept()
single.show()
#single.run()
#single.list()
