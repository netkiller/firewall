rm -rf /srv/firewall/

dnf remove -y firewalld
dnf install -y iptables

python3 setup.py sdist
python3 setup.py install

install -dv /srv/firewall/{sbin,libexec}
install -D -m 0700 -o root sbin/firewall  /srv/firewall/sbin/
install -D -m 0700 -o root libexec/*.py  /srv/firewall/libexec/
install -D -m 0700 -o root init.d/firewall  /etc/init.d/

install -D -m 0700 -o root systemd/firewall.service /usr/lib/systemd/system/
install -D -m 0700 -o root systemd/firewall /etc/sysconfig/

systemctl enable firewall
systemctl start firewall