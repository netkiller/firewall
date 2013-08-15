rm -rf /srv/firewall/
install -dv /srv/firewall/{sbin,libexec}
install -D -m 0700 -o root sbin/firewall  /srv/firewall/sbin/
install -D -m 0700 -o root libexec/*.py  /srv/firewall/libexec/
install -D -m 0700 -o root init.d/firewall  /etc/init.d/

cd packages/
python3 setup.py sdist
python3 setup.py install
cd -

