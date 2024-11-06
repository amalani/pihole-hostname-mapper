# sudo /etc/init.d/dnsmasq restart

source venv/bin/activate
sudo python3 discovery.py
sudo pihole restartdns
