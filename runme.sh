# sudo /etc/init.d/dnsmasq restart

echo "Pulling down latest git repo changes"
git pull

source ./venv/bin/activate
sudo python3 ./discovery.py -u
truncate -s 100K ./cron_log.log
sudo pihole restartdns
