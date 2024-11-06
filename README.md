# pihole-hostname-mapper

If you don't use PiHole for dhcp, then the clients show up with ip addresses. 
This script scans your local network to resolve ip addresses to their actual host names.
You can manually specify known hosts to have predefined names using their mac addresses.


# How to use
- Rename sample_hosts.csv to hosts.csv and add any known mac addresses: host name combos


# Run the script
source ./venv/bin/activate
python3 -m pip install -r requirements.txt
sudo python3 discovery.py

sudo is needed to get mac addresses when using nmap

# Add the script as a crontab - this will run the script every 30 mins and log the output to cron_log.log; truncating it to 256K
crontab -e

*/30 * * * * echo "$(date): Script started" >> /<path to folder>/cron_log.log && cd /<path to folder> && /bin/bash ./runme.sh >> /<path to folder>/cron_log.log 2>&1; truncate -s 256K /<path to folder>/cron_log.log


Originally based on 
https://github.com/zalerapraxis/pihole-hostnames/blob/master/discovery.py
and 
https://gist.github.com/drath/07bdeef0259bd68747a82ff80a5e350c