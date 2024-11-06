# pihole-hostname-mapper



# How to use
- Rename sample_hosts.csv to hosts.csv and add any known mac addresses: host name combos


# Run the script
source venv/bin/activate
python3 -m pip install -r requirements.txt
python3 discovery.py


Originally based on 
https://github.com/zalerapraxis/pihole-hostnames/blob/master/discovery.py
and 
https://gist.github.com/drath/07bdeef0259bd68747a82ff80a5e350c