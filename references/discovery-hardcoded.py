#!/usr/bin/env python3.6
'''

# https://github.com/zalerapraxis/pihole-hostnames/blob/master/discovery.py

'''


'''
Pihole is great, but the admin interface only displays device details 
by IP address which can be confusing. This script changes the display
from IP address to a more recognizable name, declared in an address list. 
We do this instead of grabbing the device's hostname as we can't change some
devices' hostnames.
Usage notes
- sudo python3 discovery.py
- Displays log messages at appropriate times
- when running as a service, remember to add 'Environment=PYTHONUNBUFFERED=1' under '[Service]'
License: MIT.
'''

import os
from scapy.all import *
from python_hosts import Hosts, HostsEntry
from shutil import copyfile
import sys
import filecmp
import nmap


'''
Global stuff
'''
addressList ={
	"E8:6F:F2:18:2E:B0": "Router",
	"70:85:C2:A1:BA:3F": "Dalamud",
	"20:39:56:DD:A6:A9": "Android-Nokia",
	"98:EE:CB:3A:9E:84": "Acer",
	"B0:C1:9E:FD:1C:B4": "Android-ZTE",
	"70:F1:A1:74:AD:97": "HP",
	"AC:AE:19:0C:11:6F": "Roku-Downstairs",
	"B8:3E:59:81:4E:4F": "Roku-Upstairs",
	"00:F6:20:45:6F:77": "Google-Home",
	"14:10:9F:03:22:DD": "iPod",
	"00:15:5D:F2:81:1F": "XIVAPI",
	"00:15:5D:2A:EB:00": "CrystalTower",
	"BC:AE:C5:7F:F6:3B": "Midgardsormr",
	# "00:15:5D:2A:EB:01" is the pihole, it's registered as localhost
}


''' main function '''

print("Starting...\n")

while True:
	copyfile("/etc/hosts", "hosts")
	hosts = Hosts(path='hosts')

	nm = nmap.PortScanner()
	nm.scan('192.168.254.0/24', arguments='-sn')
	for host in nm.all_hosts():
		if 'mac' in nm[host]['addresses']:
			ipaddress = nm[host]['addresses']['ipv4']
			macaddress = nm[host]['addresses']['mac']

			if macaddress in addressList:
				etchostname = addressList[macaddress]
				print(f"Device at {ipaddress} ({macaddress}) is in our list as {etchostname}")
			else:
				print(f"Device at {ipaddress} ({macaddress}) is NOT in our list.")
				break

			# if neither the hostname or ip address exist in hosts file
			if not hosts.exists(ipaddress, etchostname):
				print(f"Adding hostname: {etchostname} with {ipaddress} to hosts file.")
				hosts.remove_all_matching(name=etchostname)
				new_entry = HostsEntry(entry_type='ipv4', address=ipaddress, names=[etchostname])
				hosts.add([new_entry])

			# if the hostname exists but ip address in hosts file differs from nmap scan
			for entry in hosts.entries:
				if entry.entry_type in ['ipv4', 'ipv6']:
					if entry.names[0] == etchostname:
						if entry.address != ipaddress:
							print(f"Updating hostname {etchostname} with {ipaddress}.")
							hosts.remove_all_matching(name=etchostname)
							new_entry = HostsEntry(entry_type='ipv4', address=ipaddress, names=[etchostname])
							hosts.add([new_entry])

	hosts.write()

	# if the contents of our temp hosts file differs from the real hosts file
	# copy our temp file over to the real file
	if not filecmp.cmp("hosts", "/etc/hosts", shallow=False):
		print("Changes detected, writing new hosts file")
		copyfile("hosts", "/etc/hosts")

		print("==========================================")

	time.sleep(300)
	