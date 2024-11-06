import csv
import filecmp
import json
import os
import sys
import uuid
from shutil import copyfile

import nmap
from python_hosts import Hosts, HostsEntry

HOSTS_LIST = "hosts.csv"
HOSTS_TMP = "hosts.txt"
NMAP_HOSTS = "nmap_hosts.txt"
# Nmap7.8 runs into issues with /22 subnet 
NMAP_TARGETS = [
    '192.168.0.0/24',
    '192.168.1.0/24',
    '192.168.2.0/24',
    #'192.168.3.0/24', 
]


def read_mac_to_host(file_path='hosts.csv'):
    """
    Reads a CSV file with MAC addresses and hostnames and returns a dictionary.
        Parameters:
        file_path (str): Path to the CSV file containing MAC addresses and hostnames.
                         Default is 'hosts.csv'.
        Mac address can contain : or - as delimiter
    Returns:
        dict: A dictionary with MAC addresses as keys and hostnames as values.
    """
    mac_to_host = {}
    
    try:
        with open(file_path, mode='r', newline='') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                mac = row['MAC Address'].strip().replace("-", ":")
                hostname = row['Hostname'].strip()
                mac_to_host[mac] = hostname
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
    except KeyError:
        print("Error: CSV file must have 'MAC Address' and 'Hostname' columns.")
    except Exception as e:
        print(f"An error occurred: {e}")
    
    return mac_to_host


def nmap_scan(target):
    """
    Runs an nmap scan to obtain IP and MAC addresses on the specified network.
    Parameters:
        target (str): The network or IP range to scan. Default is '192.168.1.0/24'.
    Returns:
        Dictionary with details
    """
    NOT_FOUND = "NOT_FOUND"
    scan_results = {}
    nm = nmap.PortScanner()
    print(f"Starting nmap scan on network {target}...")
    try:
        nm.scan(hosts=target, arguments='-sn')
        # print(nm.all_hosts())
        for host in nm.all_hosts():
            # print(nm[host])
            ip_address = host
            mac_address = nm[host]['addresses'].get('mac', NOT_FOUND)
            scan_results[ip_address] = {
                'mac_address_found': mac_address != NOT_FOUND,
                'mac_address': mac_address,
                'vendor': nm[host]['vendor'],
            }
            # print(f"IP Address: {ip_address}, MAC Address: {mac_address}")
    except Exception as e:
        print(f"An error occurred during nmap scan: {e}")
    return scan_results

def sanitize_vendor_name(vendor_name):
    new_vendor_name = vendor_name.replace(" ", "_").replace(":", "_").replace(".", "").replace("/", "")
    return ''.join(letter for letter in new_vendor_name if letter.isalnum() or letter == '_')

def get_mac_addr_parts(mac_address):
    return mac_address[len(mac_address) - 5:]

def update_hosts(hosts, mac_dict, scan_results):
    for ip, details in scan_results.items():
        # print(f"{ip} : {details}")
        if details['mac_address_found'] is True:
            mac_address = details['mac_address']
            if mac_address in mac_dict.keys():
                etchostname = mac_dict[mac_address]
                print(f"Device at {ip} ({mac_address}) is in hardcoded list as {etchostname}")
            else:
                print(f"Device at {ip} ({mac_address}) is not in list")
                # Generate one if possible or lookup
                ip_hostname = ip.replace(".", "_")
                vendor = "_" + next(iter(details['vendor'].values())) if details['vendor'] else ""
                mac_addr_parts = get_mac_addr_parts(mac_address) if details['vendor'] else mac_address
                etchostname = sanitize_vendor_name(f"{ip_hostname}{vendor}_{mac_addr_parts}") 

            # if neither the hostname or ip address exist in hosts file
            if not hosts.exists(ip, etchostname):
                print(f"Adding hostname: {etchostname} with {ip} to hosts file.")
                # hosts.remove_all_matching(name=etchostname)
                new_entry = HostsEntry(entry_type='ipv4', address=ip, names=[etchostname])
                hosts.add([new_entry], force=True)

            # if the hostname exists but ip address in hosts file differs from nmap scan
            for entry in hosts.entries:
                if entry.entry_type in ['ipv4']: # , 'ipv6']:
                    if entry.names[0] == etchostname:
                        if entry.address != ip:
                            print(f"Updating hostname {etchostname} with {ip}.")
                            # hosts.remove_all_matching(name=etchostname)
                            # hosts.remove
                            new_entry = HostsEntry(entry_type='ipv4', address=ip, names=[etchostname])
                            hosts.add([new_entry], force=True)

#!/usr/bin/env python3.6

'''
https://gist.github.com/drath/07bdeef0259bd68747a82ff80a5e350c
'''
'''
Pihole is great, but the admin interface only displays device details 
by IP address which can be confusing. This script changes the display
from IP address to a more recognizable hostname. And as a bonus, attaches
the profile (from fingerbank.org) of the device to the hostname as well - 
so instead of something like 192.168.1.101, you see galaxys6-samsung. 
Shweet. 
Usage notes
- sudo python3.6 discovery.py
- Tested with python 3.6 only
- Requires fingerbank API key (https://api.fingerbank.org/users/register) in a secrets.py file.
- Displays log messages at appropriate times
License: MIT.
'''

import os
from scapy.all import *
from python_hosts import Hosts, HostsEntry
from shutil import copyfile
import sys
import urllib3
import requests
import json
import secrets


'''
Global stuff
'''

 
interface = "wlan0"
fingerbank_url = 'https://api.fingerbank.org/api/v2/combinations/interrogate'
headers = {
    'Content-Type': 'application/json',
}

params = (
    ('key', secrets.API_KEY),
)

'''
Log message for troubleshooting
'''

def log_fingerbank_error(e, response):
    print(f' HTTP error: {e}')
    responses = {
        404: "No device was found the the specified combination",
        502: "No API backend was able to process the request.",
        429: "The amount of requests per minute has been exceeded.",
        403: "This request is forbidden. Your account may have been blocked.",
        401: "This request is unauthorized. Either your key is invalid or wasn't specified."
    }
    print(responses.get(response.status_code, "Fingerbank API returned some unknown error"))
    return

def log_packet_info(packet):
    #print(packet.summary())
    #print(ls(packet))
    print('---')
    types = {
        1: "New DHCP Discover",
        2: "New DHCP Offer",
        3: "New DHCP Request",
        5: "New DHCP Ack",
        8: "New DHCP Inform"
    }
    if DHCP in packet:
        print(types.get(packet[DHCP].options[0][1], "Some Other DHCP Packet"))
    return

def log_fingerbank_response(json_response):
    #print(json.dumps(json_response, indent=4))
    print(f"Device Profile: {json_response['device']['name']}, Confidence score: {json_response['score']}")

# https://jcutrer.com/howto/dev/python/python-scapy-dhcp-packets
def get_option(dhcp_options, key):
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers 
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else: 
                    return i[1]        
    except:
        pass

def handle_dhcp_packet(packet):
    log_packet_info(packet)
    if DHCP in packet:
        requested_addr = get_option(packet[DHCP].options, 'requested_addr')
        hostname = get_option(packet[DHCP].options, 'hostname')
        param_req_list = get_option(packet[DHCP].options, 'param_req_list')
        vendor_class_id = get_option(packet[DHCP].options, 'vendor_class_id')
        print(f"Host {hostname} ({packet[Ether].src}) requested {requested_addr}.")
        device_profile = profile_device(param_req_list, packet[Ether].src, vendor_class_id)
        if ((device_profile != -1) and requested_addr):
            update_hosts_file(requested_addr, hostname, device_profile)
    return

def profile_device(dhcp_fingerprint, macaddr, vendor_class_id):
    data = {}
    data['dhcp_fingerprint'] = ','.join(map(str, dhcp_fingerprint))
    data['debug'] = 'on'
    data['mac'] = macaddr
    data['vendor_class_id'] = vendor_class_id
    print(f"Will attempt to profile using {dhcp_fingerprint}, {macaddr}, and {vendor_class_id}")

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.post(fingerbank_url, 
        headers=headers, 
        params=params, 
        data=json.dumps(data))
    except requests.exceptions.HTTPError as e:
        log_fingerbank_error(e, response)
        return -1
 
    log_fingerbank_response(response.json())

     # If score is less than 30, there is very little confidence on the returned profile. Ignore it.
    if (response.json()['score'] < 30):
        return -1
    
    return response.json()['device']['name']

'''
Update the hosts file with <hostname>-<profile> for hostname
'''

def update_hosts_file(address,hostname,profile):
    if profile is not None:
        copyfile("/etc/hosts", "hosts")
        etchostname = profile.replace(" ", "_") + ("-" + hostname if hostname else "")
        print(f"Updating hostname as: {etchostname} with {address}")

        hosts = Hosts(path='hosts')
        hosts.remove_all_matching(name=etchostname)
        new_entry = HostsEntry(entry_type='ipv4', address=address, names=[etchostname])
        hosts.add([new_entry])
        hosts.write()
        copyfile("hosts", "/etc/hosts")

        print(f"Updated Host name for hostsfile is {etchostname}")

            
print("Starting\n")
sniff(iface = interface, filter='udp and (port 67 or 68)', prn = handle_dhcp_packet, store = 0)
print("\n Shutting down...")

'''
End of file
'''


def main():
    # mac_dict = read_mac_to_host(HOSTS_LIST)
    # # print("MAC Address to Hostname mapping:")
    # # for mac, hostname in mac_dict.items():
    # #     print(f" {mac}: {hostname}")

    # # Make a copy of the hosts file
    # copyfile("/etc/hosts", HOSTS_TMP)  # TODO: move to temp
    # hosts = Hosts(path=HOSTS_TMP)

    # scan_results = {}
    # for target in NMAP_TARGETS:
    #     scan_result = nmap_scan(target=target)
    #     scan_results.update(scan_result)

    # update_hosts(hosts, mac_dict, scan_results)
    # hosts.write()

    # # Dump nmap data to disk
    # with open(NMAP_HOSTS, 'w') as output:
    #     output.write(json.dumps(scan_results, indent= 4, sort_keys= True))

    # # if the contents of our temp hosts file differs from the real hosts file
    # # copy our temp file over to the real file
    # if not filecmp.cmp(HOSTS_TMP, "/etc/hosts", shallow=False):
    #     print("Changes detected, writing new hosts file")
    #     copyfile(HOSTS_TMP, "/etc/hosts")



if __name__ == "__main__":
    main()



## References
# nmap -> https://medium.com/@am-shi/nmap-tryhackme-walkthrough-c62a89c750f1