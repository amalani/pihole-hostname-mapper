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


def main():
    mac_dict = read_mac_to_host(HOSTS_LIST)
    # print("MAC Address to Hostname mapping:")
    # for mac, hostname in mac_dict.items():
    #     print(f" {mac}: {hostname}")

    # Make a copy of the hosts file
    copyfile("/etc/hosts", HOSTS_TMP)  # TODO: move to temp
    hosts = Hosts(path=HOSTS_TMP)

    scan_results = {}
    for target in NMAP_TARGETS:
        scan_result = nmap_scan(target=target)
        scan_results.update(scan_result)

    update_hosts(hosts, mac_dict, scan_results)
    hosts.write()

    # Dump nmap data to disk
    with open(NMAP_HOSTS, 'w') as output:
        output.write(json.dumps(scan_results, indent= 4, sort_keys= True))

    # if the contents of our temp hosts file differs from the real hosts file
    # copy our temp file over to the real file
    if not filecmp.cmp(HOSTS_TMP, "/etc/hosts", shallow=False):
        print("Changes detected, writing new hosts file")
        copyfile(HOSTS_TMP, "/etc/hosts")


if __name__ == "__main__":
    main()



## References
# nmap -> https://medium.com/@am-shi/nmap-tryhackme-walkthrough-c62a89c750f1