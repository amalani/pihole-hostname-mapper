import csv
import filecmp
import os
import sys
from shutil import copyfile

import nmap
from python_hosts import Hosts, HostsEntry
# from scapy.all import *

HOSTS_FILE = "hosts.csv"

def read_mac_to_host(file_path='hosts.csv'):
    """
    Reads a CSV file with MAC addresses and hostnames and returns a dictionary.
        Parameters:
        file_path (str): Path to the CSV file containing MAC addresses and hostnames.
                         Default is 'hosts.csv'.
    Returns:
        dict: A dictionary with MAC addresses as keys and hostnames as values.
    """
    mac_to_host = {}
    
    try:
        with open(file_path, mode='r', newline='') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                mac = row['MAC Address'].strip()
                hostname = row['Hostname'].strip()
                mac_to_host[mac] = hostname
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
    except KeyError:
        print("Error: CSV file must have 'MAC Address' and 'Hostname' columns.")
    except Exception as e:
        print(f"An error occurred: {e}")
    
    return mac_to_host


def nmap_scan(target='192.168.1.0/24'):
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


def main():
    file_path = 'hosts.csv'
    mac_dict = read_mac_to_host(file_path)
    # print("MAC Address to Hostname mapping:")
    # for mac, hostname in mac_dict.items():
    #     print(f" {mac}: {hostname}")

    scan_results = nmap_scan()
    for ip, details in scan_results.items():
        # print(f"{ip} : {details}")

        if details['mac_address_found'] is True:
            mac_address = details['mac_address']
            if mac_address in mac_dict.keys():
                etchostname = mac_dict[mac_address]
                print(f"Device at {ip} ({mac_address}) is in hardcoded list as {etchostname}")
            else:
                print(f"Device at {ip} ({mac_address}) is not in list")


if __name__ == "__main__":
    main()



## References
# nmap -> https://medium.com/@am-shi/nmap-tryhackme-walkthrough-c62a89c750f1