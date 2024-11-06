import csv

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

def main():
    file_path = 'hosts.csv'
    mac_dict = read_mac_to_host(file_path)
    print("MAC Address to Hostname mapping:")
    for mac, hostname in mac_dict.items():
        print(f" {mac}: {hostname}")

if __name__ == "__main__":
    main()
