import subprocess
import re
from scapy.all import Ether, ARP, srp

def get_my_mac_address(interface):
    try:
        output = subprocess.check_output(['ip', 'link', 'show', interface], universal_newlines=True)
        mac_address = re.search(r'ether\s+([^\s]+)', output).group(1)
        return mac_address
    except (subprocess.CalledProcessError, AttributeError):
        return None

def get_my_ip_address(interface):
    try:
        output = subprocess.check_output(['ip', 'addr', 'show', interface], universal_newlines=True)
        ip_address = re.search(r'inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output).group(1)
        return ip_address
    except (subprocess.CalledProcessError, AttributeError):
        return None

def arp_table_mac_address(ip_address):
    try:
        output = subprocess.check_output(['arp', '-n'])
        output = output.decode('utf-8')
        lines = output.split('\n')
        for line in lines:
            if ip_address in line:
                mac_address = line.split()[2]
                return mac_address
    except subprocess.CalledProcessError:
        pass
    return None


def discover_mac(ip_address):
    # Create an ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)

    # Send the packet and capture the response
    arp_response = srp(arp_request, timeout=3, verbose=False)[0]

    # Extract the MAC address from the response
    if arp_response:
        target_mac = arp_response[0][1].hwsrc
        return target_mac
    else:
        return None
    
def get_mac_address(ip_address):
    mac_address = arp_table_mac_address(ip_address)
    if mac_address is not None:
        return mac_address
    
    mac_address = discover_mac(ip_address)
    if mac_address is not None:
        return mac_address
    
    print(f"Failed to discover MAC address for {ip_address}")
    return input(f"Provide MAC address for {ip_address}:\n >> ")