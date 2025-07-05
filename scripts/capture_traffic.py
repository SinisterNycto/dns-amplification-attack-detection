from scapy.all import *

def send_normal_dns_queries(dns_server="8.8.8.8"):
    pkt = IP(dst=dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    send(pkt)

for _ in range(5):
    send_normal_dns_queries()
