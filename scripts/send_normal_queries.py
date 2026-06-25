from scapy.all import *
import random

dns_servers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
domains = [
    "example.com", "openai.com", "wikipedia.org",
    "microsoft.com", "nasa.gov", "github.com"
]
query_types = ["A", "AAAA", "MX", "NS"]

def send_random_queries():
    for server in dns_servers:
        for domain in domains:
            for _ in range(3):
                qtype = random.choice(query_types)
                pkt = IP(dst=server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))
                send(pkt)
                print(f"Sent {qtype} query to {server} for {domain}")

send_random_queries()
