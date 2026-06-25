import random
import time
from scapy.all import *

def generate_sample_pcap():
    print("[*] Generating sample_attack.pcap...")
    packets = []
    
    victim_ip = "192.168.1.100"
    attacker_ip = "10.0.0.5"
    dns_resolver = "8.8.8.8"
    
    # 1. Normal traffic (Queries & small responses)
    # 5 queries/sec for 3 seconds
    base_time = time.time() - 100
    for s in range(3):
        for i in range(5):
            pkt_time = base_time + s + (i * 0.2)
            
            # Query
            q_pkt = IP(src=victim_ip, dst=dns_resolver)/UDP(sport=random.randint(1024, 65535), dport=53)/DNS(
                qr=0, qd=DNSQR(qname="google.com", qtype="A")
            )
            q_pkt.time = pkt_time
            packets.append(q_pkt)
            
            # Response (small)
            r_pkt = IP(src=dns_resolver, dst=victim_ip)/UDP(sport=53, dport=q_pkt[UDP].sport)/DNS(
                qr=1, qd=q_pkt[DNS].qd, an=DNSRR(rrname="google.com", type="A", rdata="142.250.190.46")
            )
            r_pkt.time = pkt_time + 0.05
            packets.append(r_pkt)
            
    # 2. Amplification Attack (Massive responses without queries)
    # 300 responses in 1 second
    attack_time = base_time + 3
    padding = "A" * 1200
    for i in range(300):
        pkt_time = attack_time + (i * 0.003)
        r_pkt = IP(src=dns_resolver, dst=victim_ip)/UDP(sport=53, dport=random.randint(1024, 65535))/DNS(
            qr=1, aa=1, rd=0, ra=0, qdcount=1, ancount=1,
            qd=DNSQR(qname="target.local", qtype=255),
            an=DNSRR(rrname="target.local", type="TXT", rdata=padding)
        )
        r_pkt.time = pkt_time
        packets.append(r_pkt)
        
    # 3. Post-attack normal traffic
    post_time = base_time + 4
    for i in range(2):
        pkt_time = post_time + (i * 0.5)
        q_pkt = IP(src=victim_ip, dst=dns_resolver)/UDP(sport=random.randint(1024, 65535), dport=53)/DNS(
            qr=0, qd=DNSQR(qname="example.com", qtype="A")
        )
        q_pkt.time = pkt_time
        packets.append(q_pkt)
        
        r_pkt = IP(src=dns_resolver, dst=victim_ip)/UDP(sport=53, dport=q_pkt[UDP].sport)/DNS(
            qr=1, qd=q_pkt[DNS].qd, an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34")
        )
        r_pkt.time = pkt_time + 0.05
        packets.append(r_pkt)
        
    wrpcap("data/sample_attack.pcap", packets)
    print(f"[+] Successfully wrote {len(packets)} packets to data/sample_attack.pcap")

if __name__ == "__main__":
    import os
    os.makedirs("data", exist_ok=True)
    generate_sample_pcap()
