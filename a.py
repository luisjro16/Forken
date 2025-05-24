from scapy.all import *
from scapy.layers.inet import IP, TCP

target_ip = "192.168.1.152"
target_port = 44444

def send_packet():
    ip = IP(dst=target_ip)
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
    pkt = ip/tcp
    send(pkt, verbose=True)
    print(f"Pacote enviado para {target_ip}:{target_port}")

send_packet()
