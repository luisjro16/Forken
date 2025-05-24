from scapy.all import *
from scapy.layers.inet import IP, TCP

def capturar(pkt):
    if TCP in pkt:
        print(pkt.summary())

sniff(filter="tcp", prn=capturar)