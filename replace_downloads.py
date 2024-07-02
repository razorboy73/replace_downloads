#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
from scapy.layers.l2 import *

scapy.conf.verb = 0


def process_packet(packet):
    # convert packet to a scapy packet
    scapy_packet = scapy.IP(packet.get_payload())
    # when you request and send a file, it goes through the HTTP layer
    # we then need to classify requests and responses
    # http data will be in raw layer
    if scapy_packet.haslayer(scapy.Raw):
        #http requests leave on port 80
        if scapy_packet.haslayer(scapy.TCP):
            if scapy_packet[scapy.TCP].dport == 80:
                # print("[+]HTTP Request")
                load = scapy_packet[scapy.Raw].load
                keywords = [".zip", ".ZIP", ".exe", ".EXE"]
                for keyword in keywords:
                    if keyword in str(load):
                        print("[+]EXE or ZIP Request")
                        print(scapy_packet.show())
            elif scapy_packet[scapy.TCP].sport == 80:
                print("[+]HTTP Response")
                print(scapy_packet.show())


    # show the packet payload, need to be converted to a scapy packet to manipulate it
    # forwards the packets with .accept()
    packet.accept()
    # drop the packet
    #packet.drop()


queue = netfilterqueue.NetfilterQueue()
# use bind to identify the queue number
queue.bind(0, process_packet)
queue.run()
