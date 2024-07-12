import json
from scapy.all import *
import scapy
import logging
import pdb
import sys

'''
ERRORS 
1. ARP request being unicast -- probably a ignore condition - task 3? 
2. Gratuitous ARP being unicast -- probably a ignore condition - task 3? 
3. ARP response without request -- probably a ignore condition - task 3? -- not necessarily an error 
4. mac not in list
5. ip not in list 
6. wrong ip being broadcasted, when it should be something else from config file?
7. 2 ips for same MAC
8.  ether mac different from arp mac // probably a ignore condition - task 3? 


Notice
1. IP being changed - advertises 192.168.178.1 previously advertised 192.168.178.2
2. ip being advertized -  de:ad:be:ef advertised 192.168.178.1 
3. arp announcement
4. arp probe  
#5. proxy arp???  -> too niche, not general

questions
1. proxy arp
2. what happens in the event of receiving two mac responses for the same broadcast request - high availibility but how 
    will we tell it apart from a arp cache poisoning attack
3. 


Permitted
1. ARP request
2. ARP response
3. Gratuitous ARP -> sent to broadcast address - classified as a request
4. arp probe? 
5. Redundant IP and MAC Addresses
6. Redundant IP Addresses - HA 
??
??

Extended Module 
MAC ca:fe:c0:ff:ee:00 sent ARP packet with de:fa:ce:db:ab:e1 as source field.
ip being advertized -  de:ad:be:ef advertised 192.168.178.1 
IP being changed - advertises 192.168.178.1 previously advertised 192.168.178.2

'''

broadcast_packet_tracker = {}


def filter_arp(packet: scapy.layers.l2.Ether):
    if packet.guess_payload_class(packet) == scapy.layers.l2.ARP:
        return True


# todo add arp probe packet
class ArpPacket:
    def __init__(self, packet: scapy.layers.l2.Ether):
        self.epoch = float(packet.time)
        self.frame_mac_src = packet.src
        self.frame_mac_dst = packet.dst
        self.arp_mac_src = packet[ARP].hwsrc
        self.arp_mac_dst = packet[ARP].hwdst
        self.src_ip = packet[ARP].psrc
        self.dst_ip = packet[ARP].pdst
        self.arp_type = 'request' if packet[ARP].op == 1 else 'reply'
        self.is_broadcast = True if self.frame_mac_dst == 'ff:ff:ff:ff:ff:ff' else False
        self.is_gratuitous = True if (self.dst_ip == self.src_ip and self.arp_type == 'reply'
                                      and self.frame_mac_dst == 'ff:ff:ff:ff:ff:ff' and
                                      self.arp_mac_dst == 'ff:ff:ff:ff:ff:ff') else False
        self.is_arp_probe = True if (self.arp_mac_dst == '00:00:00:00:00:00' and self.src_ip == '0.0.0.0'
                                     and self.frame_mac_dst == 'ff:ff:ff:ff:ff:ff') else False
        self.is_announcement = True if (self.arp_type == 'request' and self.arp_mac_dst == '00:00:00:00:00:00'
                                        and self.src_ip == self.dst_ip) else False
        self.configuration_list: dict = json.load(open(sys.argv[2]))
        self.list_of_ips = list(self.configuration_list.keys())
        self.list_of_ips.append('0.0.0.0')
        self.list_of_macs = []
        for item in list(self.configuration_list.values()):
            if type(item) == list:
                for mac in item:
                    self.list_of_macs.append(mac.lower())
            else:
                self.list_of_macs.append(item.lower())
        self.list_of_macs.append('00:00:00:00:00:00')
        self.list_of_macs.append('ff:ff:ff:ff:ff:ff')


    def validate(self):
        if (self.frame_mac_dst not in self.list_of_macs) or (self.frame_mac_src not in self.list_of_macs) \
                or (self.arp_mac_dst not in self.list_of_macs) or (self.arp_mac_src not in self.list_of_macs):
            logging.error(f'[{self.epoch}]: [Packet transmitted with unknown MAC]')
        elif (self.src_ip not in self.list_of_ips) or (self.dst_ip not in self.list_of_ips):
            # print(self.src_ip, self.dst_ip)
            logging.error(f'[{self.epoch}]: [Packet transmitted by {self.frame_mac_src} has unknown IP]')
        elif self.arp_mac_dst == 'FF:FF:FF:FF:FF:FF' and not self.is_broadcast:
            logging.error(f'[{self.epoch}]: [Unicasted packet from {self.frame_mac_src} to {self.frame_mac_dst} suspiciously marked as a broadcast packet]')
        elif self.is_announcement:
            logging.info(f'[{self.epoch}]: [ARP announcement sent by {self.frame_mac_src} claiming ip {self.dst_ip}]')
        elif self.is_arp_probe:
            logging.info(f'[{self.epoch}]: [ARP Probe sent by {self.frame_mac_src} for ip {self.dst_ip}]')
        elif self.frame_mac_dst != self.arp_mac_dst:
            logging.error(
                f'[{self.epoch}]: [MAC {self.frame_mac_src} unicasted ARP packet with src spuriously marked as {self.arp_mac_dst}]')
        elif not self.is_gratuitous and self.arp_mac_dst == 'FF:FF:FF:FF:FF:FF':
            logging.error(f'[{self.epoch}]: [Gratuitous ARP sent by {self.frame_mac_src} is '
                          f'unicasted to {self.frame_mac_dst}]')
        elif self.is_gratuitous:
            logging.info(f'[{self.epoch}]: [Gratuitous ARP sent by {self.frame_mac_src} for ip {self.dst_ip}]')
        elif self.is_broadcast:
            if self.frame_mac_src not in self.configuration_list[self.src_ip]:
                logging.error(
                    f'[{self.epoch}]: [ARP Broadcast request sent by {self.frame_mac_src} directing replies to wrong ip {self.dst_ip}]')
            else:
                broadcast_packet_tracker[self.dst_ip] = self.configuration_list[self.dst_ip]
                logging.debug(f'[{self.epoch}]: [ARP Broadcast request sent by {self.frame_mac_src} for ip {self.dst_ip}]')
        elif self.arp_type == 'reply':
            #pdb.set_trace()
            if self.src_ip in broadcast_packet_tracker:
                if str(self.frame_mac_src).upper() in self.configuration_list[self.src_ip]:
                    if type(broadcast_packet_tracker[self.src_ip]) == list:
                        broadcast_packet_tracker[self.src_ip].remove(str(self.frame_mac_src).lower())
                    else:
                        broadcast_packet_tracker.pop(self.src_ip)
                logging.debug(f'[{self.epoch}]: [ARP reply sent by {self.frame_mac_dst} to {self.frame_mac_dst} '
                              f'for ip {self.dst_ip}]')
            else:
                logging.error(f'[{self.epoch}]: [ARP response sent by {self.frame_mac_src} to {self.frame_mac_dst}'
                              f' without a request]')


def main():
    print(sys.argv)
    logging.basicConfig(format='[%(levelname)s] : %(message)s', filename=sys.argv[3], filemode='w',
                        level=logging.DEBUG)
    packets = scapy.all.rdpcap(sys.argv[1])
    arp_packets = packets.filter(filter_arp)
    for packet in arp_packets:
        ArpPacket(packet).validate();


if __name__ == '__main__':
    main()
