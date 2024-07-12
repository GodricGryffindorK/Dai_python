from scapy.all import *
import sys


def filter_arp(packet: scapy.layers.l2.Ether):
    if packet.guess_payload_class(packet) == scapy.layers.l2.ARP:
        return True


configuration_list = {}


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

    def validate(self):
        if self.frame_mac_src not in configuration_list and self.frame_mac_src != 'ff:ff:ff:ff:ff:ff':
            configuration_list[self.frame_mac_src] = self.dst_ip if (
                        self.is_announcement or self.is_arp_probe) else self.src_ip

        if self.arp_mac_dst == 'FF:FF:FF:FF:FF:FF' and not self.is_broadcast:
            #print(
            #   f'[{self.epoch}]: [Unicasted packet from {self.frame_mac_src} to {self.frame_mac_dst} suspiciously marked as a broadcast packet]')
             logging.error(f'[{self.epoch}]: [Unicasted packet suspiciously marked as a broadcast packet]')
        elif self.is_announcement:
            # print(f'[{self.epoch}]: [ARP announcement sent by {self.frame_mac_src} claiming ip {self.dst_ip}]')
            logging.info(f'[{self.epoch}]: [ARP announcement sent by {self.frame_mac_src} claiming ip {self.dst_ip}]')
            if self.dst_ip != configuration_list[self.frame_mac_src]:
                #print(
                #   f'[{self.epoch}]: [{self.frame_mac_src} changed IP to [{self.dst_ip}]. Was [{configuration_list[self.frame_mac_src]}]')
                logging.info(f'[{self.epoch}]: [{self.frame_mac_src} changed IP to [{self.dst_ip}]. Was [{configuration_list[self.frame_mac_src]}]')
                configuration_list[self.frame_mac_src] = self.dst_ip
        elif self.is_arp_probe:
            #print(f'[{self.epoch}]: [ARP Probe sent by {self.frame_mac_src} for ip {self.dst_ip}]')
            logging.info(f'[{self.epoch}]: [ARP Probe sent by {self.frame_mac_src} for ip {self.dst_ip}]')
        elif self.frame_mac_dst != self.arp_mac_dst and self.arp_mac_dst != '00:00:00:00:00:00':
             #print(
             #   f'[{self.epoch}]: [MAC {self.frame_mac_src} unicasted ARP packet with src spuriously marked as {self.arp_mac_dst}]')
             logging.error(
               f'[{self.epoch}]: [MAC {self.frame_mac_src} unicasted ARP packet with src spuriously marked as {self.arp_mac_dst}]')
        elif not self.is_gratuitous and self.arp_mac_dst == 'FF:FF:FF:FF:FF:FF':
            #print(f'[{self.epoch}]: [Gratuitous ARP sent by {self.frame_mac_src} is '
            #      f'unicasted to {self.frame_mac_dst}]')
            logging.error(f'[{self.epoch}]: [Gratuitous ARP sent by {self.frame_mac_src} is '
                         f'unicasted to {self.frame_mac_dst}]')
        elif self.is_gratuitous:
            #print(f'[{self.epoch}]: [Gratuitous ARP sent by {self.frame_mac_src} for ip {self.dst_ip}]')
            logging.info(f'[{self.epoch}]: [Gratuitous ARP sent by {self.frame_mac_src} for ip {self.dst_ip}]')
        elif self.is_broadcast:
            # print(self.configuration_list)
            if self.src_ip != configuration_list[self.frame_mac_src]:
                #print(
                #    f'[{self.epoch}]: [{self.frame_mac_src} changed IP to [{self.src_ip}]. Was [{configuration_list[self.frame_mac_src]}]')
                logging.info(
                    f'[{self.epoch}]: [{self.frame_mac_src} changed IP to [{self.dst_ip}]. Was [{configuration_list[self.frame_mac_src]}]')
                configuration_list[self.frame_mac_src] = self.src_ip
            else:
                # print(f'[{self.epoch}]: [ARP Broadcast request sent by {self.frame_mac_src} for ip {self.dst_ip}]')
                logging.debug(f'[{self.epoch}]: [ARP Broadcast request sent by {self.frame_mac_src} for ip {self.dst_ip}]')
        elif self.arp_type == 'reply':
            # pdb.set_trace()
            if self.src_ip == configuration_list[self.frame_mac_src]:
                #print(f'[{self.epoch}]: [ARP reply sent by {self.frame_mac_dst} to {self.frame_mac_dst}'
                #      f'for ip {self.dst_ip}]')
                logging.debug(f'[{self.epoch}]: [ARP reply sent by {self.frame_mac_dst} to {self.frame_mac_dst} '
                            f'for ip {self.dst_ip}]')
            else:
                #print(
                #    f'[{self.epoch}]: [{self.frame_mac_src} changed IP to [{self.src_ip}]. Was [{configuration_list[self.frame_mac_dst]}]')
                logging.info(
                    f'[{self.epoch}]: [{self.frame_mac_src} changed IP to [{self.dst_ip}]. Was [{configuration_list[self.frame_mac_src]}]')
                configuration_list[self.frame_mac_src] = self.src_ip


def main():
    logging.basicConfig(format='[%(levelname)s] : %(message)s', filename=sys.argv[2], filemode='w',
                        level=logging.INFO)
    packets = scapy.all.rdpcap(sys.argv[1])
    arp_packets = packets.filter(filter_arp)
    for packet in arp_packets:
        ArpPacket(packet).validate()


if __name__ == '__main__':
    main()
