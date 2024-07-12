from scapy.all import wrpcap, Ether, ARP
'''
An ip can be assigned to two macs - high availability - ip conflict

Valid:

Ether(src= '44:15:55:DB:DA:DC', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.28', pdst='192.168.1.13', hwsrc='44:15:55:DB:DA:DC', hwdst='FF:FF:FF:FF:FF:FF') -1S
Ether(src= '78:81:A0:12:81:09', dst= '44:15:55:DB:DA:DC') / ARP(op=2, psrc='192.168.1.13', pdst='192.168.1.28', hwsrc='78:81:A0:12:81:09', hwdst='44:15:55:DB:DA:DC') -1
Ether(src= '82:D2:42:69:0E:C8', dst= '44:15:55:DB:DA:DC') / ARP(op=2, psrc='192.168.1.13', pdst='192.168.1.28', hwsrc='82:D2:42:69:0E:C8', hwdst='44:15:55:DB:DA:DC') -1
Ether(src= '82:D2:42:69:0E:C8', dst= '44:15:55:DB:DA:DC') / ARP(op=2, psrc='192.168.1.13', pdst='192.168.1.28', hwsrc='82:D2:42:69:0E:C8', hwdst='44:15:55:DB:DA:DC') -1
 
Ether(src= 'CF:62:43:C0:AC:E3', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.15', pdst='192.168.1.6', hwsrc='CF:62:43:C0:AC:E3', hwdst='FF:FF:FF:FF:FF:FF') -2S 
Ether(src= '1A:CC:75:6D:D9:D0', dst= 'CF:62:43:C0:AC:E3') / ARP(op=2, psrc='192.168.1.6', pdst='192.168.1.15', hwsrc='1A:CC:75:6D:D9:D0', hwdst='CF:62:43:C0:AC:E3') -2 

Ether(src= 'BB:B4:C8:08:92:8E', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.16', pdst='192.168.1.25', hwsrc='CF:62:43:C0:AC:E3', hwdst='FF:FF:FF:FF:FF:FF') -3S
Ether(src= 'CC:B0:2C:1A:BA:C1', dst= 'BB:B4:C8:08:92:8E') / ARP(op=2, psrc='192.168.1.25', pdst='192.168.1.16', hwsrc='CC:B0:2C:1A:BA:C1', hwdst='BB:B4:C8:08:92:8E') -3
Ether(src= '3F:4E:2E:9A:C8:6B', dst= 'BB:B4:C8:08:92:8E') / ARP(op=2, psrc='192.168.1.25', pdst='192.168.1.16', hwsrc='3F:4E:2E:9A:C8:6B', hwdst='BB:B4:C8:08:92:8E') -3

Ether(src= '00:2B:51:CD:CA:85', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.14', pdst='192.168.1.24', hwsrc='00:2B:51:CD:CA:85', hwdst='FF:FF:FF:FF:FF:FF') -4S
Ether(src= 'C2:23:5E:C5:DF:6A', dst= '00:2B:51:CD:CA:85') / ARP(op=2, psrc='192.168.1.24', pdst='192.168.1.14', hwsrc='C2:23:5E:C5:DF:6A', hwdst='0:2B:51:CD:CA:85') -4 

Ether(src= 'B3:8B:9B:0F:29:8C', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.17', pdst='192.168.1.27', hwsrc='B3:8B:9B:0F:29:8C', hwdst='FF:FF:FF:FF:FF:FF') -5S
Ether(src= '32:2F:6B:F6:B0:51', dst= 'B3:8B:9B:0F:29:8C') / ARP(op=2, psrc='192.168.1.27', pdst='192.168.1.17', hwsrc='32:2F:6B:F6:B0:51', hwdst='B3:8B:9B:0F:29:8C') -5 


Ether(src= 'B3:8B:9B:0F:29:8C', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.16', pdst='192.168.1.16', hwsrc='B3:8B:9B:0F:29:8C', hwdst='FF:FF:FF:FF:FF:FF') - valid GARP

Ether(src= 'C2:23:5E:C5:DF:6A', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.24', pdst='192.168.1.24', hwsrc='C2:23:5E:C5:DF:6A', hwdst='FF:FF:FF:FF:FF:FF') - valid GARP

# todo add arp probe packet

Invalid:

ip not in list: 
Ether(src= '78:81:A0:12:81:09', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.178.61', pdst='192.168.1.13', hwsrc='78:81:A0:12:81:09', hwdst='FF:FF:FF:FF:FF:FF')
mac not in list: 
Ether(src= '78:81:A0:11:81:09', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.178.3', pdst='192.168.1.61', hwsrc='78:81:A0:11:81:09', hwdst='FF:FF:FF:FF:FF:FF')

mac discrepancy between layers: ??
Ether(src= 'BB:B4:C8:08:92:8E', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.25', pdst='192.168.1.16', hwsrc='3F:4E:2E:9A:C8:6B', hwdst='FF:FF:FF:FF:FF:FF')

ip mismatch: 
Ether(src= 'C2:23:5E:C5:DF:6A', dst= '00:2B:51:CD:CA:85') / ARP(op=2, psrc='192.168.1.16', pdst='192.168.1.14', hwsrc='C2:23:5E:C5:DF:6A', hwdst='0:2B:51:CD:CA:85')
 
unicast request: 
Ether(src= 'BB:B4:C8:08:92:8E', dst= '32:2F:6B:F6:B0:51') / ARP(op=1, psrc='192.168.1.16', pdst='192.168.1.25', hwsrc='CF:62:43:C0:AC:E3', hwdst='FF:FF:FF:FF:FF:FF')

unicast GARP:
Ether(src= 'C2:23:5E:C5:DF:6A', dst= '88:C7:9E:77:42:42') / ARP(op=1, psrc='192.168.1.1', pdst='192.168.1.1', hwsrc='C2:23:5E:C5:DF:6A', hwdst='88:C7:9E:77:42:42') 

ARP response without request

'''

packets = [
Ether(src= '44:15:55:DB:DA:DC', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.28', pdst='192.168.1.13', hwsrc='44:15:55:DB:DA:DC', hwdst='FF:FF:FF:FF:FF:FF'),
Ether(src= '78:81:A0:12:81:09', dst= '44:15:55:DB:DA:DC') / ARP(op=2, psrc='192.168.1.13', pdst='192.168.1.28', hwsrc='78:81:A0:12:81:09', hwdst='44:15:55:DB:DA:DC'),
Ether(src= '82:D2:42:69:0E:C8', dst= '44:15:55:DB:DA:DC') / ARP(op=2, psrc='192.168.1.13', pdst='192.168.1.28', hwsrc='82:D2:42:69:0E:C8', hwdst='44:15:55:DB:DA:DC'),
Ether(src= 'CF:62:43:C0:AC:E3', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.15', pdst='192.168.1.6', hwsrc='CF:62:43:C0:AC:E3', hwdst='FF:FF:FF:FF:FF:FF'),
Ether(src= '1A:CC:75:6D:D9:D0', dst= 'CF:62:43:C0:AC:E3') / ARP(op=2, psrc='192.168.1.6', pdst='192.168.1.15', hwsrc='1A:CC:75:6D:D9:D0', hwdst='CF:62:43:C0:AC:E3'),
Ether(src= 'BB:B4:C8:08:92:8E', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.16', pdst='192.168.1.25', hwsrc='CF:62:43:C0:AC:E3', hwdst='FF:FF:FF:FF:FF:FF'),
Ether(src= 'CC:B0:2C:1A:BA:C1', dst= 'BB:B4:C8:08:92:8E') / ARP(op=2, psrc='192.168.1.25', pdst='192.168.1.16', hwsrc='CC:B0:2C:1A:BA:C1', hwdst='BB:B4:C8:08:92:8E'),
Ether(src= '3F:4E:2E:9A:C8:6B', dst= 'BB:B4:C8:08:92:8E') / ARP(op=2, psrc='192.168.1.25', pdst='192.168.1.16', hwsrc='3F:4E:2E:9A:C8:6B', hwdst='BB:B4:C8:08:92:8E'),
Ether(src= '00:2B:51:CD:CA:85', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.14', pdst='192.168.1.24', hwsrc='00:2B:51:CD:CA:85', hwdst='FF:FF:FF:FF:FF:FF'),
Ether(src= 'C2:23:5E:C5:DF:6A', dst= '00:2B:51:CD:CA:85') / ARP(op=2, psrc='192.168.1.24', pdst='192.168.1.14', hwsrc='C2:23:5E:C5:DF:6A', hwdst='0:2B:51:CD:CA:85'),
Ether(src= 'B3:8B:9B:0F:29:8C', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.17', pdst='192.168.1.27', hwsrc='B3:8B:9B:0F:29:8C', hwdst='FF:FF:FF:FF:FF:FF'),
Ether(src= '32:2F:6B:F6:B0:51', dst= 'B3:8B:9B:0F:29:8C') / ARP(op=2, psrc='192.168.1.27', pdst='192.168.1.17', hwsrc='32:2F:6B:F6:B0:51', hwdst='B3:8B:9B:0F:29:8C'),
Ether(src= 'B3:8B:9B:0F:29:8C', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=2, psrc='192.168.1.16', pdst='192.168.1.16', hwsrc='B3:8B:9B:0F:29:8C', hwdst='FF:FF:FF:FF:FF:FF'),
Ether(src= 'C2:23:5E:C5:DF:6A', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=2, psrc='192.168.1.24', pdst='192.168.1.24', hwsrc='C2:23:5E:C5:DF:6A', hwdst='FF:FF:FF:FF:FF:FF'),
Ether(src= '78:81:A0:12:81:09', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.178.61', pdst='192.168.1.13', hwsrc='78:81:A0:12:81:09', hwdst='FF:FF:FF:FF:FF:FF'),
Ether(src= '78:81:A0:11:81:09', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.178.3', pdst='192.168.1.61', hwsrc='78:81:A0:11:81:09', hwdst='FF:FF:FF:FF:FF:FF'),
Ether(src= 'BB:B4:C8:08:92:8E', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.15', pdst='192.168.1.25', hwsrc='3F:4E:2E:9A:C8:6B', hwdst='FF:FF:FF:FF:FF:FF'),
Ether(src= 'C2:23:5E:C5:DF:6A', dst= '00:2B:51:CD:CA:85') / ARP(op=2, psrc='192.168.1.16', pdst='192.168.1.14', hwsrc='C2:23:5E:C5:DF:6A', hwdst='0:2B:51:CD:CA:85'),
Ether(src= 'BB:B4:C8:08:92:8E', dst= '32:2F:6B:F6:B0:51') / ARP(op=1, psrc='192.168.1.16', pdst='192.168.1.25', hwsrc='CF:62:43:C0:AC:E3', hwdst='FF:FF:FF:FF:FF:FF'),
Ether(src= 'C2:23:5E:C5:DF:6A', dst= '88:C7:9E:77:42:42') / ARP(op=1, psrc='192.168.1.1', pdst='192.168.1.1', hwsrc='C2:23:5E:C5:DF:6A', hwdst='88:C7:9E:77:42:42'),
Ether(src= 'C2:23:5E:C5:DF:6A', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='0.0.0.0', pdst='192.168.1.24', hwsrc='C2:23:5E:C5:DF:6A', hwdst='00:00:00:00:00:00'), # send probe
Ether(src= 'C2:23:5E:C5:DF:6A', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='0.0.0.0', pdst='192.168.1.24', hwsrc='C2:23:5E:C5:DF:6A', hwdst='00:00:00:00:00:00'),
Ether(src= 'C2:23:5E:C5:DF:6A', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='0.0.0.0', pdst='192.168.1.24', hwsrc='C2:23:5E:C5:DF:6A', hwdst='00:00:00:00:00:00'),
Ether(src= 'C2:23:5E:C5:DF:6A', dst= 'FF:FF:FF:FF:FF:FF') / ARP(op=1, psrc='192.168.1.24', pdst='192.168.1.24', hwsrc='C2:23:5E:C5:DF:6A', hwdst='00:00:00:00:00:00') # send announcement
]
wrpcap('foo.pcap', packets)
