#define class that is ARP, so each local host on the network is added as an object
#also compare it to existing list (array?) of obects
#


import nmap
import json

import time
import struct
import socket
import binascii

listofhosts = []
class ARPhost():

    def __init__(self, name, mac, ip):
#        ARPhost.__init__(self, name, ip, mac)
        self.name = name
        self.ip = ip
        self.mac = mac
#    def mac(self, mac):


nm = nmap.PortScanner()

host = '192.168.0.*'
results = nm.scan(hosts=host, arguments='-sP')


tobeparsed = results["scan"]


##all the below is jjust debugging

for host in nm.all_hosts():
#    print "host status reason"
#    print tobeparsed[host]["status"]["reason"]
#    print tobeparsed[host]
#    print tobeparsed[host]["hostnames"]
    try:
#        print "name "
#        print tobeparsed[host]["hostnames"][0]["name"]
        name = tobeparsed[host]["hostnames"][0]["name"]
    except:
        pass
  #      print "host name fetching failed"
    try:
  #      print "mac address"
   #     print tobeparsed[host]["addresses"]["mac"]
        mac = tobeparsed[host]["addresses"]["mac"]
    except:
    #    print "mac fetching failed"
        pass
    #print tobeparsed[host]["addresses"]["ipv4"]
    ip = tobeparsed[host]["addresses"]["ipv4"]
    host = ARPhost(name, mac, ip)
    listofhosts.append(host)

for host in listofhosts:
    print host.mac
    print host.ip
    print host.name
#    print nm[host].addresses()
#    print nm[host].hostnames()



rawSocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0806))

g = open('snifferlog.txt', 'w')
def arpsniff():
while True:

    receivedPacket=rawSocket.recv(66566)

    #Ethernet Header...
    ethernetHeader=receivedPacket[0:14]
    ethrheader=struct.unpack("!6s6sH",ethernetHeader)
    destinationMAC= binascii.hexlify(ethrheader[0])
    sourceMAC= binascii.hexlify(ethrheader[1])
    protocol= str(ethrheader[2])
    ipHeader=receivedPacket[14:34]
    ipHdr=struct.unpack("!BBHHHBBH4s4s",ipHeader)
    ttl = ipHdr[5]
    strttl = str(ttl)
    protocol = ipHdr[6]
    s_addr = socket.inet_ntoa(ipHdr[8]);
    d_addr = socket.inet_ntoa(ipHdr[9]);

    if protocol == 62:
#        print protocol
#        print sourceMAC
#        print destinationMAC
