
#define class that is ARP, so each local host on the network is added as an obj$
#also compare it to existing list (array?) of obects
#


class ARPhost():

    def __init__(self, name, ip, mac ):
        ARPhost.__init__(self, name)
        self.name =
        self.ip = 
        self.mac = 
#    def mac(self, mac):





import struct
import socket
import binascii
import time
rawSocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0806))

g = open('snifferlog.txt', 'w')

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
        print protocol
        print sourceMAC
        print destinationMAC
