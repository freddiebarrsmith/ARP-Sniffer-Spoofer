import struct
import socket
import binascii
import time
rawSocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))

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






    #if line = s_addr:
    #print "rogue ip spotted at " + s_addr
    #TCP Header...
    #for line in f:
    #   linestrip = line.strip()
    #   if (s_addr == linestrip):
    #       print "rogue ip at" + linestrip
    #   if (d_addr == linestrip):
    #       print "rogue ip at" + linestrip




    if str(protocol) == "1":
        #need to unpack ports
        binarypackettype = "11"
        print "ICMP"
        curtime = time.strftime("%c")
        g.write(s_addr)
        g.write(' ')
        g.write('0')
        g.write(' ')
        g.write('0')
        g.write(' ')
        g.write(curtime)
        g.write(' ')
        g.write(strttl)
        g.write(' ')
        g.write((binarypackettype))
        g.write('\n')
        pass
    elif str(protocol) == "17":
        udpheader = receivedPacket[34:42]
        udpunpacked = struct.unpack('!HHHH' , udpheader)
        source_port = udpunpacked[0]
        dest_port = udpunpacked[1]
        sourceport = str(source_port)
        destport = str(dest_port)
        curtime = time.strftime("%c")
        binarypackettype = "01"
        print "UDP"
        g.write(s_addr)
        g.write(' ')
        g.write(sourceport)
        g.write(' ')
        g.write(destport)
        g.write(' ')
        g.write(curtime)
        g.write(' ')
        g.write(strttl)
        g.write(' ')
        g.write(str(binarypackettype))
        g.write('\n')
        pass

    elif str(protocol) == "6":

        tcpHeader=receivedPacket[34:54]
        tcpHdr=struct.unpack("!HHLLBBHHH",tcpHeader)
        binarypackettype = "10"
        #the first element of the unpacked tcpheader is the source port
        #second B is the TCP flag setting
        source_port = tcpHdr[0]
        #the second element of the unpacked tcpheader is the destination port
        dest_port = tcpHdr[1]
        if (str(dest_port) != "22"):
            #this is added to discount the ssh prompt as a connection
            print "Source IP: " + s_addr
            #print "Destination IP: "+ d_addr
            g.write(s_addr)
            g.write(' ')
            #print "Source Port: " + str(source_port)
            #print "Destination Port: " + str(dest_port)
            sourceport = str(source_port)
            destport = str(dest_port)
            curtime = time.strftime("%c")
            g.write(sourceport)
            g.write(' ')
            g.write(destport)
            g.write(' ')
            g.write(curtime)
            g.write(' ')
            g.write(strttl)
            g.write(' ')
            g.write(str(binarypackettype))
            #tcp header analysis
            tcpflag = tcpHdr[5]

            #ive done bitshifts to locate each individual flag from the network traffic
            FIN = tcpflag & 0x01
            SYN = (tcpflag >> 1) & 0x01
            RST = (tcpflag >> 2) & 0x01
            PSH = (tcpflag >> 3) & 0x01
            ACK = (tcpflag >> 4) & 0x01
            URG = (tcpflag >> 5) & 0x01
            ECE = (tcpflag >> 6) & 0x01
            CWR = (tcpflag >> 7) & 0x01
            g.write(' ')
            g.write(str(FIN))
            g.write(' ')
            g.write(str(SYN))
            g.write(' ')
            g.write(str(RST))
            g.write(' ')
            g.write(str(PSH))
            g.write(' ')
            g.write(str(ACK))
            g.write(' ')
            g.write(str(URG))
            g.write(' ')
            g.write(str(ECE))
            g.write(' ')
            g.write(str(CWR))
            g.write('\n')
            pass
        else:
            pass
    else:
        binarypackettype = "00"
        g.write(s_addr)
        g.write(' ')
        g.write('0')
        g.write(' ')
        g.write('0')
        g.write(' ')
        g.write(curtime)
        g.write(' ')
        g.write(strttl)
        g.write(' ')
        g.write(str(binarypackettype))
        g.write('\n')
        pass
