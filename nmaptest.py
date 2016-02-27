import nmap
import json

class ARPhost():

    def __init__(self, name, ip, mac ):
        ARPhost.__init__(self, name)
        self.name = name
        self.ip = ip
        self.mac = mac
#    def mac(self, mac):


nm = nmap.PortScanner()

host = '192.168.0.*'
results = nm.scan(hosts=host, arguments='-sP')


tobeparsed = results["scan"]


for host in nm.all_hosts():
    print tobeparsed[host]
    print tobeparsed[host]["hostnames"]
    print "name "
    print tobeparsed[host]["hostnames"][0]["name"]
    print tobeparsed[host]["addresses"]["mac"]
    print tobeparsed[host]["addresses"]["ipv4"]
