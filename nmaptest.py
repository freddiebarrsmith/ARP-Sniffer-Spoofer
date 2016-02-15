import nmap
nm = nmap.PortScanner()

host = '192.168.0.*'
results = nm.scan(hosts=host, arguments='-sP')


hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
for host, status in hosts_list:
    print('{0}:{1}'.format(host, status))
