import nmap
import json
nm = nmap.PortScanner()

host = '192.168.0.*'
results = nm.scan(hosts=host, arguments='-sP')

#need to parse out results

print results

results2 = nm.all_hosts()

print results2


parsed_json = json.loads(results)
pprint(parsed_json)

#for host in nm.all_hosts():
#    print nm[host].addresses()
#    print nm[host].hostnames()