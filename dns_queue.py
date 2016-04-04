from netfilterqueue import NetfilterQueue
from dnslib import *
from scapy.all import *
import time
def print_and_accept(pkt):
    #print (pkt.get_payload())
    #d = DNSRecord.parse(pkt)
    #insert a rule into IP tables:sudo iptables -A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 1

    message=str(IP(pkt.get_payload())[UDP].payload)
    d = DNSRecord.parse(message)
    ip_list=[]
    for record in d.rr:
        if record.rtype==1:
            ip_list.append(record.rdata)
           
    time.sleep(10)
    print(d)
    print(ip_list)
    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print
