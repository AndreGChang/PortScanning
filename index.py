import logging
logging.getLogger("scappy.runtime").setLevel(logging.ERROR)
import sys
from scapy.all import *

if len(sys.argv) != 4:
    print("Usage: %s target startport endport"%(sys.argv[0]))
    sys.exit(0)


target = str(sys.argv[1])
startport = int(sys.argv[2])
endport = int(sys.argv[3])

print("Scaning " + target + " for open TCP ports\n")

if startport == endport:
    startport+=1

for x in range(startport, endport):
    packet = IP(dst=target)/TCP(dport=x,flag='S')
    response = sr1(packet, timeout=1, verbose=0)

    if response.haslayer(TCP) and response.getlayer(TCP).flag == 0x12:
        print("Ports "+ str(x)+" id Open")
    sr(IP(dst=target)/TCP(dport=response.sport, flag='R'), timeout=1, verbose=0)

print("Scan is complete\n")