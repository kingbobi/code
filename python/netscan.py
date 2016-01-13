#!/usr/bin/python
import subprocess
import sys
import os
if len(sys.argv) != 2:
    print "Usage: %s <ip-range>" % sys.argv[0].strip()
    print "Example: %s 192.168.178.1-25 " % sys.argv[0].strip()
    print "Example: %s 192.168.178.0/24 " % sys.argv[0].strip()
    sys.exit(0)

ips=[]
macs=[]
print "[START] nmap netscan against %s" % sys.argv[1].strip()
NMAP = "nmap -sn %s" % sys.argv[1].strip()
try:
    results = subprocess.check_output(NMAP, shell=True)
    resultArr = results.split("\n")
    for result in resultArr:
        if "Nmap scan report for" in result:
            splitResult=result.split("Nmap scan report for")
            ips.append(splitResult[1].strip())

        if "MAC Address" in result:
            macs.append(result)
except:
    print "[ERROR] Exception in %s" % sys.argv[0].strip()

for i in range(len(ips)):
    try:    
        print "[INFO] IP up:  %s - %s " % (ips[i], macs[i])
    except:
        print "[INFO] IP up:  %s - own IP - popped out of list" % ips[i]
        ips.pop()


print "[SUMMARY] %s Hosts up in %s (%s)" % (len(ips), sys.argv[1].strip(), ips)
print "[END] nmap netscan against %s" % sys.argv[1].strip()

#for ip in ips:
#    os.system("/root/Desktop/scripts/own/portscan.py "+ip)
