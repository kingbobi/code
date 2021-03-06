#!/usr/bin/python
import subprocess
import sys
import re

if len(sys.argv) != 2:
    print "Usage: %s <ip>" % sys.argv[0].strip()
    print "Example: %s 192.168.178.1" % sys.argv[0].strip()
    sys.exit(0)

ports=[]
services=[]
print "[START] nmap tcp-portscan against %s" % sys.argv[1].strip()
NMAP = "nmap -sS -PN -A -p- -T4 %s" % sys.argv[1].strip()
try:
    results = subprocess.check_output(NMAP, shell=True)
    resultArr = results.split("\n")
    for result in resultArr:
        if re.search(r"\d+\/tcp",result):
            print "[INFO] %s" % result
            splitResultPorts=result.split("/")
            outPorts=splitResultPorts[0].strip()
            
            splitResultServices=result.split()
            outServices=splitResultServices[2].strip()
            ports.append(outPorts)
            services.append(outServices)
            
        if re.search(r"^\|.*",result):
            print "[INFO] %s" % result
            
        if re.search(r"(^Running.*|^OS details.*)",result):
            print "[INFO] %s" % result
except:
    print "[ERROR] Exception in %s" % sys.argv[0].strip()
print "[SUMMARY] %s - Ports: %s" % (sys.argv[1].strip(), ports)
print "[SUMMARY] %s - Services: %s" % (sys.argv[1].strip(), services)
print "[END] nmap tcp-portscan against %s " % sys.argv[1].strip()
