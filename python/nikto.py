#!/usr/bin/python
import subprocess
import sys
import os
if len(sys.argv) != 2:
    print "Usage: %s <ip-range>" % sys.argv[0].strip()
    print "Example: %s 192.168.178.1 " % sys.argv[0].strip()
    sys.exit(0)



print "[START] nikto scan against %s" % sys.argv[1].strip()
NMAP = "nikto -h %s" % sys.argv[1].strip()
try:
    results = subprocess.check_output(NMAP, shell=True)
    resultArr = results.split("\n")
    for result in resultArr:
       print result
except:
    print "[ERROR] Exception in %s" % sys.argv[0].strip()


print "[END] nikto scan against %s" % sys.argv[1].strip()