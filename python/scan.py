#!/usr/bin/python

import os
import argparse
import subprocess
import sys
import logging
import requests
from multiprocessing.dummy import Pool


def getFormatter():
    return logging.Formatter('[%(asctime)s]  %(message)s', datefmt='%H:%M')
#netscan and returns ips
def netscan(iprange):
    ips=[]
    macs=[]
    
    netscanlogger = logging.getLogger('netscan')
    netscanlogger.setLevel(logging.DEBUG)
    netscanhandler = logging.FileHandler(logdir+'/netscan.log')
    netscanhandler.setLevel(logging.DEBUG)
    netscanhandler.setFormatter(getFormatter())
    netscanlogger.addHandler(netscanhandler)
    
    print "[START] nmap netscan against %s" % iprange
    NMAP = "nmap -sn %s" % iprange
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
        netscanlogger.critical("[ERROR] Exception in %s" % sys.argv[0].strip())
	
    for i in range(len(ips)):
        try:
	    netscanlogger.debug("[INFO] IP up:  %s - %s " % (ips[i], macs[i]))
	except:
	    netscanlogger.debug("[INFO] IP up:  %s - own IP - popped out of list" % ips[i])
	    ips.pop()
	
	
    netscanlogger.debug("[SUMMARY] %s Hosts up in %s (%s)" % (len(ips), iprange, ips))
    print "[END] nmap netscan against %s" % iprange
    return ips

def checkEnv(dir):
    if not os.path.isdir(os.getcwd()+'/'+dir):
        os.mkdir(os.getcwd()+'/'+dir)
        print '[INFO] Logdir: \"'+dir+'\" created'
        
def portscan(ip):
    back=[]
    ports=[]
    services=[]
    checkEnv(logdir+'/'+ip)
    name=ip+'.portscan'
    
    portscanlogger = logging.getLogger(name)
    portscanlogger.setLevel(logging.DEBUG)
    portscanhandler = logging.FileHandler(logdir+'/'+ip+'/'+name)
    portscanhandler.setLevel(logging.DEBUG)
    portscanhandler.setFormatter(getFormatter())
    portscanlogger.addHandler(portscanhandler)
    
    
    print "[START] nmap tcp-portscan against %s" % ip
    NMAP = "nmap -sS -PN -A -p- -T4 %s" % ip
    try:
        results = subprocess.check_output(NMAP, shell=True)
        resultArr = results.split("\n")
        for result in resultArr:
            if re.search(r"\d+\/tcp",result):
                portscanlogger.debug("[INFO] %s" % result)
                splitResultPorts=result.split("/")
                outPorts=splitResultPorts[0].strip()

                splitResultServices=result.split()
                outServices=splitResultServices[2].strip()
                ports.append(outPorts)
                services.append(outServices)

            if re.search(r"^\|.*",result):
                portscanlogger.debug("[INFO] %s" % result)

            if re.search(r"(^Running.*|^OS details.*)",result):
                portscanlogger.debug("[INFO] %s" % result)
    except:
        portscanlogger.critical("[ERROR] Exception in %s" % sys.argv[0].strip())
    portscanlogger.debug("[SUMMARY] %s - Ports: %s" % (ip , ports))
    portscanlogger.debug("[SUMMARY] %s - Services: %s" % (ip, services))
    print "[END] nmap tcp-portscan against %s " % ip
    back.append(ports)
    back.append(services)
    return back

    

def main():
    parser = argparse.ArgumentParser(prog='scan.py', description='Pentesting Scan')
    parser.add_argument('-t', dest='TARGET', required=True, help='192.168.1.0/24 or 192.168.1.0-128') #required
    parser.add_argument('-d', dest='DIR', default='results', help='specifiy output-directory')#optional
    args = parser.parse_args()
    
    global logdir
    logdir = args.DIR
    
    checkEnv(args.DIR)
    ips = netscan(args.TARGET)
    
#    print ips
#    for ip in ips:
#        portscan(ip)
    pool = Pool(2)
    results = pool.map_async(portscan, ips)
    print results
    pool.close()
    pool.join()
    
    

#    parser.print_help()

if __name__ == "__main__":
    main()



