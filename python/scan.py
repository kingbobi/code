#!/usr/bin/python

import os
import argparse
import subprocess
import sys
import logging
import requests
from multiprocessing.dummy import Pool
import re


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
        print "[ERROR] Exception in function netscan: ",sys.exc_info()
	
    for i in range(len(ips)):
        try:
            netscanlogger.debug("[INFO] IP up:  %s - %s " % (ips[i], macs[i]))
        except:
            netscanlogger.debug("[INFO] IP up:  %s - own IP - popped out of list" % ips[i])
            ips.pop()
	
	
    netscanlogger.debug("[SUMMARY] %s Hosts up in %s (%s)" % (len(ips), iprange, ips))
    print "[ END ] nmap netscan against %s" % iprange
    return ips

def checkEnv(dir):
    if not os.path.isdir(os.getcwd()+'/'+dir):
        os.mkdir(os.getcwd()+'/'+dir)
        print '[INFO ] Logdir: \"'+dir+'\" created'
        
def removeEmptyEnv(dir):
    if os.path.isdir(os.getcwd()+'/'+logdir+'/'+dir):
        os.remove(os.getcwd()+'/'+logdir+'/'+dir+'/'+dir+'.portscan')
        os.removedirs(os.getcwd()+'/'+logdir+'/'+dir)
        print '[INFO ] Logdir: \"'+dir+'\" removed'
    else:
        print '[ERROR] dir %s not empty, cant remove' % os.getcwd()+'/'+dir
        
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
    NMAP = "nmap -sS -PN -A -p80,22 -T4 %s" % ip
    try:
        results = subprocess.check_output(NMAP, shell=True)
        resultArr = results.split("\n")
        for result in resultArr:
            if re.search(r"\d+\/tcp.open",result):
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
        print "[ERROR] Exception in function portscan %s :" % ip," ",sys.exc_info()
    portscanlogger.debug("[SUMMARY] %s - Ports: %s" % (ip , ports))
    portscanlogger.debug("[SUMMARY] %s - Services: %s" % (ip, services))
    print "[ END ] nmap tcp-portscan against %s " % ip
    back.append(ports)
    back.append(services)
    #results in global var
    db[ip]=back
    
    return back

def nikto(ip,port):
    
    print "[START] nikto scan against %s on port %s" % (ip,port)
    NIKTO = "nikto -h %s -p %s -output %s -Format txt -nointeractive > /dev/null" % (ip,port,logdir+'/'+ip+'/'+ip+'-'+str(port)+'.nikto')
    try:
        results = subprocess.check_output(NIKTO, shell=True)
        #no more filtering
        
    except:
        print "[ERROR] Exception in nikto scan against %s:%s" % (ip,sys.exc_info()) 
    
    print "[ END ] nikto scan against %s" % ip
def checkServices(ip):
    print "[START] checkServices for ip %s" % ip
    for s in range(len(db[ip][1])):
            if db[ip][1][s] == "http":
                nikto(ip, db[ip][0][s])
    print "[ END ] checkServices for ip %s"  % ip
    

def main():
    #TODO clean Logs
    parser = argparse.ArgumentParser(prog='scan.py', description='Pentesting Scan')
    parser.add_argument('-t', dest='TARGET', required=True, help='192.168.1.0/24 or 192.168.1.0-128') #required
    parser.add_argument('-d', dest='DIR', default='results', help='specifiy output-directory')#optional
    args = parser.parse_args()
    
    global logdir
    logdir = args.DIR
    
    checkEnv(args.DIR)
    global targets
    targets = netscan(args.TARGET)
    global db
    db=dict()
    

    #for ip in targets:
    #    s=portscan(ip)
    #    services[ip]=s
    #    print services
        
    #print len(services["192.168.174.134"])
    #print len(services["192.168.174.134"][0]) #
    #print services["192.168.174.134"][0]    #[22,80]
    #print services["192.168.174.134"][1]    #[ssh,http]
    #print services["192.168.174.134"][0][1] # 80
    #print services["192.168.174.134"]
    

    
    pool = Pool(2)
    results = pool.map_async(portscan, targets)
    pool.close()
    pool.join()
    
    for ip in db.keys():
        if len(db[ip][1]) == 0 and len(db[ip][0]) == 0:
            print "[INFO ] no open ports in %s, delete key and remove dir" % ip
            del db[ip]
            removeEmptyEnv(ip)
    
    pool2 = Pool(3)
    results2 = pool2.map_async(checkServices, db.keys())
    pool2.close()
    pool2.join()

    
    

#    parser.print_help()

if __name__ == "__main__":
    main()



