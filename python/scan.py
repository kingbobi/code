#!/usr/bin/python

import os
import argparse
import subprocess
import sys
import logging
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
    NMAP = "nmap -sn --exclude 192.168.178 %s" % iprange
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
    NMAP = "nmap -sS -PN -A -p- -T4 %s" % ip
    try:
        results = subprocess.check_output(NMAP, shell=True)
        resultArr = results.split("\n")
        for result in resultArr:
            if re.search(r"\d+\/tcp[ |\t]+open",result):
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
    
def ssh(ip,port):
    print "[START] ssh brute against %s on port %s" % (ip,port)
    userlist=["root", "test", "admin", "user", "postgres", "mysql", "backup", "guest", "web", "tomcat", "www-data", "user1", "test1", "test2"]
    passwordlist=["1234567890\n", "123456789\n", "12345678\n", "1234567\n", "123456\n", "12345\n", "1234\n", "654321\n", "4321\n", "123123\n", "password\n", "password1\n", "iloveyou\n", "princess\n", "abc123\n", "babygirl\n", "dragon\n", "tequiero\n", "qwerty\n", "qwertz\n", "000000\n", "111111\n", "222222\n", "333333\n", "444444\n", "555555\n", "666666\n", "777777\n", "888888\n", "999999\n", "iloveu\n", "Password123\n", "password123\n", "admin123\n", "Admin123\n", "1337\n", "admin\n", "Admin\n", "root\n", "toor\n", "fuckyou\n", "test\n", "test123\n", "Test\n", "Test123\n", "Administrator\n", "Administrator123\n", "administrator\n", "administrator123\n", "1q2w3e4r\n", "1qaz2wsx\n", "qazwsx\n", "123qwe\n", "123qaz\n", "0000\n", "oracle\n", "123456qwerty\n", "1q2w3e\n", "q1w2e3r4\n", "user\n", "mysql\n", "apache\n", "pass\n", "pass123\n", "Password\n"]
    tmpfile = open('pws-'+ip+'.txt', 'w')
    tmpfile.writelines(passwordlist)
    tmpfile.close()
    
    for user in userlist:
        HYDRA = "hydra -t 4 -l "+user+" -P "+'pws-'+ip+'.txt'+" -f -o "+logdir+'/'+ip+'/'+ip+'-'+port+".sshhydra "+ip+" -s "+port+" ssh > /dev/null 2> /dev/null"
        try:
            results = subprocess.check_output(HYDRA, shell=True)
        except:
            print "[ERROR]: No valid ssh credentials found"
    
    os.remove('pws-'+ip+'.txt')
    print "[ END ] ssh brute against %s on port %s" % (ip,port)
    
def checkService(args):
    #print "[DEBUG] checkService with args %s " % args
    
    ip=args[0]
    serv=db[ip][1][args[1]]    
    
    
    if serv == "http":
        nikto(ip, db[ip][0][args[1]])
    elif (serv == "ssl/http") or ("https" in serv):
        nikto(ip, db[ip][0][args[1]])
            #elif db[ip][1][s] == "ssh":
            #    ssh(ip,db[ip][0][s])

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
    

    
    portscanPool = Pool(4)
    portscanResults = portscanPool.map_async(portscan, targets)
    portscanPool.close()
    portscanPool.join()
    
    ipServiceList= []
    
    
    for ip in db.keys():
        if len(db[ip][1]) == 0 and len(db[ip][0]) == 0:
            print "[INFO ] no open ports in %s, delete key and remove dir" % ip
            del db[ip]
            removeEmptyEnv(ip)
        else:
            for s in range(len(db[ip][1])):
                ipServiceList.append([ip, s])
                
    
    sericePool = Pool(4)
    serviceResults = sericePool.map_async(checkService, ipServiceList)
    sericePool.close()
    sericePool.join()
    
    print "[ END ] "+"="*35+" [ END ]"

    
    

#    parser.print_help()

if __name__ == "__main__":
    main()



