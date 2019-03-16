![alt tag](https://github.com/1N3/Sn1per/blob/master/Sn1per.jpg)

[![GitHub release](https://img.shields.io/github/release/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/releases) 
[![GitHub issues](https://img.shields.io/github/issues/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/issues) 
[![Github Stars](https://img.shields.io/github/stars/1N3/Sn1per.svg?style=social&label=Stars)](https://github.com/1N3/Sn1per/) 
[![GitHub Followers](https://img.shields.io/github/followers/1N3.svg?style=social&label=Follow)](https://github.com/1N3/Sn1per/)
[![Tweet](https://img.shields.io/twitter/url/http/crowdshield.svg?style=social)](https://twitter.com/intent/tweet?original_referer=https%3A%2F%2Fdeveloper.twitter.com%2Fen%2Fdocs%2Ftwitter-for-websites%2Ftweet-button%2Foverview&ref_src=twsrc%5Etfw&text=Sn1per%20-%20Automated%20Pentest%20Recon%20Scanner&tw_p=tweetbutton&url=https%3A%2F%2Fgithub.com%2F1N3%2FSn1per)
[![Follow on Twitter](https://img.shields.io/twitter/follow/crowdshield.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=crowdshield)

## ABOUT:
Sn1per Community Edition is an automated scanner that can be used during a penetration test to enumerate and scan for vulnerabilities. Sn1per Professional is Xero Security's premium reporting addon for Professional Penetration Testers, Bug Bounty Researchers and Corporate Security teams to manage large environments and pentest scopes. For more information regarding Sn1per Professional, go to https://xerosecurity.com. 

## SN1PER PROFESSIONAL FEATURES:
### Professional reporting interface
![](https://xerosecurity.com/images/Sn1per-v6_dashboard1.PNG)
### Slideshow for all gathered screenshots
![](https://xerosecurity.com/images/Sn1per-v6_screenshot6c.png)
### Searchable and sortable DNS, IP and open port database
![](https://xerosecurity.com/images/Sn1per-v6_screenshot31.PNG)
### Detailed host reports
![](https://xerosecurity.com/images/Sn1per-pro8.png)
### NMap HTML host reports
![](https://xerosecurity.com/images/Sn1per-v6_screenshot9.png)
### Quick links to online recon tools and Google hacking queries
![](https://xerosecurity.com/images/sn1per-pro5.png)
### Takeovers and Email Security
![](https://xerosecurity.com/images/Sn1per-v6_screenshot16.png)
### HTML5 Notepad
![](https://xerosecurity.com/images/Sn1per-v6_screenshot15.png)

## ORDER SN1PER PROFESSIONAL:
To obtain a Sn1per Professional license, go to https://xerosecurity.com. 

## DEMO VIDEO:
[![Demo](https://asciinema.org/a/IDckE48BNSWQ8TV8yEjJjjMNm.png)](https://asciinema.org/a/IDckE48BNSWQ8TV8yEjJjjMNm)

## SN1PER COMMUNITY FEATURES:
- [x] Automatically collects basic recon (ie. whois, ping, DNS, etc.)
- [x] Automatically launches Google hacking queries against a target domain
- [x] Automatically enumerates open ports via NMap port scanning
- [x] Automatically brute forces sub-domains, gathers DNS info and checks for zone transfers
- [x] Automatically checks for sub-domain hijacking
- [x] Automatically runs targeted NMap scripts against open ports
- [x] Automatically runs targeted Metasploit scan and exploit modules
- [x] Automatically scans all web applications for common vulnerabilities
- [x] Automatically brute forces ALL open services
- [x] Automatically test for anonymous FTP access
- [x] Automatically runs WPScan, Arachni and Nikto for all web services
- [x] Automatically enumerates NFS shares
- [x] Automatically test for anonymous LDAP access
- [x] Automatically enumerate SSL/TLS ciphers, protocols and vulnerabilities
- [x] Automatically enumerate SNMP community strings, services and users
- [x] Automatically list SMB users and shares, check for NULL sessions and exploit MS08-067
- [x] Automatically exploit vulnerable JBoss, Java RMI and Tomcat servers
- [x] Automatically tests for open X11 servers
- [x] Auto-pwn added for Metasploitable, ShellShock, MS08-067, Default Tomcat Creds
- [x] Performs high level enumeration of multiple hosts and subnets
- [x] Automatically integrates with Metasploit Pro, MSFConsole and Zenmap for reporting
- [x] Automatically gathers screenshots of all web sites
- [x] Create individual workspaces to store all scan output

## AUTO-PWN:
- [x] Apache Struts CVE-2018-11776 RCE exploit
- [x] Android Insecure ADB RCE auto exploit
- [x] Apache Tomcat CVE-2017-12617 RCE exploit
- [x] Oracle WebLogic WLS-WSAT Component Deserialisation RCE CVE-2017-10271 exploit
- [x] Drupal Drupalgedon2 RCE CVE-2018-7600
- [x] GPON Router RCE CVE-2018-10561
- [x] Apache Struts 2 RCE CVE-2017-5638
- [x] Apache Struts 2 RCE CVE-2017-9805
- [x] Apache Jakarta RCE CVE-2017-5638
- [x] Shellshock GNU Bash RCE CVE-2014-6271
- [x] HeartBleed OpenSSL Detection CVE-2014-0160
- [x] Default Apache Tomcat Creds CVE-2009-3843
- [x] MS Windows SMB RCE MS08-067
- [x] Webmin File Disclosure CVE-2006-3392
- [x] Anonymous FTP Access
- [x] PHPMyAdmin Backdoor RCE
- [x] PHPMyAdmin Auth Bypass
- [x] JBoss Java De-Serialization RCE's

## KALI LINUX INSTALL:
```
./install.sh
```

## DOCKER INSTALL:
```
docker build Dockerfile
```

## USAGE:
```
[*] NORMAL MODE
sniper -t|--target <TARGET>

[*] NORMAL MODE + OSINT + RECON + FULL PORT SCAN + BRUTE FORCE
sniper -t|--target <TARGET> -o|--osint -re|--recon -fp|--fullportonly -b|--bruteforce

[*] STEALTH MODE + OSINT + RECON
sniper -t|--target <TARGET> -m|--mode stealth -o|--osint -re|--recon

[*] DISCOVER MODE
sniper -t|--target <CIDR> -m|--mode discover -w|--workspace <WORSPACE_ALIAS>

[*] FLYOVER MODE
sniper -t|--target <TARGET> -m|--mode flyover -w|--workspace <WORKSPACE_ALIAS>

[*] AIRSTRIKE MODE
sniper -f|--file /full/path/to/targets.txt -m|--mode airstrike

[*] NUKE MODE WITH TARGET LIST, BRUTEFORCE ENABLED, FULLPORTSCAN ENABLED, OSINT ENABLED, RECON ENABLED, WORKSPACE & LOOT ENABLED
sniper -f--file /full/path/to/targets.txt -m|--mode nuke -w|--workspace <WORKSPACE_ALIAS>

[*] SCAN ONLY SPECIFIC PORT
sniper -t|--target <TARGET> -m port -p|--port <portnum>

[*] FULLPORTONLY SCAN MODE
sniper -t|--target <TARGET> -fp|--fullportonly

[*] PORT SCAN MODE
sniper -t|--target <TARGET> -m|--mode port -p|--port <PORT_NUM>

[*] WEB MODE - PORT 80 + 443 ONLY!
sniper -t|--target <TARGET> -m|--mode web

[*] HTTP WEB PORT HTTP MODE
sniper -t|--target <TARGET> -m|--mode webporthttp -p|--port <port>

[*] HTTPS WEB PORT HTTPS MODE
sniper -t|--target <TARGET> -m|--mode webporthttps -p|--port <port>

[*] ENABLE BRUTEFORCE
sniper -t|--target <TARGET> -b|--bruteforce

[*] ENABLE LOOT IMPORTING INTO METASPLOIT
sniper -t|--target <TARGET>

[*] LOOT REIMPORT FUNCTION
sniper -w <WORKSPACE_ALIAS> --reimport

[*] DELETE WORKSPACE
sniper -w <WORKSPACE_ALIAS> -d

[*] DELETE HOST FROM WORKSPACE
sniper -w <WORKSPACE_ALIAS> -t <TARGET> -dh

[*] SCAN STATUS
sniper --status

[*] UPDATE SNIPER
sniper -u|--update
```

### MODES:
* **NORMAL:** Performs basic scan of targets and open ports using both active and passive checks for optimal performance.
* **STEALTH:** Quickly enumerate single targets using mostly non-intrusive scans to avoid WAF/IPS blocking.
* **FLYOVER:** Fast multi-threaded high level scans of multiple targets (useful for collecting high level data on many hosts quickly).
* **AIRSTRIKE:** Quickly enumerates open ports/services on multiple hosts and performs basic fingerprinting. To use, specify the full location of the file which contains all hosts, IPs that need to be scanned and run ./sn1per /full/path/to/targets.txt airstrike to begin scanning.
* **NUKE:** Launch full audit of multiple hosts specified in text file of choice. Usage example: ./sniper /pentest/loot/targets.txt nuke. 
* **DISCOVER:** Parses all hosts on a subnet/CIDR (ie. 192.168.0.0/16) and initiates a sniper scan against each host. Useful for internal network scans.
* **PORT:** Scans a specific port for vulnerabilities. Reporting is not currently available in this mode.
* **FULLPORTONLY:** Performs a full detailed port scan and saves results to XML.
* **WEB:** Adds full automatic web application scans to the results (port 80/tcp & 443/tcp only). Ideal for web applications but may increase scan time significantly.   
* **WEBPORTHTTP:** Launches a full HTTP web application scan against a specific host and port.
* **WEBPORTHTTPS:** Launches a full HTTPS web application scan against a specific host and port.

## SAMPLE REPORT:
https://gist.github.com/1N3/8214ec2da2c91691bcbc

## LICENSE:
This software is free to distribute, modify and use with the condition that credit is provided to the creator (@xer0dayz @XeroSecurity) and is not for commercial use. Permission to distribute any part of the code for sale is strictly prohibited.

## DONATIONS:
Donations are welcome. This will help fascilitate improved features, frequent updates and better overall support for sniper.
- [x] BTC 1Fav36btfmdrYpCAR65XjKHhxuJJwFyKum
- [x] ETH 0x20bB09273702eaBDFbEE9809473Fd04b969a794d
- [x] LTC LQ6mPewec3xeLBYMdRP4yzeta6b9urqs2f
- [x] XMR 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbS3EN24xprAQ1Z5Sy5s
- [x] ZCASH t1fsizsk2cqqJAjRoUmXJSyoVa9utYucXt7