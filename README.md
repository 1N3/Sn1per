![alt tag](https://github.com/1N3/Sn1per/blob/master/Sn1per.jpg)

[![GitHub release](https://img.shields.io/github/release/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/releases) 
[![GitHub issues](https://img.shields.io/github/issues/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/issues) 
[![Github Stars](https://img.shields.io/github/stars/1N3/Sn1per.svg?style=social&label=Stars)](https://github.com/1N3/Sn1per/) 
[![GitHub Followers](https://img.shields.io/github/followers/1N3.svg?style=social&label=Follow)](https://github.com/1N3/Sn1per/)
[![Tweet](https://img.shields.io/twitter/url/http/xer0dayz.svg?style=social)](https://twitter.com/intent/tweet?original_referer=https%3A%2F%2Fdeveloper.twitter.com%2Fen%2Fdocs%2Ftwitter-for-websites%2Ftweet-button%2Foverview&ref_src=twsrc%5Etfw&text=Sn1per%20-%20Automated%20Pentest%20Recon%20Scanner&tw_p=tweetbutton&url=https%3A%2F%2Fgithub.com%2F1N3%2FSn1per)
[![Follow on Twitter](https://img.shields.io/twitter/follow/xer0dayz.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=xer0dayz)

## ABOUT:
Sn1per Community Edition is an automated scanner that can be used during a penetration test to enumerate and scan for vulnerabilities. Sn1per Professional is Xero Security's premium reporting addon for Professional Penetration Testers, Bug Bounty Researchers and Corporate Security teams to manage large environments and pentest scopes. For more information regarding Sn1per Professional, go to https://xerosecurity.com. 

## SN1PER PROFESSIONAL FEATURES:
### Workspace Navigator 
- [x] Easily navigate all workspaces within Sn1per
![](https://xerosecurity.com/wordpress/wp-content/uploads/2019/05/Sn1per-v7-workspacenavigator.png)
### Workspace Dashboard
- [x] Get a high level view of the attack surface with overall scan progress
![](https://xerosecurity.com/wordpress/wp-content/uploads/2019/05/Sn1per-Professional-v7.0-Top-Menu1.png)
### Slideshow 
- [x] Visualize the attack surface by easily flipping through all gathered screenshots
![](https://xerosecurity.com/images/Sn1per-v6_screenshot6c.png)
### Host List
- [x] Easily search and sort through all hosts within the workspace using various meta properties
![](https://xerosecurity.com/wordpress/wp-content/uploads/2019/05/Sn1per-Professional-v7.0-Host-List2.png)
### Detailed Host Reports 
- [x] Get more details on any host within the workspace. 
![](https://xerosecurity.com/images/Sn1per-v6_screenshot33.PNG)
### NMap HTML Reports
- [x] View low level network information on each host
![](https://xerosecurity.com/images/Sn1per-v6_screenshot9.png)
### Demo Video:
[![Demo](https://i2.wp.com/xerosecurity.com/wordpress/wp-content/uploads/2019/05/Sn1per-Professional-v7.0-Demo.png?w=1281&ssl=1)](https://www.youtube.com/watch?v=YlRRNM3vd8k)
### Purchase Sn1per Professional:
To obtain a Sn1per Professional license, go to https://xerosecurity.com. 

## SN1PER COMMUNITY FEATURES:
- [x] Automatically collects basic recon (ie. whois, ping, DNS, etc.)
- [x] Automatically launches Google hacking queries against a target domain
- [x] Automatically enumerates open ports via NMap port scanning
- [x] Automatically exploit common vulnerabilities
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
- [x] Automatically tests for open X11 servers
- [x] Performs high level enumeration of multiple hosts and subnets
- [x] Automatically integrates with Metasploit Pro, MSFConsole and Zenmap for reporting
- [x] Automatically gathers screenshots of all web sites
- [x] Create individual workspaces to store all scan output
- [x] Scheduled scans (https://github.com/1N3/Sn1per/wiki/Scheduled-Scans)
- [x] Slack API integration (https://github.com/1N3/Sn1per/wiki/Slack-API-Integration)
- [x] Hunter.io API integration (https://github.com/1N3/Sn1per/wiki/Hunter.io-API-Integration)
- [x] OpenVAS API integration (https://github.com/1N3/Sn1per/wiki/OpenVAS-Integration)
- [x] Burpsuite Professional 2.x integration (https://github.com/1N3/Sn1per/wiki/Burpsuite-Professional-2.x-Integration)
- [x] Censys API integration (https://github.com/1N3/Sn1per/wiki/Censys-API-Integration)
- [x] Metasploit integration (https://github.com/1N3/Sn1per/wiki/Metasploit-Integration)

## KALI LINUX INSTALL:
```
bash install.sh
```

## UBUNTU/DEBIAN/PARROT INSTALL:
```
sudo bash install_debian_ubuntu.sh
```

## DOCKER INSTALL:
From a new Docker console, run the following commands.
```
Download https://raw.githubusercontent.com/1N3/Sn1per/master/Dockerfile
docker build -t sn1per-docker . 
docker run -it sn1per-docker /bin/bash
```

## USAGE:
```
[*] NORMAL MODE
sniper -t <TARGET>

[*] NORMAL MODE + OSINT + RECON
sniper -t <TARGET> -o -re

[*] STEALTH MODE + OSINT + RECON
sniper -t <TARGET> -m stealth -o -re

[*] DISCOVER MODE
sniper -t <CIDR> -m discover -w <WORSPACE_ALIAS>

[*] SCAN ONLY SPECIFIC PORT
sniper -t <TARGET> -m port -p <portnum>

[*] FULLPORTONLY SCAN MODE
sniper -t <TARGET> -fp

[*] WEB MODE - PORT 80 + 443 ONLY!
sniper -t <TARGET> -m web

[*] HTTP WEB PORT MODE
sniper -t <TARGET> -m webporthttp -p <port>

[*] HTTPS WEB PORT MODE
sniper -t <TARGET> -m webporthttps -p <port>

[*] HTTP WEBSCAN MODE
sniper -t <TARGET> -m webscan 

[*] ENABLE BRUTEFORCE
sniper -t <TARGET> -b

[*] AIRSTRIKE MODE
sniper -f targets.txt -m airstrike

[*] NUKE MODE WITH TARGET LIST, BRUTEFORCE ENABLED, FULLPORTSCAN ENABLED, OSINT ENABLED, RECON ENABLED, WORKSPACE & LOOT ENABLED
sniper -f targets.txt -m nuke -w <WORKSPACE_ALIAS>

[*] MASS PORT SCAN MODE
sniper -f targets.txt -m massportscan

[*] MASS WEB SCAN MODE
sniper -f targets.txt -m massweb

[*] MASS WEBSCAN SCAN MODE
sniper -f targets.txt -m masswebscan

[*] MASS VULN SCAN MODE
sniper -f targets.txt -m massvulnscan

[*] PORT SCAN MODE
sniper -t <TARGET> -m port -p <PORT_NUM>

[*] LIST WORKSPACES
sniper --list

[*] DELETE WORKSPACE
sniper -w <WORKSPACE_ALIAS> -d

[*] DELETE HOST FROM WORKSPACE
sniper -w <WORKSPACE_ALIAS> -t <TARGET> -dh

[*] GET SNIPER SCAN STATUS
sniper --status

[*] LOOT REIMPORT FUNCTION
sniper -w <WORKSPACE_ALIAS> --reimport

[*] LOOT REIMPORTALL FUNCTION
sniper -w <WORKSPACE_ALIAS> --reimportall

[*] LOOT REIMPORT FUNCTION
sniper -w <WORKSPACE_ALIAS> --reload

[*] SCHEDULED SCANS
sniper -w <WORKSPACE_ALIAS> -s daily|weekly|monthly

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
* **MASSPORTSCAN:** Runs a "fullportonly" scan on mutiple targets specifified via the "-f" switch.
* **WEB:** Adds full automatic web application scans to the results (port 80/tcp & 443/tcp only). Ideal for web applications but may increase scan time significantly.
* **MASSWEB:** Runs "web" mode scans on mutiple targets specifified via the "-f" switch.
* **WEBPORTHTTP:** Launches a full HTTP web application scan against a specific host and port.
* **WEBPORTHTTPS:** Launches a full HTTPS web application scan against a specific host and port.
* **WEBSCAN:** Launches a full HTTP & HTTPS web application scan against via Burpsuite and Arachni.
* **MASSWEBSCAN:** Runs "webscan" mode scans of multiple targets specified via the "-f" switch.
* **VULNSCAN:** Launches a OpenVAS vulnerability scan.
* **MASSVULNSCAN:** Launches a "vulnscan" mode scans on mutiple targets specifified via the "-f" switch.

## SAMPLE REPORT:
https://gist.github.com/1N3/8214ec2da2c91691bcbc

## Help Topics

- [x] Burpsuite Professional 2.x integration (https://github.com/1N3/Sn1per/wiki/Burpsuite-Professional-2.x-Integration)
- [x] Censys API integration (https://github.com/1N3/Sn1per/wiki/Censys-API-Integration)
- [x] Hunter.io API integration (https://github.com/1N3/Sn1per/wiki/Hunter.io-API-Integration)
- [x] Metasploit integration (https://github.com/1N3/Sn1per/wiki/Metasploit-Integration)
- [x] OpenVAS API integration (https://github.com/1N3/Sn1per/wiki/OpenVAS-Integration)
- [x] Scheduled scans (https://github.com/1N3/Sn1per/wiki/Scheduled-Scans)
- [x] Slack API integration (https://github.com/1N3/Sn1per/wiki/Slack-API-Integration)
- [x] Sn1per Configuration Options (https://github.com/1N3/Sn1per/wiki/Sn1per-Configuration-Options)

## LICENSE:
This software is free to distribute, modify and use with the condition that credit is provided to the creator (@xer0dayz @XeroSecurity) and is not for commercial use or resold and rebranded. Permission to distribute any part of the code for sale is strictly prohibited.

## LEGAL DISCLAIMER:
You may not rent or lease, distribute, modify, sell or transfer the software to a third party. Sn1per Community is free for distribution, and modification with the condition that credit is provided to the creator and not used for commercial use. You may not use software for illegal or nefarious purposes. No liability for consequential damages to the maximum extent permitted by all applicable laws. In no event shall XeroSecurity or any person be liable for any consequential, reliance, incidental, special, direct or indirect damages whatsoever (including without limitation, damages for loss of business profits, business interruption, loss of business information, personal injury, or any other loss) arising out of or in connection with the use or inability to use this product, even if XeroSecurity has been advised of the possibility of such damages. 

## COPYRIGHT:
The software code and logos are owned by XeroSecurity and protected by United States copyright and/or patent laws of international treaty provisions. All rights reserved.
