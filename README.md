[![Sn1perSecurity](https://sn1persecurity.com/images/Sn1perSecurity-Attack-Surface-Management-header2.png)](https://sn1persecurity.com)

[![GitHub release](https://img.shields.io/github/release/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/releases)
[![GitHub issues](https://img.shields.io/github/issues/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/issues)
[![Github Stars](https://img.shields.io/github/stars/1N3/Sn1per.svg?style=social&label=Stars)](https://github.com/1N3/Sn1per/)
[![GitHub Followers](https://img.shields.io/github/followers/1N3.svg?style=social&label=Follow)](https://github.com/1N3/Sn1per/)
[![Tweet](https://img.shields.io/twitter/url/http/xer0dayz.svg?style=social)](https://twitter.com/intent/tweet?original_referer=https%3A%2F%2Fdeveloper.twitter.com%2Fen%2Fdocs%2Ftwitter-for-websites%2Ftweet-button%2Foverview&ref_src=twsrc%5Etfw&text=Sn1per%20-%20Automated%20Pentest%20Recon%20Scanner&tw_p=tweetbutton&url=https%3A%2F%2Fgithub.com%2F1N3%2FSn1per)
[![Follow on Twitter](https://img.shields.io/twitter/follow/xer0dayz.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=xer0dayz)

## ABOUT:
Discover the attack surface and prioritize risks with our continuous Attack Surface Management (ASM) platform - Sn1per Professional. For more information, go to https://sn1persecurity.com.

[[Website](https://sn1persecurity.com/wordpress/)] [[Blog](https://sn1persecurity.com/wordpress/blog/)] [[Shop](https://sn1persecurity.com/wordpress/shop)] [[Documentation](https://sn1persecurity.com/wordpress/documentation/)] [[Demo](https://www.youtube.com/watch?v=bsUvB4Vca7Y&list=PL40Vp978dDP9KX2V3VLnNzgJuf4nJrRo9&index=1)] [[Find Out More](https://sn1persecurity.com/wordpress/sn1per-professional-v10-released/)]

[![](https://sn1persecurity.com/images/Sn1perSecurity-attack-surface-management-header2.png)](https://sn1persecurity.com/)
[![](https://sn1persecurity.com/images/Sn1perSecurity-sn1per3.PNG)](https://www.youtube.com/watch?v=bsUvB4Vca7Y&list=PL40Vp978dDP9KX2V3VLnNzgJuf4nJrRo9&index=1)

## FEATURES:

### Attack Surface Discovery

Easily discover the attack surface (IPs, domain names, open ports, HTTP headers, etc.).

### Penetration Testing

Automate the discovery of vulnerabilities and ethical exploitation using the latest hacking and open source security tools.

### Visual Recon

Perform visual recon against all hosts in your workspace using the Slideshow widget and thumbnails.

### IT Asset Inventory

Search, sort and filter for DNS, IP, title, status, server headers, WAF and open TCP/UDP ports of the entire attack surface inventory.

### Red Team

Strengthen "blue team" response and detection capabilities against automated penetration testing techniques.

### Notepad

Store and access multiple notes in a single location to help manage your data and keep things organized.

### Vulnerability Management

Quickly scan for the latest vulnerabilities and CVEs using the latest commercial and open source vulnerability scanners.

### Web Application Scans

Launch web application scans via Burpsuite Professional 2.x, Arachni and Nikto.

### Reporting

Export the entire attack surface host list and vulnerability reports to CSV, XLS or PDF format to filter, sort and view all attack surface data.

### OSINT Collection

Collect online documents, meta data, email addresses and contact information automatically.

### Continuous Scan Coverage

Schedule scans on a daily, weekly or monthly basis for continuous coverage for changes.

### Bug Bounty

Automate the discovery of the attack surface and scan for the latest vulnerabilities and CVEs easily.

### Notifications & Changes

Receive notifications for scan and host status changes, URL and domain changes and new vulnerabilities discovered.

### Domain Takeovers

List all DNS records vulnerable to domain hijacking and takeover.

## KALI/UBUNTU/DEBIAN/PARROT LINUX INSTALL:
```
git clone https://github.com/1N3/Sn1per
cd Sn1per
bash install.sh
```

## DOCKER INSTALL:
[![](https://sn1persecurity.com/images/docker-logo.png)](https://hub.docker.com/r/sn1persecurity/sn1per)

From a new Docker console, run the following commands.
```
Download https://raw.githubusercontent.com/1N3/Sn1per/master/Dockerfile
docker build -t sn1per . 
docker run -it sn1per /bin/bash

or 

docker pull xer0dayz/sn1per
docker run -it xer0dayz/sn1per /bin/bash
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

[*] LOOT EXPORT FUNCTION
sniper -w <WORKSPACE_ALIAS> --export

[*] SCHEDULED SCANS
sniper -w <WORKSPACE_ALIAS> -s daily|weekly|monthly

[*] USE A CUSTOM CONFIG
sniper -c /path/to/sniper.conf -t <TARGET> -w <WORKSPACE_ALIAS>

[*] UPDATE SNIPER
sniper -u|--update
```

## MODES:
* **NORMAL:** Performs basic scan of targets and open ports using both active and passive checks for optimal performance.
* **STEALTH:** Quickly enumerate single targets using mostly non-intrusive scans to avoid WAF/IPS blocking.
* **FLYOVER:** Fast multi-threaded high level scans of multiple targets (useful for collecting high level data on many hosts quickly).
* **AIRSTRIKE:** Quickly enumerates open ports/services on multiple hosts and performs basic fingerprinting. To use, specify the full location of the file which contains all hosts, IPs that need to be scanned and run ./sn1per /full/path/to/targets.txt airstrike to begin scanning.
* **NUKE:** Launch full audit of multiple hosts specified in text file of choice. Usage example: ./sniper /pentest/loot/targets.txt nuke.
* **DISCOVER:** Parses all hosts on a subnet/CIDR (ie. 192.168.0.0/16) and initiates a sniper scan against each host. Useful for internal network scans.
* **PORT:** Scans a specific port for vulnerabilities. Reporting is not currently available in this mode.
* **FULLPORTONLY:** Performs a full detailed port scan and saves results to XML.
* **MASSPORTSCAN:** Runs a "fullportonly" scan on mutiple targets specified via the "-f" switch.
* **WEB:** Adds full automatic web application scans to the results (port 80/tcp & 443/tcp only). Ideal for web applications but may increase scan time significantly.
* **MASSWEB:** Runs "web" mode scans on multiple targets specified via the "-f" switch.
* **WEBPORTHTTP:** Launches a full HTTP web application scan against a specific host and port.
* **WEBPORTHTTPS:** Launches a full HTTPS web application scan against a specific host and port.
* **WEBSCAN:** Launches a full HTTP & HTTPS web application scan against via Burpsuite and Arachni.
* **MASSWEBSCAN:** Runs "webscan" mode scans of multiple targets specified via the "-f" switch.
* **VULNSCAN:** Launches a OpenVAS vulnerability scan.
* **MASSVULNSCAN:** Launches a "vulnscan" mode scans on multiple targets specified via the "-f" switch.

## HELP TOPICS:
- [x] Plugins & Tools (https://github.com/1N3/Sn1per/wiki/Plugins-&-Tools)
- [x] Scheduled scans (https://github.com/1N3/Sn1per/wiki/Scheduled-Scans)
- [x] Sn1per Configuration Options (https://github.com/1N3/Sn1per/wiki/Sn1per-Configuration-Options)
- [x] Sn1per Configuration Templates (https://github.com/1N3/Sn1per/wiki/Sn1per-Configuration-Templates)
- [x] Sc0pe Templates (https://github.com/1N3/Sn1per/wiki/Sc0pe-Templates)

## INTEGRATION GUIDES:
- [x] Github API integration (https://github.com/1N3/Sn1per/wiki/Github-API-Integration)
- [x] Burpsuite Professional 2.x integration (https://github.com/1N3/Sn1per/wiki/Burpsuite-Professional-2.x-Integration)
- [x] OWASP ZAP integration (https://github.com/1N3/Sn1per/wiki/OWASP-ZAP-Integration)
- [x] Shodan API integration (https://github.com/1N3/Sn1per/wiki/Shodan-Integration)
- [x] Censys API integration (https://github.com/1N3/Sn1per/wiki/Censys-API-Integration)
- [x] Hunter.io API integration (https://github.com/1N3/Sn1per/wiki/Hunter.io-API-Integration)
- [x] Metasploit integration (https://github.com/1N3/Sn1per/wiki/Metasploit-Integration)
- [x] Nessus integration (https://github.com/1N3/Sn1per/wiki/Nessus-Integration)
- [x] OpenVAS API integration (https://github.com/1N3/Sn1per/wiki/OpenVAS-Integration)
- [x] GVM 21.x integration (https://github.com/1N3/Sn1per/wiki/GVM-21.x-Integration)
- [x] Slack API integration (https://github.com/1N3/Sn1per/wiki/Slack-API-Integration)
- [x] WPScan API integration (https://github.com/1N3/Sn1per/wiki/WPScan-API-Integration)

## LICENSE:
This software is free to distribute and use with the condition that credit is provided to the creator (@xer0dayz @Sn1perSecurity), is not renamed and is not for commercial use or resold and rebranded. Permission to distribute any part of the code for sale is strictly prohibited.

## LEGAL DISCLAIMER:
You may not rent or lease, distribute, modify, sell or transfer the software to a third party. Sn1per Community is free for distribution, and modification with the condition that credit is provided to the creator and not used for commercial use. You may not use software for illegal or nefarious purposes. No liability for consequential damages to the maximum extent permitted by all applicable laws. In no event shall Sn1perSecurity or any person be liable for any consequential, reliance, incidental, special, direct or indirect damages whatsoever (including without limitation, damages for loss of business profits, business interruption, loss of business information, personal injury, or any other loss) arising out of or in connection with the use or inability to use this product, even if Sn1perSecurity has been advised of the possibility of such damages.

## COPYRIGHT:
The software code and logos are owned by Sn1perSecurity and protected by United States copyright and/or patent laws of international treaty provisions. All rights reserved.

## PURCHASE SN1PER PROFESSIONAL:
To obtain a Sn1per Professional license, go to https://sn1persecurity.com.

Attack Surface Management (ASM) | Continuous Attack Surface Testing (CAST) | Attack Surface Software | Attack Surface Platform | Continuous Automated Red Teaming (CART) |  Vulnerability & Attack Surface Management | Red Team | Threat Intel | Application Security | Cybersecurity | IT Asset Discovery | Automated Penetration Testing | Hacking Tools | Recon Tool | Bug Bounty Tool | Vulnerability Scanner | Attack Surface Analysis | Attack Surface Reduction | Attack Surface Detector | Attack Surface Monitoring | Attack Surface Review | Attack Surface Discovery | Digital Threat Management | Risk Assessment | Threat Remediation | Offensive Security Framework | Automated Penetration Testing Framework | External Threat Management | Internal IT Asset Discovery | Security Orchestration and Automation (SOAR) | Sn1per tutorial | Sn1per tool | Sn1per metasploit | Sn1per for windows | Sn1per review | Sn1per download | how to use Sn1per | Sn1per professional download | Sn1per professional crack | automated pentesting framework | pentest-tools github | ad pentest tools | pentest-tools review | security testing tools | ubuntu pentesting tools | pentesting tools for mac | cloud-based pen-testing tools
