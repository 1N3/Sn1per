[![Sn1perSecurity](https://sn1persecurity.com/images/Sn1perSecurity-Attack-Surface-Management-header2.png)](https://sn1persecurity.com)

[![GitHub release](https://img.shields.io/github/release/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/releases)
[![GitHub issues](https://img.shields.io/github/issues/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/issues)
[![Github Stars](https://img.shields.io/github/stars/1N3/Sn1per.svg?style=social&label=Stars)](https://github.com/1N3/Sn1per/)
[![GitHub Followers](https://img.shields.io/github/followers/1N3.svg?style=social&label=Follow)](https://github.com/1N3/Sn1per/)
[![Tweet](https://img.shields.io/twitter/url/http/xer0dayz.svg?style=social)](https://twitter.com/intent/tweet?original_referer=https%3A%2F%2Fdeveloper.twitter.com%2Fen%2Fdocs%2Ftwitter-for-websites%2Ftweet-button%2Foverview&ref_src=twsrc%5Etfw&text=Sn1per%20-%20Automated%20Pentest%20Recon%20Scanner&tw_p=tweetbutton&url=https%3A%2F%2Fgithub.com%2F1N3%2FSn1per)
[![Follow on Twitter](https://img.shields.io/twitter/follow/xer0dayz.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=xer0dayz)

## ABOUT:
Sn1per is an automated reconnaissance scanner that can be used to discover assets and scan for vulnerabilities using the latest open source tools and techniques. For our Professional and Enterprise versions of Sn1per, which includes a full featured web UI, go to https://sn1persecurity.com

[[Website](https://sn1persecurity.com/wordpress/)] [[Blog](https://sn1persecurity.com/wordpress/blog/)] [[Shop](https://sn1persecurity.com/wordpress/shop)] [[Documentation](https://sn1persecurity.com/wordpress/documentation/)] [[Demo](https://www.youtube.com/watch?v=bsUvB4Vca7Y&list=PL40Vp978dDP9KX2V3VLnNzgJuf4nJrRo9&index=1)] [[Find Out More](https://sn1persecurity.com/wordpress/sn1per-professional-v10-released/)]

[![](https://sn1persecurity.com/images/Sn1perSecurity-attack-surface-management-header2.png)](https://sn1persecurity.com/)

[![](https://sn1persecurity.com/images/Sn1perSecurity-sn1per3.PNG)](https://www.youtube.com/watch?v=bsUvB4Vca7Y&list=PL40Vp978dDP9KX2V3VLnNzgJuf4nJrRo9&index=1)

## USE CASES

### Attack Surface Management
Discover the attack surface and prioritize risk with our continuous Attack Surface Management platform.

### Automated OSINT & Reconnaissance
Automate the collection of open source intelligence data using our integrations with 3rd party API's, frameworks and automated workflows to get the data you need.

### Penetration Testing
Save time by automating the execution of the best open source and commercial security tools to discover and exploit vulnerabilities automatically.

### Automated Red Team Simulation
Simulate real world attackers with our automated attack platform in order to strengthen blue team response and defensive controls.

### Vulnerability & Risk Management
Integrate with the leading commercial and open source vulnerability scanners to scan for the latest vulnerabilities and prioritize risk with our aggregated vulnerability
reports.

### Dynamic Application Security Testing
Scan your web applications for vulnerabilities and aggregate data from multiple open source and commercial security scanners into our centralized reporting interface.

### Threat Intelligence
Stay up-to-date with the latest emerging security threats, vulnerabilities, data breaches and exploit releases.

### Bug Bounty Automation
Get the tools you need to manage large attack surfaces and gain the edge over the competition.

## FEATURES:

### Quick Installation
Get up and running with our platform in minutes with our quick and easy one-line installation script.

### Safe Execution
Get full control over your scans by setting the the scope and configuration options to ensure safe execution in your environment.

### Full Attack Surface Coverage
Discover both internal (on-prem) and external (cloud/hybrid) attack vectors for full asset visibility and vulnerability coverage.

### Vulnerability Scanning
Scan for the latest CVE's and vulnerabilities using the latest open source and commercial vulnerability scanners.

### Integrations
Aggregate data from the leading security tools, API's and 3rd party services into our centralized reporting interface.

### Continuous Scan Coverage
Schedule scans on a daily, weekly or monthly basis to identify changes in your attack surface and remediate new vulnerabilities as they appear.

### Notifications & Changes
Receive notifications for changes in your environment, such as: new domains, new URLs, port changes and more.

### IT Asset Inventory
Build a centralized repository of your company's assets that can be easily searched, sorted and filtered to provide full visibility into your attack surface.

### Attack Surface Reports
Export your entire attack surface inventory (ie. sub-domains, DNS, open ports, HTTP headers, risk score, etc.) to CSV, XLS or PDF format.

### Vulnerability Reports
Export vulnerability reports in CSV, XLS or PDF format for your entire attack surface.

## KALI/UBUNTU/DEBIAN/PARROT LINUX INSTALL:
```
git clone https://github.com/1N3/Sn1per
cd Sn1per
bash install.sh
```

## AWS AMI (FREE TIER) VPS
[![](https://sn1persecurity.com/wordpress/wp-content/uploads/2022/06/AWS-Marketplace.png)](https://aws.amazon.com/marketplace/pp/prodview-rmloab6wnymno)

To install Sn1per using a AWS EC2:

1. Go to https://aws.amazon.com/marketplace/pp/prodview-rmloab6wnymno and click the “Continue to Subscribe” button
2. Click the “Continue to Configuration” button
3. Click the “Continue to Launch” button
4. Login via SSH using the public IP of the new EC2 instance

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

## LICENSE & LEGAL AGREEMENT:
For license and legal information, refer to the LICENSE.md (https://github.com/1N3/Sn1per/blob/master/LICENSE.md) file in this repository. 

## PURCHASE SN1PER PROFESSIONAL:
To obtain a Sn1per Professional license, go to https://sn1persecurity.com.

Attack Surface Management (ASM) | Continuous Attack Surface Testing (CAST) | Attack Surface Software | Attack Surface Platform | Continuous Automated Red Teaming (CART) |  Vulnerability & Attack Surface Management | Red Team | Threat Intel | Application Security | Cybersecurity | IT Asset Discovery | Automated Penetration Testing | Hacking Tools | Recon Tool | Bug Bounty Tool | Vulnerability Scanner | Attack Surface Analysis | Attack Surface Reduction | Attack Surface Detector | Attack Surface Monitoring | Attack Surface Review | Attack Surface Discovery | Digital Threat Management | Risk Assessment | Threat Remediation | Offensive Security Framework | Automated Penetration Testing Framework | External Threat Management | Internal IT Asset Discovery | Security Orchestration and Automation (SOAR) | Sn1per tutorial | Sn1per tool | Sn1per metasploit | Sn1per for windows | Sn1per review | Sn1per download | how to use Sn1per | Sn1per professional download | Sn1per professional crack | automated pentesting framework | pentest-tools github | ad pentest tools | pentest-tools review | security testing tools | ubuntu pentesting tools | pentesting tools for mac | cloud-based pen-testing tools
