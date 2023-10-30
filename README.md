[![Sn1perSecurity](https://sn1persecurity.com/images/Sn1perSecurity-Attack-Surface-Management-header2.png)](https://sn1persecurity.com)

[![GitHub release](https://img.shields.io/github/release/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/releases)
[![GitHub issues](https://img.shields.io/github/issues/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/issues)
[![Github Stars](https://img.shields.io/github/stars/1N3/Sn1per.svg?style=social&label=Stars)](https://github.com/1N3/Sn1per/)
[![GitHub Followers](https://img.shields.io/github/followers/1N3.svg?style=social&label=Follow)](https://github.com/1N3/Sn1per/)
[![Tweet](https://img.shields.io/twitter/url/http/xer0dayz.svg?style=social)](https://twitter.com/intent/tweet?original_referer=https%3A%2F%2Fdeveloper.twitter.com%2Fen%2Fdocs%2Ftwitter-for-websites%2Ftweet-button%2Foverview&ref_src=twsrc%5Etfw&text=Sn1per%20-%20Automated%20Pentest%20Recon%20Scanner&tw_p=tweetbutton&url=https%3A%2F%2Fgithub.com%2F1N3%2FSn1per)
[![Follow on Twitter](https://img.shields.io/twitter/follow/xer0dayz.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=xer0dayz)

[[Website](https://sn1persecurity.com/wordpress/)] [[Blog](https://sn1persecurity.com/wordpress/blog/)] [[Shop](https://sn1persecurity.com/wordpress/shop)] [[Documentation](https://sn1persecurity.com/wordpress/documentation/)] [[Demo](https://www.youtube.com/c/Sn1perSecurity/videos)] [[Find Out More](https://sn1persecurity.com/wordpress/external-attack-surface-management-with-sn1per/)]


## Attack Surface Management Platform

### Discover hidden assets and vulnerabilities in your environment

#### [[Find out more](https://sn1persecurity.com/wordpress/shop)]

[![](https://sn1persecurity.com/wordpress/wp-content/uploads/2022/05/Sn1per-Enterprise-workspace-navigator1-3.png)](https://sn1persecurity.com/)

## The ultimate pentesting toolkit

Integrate with the leading commercial and open source vulnerability scanners to scan for the latest CVEs and vulnerabilities.

[![](https://sn1persecurity.com/wordpress/wp-content/uploads/2022/05/Sn1per-Enterprise-workspace-report1-3.png)](https://sn1persecurity.com/)

### Automate the most powerful tools

Security tools are expensive and time-consuming, but with Sn1per, you can save time by automating the execution of these open source and commercial tools to discover vulnerabilities across your entire attack surface.

[![](https://sn1persecurity.com/wordpress/wp-content/uploads/2022/05/Sn1per-Enterprise-host-list3-1.png)](https://sn1persecurity.com/)

### Find what you can't see

Hacking is a problem that's only getting worse. But, with Sn1per, you can find what you can’t see—hidden assets and vulnerabilities in your environment.

[![](https://sn1persecurity.com/wordpress/wp-content/uploads/2022/05/Sn1per-Enterprise-host-list2-1.png)](https://sn1persecurity.com/)

### Discover and prioritize risks in your organization

Sn1per is a next-generation information gathering tool that provides automated, deep, and continuous security for organizations of all sizes.

[![](https://sn1persecurity.com/wordpress/wp-content/uploads/2022/05/Sn1per-Enterprise-vulnerability-report1-3.png)](https://sn1persecurity.com/)

### See Sn1per in action

[![](https://sn1persecurity.com/wordpress/wp-content/uploads/2022/10/Sn1perbootcampseries1.png)](https://www.youtube.com/c/Sn1perSecurity/videos)

### News

- #### [Sn1per Enterprise v20231025 Released!](https://sn1persecurity.com/wordpress/sn1per-enterprise-v20231025-released/)
- #### [Automated Penetration Testing Guide - Your Ultimate Resource](https://sn1persecurity.com/wordpress/penetration-testing-guide/)
- #### [Dark Web Monitoring: Securing Your External Attack Surface](https://sn1persecurity.com/wordpress/dark-web-monitoring-securing-your-external-attack-surface/)
- #### [Sn1per Scan Engine v10.4 Released!](https://sn1persecurity.com/wordpress/sn1per-scan-engine-v10-4-released/)
- #### [Sn1per: The Next Generation of Tools for Security Professionals](https://sn1persecurity.com/wordpress/sn1per-the-next-generation-of-tools-for-security-professionals/)
- #### [5 Ways Sn1per Can Automate Your Security Workflow](https://sn1persecurity.com/wordpress/5-ways-sn1per-can-automate-your-security-workflow/)
- #### [External Attack Surface Management with Sn1per](https://sn1persecurity.com/wordpress/external-attack-surface-management-with-sn1per/)
- #### [Sn1per Enterprise Released!](https://sn1persecurity.com/wordpress/sn1per-enterprise-released/)
- #### [Sn1per Professional v10.0 Released!](https://sn1persecurity.com/wordpress/sn1per-professional-v10-released/)

## Kali/Ubuntu/Debian/Parrot Linux Install

```
git clone https://github.com/1N3/Sn1per
cd Sn1per
bash install.sh
```

## AWS AMI (Free Tier) VPS Install

[![](https://sn1persecurity.com/wordpress/wp-content/uploads/2022/06/AWS-Marketplace.png)](https://aws.amazon.com/marketplace/pp/prodview-rmloab6wnymno)

To install Sn1per using an AWS EC2 instance:

1. Go to <https://aws.amazon.com/marketplace/pp/prodview-rmloab6wnymno> and click the “Continue to Subscribe” button
2. Click the “Continue to Configuration” button
3. Click the “Continue to Launch” button
4. Login via SSH using the public IP of the new EC2 instance

## Docker Install

[![](https://sn1persecurity.com/images/docker-logo.png)](https://hub.docker.com/r/sn1persecurity/sn1per)

### Kali Linux-based Sn1per

1. Run the Docker Compose file

    ```bash
    sudo docker compose up
    ```

1. Run the container

    ```bash
    sudo docker run -it sn1per-kali-linux /bin/bash
    ```

### BlackArch-based Sn1per

1. Run the Docker Compose file

    ```bash
    sudo docker compose -f docker-compose-blackarch.yml up
    ```

1. Run the container

    ```bash
    sudo docker run -it sn1per-blackarch /bin/bash
    ```

## Usage

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

## Modes

- **NORMAL:** Performs basic scan of targets and open ports using both active and passive checks for optimal performance.

- **STEALTH:** Quickly enumerate single targets using mostly non-intrusive scans to avoid WAF/IPS blocking.
- **FLYOVER:** Fast multi-threaded high level scans of multiple targets (useful for collecting high level data on many hosts quickly).
- **AIRSTRIKE:** Quickly enumerates open ports/services on multiple hosts and performs basic fingerprinting. To use, specify the full location of the file which contains all hosts, IPs that need to be scanned and run ./sn1per /full/path/to/targets.txt airstrike to begin scanning.
- **NUKE:** Launch full audit of multiple hosts specified in text file of choice. Usage example: ./sniper /pentest/loot/targets.txt nuke.
- **DISCOVER:** Parses all hosts on a subnet/CIDR (ie. 192.168.0.0/16) and initiates a sniper scan against each host. Useful for internal network scans.
- **PORT:** Scans a specific port for vulnerabilities. Reporting is not currently available in this mode.
- **FULLPORTONLY:** Performs a full detailed port scan and saves results to XML.
- **MASSPORTSCAN:** Runs a "fullportonly" scan on mutiple targets specified via the "-f" switch.
- **WEB:** Adds full automatic web application scans to the results (port 80/tcp & 443/tcp only). Ideal for web applications but may increase scan time significantly.
- **MASSWEB:** Runs "web" mode scans on multiple targets specified via the "-f" switch.
- **WEBPORTHTTP:** Launches a full HTTP web application scan against a specific host and port.
- **WEBPORTHTTPS:** Launches a full HTTPS web application scan against a specific host and port.
- **WEBSCAN:** Launches a full HTTP & HTTPS web application scan against via Burpsuite and Arachni.
- **MASSWEBSCAN:** Runs "webscan" mode scans of multiple targets specified via the "-f" switch.
- **VULNSCAN:** Launches a OpenVAS vulnerability scan.
- **MASSVULNSCAN:** Launches a "vulnscan" mode scans on multiple targets specified via the "-f" switch.

## Help Topics

- [x] [Plugins & Tools](https://github.com/1N3/Sn1per/wiki/Plugins-&-Tools)
- [x] [Scheduled Scans](https://github.com/1N3/Sn1per/wiki/Scheduled-Scans)
- [x] [Sn1per Configuration Options](https://github.com/1N3/Sn1per/wiki/Sn1per-Configuration-Options)
- [x] [Sn1per Configuration Templates](https://github.com/1N3/Sn1per/wiki/Sn1per-Configuration-Templates)
- [x] [Sc0pe Templates](https://github.com/1N3/Sn1per/wiki/Sc0pe-Templates)

## Integration Guides

- [x] [Github API integration](https://github.com/1N3/Sn1per/wiki/Github-API-Integration)
- [x] [Burpsuite Professional 2.x integration](https://github.com/1N3/Sn1per/wiki/Burpsuite-Professional-2.x-Integration)
- [x] [OWASP ZAP integration](https://github.com/1N3/Sn1per/wiki/OWASP-ZAP-Integration)
- [x] [Shodan API integration](https://github.com/1N3/Sn1per/wiki/Shodan-Integration)
- [x] [Censys API integration](https://github.com/1N3/Sn1per/wiki/Censys-API-Integration)
- [x] [Hunter.io API integration](https://github.com/1N3/Sn1per/wiki/Hunter.io-API-Integration)
- [x] [Metasploit integration](https://github.com/1N3/Sn1per/wiki/Metasploit-Integration)
- [x] [Nessus integration](https://github.com/1N3/Sn1per/wiki/Nessus-Integration)
- [x] [OpenVAS API integration](https://github.com/1N3/Sn1per/wiki/OpenVAS-Integration)
- [x] [GVM 21.x integration](https://github.com/1N3/Sn1per/wiki/GVM-21.x-Integration)
- [x] [Slack API integration](https://github.com/1N3/Sn1per/wiki/Slack-API-Integration)
- [x] [WPScan API integration](https://github.com/1N3/Sn1per/wiki/WPScan-API-Integration)

## License & Legal Agreement

For license and legal information, refer to the [LICENSE.md](https://github.com/1N3/Sn1per/blob/master/LICENSE.md) file in this repository.

## Purchase Sn1per Professional

To obtain a Sn1per Professional license, go to <https://sn1persecurity.com>.

External attack surface management, Attack surface monitoring, Attack Surface Management Platform, Attack Surface Management Solutions, Vulnerability management, Threat intelligence, Cybersecurity risk assessment, Security posture assessment, Digital footprint analysis, Attack surface mapping, Web application security, Network security, Infrastructure security, Cloud security, Third-party risk management, Incident response, Penetration testing, Asset discovery, Patch management, Security scanning, Firewall configuration, Intrusion detection system, Security awareness training, Data breach prevention, Web server security, Endpoint security, Phishing protection, Vulnerability assessment, Network security, Web application testing, Ethical hacking, Security assessment, Information security, Red teaming, Cybersecurity testing, Pen testing tools, Exploitation techniques, Wireless network testing, Social engineering, Security auditing, Incident response, Intrusion detection, Firewall testing, Security assessment methodology, Risk assessment, Security controls, Web vulnerability scanning, Password cracking, Security testing services, Security architecture, System hardening, Network reconnaissance, Red teaming, Penetration testing, Cybersecurity, Vulnerability assessment, Attack simulation, Threat intelligence, Risk assessment, Security testing, Adversarial tactics, Incident response, Security assessment, Network security, Defensive measures, Security controls, Social engineering, Exploitation techniques, Security awareness, Defensive strategies, Risk mitigation, Blue teaming, Security operations, Intrusion detection, Security frameworks, Cyber defense, Information security
