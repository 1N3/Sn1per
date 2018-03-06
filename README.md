![alt tag](https://github.com/1N3/Sn1per/blob/master/Sn1per.jpg)

## ABOUT:
Sn1per is an automated scanner that can be used during a penetration test to enumerate and scan for vulnerabilities. 

## DEMO VIDEO:
[![Demo](https://asciinema.org/a/IDckE48BNSWQ8TV8yEjJjjMNm.png)](https://asciinema.org/a/IDckE48BNSWQ8TV8yEjJjjMNm)

## FEATURES:
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

## KALI LINUX INSTALL:
```
./install.sh
```

## DOCKER INSTALL:

Credits: @menzow

Docker Install:
https://github.com/menzow/sn1per-docker

Docker Build:
https://hub.docker.com/r/menzo/sn1per-docker/builds/bqez3h7hwfun4odgd2axvn4/

Example usage:
```
$ docker pull menzo/sn1per-docker
$ docker run --rm -ti menzo/sn1per-docker sniper menzo.io
```

## USAGE:
```
[*] NORMAL MODE
sniper -t|--target <TARGET>

[*] NORMAL MODE + OSINT + RECON
sniper -t|--target <TARGET> -o|--osint -re|--recon

[*] STEALTH MODE + OSINT + RECON
sniper -t|--target <TARGET> -m|--mode stealth -o|--osint -re|--recon

[*] DISCOVER MODE
sniper -t|--target <CIDR> -m|--mode discover -w|--workspace <WORSPACE_ALIAS>

[*] SCAN ONLY SPECIFIC PORT
sniper -t|--target <TARGET> -m port -p|--port <portnum>

[*] FULLPORTONLY SCAN MODE
sniper -t|--target <TARGET> -fp|--fullportonly

[*] PORT SCAN MODE
sniper -t|--target <TARGET> -m|--mode port -p|--port <PORT_NUM>

[*] WEB MODE - PORT 80 + 443 ONLY!
sniper -t|--target <TARGET> -m|--mode web

[*] HTTP WEB PORT MODE
sniper -t|--target <TARGET> -m|--mode webporthttp -p|--port <port>

[*] HTTPS WEB PORT MODE
sniper -t|--target <TARGET> -m|--mode webporthttps -p|--port <port>

[*] ENABLE BRUTEFORCE
sniper -t|--target <TARGET> -b|--bruteforce

[*] AIRSTRIKE MODE
sniper -f|--file /full/path/to/targets.txt -m|--mode airstrike

[*] NUKE MODE WITH TARGET LIST, BRUTEFORCE ENABLED, FULLPORTSCAN ENABLED, OSINT ENABLED, RECON ENABLED, WORKSPACE & LOOT ENABLED
sniper -f--file /full/path/to/targets.txt -m|--mode nuke -w|--workspace <WORKSPACE_ALIAS>

[*] ENABLE LOOT IMPORTING INTO METASPLOIT
sniper -t|--target <TARGET>

[*] LOOT REIMPORT FUNCTION
sniper -w <WORKSPACE_ALIAS> --reimport

[*] UPDATE SNIPER
sniper -u|--update
```

### MODES:
* **NORMAL:** Performs basic scan of targets and open ports using both active and passive checks for optimal performance.
* **STEALTH:** Quickly enumerate single targets using mostly non-intrusive scans to avoid WAF/IPS blocking.
* **AIRSTRIKE:** Quickly enumerates open ports/services on multiple hosts and performs basic fingerprinting. To use, specify the full location of the file which contains all hosts, IPs that need to be scanned and run ./sn1per /full/path/to/targets.txt airstrike to begin scanning.
* **NUKE:** Launch full audit of multiple hosts specified in text file of choice. Usage example: ./sniper /pentest/loot/targets.txt nuke. 
* **DISCOVER:** Parses all hosts on a subnet/CIDR (ie. 192.168.0.0/16) and initiates a sniper scan against each host. Useful for internal network scans.
* **PORT:** Scans a specific port for vulnerabilities. Reporting is not currently available in this mode.
* **FULLPORTONLY:** Performs a full detailed port scan and saves results to XML.
* **WEB:** Adds full automatic web application scans to the results (port 80/tcp & 443/tcp only). Ideal for web applications but may increase scan time significantly.   
* **WEBPORTHTTP:** Launches a full HTTP web application scan against a specific host and port.
* **WEBPORTHTTPS:** Launches a full HTTPS web application scan against a specific host and port.
* **UPDATE:** Checks for updates and upgrades all components used by sniper.
* **REIMPORT:** Reimport all workspace files into Metasploit and reproduce all reports.

## SAMPLE REPORT:
https://gist.github.com/1N3/8214ec2da2c91691bcbc

## LICENSE:
This software is free to distribute, modify and use with the condition that credit is provided to the creator (1N3@CrowdShield) and is not for commercial use.

## LOGO:
Credit to Sponge Nutter for the original sniper penguin logo.

## DONATIONS:
Donations are welcome. This will help fascilitate improved features, frequent updates and better overall support for sniper.
- [x] BTC 1Fav36btfmdrYpCAR65XjKHhxuJJwFyKum
- [x] ETH 0x20bB09273702eaBDFbEE9809473Fd04b969a794d
- [x] LTC LQ6mPewec3xeLBYMdRP4yzeta6b9urqs2f
- [x] XMR 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbS3EN24xprAQ1Z5Sy5s
- [x] ZCASH t1fsizsk2cqqJAjRoUmXJSyoVa9utYucXt7