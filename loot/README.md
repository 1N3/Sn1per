# Sn1per - Automated Pentest Recon Scanner
![alt tag](https://github.com/1N3/Sn1per/blob/master/Sn1per-logo.png)

## ABOUT:
Sn1per is an automated scanner that can be used during a penetration test to enumerate and scan for vulnerabilities. 

## FEATURES:
* Automatically collects basic recon (ie. whois, ping, DNS, etc.)
* Automatically launches Google hacking queries against a target domain
* Automatically enumerates open ports
* Automatically brute forces sub-domains and DNS info
* Automatically runs targeted NMap scripts against open ports
* Automatically runs targeted Metasploit scan and exploit modules
* Automatically scans all web applications for common vulnerabilities
* Automatically brute forces all open services

## INSTALL:
```
./install.sh - Installs all dependencies OR upgrades existing Sn1per installations. Best run from Kali Linux. 
```

## USAGE:
```
./sn1per <target>
```

## SAMPLE REPORT:
```
https://gist.github.com/1N3/8214ec2da2c91691bcbc
```

## CHANGELOG:
* v1.5a - Fixed syntax error with port 8081 checks
* v1.5a - Added Arachni integration
* v1.5a - Added vsftpd, proftpd, mysql, unrealircd auto exploits
* v1.5 - Added Metasploit scan and auto-exploit modules
* v1.5 - Added additional port checks
* v1.5 - Added full TCP/UDP NMap XML output
* v1.5 - Auto tune scan for either IP or hostname/domain
* v1.4h - Added auto IP/domain name scan configurations
* v1.4g - Added finger enumeration scripts
* v1.4g - Fixed nmap -p 445 target issue
* v1.4g - Fixed smtp-enum target issue
* v1.4f - Fixed BruteX directory bug
* v1.4e - Fixed reported errors install.sh
* v1.4e - Added auto-upgrade option to install.sh for existing Sn1per installs
* v1.4d - Fixed missing rake gem install dependency
* v1.4c - Reordered 3rd party extensions
* v1.4b - Fixed install.sh executable references
* v1.4b - Fixed Yasou dependencies in install.sh
* v1.4b - Fixed minor issues with BruteX loot directory
* v1.4 - Added Yasou for automatic web form brute forcing
* v1.4 - Added MassBleed for SSL vulnerability detection
* v1.4 - Added Breach-Miner for detection of breached accounts
* v1.4 - Fixed minor errors with nmap
* v1.4 - Removed debug output from goohak from displaying on console

## FUTURE:
* Add in detection and auto exploitation for Tomcat, JBoss, PHPMyAdmin
* Add in Juniper backdoor password to password list
* Add auth bypass string to password list
* Add in OpenVAS integration
* Look into HTML reporting or text based output options to save scan data
