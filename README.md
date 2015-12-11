+ -- --=[Sn1per v1.4c by 1N3
+ -- --=[http://crowdshield.com
 
# Sn1per - Automated Pentest Recon Scanner

## ABOUT:
Sn1per is an automated scanner that can be used during a penetration test to enumerate and scan for vulnerabilities. 

## FEATURES:
* Automatically collects basic recon (ie. whois, ping, DNS, etc.)
* Automatically launches Google hacking queries against a target domain
* Automatically enumerates open ports
* Automatically brute forces sub-domains and DNS info
* Automatically runs targeted nmap scripts against open ports
* Automatically scans all web applications for common vulnerabilities
* Automatically brute forces all open services

## INSTALL:
```
./install.sh - Installs all dependencies. Best run from Kali Linux. 
```

## USAGE:
```
./sn1per <target>
```

## SAMPLE REPORT:
https://goo.gl/96LCAg

## CHANGELOG:
* v1.4c - Reordered 3rd party extensions
* v1.4b - Fixed install.sh executable references
* v1.4b - Fixed Yasou dependencies in install.sh
* v1.4b - Fixed minor issues with BruteX loot directory
* v1.4 - Added Yasou for automatic web form brute forcing
* v1.4 - Added MassBleed for SSL vulnerability detection
* v1.4 - Added Breach-Miner for detection of breached accounts
* v1.4 - Fixed minor errors with nmap
* v1.4 - Removed debug output from goohak from displaying on console

