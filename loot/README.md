+ -- --=[Sn1per v1.4g by 1N3
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
./install.sh - Installs all dependencies OR upgrades existing Sn1per installations. Best run from Kali Linux. 
```

## USAGE:
```
./sn1per <target>
```

## SAMPLE REPORT:
https://goo.gl/96LCAg

## CHANGELOG:
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

