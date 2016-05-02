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
* Automatically exploit remote hosts to gain remote shell access
* Performs high level enumeration of multiple hosts
* Auto-pwn added for Metasploitable, ShellShock, MS08-067, Default Tomcat Creds

## INSTALL:
```
./install.sh - Installs all dependencies OR upgrades existing Sn1per installations. Best run from Kali Linux. 
```

## USAGE:
```
# ./sniper <target> <report>
# ./sniper <target> stealth <report>
# ./sniper <target> port <portnum> 
# ./sniper <target> web <report>
# ./sniper <target> nobrute <report>
# ./sniper <targets.txt> airstrike <report>
# ./sniper <targets.txt> nuke <report>
```

### MODES:
* REPORT: Outputs all results to text in the loot directory for later reference. To enable reporting, append 'report' to any sniper mode or command.
* STEALTH: Quickly enumerate single targets using mostly non-intrusive scans to avoid WAF/IPS blocking
* PORT: Scans a specific port for vulnerabilities. Reporting is not currently available in this mode.
* WEB: Adds full automatic web application scans to the results (port 80/tcp & 443/tcp only). Ideal for web applications but may increase scan time significantly.   
* NOBRUTE: Launches a full scan against a target host/domain without brute forcing services.
* AIRSTRIKE: Quickly enumerates open ports/services on multiple hosts and performs basic fingerprinting. To use, specify the full location of the file which contains all hosts, IP's that need to be scanned and run ./sn1per /full/path/to/targets.txt airstrike to begin scanning.
* NUKE: Launch full audit of multiple hosts specified in text file of choice. Usage example: ./sniper /pentest/loot/targets.txt nuke. 

## SAMPLE REPORT:
```
https://gist.github.com/1N3/8214ec2da2c91691bcbc
```

## CHANGELOG:
* v1.7 - Improved web scan performance
* v1.7 - Fixed issue with inurlbr output
* v1.7 - Added remote desktop viewing for RDP connections
* v1.7 - Added experimental Metasploit exploit for Apache Struts RCE (CVE-2016-3081)
* v1.6e - Added reporting option for nobrute mode (CC. @mero01)
* v1.6e - Improved SMB scan performance/optimization added
* v1.6d - Improved NMap scan performance options
* v1.6d - Added xprobe2 OS finger printing tool
* v1.6d - Added jexbos JBoss autopwn
* v1.6d - Merged fix for theharvester package (CC. @RubenRocha)
* v1.6d - Merged fix for SuperMicroScanner (CC. @mero01)
* v1.6c - Add report mode for web scans
* v1.6c - Fixed issues with Sublist3r and theharvester
* v1.6c - Added Shocker Shellshock exploitation scanner
* v1.6b - Added Sublist3r sub-domain brute tool
* v1.6b - Added cutycapt web screenshot util
* v1.6a - Added improvements to recon phase
* v1.6a - Fixed small issue with 3rd party extension
* v1.6a - Various improvements to overall optimization of scans
* v1.6a - Added new "web" mode for full web application scans 
* v1.6 - Added 4 new modes including: stealth, port, airstrike and nuke
* v1.6 - Added Java de-serialization scanner
* v1.6 - Added reporting option to output to console and text file for all scans
* v1.6 - Added option to set Sn1per full path for universal command line access
* v1.6 - Added in DirBuster for web file brute forcing
* v1.6 - Fixed issue with sderr errors in TheHarvester
* v1.5e - Removed shodan command line tool due to issues
* v1.5e - Fixed wafwoof installation in kali 2.0
* v1.5d - Fixed minor issues with port 513/tmp and 514/tcp checks
* v1.5c - Fixed issue which broke link to sniper directory
* v1.5b - Added Squid Proxy checks port 3128/tcp
* v1.5b - Fixed shodan setup options in install.sh
* v1.5b - Fixed syntax error with theHarvester in install.sh
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
* Look into HTML reporting options
