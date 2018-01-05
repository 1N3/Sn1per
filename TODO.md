###TODO:

* Implement a module system for running specific commands/modules
* Add checks to make sure all commands exist at startup. If not, refer to installer. 
* Add command line parsing of options/modes

sniper --target crowdshield.com --workspace crowdshield.com --report --bruteforce --web --recon --portscan
sniper --target crowdshield.com --kalionly --offline --webportonly 443

* Create a sniper-kali release to only use base Kali image toolsets
* Check if there's an active internet connection, if not, run offline mode
* Add automatic reporting and workspace creation for all scans by default
* Add proxy support for all scans
* Create uninstall.sh script
* Add AWS security checks
* Look into adding aquatone
* Look into adding gobuster
* Update subdomain list with aquatone list
* Increase thread count for file/dir brute force