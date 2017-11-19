###TODO:

* Add command line parsing of options/modes

sniper --target crowdshield.com --workspace crowdshield.com --report --bruteforce --web --recon --portscan
sniper --target crowdshield.com --kalionly --offline --webportonly 443

* Create a sniper-kali release to only use base Kali image toolsets
* Check if there's an active internet connection, if not, run offline mode
* Add automatic reporting and workspace creation for all scans by default
* Add proxy support for all scans
* Create uninstall.sh script
* Add AWS security checks