#!/bin/bash
# Install script for sn1per
#
echo "Installing sn1per dependencies..."
apt-get install host whois theharvester dnsenum curl nmap php5 php5-curl wapiti hydra iceweasel wpscan sqlmap arachni w3af golismero nbtscan enum4linux cisco-torch metasploit-framework theharvester nmap dnsenum nikto smtp-user-enum whatweb python nbtscan sslscan amap
git clone https://github.com/1N3/Findsploit.git
git clone https://github.com/1N3/BruteX.git
git clone https://github.com/1N3/Goohak.git
git clone https://github.com/1N3/XSSTracer.git
git clone https://github.com/1N3/SuperMicro-Password-Scanner
git clone https://github.com/Dionach/CMSmap.git
mkdir loot
chmod +rx sniper
echo "Be sure to install the following packages manually and update the sniper script references: dig dnsdict6 cmsmap samrdump inurlbr wafw00f showmount samrdump rpcinfo snmpwalk"
echo "Done!"
