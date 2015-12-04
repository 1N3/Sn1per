#!/bin/bash
# Install script for sn1per
#
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
echo "Installing sn1per dependencies..."
apt-get install host whois theharvester dnsenum dnsrecon curl nmap php5 php5-curl wapiti hydra iceweasel wpscan sqlmap arachni w3af golismero nbtscan enum4linux cisco-torch metasploit-framework nikto smtp-user-enum whatweb python sslscan amap
git clone https://github.com/1N3/Findsploit.git
git clone https://github.com/1N3/BruteX.git
git clone https://github.com/1N3/Goohak.git
cp Goohak/goohak /usr/bin/ -f
git clone https://github.com/1N3/XSSTracer.git
git clone https://github.com/1N3/MassBleed.git
git clone https://github.com/1N3/SuperMicro-Password-Scanner
git clone https://github.com/Dionach/CMSmap.git
git clone https://github.com/0xsauby/yasuo.git
git clone https://github.com/vishnuraju/Breach-Miner-automated-.git Breach-Miner
mkdir loot
chmod +rx sniper
chmod +rx bin/dnsdict6
chmod +rx Goohak/goohak
ln -s $DIR/sniper /usr/bin/sniper
echo "Be sure to install the following packages manually and update the sniper script references: dig dnsdict6 cmsmap samrdump inurlbr wafw00f showmount samrdump rpcinfo snmpwalk"
echo "Done!"
