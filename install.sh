#!/bin/bash
# Install script for sn1per
#
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
echo "Installing sn1per dependencies..."
apt-get install host whois theharvester dnsenum dnsrecon curl nmap php5 php5-curl wapiti hydra iceweasel wpscan sqlmap arachni w3af golismero nbtscan enum4linux cisco-torch metasploit-framework theharvester dnsenum nikto smtp-user-enum whatweb python nbtscan sslscan amap
git clone https://github.com/1N3/Findsploit.git
git clone https://github.com/1N3/BruteX.git
git clone https://github.com/1N3/Goohak.git
git clone https://github.com/1N3/XSSTracer.git
git clone https://github.com/1N3/MassBleed.git
git clone https://github.com/1N3/SuperMicro-Password-Scanner
git clone https://github.com/Dionach/CMSmap.git
git clone https://github.com/0xsauby/yasuo.git
gem install ruby-nmap net-http-persistent mechanize text-table
git clone https://github.com/vishnuraju/Breach-Miner-automated-.git Breach-Miner
mkdir loot
chmod +rx $DIR/sniper
chmod +rx $DIR/bin/dnsdict6
chmod +rx $DIR/Goohak/goohak
chmod +rx $DIR/XSSTracer/xsstracer.py
ln -s $DIR/sniper /usr/bin/sniper
ln -s $DIR/Goohak/goohak /usr/bin/goohak
ln -s $DIR/XSSTracer/xsstracer.py /usr/bin/xsstracer
ln -s $DIR/Findsploit/findsploit /usr/bin/findsploit
ln -s $DIR/Findsploit/copysploit /usr/bin/copysploit
ln -s $DIR/Findsploit/compilesploit /usr/bin/compilesploit
ln -s $DIR/MassBleed/massbleed /usr/bin/massbleed
ln -s $DIR/BruteX/brutex /usr/bin/brutex
echo "Be sure to install the following packages manually and update the sniper script references: dig dnsdict6 cmsmap samrdump inurlbr wafw00f showmount samrdump rpcinfo snmpwalk"
echo "Done!"
