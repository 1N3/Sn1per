#!/bin/bash
# Install script for sn1per
#
# VARS
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'

echo -e "$OKRED                ____               $RESET"
echo -e "$OKRED    _________  /  _/___  ___  _____$RESET"
echo -e "$OKRED   / ___/ __ \ / // __ \/ _ \/ ___/$RESET"
echo -e "$OKRED  (__  ) / / // // /_/ /  __/ /    $RESET"
echo -e "$OKRED /____/_/ /_/___/ .___/\___/_/     $RESET"
echo -e "$OKRED               /_/                 $RESET"
echo -e "$RESET"
echo -e "$OKORANGE + -- --=[http://crowdshield.com$RESET"
echo ""

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

echo -e "$OKGREEN + -- --=[This script will install or upgrade your Sn1per installation. Are you sure you want to continue?$RESET"
read answer

echo -e "$OKORANGE + -- --=[Installing package dependencies...$RESET"
apt-get install host whois theharvester dnsenum dnsrecon curl nmap php5 php5-curl wapiti hydra iceweasel wpscan sqlmap arachni w3af golismero nbtscan enum4linux cisco-torch metasploit-framework theharvester dnsenum nikto smtp-user-enum whatweb python nbtscan sslscan amap

echo -e "$OKORANGE + -- --=[Installing gem dependencies...$RESET"
gem install ruby-nmap net-http-persistent mechanize text-table rake

echo -e "$OKORANGE + -- --=[Cleaning up old extensions...$RESET"
rm -Rf Findsploit/ Brutex/ Goohak/ XSSTracer/ MassBleed/ SuperMicro-Password-Scanner/ CMSmap/ yasuo/ Breach-Miner/

echo -e "$OKORANGE + -- --=[Downloading extensions...$RESET"
git clone https://github.com/1N3/Findsploit.git
git clone https://github.com/1N3/BruteX.git
git clone https://github.com/1N3/Goohak.git
git clone https://github.com/1N3/XSSTracer.git
git clone https://github.com/1N3/MassBleed.git
git clone https://github.com/1N3/SuperMicro-Password-Scanner
git clone https://github.com/Dionach/CMSmap.git
git clone https://github.com/0xsauby/yasuo.git
git clone https://github.com/vishnuraju/Breach-Miner-automated-.git Breach-Miner

echo -e "$OKORANGE + -- --=[Setting up environment...$RESET"
mkdir loot 2> /dev/null
chmod +x $DIR/sniper
chmod +x $DIR/bin/dnsdict6
chmod +x $DIR/Goohak/goohak
chmod +x $DIR/XSSTracer/xsstracer.py
chmod +x $DIR/MassBleed/massbleed
chmod +x $DIR/MassBleed/heartbleed.py
chmod +x $DIR/MassBleed/openssl_ccs.pl
rm -f /usr/bin/sniper
rm -f /usr/bin/goohak
rm -f /usr/bin/xsstracer
rm -f /usr/bin/findsploit
rm -f /usr/bin/copysploit
rm -f /usr/bin/compilesploit
rm -f /usr/bin/massbleed
rm -f /usr/bin/brutex
ln -s $DIR/sniper /usr/bin/sniper
ln -s $DIR/Goohak/goohak /usr/bin/goohak
ln -s $DIR/XSSTracer/xsstracer.py /usr/bin/xsstracer
ln -s $DIR/Findsploit/findsploit /usr/bin/findsploit
ln -s $DIR/Findsploit/copysploit /usr/bin/copysploit
ln -s $DIR/Findsploit/compilesploit /usr/bin/compilesploit
ln -s $DIR/MassBleed/massbleed /usr/bin/massbleed
ln -s $DIR/BruteX/brutex /usr/bin/brutex

echo -e "$OKORANGE + -- --=[Done!$RESET"

# REMOVED BUT STILL AVAILABLE IF NEEDED
# echo -e "$OKGREEN + -- --=[Be sure to install the following packages manually and update the sniper script references: dig dnsdict6 cmsmap samrdump inurlbr wafw00f showmount samrdump rpcinfo snmpwalk$RESET"

