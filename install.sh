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

INSTALL_DIR=/usr/share/sniper
LOOT_DIR=/usr/share/sniper/loot
PLUGINS_DIR=/usr/share/sniper/plugins

echo -e "$OKGREEN + -- --=[This script will install sniper under $INSTALL_DIR. Are you sure you want to continue?$RESET"
read answer 

mkdir -p $INSTALL_DIR 2> /dev/null
mkdir -p $LOOT_DIR 2> /dev/null
mkdir $LOOT_DIR/domains 2> /dev/null
mkdir $LOOT_DIR/screenshots 2> /dev/null
mkdir $LOOT_DIR/nmap 2> /dev/null
mkdir $LOOT_DIR/reports 2> /dev/null
mkdir $LOOT_DIR/output 2> /dev/null
mkdir $LOOT_DIR/osint 2> /dev/null
cp -Rf $PWD/* $INSTALL_DIR 2> /dev/null
cd $INSTALL_DIR

echo -e "$OKORANGE + -- --=[Installing package dependencies...$RESET"
apt-get install eyewitness nodejs wafw00f xdg-utils metagoofil clusterd ruby rubygems python dos2unix zenmap sslyze arachni aha libxml2-utils rpcbind uniscan xprobe2 cutycapt unicornscan host whois dirb dnsrecon curl nmap php php-curl hydra iceweasel wpscan sqlmap nbtscan enum4linux cisco-torch metasploit-framework theharvester dnsenum nikto smtp-user-enum whatweb sslscan amap
apt-get install waffit 2> /dev/null
pip install dnspython colorama tldextract urllib3 ipaddress requests
curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.33.8/install.sh | bash

echo -e "$OKORANGE + -- --=[Installing gem dependencies...$RESET"
gem install aquatone
gem install rake
gem install ruby-nmap net-http-persistent mechanize text-table

echo -e "$OKORANGE + -- --=[Cleaning up old extensions...$RESET"
rm -Rf Findsploit/ BruteX/ Goohak/ XSSTracer/ MassBleed/ SuperMicro-Password-Scanner/ CMSmap/ yasuo/ Sublist3r/ shocker/ jexboss/ serializekiller/ testssl.sh/ SimpleEmailSpoofer/ ssh-audit/ plugins/ 2> /dev/null
mkdir $PLUGINS_DIR 2> /dev/null
cd $PLUGINS_DIR
mkdir -p $PLUGINS_DIR/nmap_scripts/ 2> /dev/null

echo -e "$OKORANGE + -- --=[Downloading extensions...$RESET"
git clone https://github.com/1N3/Findsploit.git 
git clone https://github.com/1N3/BruteX.git 
git clone https://github.com/1N3/Goohak.git 
git clone https://github.com/1N3/XSSTracer.git 
git clone https://github.com/1N3/MassBleed.git 
git clone https://github.com/1N3/SuperMicro-Password-Scanner 
git clone https://github.com/Dionach/CMSmap.git 
git clone https://github.com/0xsauby/yasuo.git 
git clone https://github.com/johndekroon/serializekiller.git 
git clone https://github.com/aboul3la/Sublist3r.git 
git clone https://github.com/nccgroup/shocker.git 
git clone --depth 1 https://github.com/drwetter/testssl.sh.git 
git clone https://github.com/lunarca/SimpleEmailSpoofer 
git clone https://github.com/arthepsy/ssh-audit 
git clone https://github.com/m0rtem/CloudFail.git
git clone https://github.com/deibit/cansina
git clone https://github.com/1N3/jexboss.git
wget https://github.com/bbb31/slurp/releases/download/1.3/slurp.zip
unzip slurp.zip
rm -f slurp.zip
wget https://github.com/michenriksen/aquatone/blob/master/subdomains.lst -O /usr/share/sniper/plugins/Sublist3r/subdomains.lst
wget https://raw.githubusercontent.com/1N3/IntruderPayloads/master/FuzzLists/dirbuster-quick.txt -O /usr/share/sniper/plugins/cansina/dirbuster-quick.txt
wget https://svn.nmap.org/nmap/scripts/http-vuln-cve2017-5638.nse -O /usr/share/nmap/scripts/http-vuln-cve2017-5638.nse
wget https://raw.githubusercontent.com/xorrbit/nmap/865142904566e416944ebd6870d496c730934965/scripts/http-vuln-INTEL-SA-00075.nse -O /usr/share/nmap/scripts/http-vuln-INTEL-SA-00075.nse
cp $INSTALL_DIR/bin/iis-buffer-overflow.nse /usr/share/nmap/scripts/iis-buffer-overflow.nse 2> /dev/null
echo -e "$OKORANGE + -- --=[Setting up environment...$RESET"
cd $PLUGINS_DIR/CloudFail/ && apt-get install python3-pip && pip3 install -r requirements.txt
cd $PLUGINS_DIR/Findsploit/ && bash install.sh
cd $PLUGINS_DIR/BruteX/ && bash install.sh
cd $INSTALL_DIR 
mkdir $LOOT_DIR 2> /dev/null
mkdir $LOOT_DIR/screenshots/ -p 2> /dev/null
mkdir $LOOT_DIR/nmap -p 2> /dev/null
mkdir $LOOT_DIR/domains -p 2> /dev/null
mkdir $LOOT_DIR/output -p 2> /dev/null
mkdir $LOOT_DIR/reports -p 2> /dev/null
cp -f $INSTALL_DIR/bin/clamav-exec.nse /usr/share/nmap/scripts/ 2> /dev/null
chmod +x $INSTALL_DIR/sniper
chmod +x $INSTALL_DIR/bin/dnsdict6
chmod +x $PLUGINS_DIR/Goohak/goohak
chmod +x $PLUGINS_DIR/XSSTracer/xsstracer.py
chmod +x $PLUGINS_DIR/MassBleed/massbleed
chmod +x $PLUGINS_DIR/MassBleed/heartbleed.py
chmod +x $PLUGINS_DIR/MassBleed/openssl_ccs.pl
chmod +x $PLUGINS_DIR/MassBleed/winshock.sh 
chmod +x $PLUGINS_DIR/SuperMicro-Password-Scanner/supermicro_scan.sh
chmod +x $PLUGINS_DIR/testssl.sh/testssl.sh
rm -f /usr/bin/sniper
rm -f /usr/bin/goohak
rm -f /usr/bin/xsstracer
rm -f /usr/bin/findsploit
rm -f /usr/bin/copysploit
rm -f /usr/bin/compilesploit
rm -f /usr/bin/massbleed
rm -f /usr/bin/testssl
ln -s $INSTALL_DIR/sniper /usr/bin/sniper
ln -s $PLUGINS_DIR/Goohak/goohak /usr/bin/goohak
ln -s $PLUGINS_DIR/XSSTracer/xsstracer.py /usr/bin/xsstracer
ln -s $PLUGINS_DIR/Findsploit/findsploit /usr/bin/findsploit
ln -s $PLUGINS_DIR/Findsploit/copysploit /usr/bin/copysploit
ln -s $PLUGINS_DIR/Findsploit/compilesploit /usr/bin/compilesploit
ln -s $PLUGINS_DIR/MassBleed/massbleed /usr/bin/massbleed
ln -s $PLUGINS_DIR/testssl.sh/testssl.sh /usr/bin/testssl
msfdb init 
msfdb start
echo -e "$OKORANGE + -- --=[Done!$RESET"
echo -e "$OKORANGE + -- --=[To run, type 'sniper'! $RESET"
