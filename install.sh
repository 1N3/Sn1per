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

# DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
INSTALL_DIR=/usr/share/sniper

echo -e "$OKGREEN + -- --=[This script will install sniper under $INSTALL_DIR. Are you sure you want to continue?$RESET"
read answer 

mkdir -p $INSTALL_DIR 2> /dev/null
cp -Rf $PWD/* $INSTALL_DIR 
cd $INSTALL_DIR

echo -e "$OKORANGE + -- --=[Installing package dependencies...$RESET"
apt-get install ruby nslookup rubygems python dos2unix zenmap sslyze uniscan xprobe2 cutycapt unicornscan waffit host whois dirb dnsrecon curl nmap php5 php5-curl hydra iceweasel wpscan sqlmap nbtscan enum4linux cisco-torch metasploit-framework theharvester dnsenum nikto smtp-user-enum whatweb sslscan amap
pip install dnspython colorama tldextract urllib3 ipaddress

echo -e "$OKORANGE + -- --=[Installing gem dependencies...$RESET"
gem install rake
gem install ruby-nmap net-http-persistent mechanize text-table

echo -e "$OKORANGE + -- --=[Cleaning up old extensions...$RESET"
rm -Rf Findsploit/ BruteX/ Goohak/ XSSTracer/ MassBleed/ SuperMicro-Password-Scanner/ CMSmap/ yasuo/ Sublist3r/ shocker/ jexboss/ serializekiller/ testssl.sh/ SimpleEmailSpoofer/ ssh-audit/

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
git clone https://github.com/joaomatosf/jexboss.git
git clone https://github.com/drwetter/testssl.sh.git
git clone https://github.com/lunarca/SimpleEmailSpoofer
git clone https://github.com/arthepsy/ssh-audit
echo -e "$OKORANGE + -- --=[Setting up environment...$RESET"
cd $INSTALL_DIR/BruteX/
bash install.sh
cd .. 
mkdir loot 2> /dev/null
cp -f $INSTALL_DIR/bin/clamav-exec.nse /usr/share/nmap/scripts/ 2> /dev/null
chmod +x $INSTALL_DIR/sniper
chmod +x $INSTALL_DIR/bin/dnsdict6
chmod +x $INSTALL_DIR/Goohak/goohak
chmod +x $INSTALL_DIR/XSSTracer/xsstracer.py
chmod +x $INSTALL_DIR/MassBleed/massbleed
chmod +x $INSTALL_DIR/MassBleed/heartbleed.py
chmod +x $INSTALL_DIR/MassBleed/openssl_ccs.pl
chmod +x $INSTALL_DIR/MassBleed/winshock.sh 
chmod +x $INSTALL_DIR/SuperMicro-Password-Scanner/supermicro_scan.sh
chmod +x $INSTALL_DIR/testssl.sh/testssl.sh
rm -f /usr/bin/sniper
rm -f /usr/bin/goohak
rm -f /usr/bin/xsstracer
rm -f /usr/bin/findsploit
rm -f /usr/bin/copysploit
rm -f /usr/bin/compilesploit
rm -f /usr/bin/massbleed
rm -f /usr/bin/testssl
ln -s $INSTALL_DIR/sniper /usr/bin/sniper
ln -s $INSTALL_DIR/Goohak/goohak /usr/bin/goohak
ln -s $INSTALL_DIR/XSSTracer/xsstracer.py /usr/bin/xsstracer
ln -s $INSTALL_DIR/Findsploit/findsploit /usr/bin/findsploit
ln -s $INSTALL_DIR/Findsploit/copysploit /usr/bin/copysploit
ln -s $INSTALL_DIR/Findsploit/compilesploit /usr/bin/compilesploit
ln -s $INSTALL_DIR/MassBleed/massbleed /usr/bin/massbleed
ln -s $INSTALL_DIR/testssl.sh/testssl.sh /usr/bin/testssl
echo -e "$OKORANGE + -- --=[Done!$RESET"
echo -e "$OKORANGE + -- --=[To run, type 'sniper'! $RESET"


