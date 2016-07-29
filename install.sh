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
apt-get install dos2unix zenmap sslyze joomscan uniscan xprobe2 cutycapt unicornscan waffit host whois arachni theharvester dnsenum dirb dnsrecon curl nmap php5 php5-curl wapiti hydra iceweasel wpscan sqlmap arachni w3af golismero nbtscan enum4linux cisco-torch metasploit-framework theharvester dnsenum nikto smtp-user-enum whatweb python nbtscan sslscan amap
pip install dnspython colorama tldextract urllib3 ipaddress

echo -e "$OKORANGE + -- --=[Installing gem dependencies...$RESET"
gem install rake
gem install ruby-nmap net-http-persistent mechanize text-table

echo -e "$OKORANGE + -- --=[Cleaning up old extensions...$RESET"
rm -Rf Findsploit/ Brutex/ Goohak/ XSSTracer/ MassBleed/ SuperMicro-Password-Scanner/ CMSmap/ yasuo/ Sublist3r/ shocker/ jexboss/ CrackMapExec/

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
git clone https://github.com/byt3bl33d3r/CrackMapExec.git
git clone https://github.com/drwetter/testssl.sh.git
git clone https://github.com/lunarca/SimpleEmailSpoofer

echo -e "$OKORANGE + -- --=[Setting up environment...$RESET"
mkdir loot 2> /dev/null
cp -f $DIR/bin/clamav-exec.nse /usr/share/nmap/scripts/ 2> /dev/null
chmod +x $DIR/sniper
chmod +x $DIR/bin/dnsdict6
chmod +x $DIR/Goohak/goohak
chmod +x $DIR/XSSTracer/xsstracer.py
chmod +x $DIR/MassBleed/massbleed
chmod +x $DIR/MassBleed/heartbleed.py
chmod +x $DIR/MassBleed/openssl_ccs.pl
chmod +x $DIR/SuperMicro-Password-Scanner/supermicro_scan.sh
chmod +x $DIR/testssl.sh/testssl.sh
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
ln -s $DIR/testssl.sh/testssl.sh /usr/bin/testssl

echo -e "$OKORANGE + -- --=[For universal sniper access, be sure to edit sniper to include the full path for the SNIPER_DIR variable. $RESET"
echo -e "$OKORANGE + -- --=[Done!$RESET"


