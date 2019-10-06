#!/bin/bash
# Install script for Sn1per
# Crated by @xer0dayz - https://xerosecurity.com

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
echo -e "$OKORANGE + -- --=[https://xerosecurity.com$RESET"
echo ""

INSTALL_DIR=/usr/share/sniper
LOOT_DIR=/usr/share/sniper/loot
PLUGINS_DIR=/usr/share/sniper/plugins
GO_DIR=~/go/bin

echo -e "$OKGREEN + -- --=[This script will install sniper under $INSTALL_DIR. Are you sure you want to continue? (Hit Ctrl+C to exit)$RESET"
read answer

mkdir -p $INSTALL_DIR 2> /dev/null
mkdir -p $LOOT_DIR 2> /dev/null
mkdir $LOOT_DIR/domains 2> /dev/null
mkdir $LOOT_DIR/screenshots 2> /dev/null
mkdir $LOOT_DIR/nmap 2> /dev/null
mkdir $LOOT_DIR/reports 2> /dev/null
mkdir $LOOT_DIR/output 2> /dev/null
mkdir $LOOT_DIR/osint 2> /dev/null
cp -Rf * $INSTALL_DIR 2> /dev/null
cd $INSTALL_DIR

echo -e "$OKORANGE + -- --=[Installing package dependencies...$RESET"
apt-get update
apt-get install -y python3-uritools python3-paramiko nfs-common eyewitness nodejs wafw00f xdg-utils metagoofil clusterd ruby rubygems python dos2unix sslyze arachni aha libxml2-utils rpcbind cutycapt host whois dnsrecon curl nmap php php-curl hydra wpscan sqlmap nbtscan enum4linux cisco-torch metasploit-framework theharvester dnsenum nikto smtp-user-enum whatweb sslscan amap jq golang adb xsltproc
apt-get install -y waffit 2> /dev/null
apt-get install -y libssl-dev 2> /dev/null
apt-get install -y python-pip 
apt-get remove -y python3-pip
apt-get install -y python3-pip
pip install dnspython colorama tldextract urllib3 ipaddress requests
curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.33.8/install.sh | bash

echo -e "$OKORANGE + -- --=[Installing gem dependencies...$RESET"
gem install rake
gem install ruby-nmap net-http-persistent mechanize text-table
gem install public_suffix

echo -e "$OKORANGE + -- --=[Setting up Ruby...$RESET"
dpkg-reconfigure ruby

echo -e "$OKORANGE + -- --=[Cleaning up old extensions...$RESET"
rm -Rf $PLUGINS_DIR 2> /dev/null
mkdir $PLUGINS_DIR 2> /dev/null
cd $PLUGINS_DIR
mkdir -p $PLUGINS_DIR/nmap_scripts/ 2> /dev/null
mkdir -p $GO_DIR 2> /dev/null

echo -e "$OKORANGE + -- --=[Downloading extensions...$RESET"
git clone https://github.com/1N3/BruteX.git 
git clone https://github.com/1N3/Goohak.git 
git clone https://github.com/1N3/BlackWidow
cp /usr/share/sniper/plugins/BlackWidow/blackwidow /usr/bin/blackwidow 
cp /usr/share/sniper/plugins/BlackWidow/injectx.py /usr/bin/injectx.py
pip install -r /usr/share/sniper/plugins/BlackWidow/requirements.txt
git clone https://github.com/Dionach/CMSmap.git 
git clone https://github.com/0xsauby/yasuo.git 
git clone https://github.com/aboul3la/Sublist3r.git 
git clone https://github.com/nccgroup/shocker.git 
git clone https://github.com/BishopFox/spoofcheck.git
git clone https://github.com/arthepsy/ssh-audit 
git clone https://github.com/1N3/jexboss.git
git clone https://github.com/maurosoria/dirsearch.git
git clone https://github.com/jekyc/wig.git
git clone https://github.com/rbsec/dnscan.git
git clone https://github.com/christophetd/censys-subdomain-finder.git
pip install -r $PLUGINS_DIR/censys-subdomain-finder/requirements.txt
pip3 install -r $PLUGINS_DIR/dnscan/requirements.txt 
git clone https://github.com/infosec-au/altdns.git 
git clone https://github.com/blechschmidt/massdns.git
git clone https://github.com/ProjectAnte/dnsgen
cd dnsgen
pip3 install -r requirements.txt
python3 setup.py install
cd ..
pip install py-altdns
pip3 install webtech
mv $INSTALL_DIR/bin/slurp.zip $PLUGINS_DIR
unzip slurp.zip
rm -f slurp.zip
cd ~/go/bin/;go get github.com/haccer/subjack
cd ~/go/bin/;go get -u github.com/Ice3man543/SubOver; mv SubOver /usr/local/bin/subover
rm -Rf ~/go/src/amass_2.9.0_linux_amd64 2> /dev/null
wget https://github.com/OWASP/Amass/releases/download/2.9.0/amass_2.9.0_linux_amd64.zip -O ~/go/src/amass.zip
cd ~/go/src/
unzip ~/go/src/amass.zip
ln -s ~/go/src/amass_2.9.0_linux_amd64/amass /usr/local/bin/amass2.9 -f
rm -f ~/go/src/amass.zip
cd ~/go/bin;go get -u github.com/subfinder/subfinder; mv subfinder /usr/local/bin/subfinder
cd /usr/share/nmap/scripts/
git clone https://github.com/scipag/vulscan
wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse
mkdir -p ~/.msf4/modules/exploits/web
wget https://raw.githubusercontent.com/1N3/Exploits/master/defcon_webmin_unauth_rce.rb -O ~/.msf4/modules/exploits/web/defcon_webmin_unauth_rce.rb
cd $PLUGINS_DIR
echo -e "$OKORANGE + -- --=[Setting up environment...$RESET"
mv ~/.sniper.conf ~/.sniper.conf.old 2> /dev/null
cp $INSTALL_DIR/sniper.conf ~/.sniper.conf 2> /dev/null
cd $PLUGINS_DIR/BruteX/ && bash install.sh 2> /dev/null
cd $PLUGINS_DIR/spoofcheck/ && pip install -r requirements.txt 2> /dev/null
cd $PLUGINS_DIR/CMSmap/ && pip3 install . && python3 setup.py install
cd $INSTALL_DIR 
mkdir $LOOT_DIR 2> /dev/null
mkdir $LOOT_DIR/screenshots/ -p 2> /dev/null
mkdir $LOOT_DIR/nmap -p 2> /dev/null
mkdir $LOOT_DIR/domains -p 2> /dev/null
mkdir $LOOT_DIR/output -p 2> /dev/null
mkdir $LOOT_DIR/reports -p 2> /dev/null
chmod +x $INSTALL_DIR/sniper
chmod +x $PLUGINS_DIR/Goohak/goohak
rm -f /usr/bin/sniper
rm -f /usr/bin/goohak
rm -f /usr/bin/dirsearch
ln -s $INSTALL_DIR/sniper /usr/bin/sniper
ln -s $PLUGINS_DIR/Goohak/goohak /usr/bin/goohak
ln -s $PLUGINS_DIR/dirsearch/dirsearch.py /usr/bin/dirsearch
msfdb init 
echo -e "$OKORANGE + -- --=[Done!$RESET"
echo -e "$OKORANGE + -- --=[To run, type 'sniper'! $RESET"
