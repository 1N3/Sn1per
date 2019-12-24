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
echo -e "$OKORANGE + -- --=[ https://xerosecurity.com $RESET"
echo -e "$OKORANGE + -- --=[ Sn1per by @xer0dayz $RESET"
echo ""

INSTALL_DIR=/usr/share/sniper
LOOT_DIR=/usr/share/sniper/loot
PLUGINS_DIR=/usr/share/sniper/plugins
GO_DIR=~/go/bin

echo -e "$OKGREEN + -- --=[ This script will install sniper under $INSTALL_DIR. Are you sure you want to continue? (Hit Ctrl+C to exit)$RESET"
if [ "$1" != "force" ]; then
	read answer
fi

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

# CHECK FOR UBUNTU...
UBUNTU_CHECK=$(egrep DISTRIB_ID /etc/lsb-release)
if [ $UBUNTU_CHECK == "DISTRIB_ID=Ubuntu" ]; then
	if [ ! -f "/etc/apt/sources.list.bak" ]; then
		cp /etc/apt/sources.list /etc/apt/sources.list.bak
		echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list
		echo "deb-src http://http.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list
	fi
	wget https://http.kali.org/kali/pool/main/k/kali-archive-keyring/kali-archive-keyring_2018.2_all.deb -O /tmp/kali-archive-keyring_2018.2_all.deb
	apt install /tmp/kali-archive-keyring_2018.2_all.deb
	apt update
	cp /root/.Xauthority /root/.Xauthority.bak 2> /dev/null
	cp -a /run/user/1000/gdm/Xauthority /root/.Xauthority 2> /dev/null
	cp -a /home/user/.Xauthority /root/.Xauthority 2> /dev/null 
	chown root /root/.Xauthority
	XAUTHORITY=/root/.Xauthority
fi

echo -e "$OKORANGE + -- --=[ Installing package dependencies...$RESET"
apt-get update
apt-get install -y python3-uritools python3-paramiko nfs-common eyewitness nodejs wafw00f xdg-utils metagoofil clusterd ruby rubygems python dos2unix sslyze arachni aha libxml2-utils rpcbind cutycapt host whois dnsrecon curl nmap php php-curl hydra wpscan sqlmap nbtscan enum4linux cisco-torch metasploit-framework theharvester dnsenum nikto smtp-user-enum whatweb sslscan amap jq golang adb xsltproc urlcrazy ldapscripts
apt-get install -y waffit 2> /dev/null
apt-get install -y libssl-dev 2> /dev/null
apt-get install -y python-pip 
apt-get remove -y python3-pip
apt-get install -y python3-pip
apt-get install -y xmlstarlet
apt-get install -y chromium
apt-get install -y net-tools
apt-get install -y p7zip-full
pip install dnspython colorama tldextract urllib3 ipaddress requests
curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.33.8/install.sh | bash

echo -e "$OKORANGE + -- --=[ Installing gem dependencies...$RESET"
gem install rake
gem install ruby-nmap net-http-persistent mechanize text-table
gem install public_suffix

echo -e "$OKORANGE + -- --=[ Setting up Ruby...$RESET"
dpkg-reconfigure ruby

echo -e "$OKORANGE + -- --=[ Cleaning up old extensions...$RESET"
rm -Rf $PLUGINS_DIR 2> /dev/null
mkdir $PLUGINS_DIR 2> /dev/null
cd $PLUGINS_DIR
mkdir -p $PLUGINS_DIR/nmap_scripts/ 2> /dev/null
mkdir -p $GO_DIR 2> /dev/null

echo -e "$OKORANGE + -- --=[ Downloading extensions...$RESET"
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
git clone https://github.com/RUB-NDS/CORStest.git
git clone https://github.com/christophetd/censys-subdomain-finder.git
pip install -r $PLUGINS_DIR/censys-subdomain-finder/requirements.txt
pip3 install -r $PLUGINS_DIR/dnscan/requirements.txt 
git clone https://github.com/infosec-au/altdns.git 
cd altdns
pip install -r requirements.txt 
python2 setup.py install 
pip install py-altdns
cd ..
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make && make install
cd ..
git clone https://github.com/ProjectAnte/dnsgen
cd dnsgen
pip3 install -r requirements.txt
python3 setup.py install
cd ..
pip3 install webtech
mv $INSTALL_DIR/bin/slurp.zip $PLUGINS_DIR
unzip slurp.zip
rm -f slurp.zip
cd ~/go/bin/;go get github.com/haccer/subjack
cd ~/go/bin/;go get -u github.com/Ice3man543/SubOver; mv SubOver /usr/local/bin/subover
go get github.com/harleo/asnip
ln -s ~/go/bin/asnip /usr/bin/asnip 2>/dev/null
rm -Rf ~/go/src/amass*
wget https://github.com/OWASP/Amass/releases/download/v3.1.10/amass_v3.1.10_linux_amd64.zip -O ~/go/src/amass.zip
cd ~/go/src/
unzip ~/go/src/amass.zip
mv amass_v3.1.10_linux_amd64 amass 2> /dev/null
cd amass
cp amass /usr/bin/amass -f 2> /dev/null
rm -f ~/go/src/amass.zip 2> /dev/null
cd ~/go/bin; wget https://github.com/projectdiscovery/subfinder/releases/download/v2.2.4/subfinder-linux-amd64.tar; tar -xvf subfinder-linux-amd64.tar; rm -f subfinder-linux-amd64.tar; mv subfinder-linux-amd64 /usr/local/bin/subfinder
cd /usr/share/nmap/scripts/
rm -Rf vulscan 2> /dev/null
git clone https://github.com/scipag/vulscan
rm -f /usr/share/nmap/scripts/vulners.nse
wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse
mkdir -p ~/.msf4/modules/exploits/web
wget https://raw.githubusercontent.com/1N3/Exploits/master/defcon_webmin_unauth_rce.rb -O ~/.msf4/modules/exploits/web/defcon_webmin_unauth_rce.rb
wget https://github.com/OJ/gobuster/releases/download/v3.0.1/gobuster-linux-amd64.7z -O /tmp/gobuster.7z
cd /tmp/
7z e gobuster.7z
chmod +rx gobuster 
mv gobuster /usr/bin/gobuster 
cd $PLUGINS_DIR
wget https://github.com/laramies/theHarvester/archive/3.0.6.tar.gz
tar -zxvf 3.0.6.tar.gz
rm 3.0.6.tar.gz
rm -f /usr/bin/theharvester
ln -s /usr/share/sniper/plugins/theHarvester-3.0.6/theHarvester.py /usr/bin/theharvester
git clone https://github.com/laramies/metagoofil.git
git clone https://github.com/achillean/shodan-python
cd shodan-python 
python setup.py install
cd ..
echo -e "$OKORANGE + -- --=[ Setting up environment...$RESET"
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

echo -e "$OKORANGE + -- --=[ Done!$RESET"
echo -e "$OKORANGE + -- --=[ To run, type 'sniper'! $RESET"
