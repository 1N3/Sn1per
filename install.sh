#!/bin/bash
# Install script for Sn1per CE
# Created by @xer0dayz - https://sn1persecurity.com

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
echo -e "$OKORANGE + -- --=[ https://sn1persecurity.com $RESET"
echo -e "$OKORANGE + -- --=[ Sn1per CE by @xer0dayz $RESET"
echo ""

INSTALL_DIR=/usr/share/sniper
LOOT_DIR=/usr/share/sniper/loot
PLUGINS_DIR=/usr/share/sniper/plugins
GO_DIR=~/go/bin

echo -e "$OKRED[>]$RESET This script will install Sn1per under $INSTALL_DIR. Are you sure you want to continue? (Hit Ctrl+C to exit)$RESET"
if [[ "$1" != "force" ]]; then
	read answer
fi

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

mkdir -p $INSTALL_DIR 2> /dev/null
chmod 755 -Rf $INSTALL_DIR 2> /dev/null
chown root $INSTALL_DIR/sniper 2> /dev/null
mkdir -p $LOOT_DIR 2> /dev/null
mkdir $LOOT_DIR/domains 2> /dev/null
mkdir $LOOT_DIR/screenshots 2> /dev/null
mkdir $LOOT_DIR/nmap 2> /dev/null
mkdir $LOOT_DIR/reports 2> /dev/null
mkdir $LOOT_DIR/output 2> /dev/null
mkdir $LOOT_DIR/osint 2> /dev/null
cp -Rf * $INSTALL_DIR 2> /dev/null
cd $INSTALL_DIR

sudo cp -a /root/.Xauthority /root/.Xauthority.bak 2> /dev/null
sudo cp -a /home/$USER/.Xauthority /root/.Xauthority 2> /dev/null
sudo cp -a /home/kali/.Xauthority /root/.Xauthority 2> /dev/null
sudo chown root: /root/.Xauthority 2> /dev/null
XAUTHORITY=/root/.Xauthority

# CHECK FOR UBUNTU...
UBUNTU_CHECK=$(egrep DISTRIB_ID /etc/lsb-release 2> /dev/null)
if [[ $UBUNTU_CHECK == "DISTRIB_ID=Ubuntu" ]]; then
	cp /root/.Xauthority /root/.Xauthority.bak 2> /dev/null
	cp -a /run/user/1000/gdm/Xauthority /root/.Xauthority 2> /dev/null
	cp -a /home/user/.Xauthority /root/.Xauthority 2> /dev/null
	chown root /root/.Xauthority 2> /dev/null
	XAUTHORITY=/root/.Xauthority 2> /dev/null
	snap install chromium 2> /dev/null
	ln -s /snap/bin/chromium /usr/bin/chromium 2> /dev/null
	xhost + 2> /dev/null
	mkdir -p /run/user/0 2> /dev/null
	add-apt-repository ppa:longsleep/golang-backports
	sudo apt update
	apt install golang
fi

echo -e "$OKBLUE[*]$RESET Installing package dependencies...$RESET"
apt update
apt install -y python3-paramiko
apt install -y nfs-common
apt install -y nodejs
apt install -y wafw00f
apt install -y xdg-utils
apt install -y ruby
apt install -y rubygems
apt install -y python
apt install -y dos2unix
apt install -y aha
apt install -y libxml2-utils
apt install -y rpcbind
apt install -y cutycapt
apt install -y host
apt install -y whois
apt install -y dnsrecon
apt install -y curl
apt install -y nmap
apt install -y php7.4
apt install -y php7.4-curl
apt install -y hydra
apt install -y sqlmap
apt install -y nbtscan
apt install -y nikto
apt install -y whatweb
apt install -y sslscan
apt install -y jq
apt install -y golang
apt install -y adb
apt install -y xsltproc
apt install -y ldapscripts
apt install -y libssl-dev 2> /dev/null
apt install -y python-pip 2> /dev/null
apt purge -y python3-pip
apt install -y python3-pip
apt install -y xmlstarlet
apt install -y net-tools
apt install -y p7zip-full
apt install -y jsbeautifier
apt install -y theharvester 2> /dev/null
apt install -y phantomjs 2> /dev/null
apt install -y chromium 2> /dev/null
apt install -y xvfb
apt install -y urlcrazy
apt install -y iputils-ping
apt install -y enum4linux
apt install -y dnsutils

echo -e "$OKBLUE[*]$RESET Installing Metasploit...$RESET"
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
chmod 755 /tmp/msfinstall
/tmp/msfinstall

pip3 install dnspython colorama tldextract urllib3 ipaddress requests
curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.33.8/install.sh | bash

echo -e "$OKBLUE[*]$RESET Installing gem dependencies...$RESET"
gem install rake 2> /dev/null > /dev/null
gem install ruby-nmap 2> /dev/null > /dev/null
gem install net-http-persistent 2> /dev/null > /dev/null
gem install mechanize 2> /dev/null > /dev/null
gem install text-table 2> /dev/null > /dev/null
gem install public_suffix 2> /dev/null > /dev/null

echo -e "$OKBLUE[*]$RESET Setting up Ruby...$RESET"
dpkg-reconfigure ruby

echo -e "$OKBLUE[*]$RESET Upgrading Pip...$RESET"
python3 -m pip install --upgrade pip

echo -e "$OKBLUE[*]$RESET Cleaning up old extensions...$RESET"
rm -Rf $PLUGINS_DIR 2> /dev/null
mkdir $PLUGINS_DIR 2> /dev/null
cd $PLUGINS_DIR
mkdir -p $GO_DIR 2> /dev/null

echo -e "$OKBLUE[*]$RESET Downloading extensions...$RESET"

# SUBLIST3R INSTALLER
echo -e "$OKBLUE[*]$RESET Installing Sublist3r...$RESET"
git clone https://github.com/1N3/Sublist3r.git

# SHOCKER INSTALLER
echo -e "$OKBLUE[*]$RESET Installing Shocker...$RESET"
git clone https://github.com/nccgroup/shocker.git

# SSH-AUDIT INSTALLER
echo -e "$OKBLUE[*]$RESET Installing SSH-Audit...$RESET"
git clone https://github.com/arthepsy/ssh-audit

# JEXBOSS INSTALLER
echo -e "$OKBLUE[*]$RESET Installing Jexboss...$RESET"
git clone https://github.com/1N3/jexboss.git

# WIG INSTALLER
echo -e "$OKBLUE[*]$RESET Installing Wig...$RESET"
git clone https://github.com/jekyc/wig.git

# CORSTEST INSTALLER
echo -e "$OKBLUE[*]$RESET Installing CORStest...$RESET"
git clone https://github.com/RUB-NDS/CORStest.git

# VULSCAN INSTALLER
echo -e "$OKBLUE[*]$RESET Installing Vulscan...$RESET"
git clone https://github.com/scipag/vulscan

# METAGOOFIL INSTALLER
echo -e "$OKBLUE[*]$RESET Installing Metagoofil...$RESET"
git clone https://github.com/laramies/metagoofil.git

# SHODAN INSTALLER
echo -e "$OKBLUE[*]$RESET Installing Shodan...$RESET"
git clone https://github.com/achillean/shodan-python

# CMSMAP INSTALLER
echo -e "$OKBLUE[*]$RESET Installing CMSMap...$RESET"
git clone https://github.com/Dionach/CMSmap.git

# SMUGGLER INSTALLER
echo -e "$OKBLUE[*]$RESET Installing Smuggler...$RESET"
git clone https://github.com/defparam/smuggler.git

# DIRSEARCH INSTALLER
echo -e "$OKBLUE[*]$RESET Installing Dirsearch...$RESET"
cd $PLUGINS_DIR
rm -Rf dirsearch/ 2> /dev/null
wget https://github.com/maurosoria/dirsearch/archive/refs/tags/v0.4.2.tar.gz
tar -zxvf v0.4.2.tar.gz
mv dirsearch-0.4.2/ dirsearch/
cd dirsearch/
pip3 install -r requirements.txt
cd $PLUGINS_DIR

# SECRETFINDER INSTALLER
echo -e "$OKBLUE[*]$RESET Installing SecretFinder...$RESET"
git clone https://github.com/m4ll0k/SecretFinder.git secretfinder
pip install -r $PLUGINS_DIR/secretfinder/requirements.txt

# LINKFINDER INSTALLER
echo -e "$OKBLUE[*]$RESET Installing LinkFinder...$RESET"
git clone https://github.com/1N3/LinkFinder
cd LinkFinder
python3 setup.py install
cd ..

# GITGRABER INSTALLER
echo -e "$OKBLUE[*]$RESET Installing GitGrabber...$RESET"
git clone https://github.com/hisxo/gitGraber.git
pip3 install -r $PLUGINS_DIR/gitGraber/requirements.txt 2> /dev/null

# CENSYS-SUBDOMAIN-FINDER INSTALLER
echo -e "$OKBLUE[*]$RESET Installing Censys-Subdomain-Finder...$RESET"
git clone https://github.com/christophetd/censys-subdomain-finder.git
pip3 install -r $PLUGINS_DIR/censys-subdomain-finder/requirements.txt

# DNSCAN INSTALLER
echo -e "$OKBLUE[*]$RESET Installing DNScan...$RESET"
git clone https://github.com/rbsec/dnscan.git
pip3 install -r $PLUGINS_DIR/dnscan/requirements.txt

# ALTDNS INSTALLER
echo -e "$OKBLUE[*]$RESET Installing AltDNS...$RESET"
git clone https://github.com/infosec-au/altdns.git
cd altdns
pip3 install -r requirements.txt
python3 setup.py install
pip3 install py-altdns
cd ..

# MASSDNS INSTALLER
echo -e "$OKBLUE[*]$RESET Installing MassDNS...$RESET"
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make && make install
cd ..

# DNSGEN INSTALLER
echo -e "$OKBLUE[*]$RESET Installing DNSGen...$RESET"
git clone https://github.com/ProjectAnte/dnsgen
cd dnsgen
pip3 install -r requirements.txt
python3 setup.py install
cd ..

# NUCLEI UPDATES
echo -e "$OKBLUE[*]$RESET Installing Nuclei...$RESET"
GO111MODULE=on go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
ln -fs /root/go/bin/nuclei /usr/local/bin/nuclei 2> /dev/null
nuclei --update
nuclei

# INSTALL WEBTECH
echo -e "$OKBLUE[*]$RESET Installing WebTech...$RESET"
pip3 install -U webtech

# INSTALL SUBJACK
echo -e "$OKBLUE[*]$RESET Installing SubJack...$RESET"
cd ~/go/bin/;go install github.com/haccer/subjack@latest

# INSTALL SUBOVER
echo -e "$OKBLUE[*]$RESET Installing SubOver...$RESET"
cd ~/go/bin/;go install github.com/Ice3man543/SubOver@latest; mv /root/go/bin/SubOver /usr/local/bin/subover

# INSTALL FPROBE
echo -e "$OKBLUE[*]$RESET Installing FProbe...$RESET"
go install github.com/theblackturtle/fprobe@latest; ln -fs ~/go/bin/fprobe /usr/bin/fprobe

# INSTALL ASNIP
echo -e "$OKBLUE[*]$RESET Installing ASnip...$RESET"
go install github.com/harleo/asnip@latest; ln -fs ~/go/bin/asnip /usr/bin/asnip

# GAU INSTALLER
echo -e "$OKBLUE[*]$RESET Installing GAU...$RESET"
GO111MODULE=on go install github.com/lc/gau@latest
rm -f /usr/bin/gau 2> /dev/null
ln -fs /root/go/bin/gau /usr/bin/gau 2> /dev/null

# INSTALL HTTPX
echo -e "$OKBLUE[*]$RESET Installing HTTPX...$RESET"
go install github.com/projectdiscovery/httpx@latest; ln -fs /root/go/bin/httpx /usr/bin/httpx

# INSTALL FFUF
echo -e "$OKBLUE[*]$RESET Installing FFuF...$RESET"
go install github.com/ffuf/ffuf@latest; ln -fs /root/go/bin/ffuf /usr/bin/ffuf

# GITHUB-ENDPOINTS INSTALLER
echo -e "$OKBLUE[*]$RESET Installing Github-Endpoints...$RESET"
go install github.com/gwen001/github-endpoints@latest; ln -fs /root/go/bin/github-endpoints /usr/bin/github-endpoints

# PUREDNS INSTALLER
echo -e "$OKBLUE[*]$RESET Installing PureDNS...$RESET"
go install github.com/d3mondev/puredns/v2@latest; ln -fs /root/go/bin/puredns /usr/bin/puredns

# AMASS INSTALLER
echo -e "$OKBLUE[*]$RESET Installing AMass...$RESET"
go install -v github.com/OWASP/Amass/v3/...@master
cd /root/go/bin/

# SUBFINDER INSTALLER
echo -e "$OKBLUE[*]$RESET Installing SubFinder...$RESET"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; ln -fs /root/go/bin/subfinder /usr/local/bin/subfinder

# DIRDAR INSTALLER
echo -e "$OKBLUE[*]$RESET Installing DirDar...$RESET"
go install github.com/1N3/dirdar@latest; ln -fs /root/go/bin/dirdar /usr/local/bin/dirdar

# VULNERS NMAP INSTALLER
echo -e "$OKBLUE[*]$RESET Installing Vulners...$RESET"
cd /usr/share/nmap/scripts/
rm -f /usr/share/nmap/scripts/vulners.nse
wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse

# GOBUSTER INSTALLER
echo -e "$OKBLUE[*]$RESET Installing GoBuster...$RESET"
wget https://github.com/OJ/gobuster/releases/download/v3.0.1/gobuster-linux-amd64.7z -O /tmp/gobuster.7z
cd /tmp/
7z e gobuster.7z
chmod +rx gobuster
mv gobuster /usr/bin/gobuster

# SHODAN INSTALLER
echo -e "$OKBLUE[*]$RESET Installing Shodan...$RESET"
cd $PLUGINS_DIR
cd shodan-python
python setup.py install
cd ..

# H8MAIL INSTALLER
echo -e "$OKBLUE[*]$RESET Installing H8Mail...$RESET"
pip3 install h8mail 2> /dev/null

# CMSMAP INSTALLER
echo -e "$OKBLUE[*]$RESET Installing CMSMap...$RESET"
cd $PLUGINS_DIR/CMSmap/ && pip3 install . && python3 setup.py install

cd $PLUGINS_DIR

# ARACHNI MANUAL INSTALL
echo -e "$OKBLUE[*]$RESET Installing Arachni...$RESET"
wget https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz -O /tmp/arachni.tar.gz
cd /tmp/
tar -zxf arachni.tar.gz
rm -f /tmp/arachni.tar.gz 2> /dev/null
cd arachni-*
mkdir -p /usr/share/arachni 2> /dev/null
cp -Rf * /usr/share/arachni/ 2> /dev/null
cd /usr/share/arachni/bin/
for a in `ls`; do ln -fs $PWD/$a /usr/bin/$a; done;

# REMOVE CVE TEMPLATES (ALL CVEs GOING FORWARD COVERED BY NUCLEI)
rm -f /usr/share/sniper/templates/active/CVE*

# PHANTOMJS MANUAL INSTALL
echo -e "$OKBLUE[*]$RESET Installing PhantomJS...$RESET"
cd /usr/local/share
wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-1.9.7-linux-x86_64.tar.bz2 2> /dev/null
tar xjf phantomjs-1.9.7-linux-x86_64.tar.bz2 2> /dev/null
ln -s /usr/local/share/phantomjs-1.9.7-linux-x86_64/bin/phantomjs /usr/local/share/phantomjs 2> /dev/null
ln -s /usr/local/share/phantomjs-1.9.7-linux-x86_64/bin/phantomjs /usr/local/bin/phantomjs 2> /dev/null
ln -s /usr/local/share/phantomjs-1.9.7-linux-x86_64/bin/phantomjs /usr/bin/phantomjs 2> /dev/null

# DNS RESOLVERS DOWNLOAD
echo -e "$OKBLUE[*]$RESET Installing DNS Resolvers...$RESET"
wget https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O /usr/share/sniper/wordlists/resolvers.txt

# THEHARVESTER KALI SETUP
echo -e "$OKBLUE[*]$RESET Installing TheHarvester...$RESET"
cp -f /usr/bin/theHarvester /usr/bin/theharvester 2> /dev/null

# BLACKWIDOW INSTALLER
echo -e "$OKBLUE[*]$RESET Installing BlackWidow...$RESET"
cd $PLUGINS_DIR
git clone https://github.com/1N3/BlackWidow
cd $PLUGINS_DIR/BlackWidow/ && bash install.sh force 2> /dev/null

# BRUTEX INSTALLER
echo -e "$OKBLUE[*]$RESET Installing BruteX...$RESET"
cd $PLUGINS_DIR
git clone https://github.com/1N3/BruteX.git
cd $PLUGINS_DIR/BruteX/ && bash install.sh 2> /dev/null

# FINDSPLOIT INSTALLER
echo -e "$OKBLUE[*]$RESET Installing FindSploit...$RESET"
cd $PLUGINS_DIR
git clone https://github.com/1N3/Findsploit.git
cd $PLUGINS_DIR/Findsploit/ && bash install.sh 2> /dev/null

# GOOHAK INSTALLER
echo -e "$OKBLUE[*]$RESET Installing GooHak...$RESET"
cd $PLUGINS_DIR
git clone https://github.com/1N3/Goohak.git

echo -e "$OKBLUE[*]$RESET Setting up environment...$RESET"
cd $INSTALL_DIR
mkdir $LOOT_DIR 2> /dev/null
mkdir $LOOT_DIR/screenshots/ -p 2> /dev/null
mkdir $LOOT_DIR/nmap -p 2> /dev/null
mkdir $LOOT_DIR/domains -p 2> /dev/null
mkdir $LOOT_DIR/output -p 2> /dev/null
mkdir $LOOT_DIR/reports -p 2> /dev/null
chmod +x $INSTALL_DIR/sniper
chmod +x $PLUGINS_DIR/Goohak/goohak
rm -f /usr/bin/dirsearch
ln -s $INSTALL_DIR/sniper /usr/bin/sniper 2> /dev/null
ln -s $PLUGINS_DIR/Goohak/goohak /usr/bin/goohak 2> /dev/null
ln -s $PLUGINS_DIR/dirsearch/dirsearch.py /usr/bin/dirsearch 2> /dev/null
ln -s /usr/share/sniper /sniper 2> /dev/null
ln -s /usr/share/sniper /usr/share/sn1per 2> /dev/null
ln -s /usr/share/sniper/loot/workspace /workspace 2> /dev/null
ln -s /usr/share/sniper/loot/workspace /root/workspace 2> /dev/null
ln -s /usr/share/sniper /root/sniper 2> /dev/null
ln -s /root/.sniper.conf /usr/share/sniper/conf/sniper.conf 2> /dev/null
ln -s /root/.sniper_api_keys.conf /usr/share/sniper/conf/sniper_api_keys.conf 2> /dev/null
mv /root/.sniper.conf /root/.sniper.conf.bak 2> /dev/null
cp -vf /usr/share/sniper/sniper.conf /root/.sniper.conf 2> /dev/null
msfdb init 2> /dev/null

echo -e "$OKBLUE[*]$RESET Adding start menu and desktop shortcuts... $RESET"
cp -f $INSTALL_DIR/sn1per.desktop /usr/share/applications/ 2> /dev/null
cp -f $INSTALL_DIR/sn1per.desktop /usr/share/applications/sn1per.desktop 2> /dev/null
cp -f $INSTALL_DIR/sn1per.desktop /usr/share/kali-menu/applications/sn1per.desktop 2> /dev/null
cp -f $INSTALL_DIR/sn1per.png /usr/share/pixmaps/ 2> /dev/null
cp -f $PLUGINS_DIR/BruteX/brutex.desktop /usr/share/applications/ 2> /dev/null
cp -f $PLUGINS_DIR/BruteX/brutex.desktop /usr/share/applications/brutex.desktop 2> /dev/null
cp -f $PLUGINS_DIR/BruteX/brutex.desktop /usr/share/kali-menu/applications/brutex.desktop 2> /dev/null
cp -f $PLUGINS_DIR/BlackWidow/blackwidow.desktop /usr/share/applications/ 2> /dev/null
cp -f $PLUGINS_DIR/BlackWidow/blackwidow.desktop /usr/share/applications/blackwidow.desktop 2> /dev/null
cp -f $PLUGINS_DIR/BlackWidow/blackwidow.desktop /usr/share/kali-menu/applications/blackwidow.desktop 2> /dev/null
cp -f $PLUGINS_DIR/Findsploit/findsploit.desktop /usr/share/applications/ 2> /dev/null
cp -f $PLUGINS_DIR/Findsploit/findsploit.desktop /usr/share/applications/findsploit.desktop 2> /dev/null
cp -f $PLUGINS_DIR/Findsploit/findsploit.desktop /usr/share/kali-menu/applications/findsploit.desktop 2> /dev/null
mkdir -p /usr/share/sniper/loot/workspaces/ 2> /dev/null
ln -fs /usr/share/sniper/loot/workspaces/ /home/kali/Desktop/workspaces 2> /dev/null
ln -fs /usr/share/sniper/loot/workspaces/ /root/Desktop/workspaces 2> /dev/null

echo -e "$OKRED[>]$RESET Done! $RESET"
echo -e "$OKRED[>]$RESET To run, type 'sniper'! $RESET"
