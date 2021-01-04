#!/bin/bash
# Install script for sn1per
# Created by @xer0dayz - https://xerosecurity.com

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

echo -e "$OKRED[>]$RESET This script will install sn1per under $INSTALL_DIR. Are you sure you want to continue? (Hit Ctrl+C to exit)$RESET"
if [[ "$1" != "force" ]]; then
	read answer
fi

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

mkdir -p $INSTALL_DIR 2> /dev/null
chmod 777 -Rf $INSTALL_DIR 2> /dev/null
chown root $INSTALL_DIR/sniper 2> /dev/null
chmod 4777 $INSTALL_DIR/sniper 2> /dev/null
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
fi

echo -e "$OKBLUE[*]$RESET Installing package dependencies...$RESET"
apt-get update
apt-get install -y python3-paramiko
apt-get install -y nfs-common
apt-get install -y nodejs
apt-get install -y wafw00f
apt-get install -y xdg-utils
apt-get install -y ruby
apt-get install -y rubygems
apt-get install -y python
apt-get install -y dos2unix
apt-get install -y aha
apt-get install -y libxml2-utils
apt-get install -y rpcbind
apt-get install -y cutycapt
apt-get install -y host
apt-get install -y whois
apt-get install -y dnsrecon
apt-get install -y curl
apt-get install -y nmap
apt-get install -y php7.4
apt-get install -y php7.4-curl
apt-get install -y hydra
apt-get install -y sqlmap
apt-get install -y nbtscan
apt-get install -y nikto
apt-get install -y whatweb
apt-get install -y sslscan
apt-get install -y jq
apt-get install -y golang
apt-get install -y adb
apt-get install -y xsltproc
apt-get install -y ldapscripts
apt-get install -y libssl-dev 2> /dev/null
apt-get install -y python-pip 2> /dev/null
apt-get remove -y python3-pip
apt-get install -y python3-pip
apt-get install -y xmlstarlet
apt-get install -y net-tools
apt-get install -y p7zip-full
apt-get install -y jsbeautifier
apt-get install -y theharvester 2> /dev/null
apt-get install -y phantomjs 2> /dev/null
apt-get install -y chromium 2> /dev/null

echo -e "$OKBLUE[*]$RESET Installing Metasploit...$RESET"
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
chmod 755 /tmp/msfinstall
/tmp/msfinstall

pip3 install dnspython colorama tldextract urllib3 ipaddress requests
curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.33.8/install.sh | bash

echo -e "$OKBLUE[*]$RESET Installing gem dependencies...$RESET"
echo -e "$OKBLUE[*]$RESET Installing rake...$RESET"
gem install rake 2> /dev/null > /dev/null
echo -e "$OKBLUE[*]$RESET Installing ruby-nmap...$RESET"
gem install ruby-nmap 2> /dev/null > /dev/null
echo -e "$OKBLUE[*]$RESET Installing net-http-persistent...$RESET"
gem install net-http-persistent 2> /dev/null > /dev/null
echo -e "$OKBLUE[*]$RESET Installing mechanize...$RESET"
gem install mechanize 2> /dev/null > /dev/null
echo -e "$OKBLUE[*]$RESET Installing text-table...$RESET"
gem install text-table 2> /dev/null > /dev/null
echo -e "$OKBLUE[*]$RESET Installing public_suffix...$RESET"
gem install public_suffix 2> /dev/null > /dev/null

echo -e "$OKBLUE[*]$RESET Setting up Ruby...$RESET"
dpkg-reconfigure ruby

echo -e "$OKBLUE[*]$RESET Cleaning up old extensions...$RESET"
rm -Rf $PLUGINS_DIR 2> /dev/null
mkdir $PLUGINS_DIR 2> /dev/null
cd $PLUGINS_DIR
mkdir -p $GO_DIR 2> /dev/null

echo -e "$OKBLUE[*]$RESET Downloading extensions...$RESET"
git clone https://github.com/1N3/BruteX.git 
git clone https://github.com/1N3/Findsploit.git 
git clone https://github.com/1N3/Goohak.git
git clone https://github.com/1N3/BlackWidow
git clone https://github.com/1N3/Sublist3r.git
git clone https://github.com/nccgroup/shocker.git 
git clone https://github.com/BishopFox/spoofcheck.git
git clone https://github.com/arthepsy/ssh-audit 
git clone https://github.com/1N3/jexboss.git
git clone https://github.com/maurosoria/dirsearch.git
git clone https://github.com/jekyc/wig.git
git clone https://github.com/RUB-NDS/CORStest.git
git clone https://github.com/hisxo/gitGraber.git
git clone https://github.com/1N3/LinkFinder
git clone https://github.com/christophetd/censys-subdomain-finder.git
git clone https://github.com/rbsec/dnscan.git
git clone https://github.com/infosec-au/altdns.git 
git clone https://github.com/blechschmidt/massdns.git
git clone https://github.com/ProjectAnte/dnsgen
git clone https://github.com/scipag/vulscan
git clone https://github.com/laramies/metagoofil.git
git clone https://github.com/achillean/shodan-python
git clone https://github.com/Dionach/CMSmap.git 
git clone https://github.com/defparam/smuggler.git

cd $PLUGINS_DIR
cd LinkFinder
python setup.py install 
cd ..
pip3 install -r $PLUGINS_DIR/gitGraber/requirements.txt
pip3 install -r $PLUGINS_DIR/censys-subdomain-finder/requirements.txt
pip3 install -r $PLUGINS_DIR/dnscan/requirements.txt 
cd altdns
pip3 install -r requirements.txt 
python2 setup.py install 
pip3 install py-altdns 2> /dev/null
cd ..
cd massdns
make && make install
cd ..
cd dnsgen
pip3 install -r requirements.txt
python3 setup.py install
cd ..
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
ln -s /root/go/bin/nuclei /usr/local/bin/nuclei 2> /dev/null
nuclei -update-directory /usr/share/sniper/plugins/ -update-templates
pip3 install -U webtech
cd ~/go/bin/;go get github.com/haccer/subjack
cd ~/go/bin/;go get -u github.com/Ice3man543/SubOver; mv SubOver /usr/local/bin/subover
GO111MODULE=on go get -u github.com/theblackturtle/fprobe; ln -fs ~/go/bin/fprobe /usr/bin/fprobe
go get github.com/harleo/asnip
ln -s ~/go/bin/asnip /usr/bin/asnip 2>/dev/null
GO111MODULE=on go get -u -v github.com/lc/gau
ln -s /root/go/bin/gau /usr/bin/gau2 2> /dev/null
GO111MODULE=auto go get -u -v github.com/projectdiscovery/httpx/cmd/httpx
ln -s /root/go/bin/httpx /usr/bin/httpx 2> /dev/null
rm -Rf ~/go/src/amass*
wget https://github.com/OWASP/Amass/releases/download/v3.5.4/amass_v3.5.4_linux_amd64.zip -O ~/go/src/amass.zip
cd ~/go/src/
unzip ~/go/src/amass.zip
mv amass_v3.5.4_linux_amd64 amass 2> /dev/null
cd amass
cp amass /usr/bin/amass -f 2> /dev/null
rm -f ~/go/src/amass.zip 2> /dev/null
cd ~/go/bin; wget https://github.com/projectdiscovery/subfinder/releases/download/v2.2.4/subfinder-linux-amd64.tar; tar -xvf subfinder-linux-amd64.tar; rm -f subfinder-linux-amd64.tar; mv subfinder-linux-amd64 /usr/local/bin/subfinder
cd /usr/share/nmap/scripts/
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
cd shodan-python 
python setup.py install
cd ..
pip3 install spyse.py
pip3 install h8mail 2> /dev/null 
cd $PLUGINS_DIR/CMSmap/ && pip3 install . && python3 setup.py install
cd $PLUGINS_DIR

# ARACHNI MANUAL INSTALL
wget https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz -O /tmp/arachni.tar.gz
cd /tmp/
tar -zxf arachni.tar.gz 
rm -f /tmp/arachni.tar.gz 2> /dev/null
cd arachni-*
mkdir -p /usr/share/arachni 2> /dev/null
cp -Rf * /usr/share/arachni/ 2> /dev/null
cd /usr/share/arachni/bin/
for a in `ls`; do ln -fs $PWD/$a /usr/bin/$a; done;

# PHANTOMJS MANUAL INSTALL
cd /usr/local/share
wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-1.9.7-linux-x86_64.tar.bz2 2> /dev/null
tar xjf phantomjs-1.9.7-linux-x86_64.tar.bz2 2> /dev/null
ln -s /usr/local/share/phantomjs-1.9.7-linux-x86_64/bin/phantomjs /usr/local/share/phantomjs 2> /dev/null
ln -s /usr/local/share/phantomjs-1.9.7-linux-x86_64/bin/phantomjs /usr/local/bin/phantomjs 2> /dev/null
ln -s /usr/local/share/phantomjs-1.9.7-linux-x86_64/bin/phantomjs /usr/bin/phantomjs 2> /dev/null

echo -e "$OKBLUE[*]$RESET Setting up environment...$RESET"
cd $PLUGINS_DIR/BlackWidow/ && bash install.sh force 2> /dev/null
cd $PLUGINS_DIR/BruteX/ && bash install.sh 2> /dev/null
cd $PLUGINS_DIR/Findsploit/ && bash install.sh 2> /dev/null
cd $PLUGINS_DIR/spoofcheck/ && pip3 install -r requirements.txt 2> /dev/null

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
cp -f $INSTALL_DIR/sn1per.png /usr/share/pixmaps/ 2> /dev/null
mkdir -p /usr/share/sniper/loot/workspaces/ 2> /dev/null
ln -fs /usr/share/sniper/loot/workspaces/ /home/kali/Desktop/workspaces 2> /dev/null
ln -fs /usr/share/sniper/loot/workspaces/ /root/Desktop/workspaces 2> /dev/null

echo -e "$OKRED[>]$RESET Done! $RESET"
echo -e "$OKRED[>]$RESET To run, type 'sniper'! $RESET"
