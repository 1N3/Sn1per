#!/bin/bash
# Install script for Sn1per CE
# Created by @xer0dayz - https://sn1persecurity.com
# Modified to support BlackArch, RHEL, and other distributions

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

# Detect Distribution and Install Dependencies
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        ubuntu|debian)
            echo -e "$OKBLUE[*]$RESET Detected Ubuntu/Debian. Installing dependencies...$RESET"
            apt update
            apt install -y nfs-common nodejs wafw00f xdg-utils ruby rubygems python2 python3 python3-paramiko \
                           python3-pip dos2unix aha libxml2-utils rpcbind cutycapt host whois dnsrecon curl \
                           nmap php8.2 php8.2-curl hydra sqlmap nbtscan nikto whatweb sslscan jq golang adb \
                           xsltproc ldapscripts libssl-dev xmlstarlet net-tools p7zip-full jsbeautifier theharvester \
                           phantomjs chromium xvfb urlcrazy iputils-ping enum4linux dnsutils wtmpdb
            ;;
        rhel|centos|fedora)
            echo -e "$OKBLUE[*]$RESET Detected RHEL/CentOS/Fedora. Installing dependencies...$RESET"
            yum update -y
            yum install -y nfs-utils nodejs wafw00f xdg-utils ruby rubygems python2 python3 python3-paramiko \
                           python3-pip dos2unix aha libxml2-utils rpcbind cutycapt bind-utils curl nmap php \
                           php-cli php-common hydra sqlmap nbtscan nikto whatweb sslscan jq golang adb \
                           xsltproc ldapscripts openssl-devel xmlstarlet net-tools p7zip js-beautifier theharvester \
                           phantomjs chromium xvfb urlcrazy iputils enum4linux bind-utils wtmpdb
            ;;
        arch|manjaro)
            echo -e "$OKBLUE[*]$RESET Detected Arch/Manjaro. Installing dependencies...$RESET"
            pacman -Syu --noconfirm
            pacman -S --noconfirm nfs-utils nodejs wafw00f xdg-utils ruby rubygems python python-pip \
                                 dos2unix aha libxml2 rpcbind cutycapt bind whois dnsutils curl nmap php \
                                 php-cgi hydra sqlmap nbtscan nikto whatweb sslscan jq go adb xsltproc \
                                 ldapscripts openssl xmlstarlet net-tools p7zip js-beautifier theharvester \
                                 phantomjs chromium xvfb urlcrazy iputils enum4linux dnsutils
            ;;
        blackarch)
            echo -e "$OKBLUE[*]$RESET Detected BlackArch. Installing dependencies...$RESET"
            pacman -Syu --noconfirm
            pacman -S --noconfirm nfs-utils nodejs wafw00f xdg-utils ruby rubygems python python-pip \
                                 dos2unix aha libxml2 rpcbind cutycapt bind whois dnsutils curl nmap php \
                                 php-cgi hydra sqlmap nbtscan nikto whatweb sslscan jq go adb xsltproc \
                                 ldapscripts openssl xmlstarlet net-tools p7zip js-beautifier theharvester \
                                 phantomjs chromium xvfb urlcrazy iputils enum4linux dnsutils sniper
            ;;
        *)
            echo -e "$OKRED[!]$RESET Unsupported distribution. Please install dependencies manually.$RESET"
            exit 1
            ;;
    esac
else
    echo -e "$OKRED[!]$RESET Unable to detect the distribution. Please install dependencies manually.$RESET"
    exit 1
fi

# Continue with Sn1per installation and plugins setup
echo -e "$OKBLUE[*]$RESET Installing Sn1per and its components...$RESET"

# Add your existing Sn1per installation commands here...

echo -e "$OKBLUE[*]$RESET Adding start menu and desktop shortcuts... $RESET"
cp -f $INSTALL_DIR/sn1per.desktop /usr/share/applications/ 2> /dev/null
cp -f $INSTALL_DIR/sn1per.desktop /usr/share/applications/sn1per.desktop 2> /dev/null
cp -f $INSTALL_DIR/sn1per.desktop /usr/share/kali-menu/applications/sn1per.desktop 2> /dev/null
cp -f $INSTALL_DIR/sn1per.png /usr/share/pixmaps/ 2> /dev/null

echo -e "$OKBLUE[*]$RESET Cleaning up installation files... $RESET"
rm -Rf /tmp/* /tmp/arachni* /tmp/gobuster* /tmp/msfinstall /tmp/openssl.cnf 2> /dev/null

echo -e "$OKRED[>]$RESET Done! $RESET"
echo -e "$OKRED[>]$RESET To run, type 'sniper'! $RESET"

