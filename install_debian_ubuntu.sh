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
echo -e "$OKGREEN + -- --=[This script will setup Ubuntu and Debian based OS's for the Sn1per installation. (Hit enter to continue): $RESET"
read answer
if [ ! -f "/etc/apt/sources.list.bak" ]; then
	cp /etc/apt/sources.list /etc/apt/sources.list.bak
	echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list
	echo "deb-src http://http.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list
fi
wget https://http.kali.org/kali/pool/main/k/kali-archive-keyring/kali-archive-keyring_2018.1_all.deb
apt install ./kali-archive-keyring_2018.1_all.deb
apt update
cp /root/.Xauthority /root/.Xauthority.bak 2> /dev/null
cp -a /run/user/1000/gdm/Xauthority /root/.Xauthority 2> /dev/null
cp -a /home/user/.Xauthority /root/.Xauthority 2> /dev/null 
chown root /root/.Xauthority
XAUTHORITY=/root/.Xauthority
git clone https://github.com/1N3/Sn1per /tmp/Sn1per
cd /tmp/Sn1per
bash install.sh