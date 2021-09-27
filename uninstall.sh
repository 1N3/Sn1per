#!/bin/bash
# Uninstall script for Sn1per
# Created by @xer0dayz - https://sn1persecurity.com

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

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
echo -e "$OKORANGE + -- --=[https://sn1persecurity.com$RESET"
echo ""

INSTALL_DIR=/usr/share/sniper

echo -e "$OKRED[>]$RESET This script will uninstall sniper and remove ALL files under $INSTALL_DIR. Are you sure you want to continue?$RESET"
read answer

rm -Rf /usr/share/sniper/
rm -f /usr/bin/sniper

echo -e "$OKBLUE[*]$RESET Done!$RESET"