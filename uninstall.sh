#!/bin/bash
# Uninstall script for sn1per
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

echo -e "$OKGREEN + -- --=[This script will uninstall sniper and remove ALL files under $INSTALL_DIR. Are you sure you want to continue?$RESET"
read answer 

rm -Rf /usr/share/sniper/
rm -f /usr/bin/sniper

echo -e "$OKORANGE + -- --=[Done!$RESET"
echo -e "$OKORANGE + -- --=[To run, type 'sniper'! $RESET"