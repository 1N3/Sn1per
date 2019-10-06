if [ "$OSINT" = "1" ]; then
	if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
		/bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Started Sn1per OSINT scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
	fi
	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	echo -e "$OKRED GATHERING WHOIS INFO $RESET"
	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	if [ "$WHOIS" == "1" ]; then
		if [ "$VERBOSE" == "1" ]; then
			echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN whois $TARGET 2> /dev/null | tee $LOOT_DIR/osint/whois-$TARGET.txt 2> /dev/null $RESET"
		fi
		whois $TARGET 2> /dev/null | tee $LOOT_DIR/osint/whois-$TARGET.txt 2> /dev/null 


		if [ "$SLACK_NOTIFICATIONS_WHOIS" == "1" ]; then
			/bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/osint/whois-$TARGET.txt"
		fi
	fi
	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	echo -e "$OKRED GATHERING OSINT INFO $RESET"
	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	if [ "$THEHARVESTER" == "1" ]; then
		if [ "$VERBOSE" == "1" ]; then
			echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN python2.7 $THEHARVESTER_PATH -d $TARGET -l 100 -b all 2> /dev/null | tee $LOOT_DIR/osint/theharvester-$TARGET.txt 2> /dev/null  $RESET"
		fi
		theharvester -d $TARGET -l 100 -b all 2> /dev/null | tee $LOOT_DIR/osint/theharvester-$TARGET.txt 2> /dev/null 

		if [ "$SLACK_NOTIFICATIONS_THEHARVESTER" == "1" ]; then
			/bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/osint/theharvester-$TARGET.txt"
		fi

	fi
	if [ "$METAGOOFIL" == "1" ]; then
		if [ "$VERBOSE" == "1" ]; then
			echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN metagoofil -d $TARGET -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html 2> /dev/null | tee $LOOT_DIR/osint/metagoofil-$TARGET.txt 2> /dev/null  $RESET"
		fi
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED COLLECTING OSINT FROM ONLINE DOCUMENTS $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		metagoofil -d $TARGET -t doc,pdf,xls,csv,txt -l 100 -n 100 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html 2> /dev/null | tee $LOOT_DIR/osint/metagoofil-$TARGET.txt 2> /dev/null 

		if [ "$SLACK_NOTIFICATIONS_METAGOOFIL" == "1" ]; then
			/bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/osint/metagoofil-$TARGET.txt"
		fi
	fi
	if [ "$HUNTERIO" == "1" ]; then
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED GATHERING EMAILS VIA HUNTER.IO $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		curl -s "https://api.hunter.io/v2/domain-search?domain=$TARGET&api_key=$HUNTERIO_KEY" | egrep "name|value|domain|company|uri|position|phone" 2> /dev/null | tee $LOOT_DIR/osint/hunterio-$TARGET.txt 2> /dev/null
	fi
	if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
		/bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Finished Sn1per OSINT scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
	fi
fi
