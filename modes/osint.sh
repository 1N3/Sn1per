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
	echo -e "$OKRED GATHERING ULTATOOLS DNS INFO $RESET"
	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	if [ "$ULTRATOOLS" == "1" ]; then
		curl -s https://www.ultratools.com/tools/ipWhoisLookupResult\?ipAddress\=$TARGET | grep -A2 label | grep -v input | grep span | cut -d">" -f2 | cut -d"<" -f1 | sed 's/\&nbsp\;//g' 2> /dev/null | tee $LOOT_DIR/osint/ultratools-$TARGET.txt 2> /dev/null
	fi
	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	echo -e "$OKRED GATHERING DNS INFO $RESET"
	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	if [ "$INTODNS" == "1" ]; then
		wget -q http://www.intodns.com/$TARGET -O $LOOT_DIR/osint/intodns-$TARGET.html 2> /dev/null
		echo -e "$OKRED[+]$RESET Report saved to: $LOOT_DIR/osint/intodns-$TARGET.html"
	fi
	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	echo -e "$OKRED GATHERING THEHARVESTER OSINT INFO $RESET"
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
	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	echo -e "$OKRED GATHERING EMAILS FROM EMAIL-FORMAT.COM $RESET"
	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	if [ "$EMAILFORMAT" == "1" ]; then
		curl -s https://www.email-format.com/d/$TARGET| grep @$TARGET | grep -v div | sed "s/\t//g" | sed "s/ //g" 2> /dev/null | tee $LOOT_DIR/osint/email-format-$TARGET.txt 2> /dev/null 

		if [ "$SLACK_NOTIFICATIONS_EMAIL_FORMAT" == "1" ]; then
			/bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/osint/email-format-$TARGET.txt"
		fi
	fi
	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	echo -e "$OKRED GATHERING DNS ALTERATIONS $RESET"
	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	if [ "$URLCRAZY" == "1" ]; then
		urlcrazy $TARGET 2> /dev/null | tee $LOOT_DIR/osint/urlcrazy-$TARGET.txt 2> /dev/null
	fi
	if [ "$METAGOOFIL" == "1" ]; then
		if [ "$VERBOSE" == "1" ]; then
			echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN metagoofil -d $TARGET -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html 2> /dev/null | tee $LOOT_DIR/osint/metagoofil-$TARGET.txt 2> /dev/null  $RESET"
		fi
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED COLLECTING OSINT FROM ONLINE DOCUMENTS $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		cd $INSTALL_DIR/plugins/metagoofil/
		python metagoofil.py -d $TARGET -t doc,pdf,xls,csv,txt -l 100 -n 100 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html 2> /dev/null | tee $LOOT_DIR/osint/metagoofil-$TARGET.txt 2> /dev/null 
		cd $INSTALL_DIR
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
	if [ "$METASPLOIT_EXPLOIT" == "1" ]; then
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED GATHERING EMAILS VIA METASPLOIT $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		msfconsole -x "use auxiliary/gather/search_email_collector; set DOMAIN $TARGET; run; exit y" | tee $LOOT_DIR/osint/msf-emails-$TARGET.txt 2> /dev/null
	fi
	if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
		/bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Finished Sn1per OSINT scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
	fi
fi
