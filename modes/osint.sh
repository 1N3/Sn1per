if [[ "$OSINT" = "1" ]]; then
	echo "[sn1persecurity.com] •?((¯°·._.• Started Sn1per OSINT scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
	if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
		/bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Started Sn1per OSINT scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
	fi	
	if [[ "$WHOIS" == "1" ]]; then
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED GATHERING WHOIS INFO $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		if [[ "$VERBOSE" == "1" ]]; then
			echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN whois $TARGET 2> /dev/null | tee $LOOT_DIR/osint/whois-$TARGET.txt 2> /dev/null $RESET"
		fi
		whois $TARGET 2> /dev/null | tee $LOOT_DIR/osint/whois-$TARGET.txt 2> /dev/null 
		if [[ "$SLACK_NOTIFICATIONS_WHOIS" == "1" ]]; then
			/bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/osint/whois-$TARGET.txt"
		fi
	fi
    if [[ "$SPOOF_CHECK" = "1" ]]; then
	    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	    echo -e "$OKRED CHECKING FOR EMAIL SECURITY $RESET"
	    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	    dig $TARGET txt | egrep -i 'spf|DMARC|dkim' | tee $LOOT_DIR/nmap/email-$TARGET.txt 2>/dev/null
	    dig iport._domainkey.${TARGET} txt | egrep -i 'spf|DMARC|DKIM' | tee -a $LOOT_DIR/nmap/email-$TARGET.txt 2>/dev/null
	    dig _dmarc.${TARGET} txt | egrep -i 'spf|DMARC|DKIM' | tee -a $LOOT_DIR/nmap/email-$TARGET.txt 2>/dev/null
	    echo ""
	    if [[ "$SLACK_NOTIFICATIONS_EMAIL_SECURITY" == "1" ]]; then
	      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/email-$TARGET.txt"
	    fi
	fi
	if [[ "$ULTRATOOLS" == "1" ]]; then
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED GATHERING ULTATOOLS DNS INFO $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		curl -s https://www.ultratools.com/tools/ipWhoisLookupResult\?ipAddress\=$TARGET | grep -A2 label | grep -v input | grep span | cut -d">" -f2 | cut -d"<" -f1 | sed 's/\&nbsp\;//g' 2> /dev/null | tee $LOOT_DIR/osint/ultratools-$TARGET.txt 2> /dev/null
	fi
	if [[ "$INTODNS" == "1" ]]; then
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED GATHERING DNS INFO $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		wget -q http://www.intodns.com/$TARGET -O $LOOT_DIR/osint/intodns-$TARGET.html 2> /dev/null
		echo -e "$OKRED[+]$RESET Report saved to: $LOOT_DIR/osint/intodns-$TARGET.html"
	fi
	if [[ "$THEHARVESTER" == "1" ]]; then
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED GATHERING THEHARVESTER OSINT INFO $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		cp -f /etc/theHarvester/api-keys.yaml ~/api-keys.yaml 2> /dev/null
		cd ~ 2> /dev/null
		theHarvester -d $TARGET -b all 2> /dev/null | tee $LOOT_DIR/osint/theharvester-$TARGET.txt 2> /dev/null 
		cd $INSTALL_DIR 2> /dev/null
		if [[ "$SLACK_NOTIFICATIONS_THEHARVESTER" == "1" ]]; then
			/bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/osint/theharvester-$TARGET.txt"
		fi
	fi
	if [[ "$EMAILFORMAT" == "1" ]]; then
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED GATHERING EMAILS FROM EMAIL-FORMAT.COM $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		curl -s https://www.email-format.com/d/$TARGET| grep @$TARGET | grep -v div | sed "s/\t//g" | sed "s/ //g" 2> /dev/null | tee $LOOT_DIR/osint/email-format-$TARGET.txt 2> /dev/null 

		if [[ "$SLACK_NOTIFICATIONS_EMAIL_FORMAT" == "1" ]]; then
			/bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/osint/email-format-$TARGET.txt"
		fi
	fi
	if [[ "$URLCRAZY" == "1" ]]; then
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED GATHERING DNS ALTERATIONS $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		urlcrazy $TARGET 2> /dev/null | tee $LOOT_DIR/osint/urlcrazy-$TARGET.txt 2> /dev/null
	fi
	if [[ "$METAGOOFIL" == "1" ]]; then
		if [[ "$VERBOSE" == "1" ]]; then
			echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN metagoofil -d $TARGET -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html 2> /dev/null | tee $LOOT_DIR/osint/metagoofil-$TARGET.txt 2> /dev/null  $RESET"
		fi
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED COLLECTING OSINT FROM ONLINE DOCUMENTS $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		cd $INSTALL_DIR/plugins/metagoofil/
		python3 metagoofil.py -d $TARGET -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html 2> /dev/null | tee $LOOT_DIR/osint/metagoofil-$TARGET.txt 2> /dev/null 
		cd $INSTALL_DIR
		if [[ "$SLACK_NOTIFICATIONS_METAGOOFIL" == "1" ]]; then
			/bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/osint/metagoofil-$TARGET.txt"
		fi
	fi
	if [[ "$URLSCANIO" == "1" ]]; then
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED COLLECTING OSINT FROM URLSCAN.IO $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		curl --insecure -L -s "https://urlscan.io/api/v1/search/?q=domain:$TARGET" 2> /dev/null | egrep "country|server|domain|ip|asn|$TARGET|prt"| sort -u | tee $LOOT_DIR/osint/urlscanio-$TARGET.txt 2> /dev/null
	fi
	if [[ "$HUNTERIO" == "1" ]]; then
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED GATHERING EMAILS VIA HUNTER.IO $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		curl -s "https://api.hunter.io/v2/domain-search?domain=$TARGET&api_key=$HUNTERIO_KEY" | egrep "name|value|domain|company|uri|position|phone" 2> /dev/null | tee $LOOT_DIR/osint/hunterio-$TARGET.txt 2> /dev/null
	fi
	if [[ "$TOMBAIO" == "1" ]]; then
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED GATHERING EMAILS VIA TOMBA.IO $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		curl -H "X-Tomba-Key: $TOMBAIO_KEY" -H "X-Tomba-Secret: $TOMBAIO_SECRET" -s "https://api.tomba.io/v1/domain-search?domain=$TARGET" | egrep "email|organization|uri|position|phone" 2> /dev/null | tee $LOOT_DIR/osint/tombaio$TARGET.txt 2> /dev/null
	fi
	if [[ "$METASPLOIT_EXPLOIT" == "1" ]]; then
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED GATHERING EMAILS VIA METASPLOIT $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		msfconsole -x "use auxiliary/gather/search_email_collector; set DOMAIN $TARGET; run; exit y" | tee $LOOT_DIR/osint/msf-emails-$TARGET.txt 2> /dev/null
	fi
	if [[ "$H8MAIL" == "1" ]]; then
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED CHECKING FOR COMPROMISED CREDENTIALS $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		h8mail -q domain --target $TARGET -o $LOOT_DIR/osint/h8mail-$TARGET.csv 2> /dev/null
	fi
	if [[ "$GITHUB_SECRETS" == "1" ]]; then
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo -e "$OKRED CHECKING FOR GITHUB SECRETS $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		cd $INSTALL_DIR/plugins/gitGraber/
		ORGANIZATION=$(echo $TARGET | awk -F. '{print $(NF-1)}' 2> /dev/null)
		mv $LOOT_DIR/osint/github-urls-$ORGANIZATION.txt $LOOT_DIR/osint/github-urls-$ORGANIZATION.old 2> /dev/null
		mv -f rawGitUrls.txt $LOOT_DIR/osint/github-urls-$ORGANIZATION.txt 2> /dev/null
		touch rawGitUrls.txt 2> /dev/null
		python3 gitGraber.py -q "\"org:$ORGANIZATION\"" -s 2>&1 | tee $LOOT_DIR/osint/gitGrabber-$ORGANIZATION.txt 2> /dev/null
		diff $LOOT_DIR/osint/github-urls-$ORGANIZATION.txt $LOOT_DIR/osint/github-urls-$ORGANIZATION.old 2> /dev/null > $LOOT_DIR/osint/github-urls-$ORGANIZATION.diff
		cat $LOOT_DIR/osint/github-urls-$ORGANIZATION.diff 2> /dev/null
		#python3 gitGraber.py -k wordlists/keywords.txt -q "\"$TARGET\"" -s 2>&1 | tee $LOOT_DIR/osint/gitGrabber-$TARGET.txt 2> /dev/null
	fi
	echo "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per OSINT scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
	if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
		/bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per OSINT scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
	fi
fi
