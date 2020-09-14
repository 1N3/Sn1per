if [[ "$MODE" = "webscan" ]]; then
	echo -e "$OKRED                ____               $RESET"
	echo -e "$OKRED    _________  /  _/___  ___  _____$RESET"
	echo -e "$OKRED   / ___/ __ \ / // __ \/ _ \/ ___/$RESET"
	echo -e "$OKRED  (__  ) / / // // /_/ /  __/ /    $RESET"
	echo -e "$OKRED /____/_/ /_/___/ .___/\___/_/     $RESET"
	echo -e "$OKRED               /_/                 $RESET"
	echo -e "$RESET"
	echo -e "$OKORANGE + -- --=[https://xerosecurity.com"
	echo -e "$OKORANGE + -- --=[Sn1per v$VER by @xer0dayz"
	echo -e ""
	echo -e ""
	echo -e "               ;               ,           "
	echo -e "             ,;                 '.         "
	echo -e "            ;:                   :;        "
	echo -e "           ::                     ::       "
	echo -e "           ::                     ::       "
	echo -e "           ':                     :        "
	echo -e "            :.                    :        "
	echo -e "         ;' ::                   ::  '     "
	echo -e "        .'  ';                   ;'  '.    "
	echo -e "       ::    :;                 ;:    ::   "
	echo -e "       ;      :;.             ,;:     ::   "
	echo -e "       :;      :;:           ,;\"      ::   "
	echo -e "       ::.      ':;  ..,.;  ;:'     ,.;:   "
	echo -e "        \"'\"...   '::,::::: ;:   .;.;\"\"'    "
	echo -e "            '\"\"\"....;:::::;,;.;\"\"\"         "
	echo -e "        .:::.....'\"':::::::'\",...;::::;.   "
	echo -e "       ;:' '\"\"'\"\";.,;:::::;.'\"\"\"\"\"\"  ':;   "
	echo -e "      ::'         ;::;:::;::..         :;  "
	echo -e "     ::         ,;:::::::::::;:..       :: "
	echo -e "     ;'     ,;;:;::::::::::::::;\";..    ':."
	echo -e "    ::     ;:\"  ::::::\"\"\"'::::::  \":     ::"
	echo -e "     :.    ::   ::::::;  :::::::   :     ; "
	echo -e "      ;    ::   :::::::  :::::::   :    ;  "
	echo -e "       '   ::   ::::::....:::::'  ,:   '   "
	echo -e "        '  ::    :::::::::::::\"   ::       "
	echo -e "           ::     ':::::::::\"'    ::       "
	echo -e "           ':       \"\"\"\"\"\"\"'      ::       "
	echo -e "            ::                   ;:        "
	echo -e "            ':;                 ;:\"        "
	echo -e "    -hrr-     ';              ,;'          "
	echo -e "                \"'           '\"            "
	echo -e "                  ''''$RESET"
	echo ""
	echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2> /dev/null
	echo "$TARGET" >> $LOOT_DIR/domains/targets.txt
	touch $LOOT_DIR/scans/$TARGET-webscan.txt 2> /dev/null 
	echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt 2> /dev/null
	ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt
	if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
		/bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Started Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
		echo "[xerosecurity.com] •?((¯°·._.• Started Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications.txt
	fi
	
    if [[ "$BURP_SCAN" == "1" ]]; then
    	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    	echo -e "$OKRED RUNNING BURPSUITE SCAN $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		curl -s -X POST "http://$BURP_HOST:$BURP_PORT/v0.1/scan" -d "{\"scope\":{\"include\":[{\"rule\":\"http://$TARGET:80\"}],\"type\":\"SimpleScope\"},\"urls\":[\"http://$TARGET:80\"]}"
		curl -s -X POST "http://$BURP_HOST:$BURP_PORT/v0.1/scan" -d "{\"scope\":{\"include\":[{\"rule\":\"https://$TARGET:443\"}],\"type\":\"SimpleScope\"},\"urls\":[\"https://$TARGET:443\"]}"
		echo ""	
		for a in {1..30}; 
		do 
			echo -n "[-] SCAN #$a: "
			curl -sI "http://$BURP_HOST:$BURP_PORT/v0.1/scan/$a" | grep HTTP | awk '{print $2}'
			BURP_STATUS=$(curl -s http://$BURP_HOST:$BURP_PORT/v0.1/scan/$a | grep -o -P "crawl_and_audit.{1,100}" | cut -d\" -f3 | grep "remaining")
			while [[ ${#BURP_STATUS} -gt "5" ]]; 
			do 
				BURP_STATUS=$(curl -s http://$BURP_HOST:$BURP_PORT/v0.1/scan/$a | grep -o -P "crawl_and_audit.{1,100}" | cut -d\" -f3 | grep "remaining")
				BURP_STATUS_FULL=$(curl -s http://$BURP_HOST:$BURP_PORT/v0.1/scan/$a | grep -o -P "crawl_and_audit.{1,100}" | cut -d\" -f3)
				echo "[i] STATUS: $BURP_STATUS_FULL"
				sleep 15
			done
		done 

		echo "[+] VULNERABILITIES: "
		echo "----------------------------------------------------------------"
		for a in {1..30}; 
		do
			curl -s "http://$BURP_HOST:$BURP_PORT/v0.1/scan/$a" | jq '.issue_events[].issue | "[" + .severity + "] " + .name + " - " + .origin + .path' | sort -u | sed 's/\"//g' | tee $LOOT_DIR/web/burpsuite-$TARGET-$a.txt
		done

		echo "[-] Done!"
    fi
    if [[ "$ZAP_SCAN" == "1" ]]; then
    	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    	echo -e "$OKRED RUNNING OWASP ZAP SCAN $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		echo "[i] Scanning: http://$TARGET/"
    	sudo python3 /usr/share/sniper/bin/zap-scan.py "http://$TARGET/" 
    	DATE=$(date +"%Y%m%d%H%M")
    	sudo grep "'" /usr/share/sniper/bin/zap-report.txt | cut -d\' -f2 | cut -d\\ -f1 > $LOOT_DIR/web/zap-report-$TARGET-http-$DATE.html
    	cp -f $LOOT_DIR/web/zap-report-$TARGET-http-$DATE.html $LOOT_DIR/web/zap-report-$TARGET-http.html 2> /dev/null
    	echo "[i] Scan complete."
    	echo "[+] Report saved to: $LOOT_DIR/web/zap-report-$TARGET-http-$DATE.html"
    	sleep 5
    	echo "[i] Scanning: https://$TARGET/"
    	sudo python3 /usr/share/sniper/bin/zap-scan.py "https://$TARGET/"
    	sudo grep "'" /usr/share/sniper/bin/zap-report.txt | cut -d\' -f2 | cut -d\\ -f1 > $LOOT_DIR/web/zap-report-$TARGET-https-$DATE.html
    	cp -f $LOOT_DIR/web/zap-report-$TARGET-https-$DATE.html $LOOT_DIR/web/zap-report-$TARGET-https.html 2> /dev/null
    	echo "[i] Scan complete."
    	echo "[+] Report saved to: $LOOT_DIR/web/zap-report-$TARGET-https-$DATE.html"
    fi
    if [[ "$ARACHNI_SCAN" == "1" ]]; then
    	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    	echo -e "$OKRED RUNNING ARACHNI SCAN $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		DATE=$(date +"%Y%m%d%H%M")
		mkdir -p $LOOT_DIR/web/http-$TARGET/
		mkdir -p $LOOT_DIR/web/https-$TARGET/
		arachni --report-save-path=$LOOT_DIR/web/http-$TARGET/ --output-only-positives http://$TARGET | tee $LOOT_DIR/output/sniper-$TARGET-webscan-http-${DATE}.txt
		cp -vf $LOOT_DIR/output/sniper-$TARGET-webscan-http-${DATE}.txt $LOOT_DIR/web/arachni-$TARGET-webscan-http.txt
		sleep 1
		arachni --report-save-path=$LOOT_DIR/web/https-$TARGET/ --output-only-positives https://$TARGET | tee $LOOT_DIR/output/sniper-$TARGET-webscan-https-${DATE}.txt
		cp -vf $LOOT_DIR/output/sniper-$TARGET-webscan-https-${DATE}.txt $LOOT_DIR/web/arachni-$TARGET-webscan-https.txt
		if [[ "$SLACK_NOTIFICATIONS_ARACHNI_SCAN" == "1" ]]; then
			bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/output/sniper-$TARGET-webscan-http-$DATE.txt"
			bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/output/sniper-$TARGET-webscan-https-$DATE.txt"
		fi
		cd $LOOT_DIR/web/http-$TARGET/
		cd $LOOT_DIR/web/https-$TARGET/
		arachni_reporter $LOOT_DIR/web/http-$TARGET/*.afr --report=html:outfile=$LOOT_DIR/web/http-$TARGET/arachni.zip
		arachni_reporter $LOOT_DIR/web/https-$TARGET/*.afr --report=html:outfile=$LOOT_DIR/web/https-$TARGET/arachni.zip
		cd $LOOT_DIR/web/http-$TARGET/
		unzip arachni.zip
		cd $LOOT_DIR/web/https-$TARGET/
		unzip arachni.zip
		cd $INSTALL_DIR
	fi
	if [[ "$SC0PE_VULNERABLITY_SCANNER" == "1" ]]; then
	    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	    echo -e "$OKRED RUNNING SC0PE WEB VULNERABILITY SCAN $RESET"
	    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	    SSL="false"
	    PORT="80"
	    source $INSTALL_DIR/modes/sc0pe-passive-webscan.sh
	    source $INSTALL_DIR/modes/sc0pe-active-webscan.sh
	    SSL="true"
	    PORT="443"
	    source $INSTALL_DIR/modes/sc0pe-passive-webscan.sh
	    source $INSTALL_DIR/modes/sc0pe-active-webscan.sh
	    for file in `ls $INSTALL_DIR/templates/passive/web/recursive/*.sh 2> /dev/null`; do
          source $file
        done
	    source $INSTALL_DIR/modes/sc0pe-network-scan.sh
	fi
	source $INSTALL_DIR/modes/sc0pe.sh 
	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	echo -e "$OKRED SCAN COMPLETE! $RESET"
	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo "$TARGET" >> $LOOT_DIR/scans/updated.txt
    rm -f $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt 2> /dev/null
    ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt

    if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
		/bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
		echo "[xerosecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications.txt
	fi

	loot 
	exit
fi