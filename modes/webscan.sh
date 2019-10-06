if [ "$MODE" = "webscan" ]; then
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
	if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
		/bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Started Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
	fi
    if [ "$BURP_SCAN" == "1" ]; then
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
			echo "[+] VULNERABILITIES: "
			echo "----------------------------------------------------------------"
			curl -s "http://$BURP_HOST:$BURP_PORT/v0.1/scan/$a" | grep -o -P "name.{1,100}" | cut -d\" -f3 | sort -u | grep -Ev 'caption|evidence' | tee $LOOT_DIR/web/burpsuite-$TARGET-$a.txt
		done 
		echo "[-] Done!"
    fi
    if [ "$ARACHNI_SCAN" == "1" ]; then
    	echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    	echo -e "$OKRED RUNNING ARACHNI SCAN $RESET"
		echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
		mkdir -p $LOOT_DIR/web/http-$TARGET/
		mkdir -p $LOOT_DIR/web/https-$TARGET/
		arachni --report-save-path=$LOOT_DIR/web/http-$TARGET/ --output-only-positives http://$TARGET | tee $LOOT_DIR/output/sniper-$TARGET-webscan-http-`date +"%Y%m%d%H%M"`.txt 2>&1
		arachni --report-save-path=$LOOT_DIR/web/https-$TARGET/ --output-only-positives https://$TARGET | tee $LOOT_DIR/output/sniper-$TARGET-webscan-https-`date +"%Y%m%d%H%M"`.txt 2>&1

		if [ "$SLACK_NOTIFICATIONS_ARACHNI_SCAN" == "1" ]; then
			bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/output/sniper-$TARGET-webscan-http-`date +"%Y%m%d%H%M"`.txt"
			bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/output/sniper-$TARGET-webscan-https-`date +"%Y%m%d%H%M"`.txt"
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
    echo "$TARGET" >> $LOOT_DIR/scans/updated.txt
	loot 
	if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
		/bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
	fi
	exit
fi