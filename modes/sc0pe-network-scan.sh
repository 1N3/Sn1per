      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
	    echo -e "$OKRED RUNNING SC0PE NETWORK VULNERABILITY SCAN $RESET"
	    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
        for file in `ls $INSTALL_DIR/templates/passive/network/*.sh 2> /dev/null`; do
              source $file
              OUTPUT_NAME=$(echo $VULN_NAME | sed -E 's/[^[:alnum:]]+/_/g')
              if [[ "$SEARCH" == "negative" ]]; then
                    cat $FILENAME 2> /dev/null | egrep $GREP_OPTIONS "$MATCH" $SECONDARY_COMMANDS 2> /dev/null >/tmp/${TARGET}_${OUTPUT_NAME}.out || echo "$SEVERITY, $VULN_NAME, $TARGET, $(head -n 1 /tmp/${TARGET}_${OUTPUT_NAME}.out | sed -r "s/</\&lh\;/g")" | tee "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt" 2> /dev/null && /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - $TARGET - EVIDENCE: $(head -n 1 /tmp/${TARGET}_${OUTPUT_NAME}.out) (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" && echo "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - $TARGET - EVIDENCE: $(head -n 1 /tmp/${TARGET}_${OUTPUT_NAME}.out | sed -r "s/</\&lh\;/g") (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications.txt 2> /dev/null
              else
                    cat $FILENAME 2> /dev/null | egrep $GREP_OPTIONS "$MATCH" $SECONDARY_COMMANDS 2> /dev/null >/tmp/${TARGET}_${OUTPUT_NAME}.out && echo "$SEVERITY, $VULN_NAME, $TARGET, $(head -n 1 /tmp/${TARGET}_${OUTPUT_NAME}.out | sed -r "s/</\&lh\;/g")" | tee "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt" 2> /dev/null && /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - $TARGET - EVIDENCE: $(head -n 1 /tmp/${TARGET}_${OUTPUT_NAME}.out) (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" && echo "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - $FILENME - EVIDENCE: $(head -n 1 /tmp/${TARGET}_${OUTPUT_NAME}.out | sed -r "s/</\&lh\;/g") (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications.txt 2> /dev/null
              fi
              rm -f /tmp/${TARGET}_${OUTPUT_NAME}.out 2> /dev/null
        done

        for file in `ls $INSTALL_DIR/templates/passive/network/recursive/*.sh 2> /dev/null`; do
          source $file
        done
	    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"