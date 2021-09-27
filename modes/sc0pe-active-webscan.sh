        for file in `ls $INSTALL_DIR/templates/active/*.sh 2> /dev/null`; do
            source $file
            OUTPUT_NAME=$(echo $VULN_NAME | sed -E 's/[^[:alnum:]]+/_/g')
            if [[ "$SSL" == "true" ]]; then
                if [[ -z "$PORT" ]]; then
                    PORT="443"
                fi
                rm -f "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-https-$PORT-$OUTPUT_NAME.txt" 2> /dev/null
                curl --connect-timeout 3 --max-time 5 -k -X $METHOD $CURL_OPTS "https://${TARGET}:${PORT}${URI}" 2> /dev/null | egrep $GREP_OPTIONS "$MATCH" $SECONDARY_COMMANDS 2> /dev/null >/tmp/${TARGET}_${OUTPUT_NAME}.out && echo "$SEVERITY, $VULN_NAME,https://${TARGET}:${PORT}${URI},$(head -n 1 /tmp/${TARGET}_${OUTPUT_NAME}.out | sed -r "s/</\&lh\;/g")" | tee "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-https-$PORT-$OUTPUT_NAME.txt" 2> /dev/null && echo "[sn1persecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: https://${TARGET}:${PORT}${URI} - EVIDENCE: $(cat /tmp/${TARGET}_${OUTPUT_NAME}.out | sed -r "s/</\&lh\;/g") (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt 2> /dev/null 
            else
                if [[ -z "$PORT" ]]; then
                    PORT="80"
                fi
                rm -f "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-http-$PORT-$OUTPUT_NAME.txt" 2> /dev/null
                curl --connect-timeout 3 --max-time 5 -k -X $METHOD $CURL_OPTS "http://${TARGET}:${PORT}${URI}" 2> /dev/null | egrep $GREP_OPTIONS "$MATCH" $SECONDARY_COMMANDS 2> /dev/null >/tmp/${TARGET}_${OUTPUT_NAME}.out && echo "$SEVERITY, $VULN_NAME,http://${TARGET}:${PORT}${URI},$(head -n 1 /tmp/${TARGET}_${OUTPUT_NAME}.out | sed -r "s/</\&lh\;/g")" | tee "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-http-$PORT-$OUTPUT_NAME.txt" 2> /dev/null && echo "[sn1persecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: http://${TARGET}:${PORT}${URI} - EVIDENCE: $(cat /tmp/${TARGET}_${OUTPUT_NAME}.out | sed -r "s/</\&lh\;/g") (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt 2> /dev/null
            fi
            rm -f /tmp/${TARGET}_${OUTPUT_NAME}.out 2> /dev/null
        done