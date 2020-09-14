            for file in `ls $INSTALL_DIR/templates/passive/web/*.sh 2> /dev/null`; do
                  source $file
                  OUTPUT_NAME=$(echo $VULN_NAME | sed -E 's/[^[:alnum:]]+/_/g')
                  if [[ "$SEARCH" == "negative" ]]; then
                        if [[ "$SSL" == "true" ]]; then
                            if [[ -z "$PORT" ]]; then
                                PORT="443"
                            fi
                            cat $FILENAME 2> /dev/null | egrep $GREP_OPTIONS "$MATCH" $SECONDARY_COMMANDS 2> /dev/null >/tmp/match.out || echo "$SEVERITY, $VULN_NAME, https://$TARGET:$PORT/$URI, $(head -n 1 /tmp/match.out | sed -r "s/</\&lh\;/g")" | tee "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-https-$OUTPUT_NAME.txt" 2> /dev/null && /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: $TARGET:$PORT/$URI - EVIDENCE: $(head -n 1 /tmp/match.out) (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" && echo "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: $TARGET:$PORT/$URI - EVIDENCE: $(head -n 1 /tmp/match.out | sed -r "s/</\&lh\;/g") (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications.txt || rm -f "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-https-$OUTPUT_NAME.txt" 2> /dev/null 
                        else
                            if [[ -z "$PORT" ]]; then
                                PORT="80"
                            fi
                            cat $FILENAME 2> /dev/null | egrep $GREP_OPTIONS "$MATCH" $SECONDARY_COMMANDS 2> /dev/null >/tmp/match.out || echo "$SEVERITY, $VULN_NAME, http://$TARGET:$PORT/$URI, $(head -n 1 /tmp/match.out | sed -r "s/</\&lh\;/g")" | tee "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-http-$OUTPUT_NAME.txt" 2> /dev/null && /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: http://$TARGET:$PORT/$URI - EVIDENCE: $(head -n 1 /tmp/match.out) (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" && echo "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: http://$TARGET:$PORT/$URI - EVIDENCE: $(head -n 1 /tmp/match.out | sed -r "s/</\&lh\;/g") (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications.txt || rm -f "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-http-$OUTPUT_NAME.txt" 2> /dev/null
                        fi
                  else
                        if [[ "$SSL" == "true" ]]; then
                            if [[ -z "$PORT" ]]; then
                                PORT="443"
                            fi
                            cat $FILENAME 2> /dev/null | egrep $GREP_OPTIONS "$MATCH" $SECONDARY_COMMANDS 2> /dev/null >/tmp/match.out && echo "$SEVERITY, $VULN_NAME, https://$TARGET:$PORT/$URI, $(head -n 1 /tmp/match.out | sed -r "s/</\&lh\;/g")" | tee "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-https-$OUTPUT_NAME.txt" 2> /dev/null && /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: $TARGET:$PORT/$URI - EVIDENCE: $(head -n 1 /tmp/match.out) (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" && echo "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: $TARGET:$PORT/$URI - EVIDENCE: $(head -n 1 /tmp/match.out | sed -r "s/</\&lh\;/g") (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications.txt || rm -f "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-https-$OUTPUT_NAME.txt" 2> /dev/null 
                        else
                            if [[ -z "$PORT" ]]; then
                                PORT="80"
                            fi
                            cat $FILENAME 2> /dev/null | egrep $GREP_OPTIONS "$MATCH" $SECONDARY_COMMANDS 2> /dev/null >/tmp/match.out && echo "$SEVERITY, $VULN_NAME, http://$TARGET:$PORT/$URI, $(head -n 1 /tmp/match.out | sed -r "s/</\&lh\;/g")" | tee "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-http-$OUTPUT_NAME.txt" 2> /dev/null && /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: http://$TARGET:$PORT/$URI - EVIDENCE: $(head -n 1 /tmp/match.out) (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" && echo "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: http://$TARGET:$PORT/$URI - EVIDENCE: $(head -n 1 /tmp/match.out | sed -r "s/</\&lh\;/g") (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications.txt || rm -f "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-http-$OUTPUT_NAME.txt" 2> /dev/null
                        fi
                  fi
                  rm -f /tmp/match.out 2> /dev/null
            done
