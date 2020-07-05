AUTHOR='@xer0dayz'
VULN_NAME='Interesting Ports Found'
FILENAME="$LOOT_DIR/nmap/ports-$TARGET.txt"
MATCH='80|443'
SEVERITY='P5 - INFO'
GREP_OPTIONS='-iv'
SEARCH='positive'
SECONDARY_COMMANDS=''

rm -f /tmp/match.out 2> /dev/null

for line in `cat $FILENAME 2> /dev/null`; do
	echo $line
	OUTPUT_NAME=$(echo $VULN_NAME | sed -E 's/[^[:alnum:]]+/_/g')
	if [[ "$SEARCH" == "negative" ]]; then
        cat $FILENAME 2> /dev/null | egrep $GREP_OPTIONS "$MATCH" $SECONDARY_COMMANDS 2> /dev/null >/tmp/match.out || echo "[+] [$SEVERITY] $VULN_NAME - URL: https://$TARGET:$PORT - EVIDENCE: $(head -n 1 /tmp/match.out | sed -r "s/</\&lh\;/g")" | tee "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-https-$OUTPUT_NAME.txt" 2> /dev/null && /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: https://$TARGET:$PORT/$URI - EVIDENCE: $(head -n 1 /tmp/match.out) (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" && echo "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: https://$TARGET:$PORT/$URI - EVIDENCE: $(head -n 1 /tmp/match.out | sed -r "s/</\&lh\;/g") (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications.txt || rm -f "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-https-$OUTPUT_NAME.txt" 2> /dev/null 
	else
        cat $FILENAME 2> /dev/null | egrep $GREP_OPTIONS "$MATCH" $SECONDARY_COMMANDS 2> /dev/null >/tmp/match.out && echo "[+] [$SEVERITY] $VULN_NAME - URL: https://$TARGET:$PORT - EVIDENCE: $(head -n 1 /tmp/match.out | sed -r "s/</\&lh\;/g")" | tee "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-https-$OUTPUT_NAME.txt" 2> /dev/null && /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: https://$TARGET:$PORT/$URI - EVIDENCE: $(head -n 1 /tmp/match.out) (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" && echo "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: https://$TARGET:$PORT/$URI - EVIDENCE: $(head -n 1 /tmp/match.out | sed -r "s/</\&lh\;/g") (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications.txt || rm -f "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-https-$OUTPUT_NAME.txt" 2> /dev/null 
	fi
	rm -f /tmp/match.out 2> /dev/null
done