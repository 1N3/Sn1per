AUTHOR='@xer0dayz'
VULN_NAME='Interesting Ports Found'
FILENAME="$LOOT_DIR/nmap/ports-$TARGET.txt"
MATCH="21\ |22\ |23\ |137\ |139\ |445\ |8080\ |8443\ |3306\ |5900\ |53\ |8081\ |5432\ "
SEVERITY='P5 - INFO'
GREP_OPTIONS='-i'
SECONDARY_COMMANDS=''
OUTPUT_NAME=$(echo $VULN_NAME | sed -E 's/[^[:alnum:]]+/_/g')
TYPE='network'

rm -f /tmp/match.out 2> /dev/null
cat $FILENAME 2> /dev/null | egrep $GREP_OPTIONS "$MATCH" $SECONDARY_COMMANDS 2> /dev/null | head -n 1 2> /dev/null > /tmp/match.out

CHARS="$(wc -c /tmp/match.out 2> /dev/null | awk '{print $1}' 2> /dev/null)"
if [[ $CHARS > 0 ]]; then
	echo "$SEVERITY, $VULN_NAME, $TARGET, $(cat /tmp/match.out 2> /dev/null)" | tee "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt" 2> /dev/null
	# /bin/bash "$INSTALL_DIR/bin/slack.sh" "[+] [$SEVERITY] $VULN_NAME - $TARGET - EVIDENCE: $(cat /tmp/match.out | tr '\n' ' ') (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
	#echo "•?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - $TARGET - EVIDENCE: $(cat /tmp/match.out) (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
else
	rm -f "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt" 2> /dev/null
fi

rm -f /tmp/match.out 2> /dev/null
