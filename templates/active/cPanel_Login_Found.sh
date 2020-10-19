AUTHOR='@xer0dayz'
VULN_NAME='cPanel Login Found'
URI='/'
METHOD='GET'
MATCH="cPanel\ Login"
SEVERITY='P5 - INFO'
CURL_OPTS="--user-agent '' -s -L --insecure"
SECONDARY_COMMANDS=''
GREP_OPTIONS=''

curl --connect-timeout 3 --max-time 5 -k -X $METHOD $CURL_OPTS "https://${TARGET}:2083${URI}" 2> /dev/null | egrep $GREP_OPTIONS "$MATCH" $SECONDARY_COMMANDS 2> /dev/null >/tmp/match.out && echo "$SEVERITY, $VULN_NAME,https://${TARGET}:2083${URI},$(head -n 1 /tmp/match.out | sed -r "s/</\&lh\;/g")" | tee "$LOOT_DIR/vulnerabilities/sc0pe-$TARGET-https-2083-$OUTPUT_NAME.txt" 2> /dev/null && /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: https://$TARGET:2083/$URI - EVIDENCE: $(cat /tmp/match.out) (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" && echo "[xerosecurity.com] •?((¯°·._.• [+] [$SEVERITY] $VULN_NAME - URL: https://${TARGET}:2083${URI} - EVIDENCE: $(cat /tmp/match.out | sed -r "s/</\&lh\;/g") (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications.txt 2> /dev/null 