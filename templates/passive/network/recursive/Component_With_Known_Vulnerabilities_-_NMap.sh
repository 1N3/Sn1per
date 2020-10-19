AUTHOR='@xer0dayz'
VULN_NAME='Component With Known Vulnerabilities - NMap'
FILENAME="$LOOT_DIR/nmap/nmap-$TARGET.txt $LOOT_DIR/output/nmap-$TARGET.txt $LOOT_DIR/output/nmap-$TARGET-*.txt"
MATCH="vulners.com"
GREP_OPTIONS='-ih'
TYPE="network"

rm -f $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt 2> /dev/null
egrep "$GREP_OPTIONS" "$MATCH" $FILENAME 2> /dev/null | awk -v AWK_TARGET="$TARGET" '$5=AWK_TARGET{print "P3 - MEDIUM, Components with Known Vulnerabilities - NMap, " $5 ", " $2 " " $3 " " $4}' 2> /dev/null >> $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt
cat $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt 2> /dev/null