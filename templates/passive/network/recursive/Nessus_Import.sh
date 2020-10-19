AUTHOR='@xer0dayz'
VULN_NAME='Nessus Import'
FILENAME="${LOOT_DIR}/output/nessus-report_${TARGET}_*.csv"
OUTPUT_NAME=$(echo $VULN_NAME | sed -E 's/[^[:alnum:]]+/_/g')
TYPE="network"

rm -f $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt 2> /dev/null
grep Critical $FILENAME 2> /dev/null | egrep "tcp|udp" | cut -d, -f4,5,6,7,8,9 | tr \" " " | tr \, " " | sort -u | awk -F '   ' '{print "P1 - CRITICAL, " $5 ", " $2 ":" $4 ", " $6}' | grep -v 'was found to be open' 2> /dev/null >> $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt
grep High $FILENAME 2> /dev/null | egrep "tcp|udp" | cut -d, -f4,5,6,7,8,9 | tr \" " " | tr \, " " | sort -u | awk -F '   ' '{print "P2 - HIGH, " $5 ", " $2 ":" $4 ", " $6}' | grep -v 'was found to be open' 2> /dev/null >> $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt
grep Medium $FILENAME 2> /dev/null | egrep "tcp|udp" | cut -d, -f4,5,6,7,8,9 | tr \" " " | tr \, " " | sort -u | awk -F '   ' '{print "P3 - MEDIUM, " $5 ", " $2 ":" $4 ", " $6}' | grep -v 'was found to be open' 2> /dev/null >> $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt
grep Low $FILENAME 2> /dev/null | egrep "tcp|udp" | cut -d, -f4,5,6,7,8,9 | tr \" " " | tr \, " " | sort -u | awk -F '   ' '{print "P4 - LOW, " $5 ", " $2 ":" $4 ", " $6}' | grep -v 'was found to be open' 2> /dev/null >> $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt
grep None $FILENAME 2> /dev/null | egrep "tcp|udp" | cut -d, -f4,5,6,7,8,9 | tr \" " " | tr \, " " | sort -u | awk -F '   ' '{print "P5 - INFO, " $5 ", " $2 ":" $4 ", " $6}' | grep -v 'was found to be open' | grep -v "None" 2> /dev/null >> $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt

cat $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt 2> /dev/null