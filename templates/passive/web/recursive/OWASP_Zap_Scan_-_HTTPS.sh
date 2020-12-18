AUTHOR='@xer0dayz'
VULN_NAME='OWASP Zap Scan - HTTPS'
FILENAME="$LOOT_DIR/web/zap-report-${TARGET}-https.html"
OUTPUT_NAME=$(echo $VULN_NAME | sed -E 's/[^[:alnum:]]+/_/g')

rm -f $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt 2> /dev/null
cat $FILENAME 2> /dev/null | egrep '<name>' -A20 | egrep '<name>|<riskdesc>|<uri>|<desc>' > /tmp/raw_out.txt 2> /dev/null
grep '<name>' /tmp/raw_out.txt 2> /dev/null| cut -d'<' -f2 | cut -d'>' -f2 > /tmp/vulns.txt 2> /dev/null
grep '<riskdesc>' /tmp/raw_out.txt 2> /dev/null| cut -d'<' -f2 | cut -d'>' -f2 > /tmp/risk.txt 2> /dev/null
grep '<desc>' /tmp/raw_out.txt 2> /dev/null| cut -d\; -f3 > /tmp/desc.txt 2> /dev/null

awk 'FNR==1' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' > /tmp/report.csv  2> /dev/null
awk 'FNR==2' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==3' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==4' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==5' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==6' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==7' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==8' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==9' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==10' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==11' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==12' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==13' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==14' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==15' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==16' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==17' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==18' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==19' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==20' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==21' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==22' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==23' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==24' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==25' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==26' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==27' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==28' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==29' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==30' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==31' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==32' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==33' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==34' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==35' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==36' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==37' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==38' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==39' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==40' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==50' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==51' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==52' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==53' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==54' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==55' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==56' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==57' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==58' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==59' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null
awk 'FNR==60' /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' >> /tmp/report.csv  2> /dev/null

egrep '^High' /tmp/report.csv 2> /dev/null | awk -v AWK_TARGET="$TARGET" -F',' '$50=AWK_TARGET{print "P2 - HIGH, " $2 ", http://" $50 ", " $3}' > /tmp/report_final.csv 2> /dev/null
egrep '^Medium' /tmp/report.csv 2> /dev/null | awk -v AWK_TARGET="$TARGET" -F',' '$50=AWK_TARGET{print "P3 - MEDIUM, " $2 ", http://" $50 ", " $3}' >> /tmp/report_final.csv 2> /dev/null
egrep '^Low' /tmp/report.csv 2> /dev/null | awk -v AWK_TARGET="$TARGET" -F',' '$50=AWK_TARGET{print "P4 - LOW, " $2 ", http://" $50 ", " $3}' >> /tmp/report_final.csv 2> /dev/null
egrep '^Informational' /tmp/report.csv 2> /dev/null | awk -v AWK_TARGET="$TARGET" -F',' '$50=AWK_TARGET{print "P5 - INFO, " $2 ", http://" $50 ", " $3}' >> /tmp/report_final.csv 2> /dev/null

mv -f /tmp/report_final.csv $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt 2> /dev/null

cat $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-$OUTPUT_NAME.txt 2> /dev/null

rm -f /tmp/report_final.csv /tmp/report.csv /tmp/risk.txt /tmp/vulns.txt /tmp/desc.txt 2> /dev/null