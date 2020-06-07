      echo "====================================================================================" | tee $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      CRITICAL_VULNS=$(egrep CRITICAL $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-*.txt 2> /dev/null | wc -l)
      HIGH_VULNS=$(egrep HIGH $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-*.txt 2> /dev/null | wc -l)
      MEDIUM_VULNS=$(egrep MEDIUM $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-*.txt 2> /dev/null | wc -l)
      LOW_VULNS=$(egrep LOW $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-*.txt 2> /dev/null | wc -l)
      INFO_VULNS=$(egrep INFO $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-*.txt 2> /dev/null | wc -l)
      VULN_SCORE=$(($CRITICAL_VULNS*5+$HIGH_VULNS*4+$MEDIUM_VULNS*3+$LOW_VULNS*2+$INFO_VULNS*1))
      echo "•?((¯°·..• Sc0pe Vulnerability Report by @xer0dayz •._.·°¯))؟• " | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      echo "====================================================================================" | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      echo "Critical: $CRITICAL_VULNS" | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      echo "High: $HIGH_VULNS" | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      echo "Medium: $MEDIUM_VULNS" | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      echo "Low: $LOW_VULNS" | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      echo "Info: $INFO_VULNS" | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      echo "Score: $VULN_SCORE" | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      echo "$VULN_SCORE" 2> /dev/null > $LOOT_DIR/vulnerabilities/vulnerability-risk-$TARGET.txt 2> /dev/null | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      echo "====================================================================================" | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      egrep -h CRITICAL $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-*.txt 2> /dev/null | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      egrep -h HIGH $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-*.txt 2> /dev/null | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      egrep -h MEDIUM $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-*.txt 2> /dev/null | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      egrep -h LOW $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-*.txt 2> /dev/null | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      egrep -h INFO $LOOT_DIR/vulnerabilities/sc0pe-$TARGET-*.txt 2> /dev/null | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      echo "====================================================================================" | tee -a $LOOT_DIR/vulnerabilities/vulnerability-report-$TARGET.txt 2> /dev/null
      