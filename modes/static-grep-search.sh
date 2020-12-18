if [[ $STATIC_GREP_SEARCH == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING INTERESTING EXTENSIONS STATIC ANALYSIS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cat $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -iE "$GREP_EXTENSIONS" | tee $LOOT_DIR/web/static-extensions-$TARGET.txt | head -n $GREP_MAX_LINES
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING INTERESTING PARAMETERS STATIC ANALYSIS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      grep '?' $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -iE "$GREP_PARAMETERS" | tee $LOOT_DIR/web/static-parameters-$TARGET.txt | head -n $GREP_MAX_LINES
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING XSS STATIC ANALYSIS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      grep '?' $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -iE "$GREP_XSS" | tee $LOOT_DIR/web/static-xss-$TARGET.txt | head -n $GREP_MAX_LINES
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING SSRF STATIC ANALYSIS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      grep '?' $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -iE "$GREP_SSRF" | tee $LOOT_DIR/web/static-ssrf-$TARGET.txt | head -n $GREP_MAX_LINES
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING REDIRECT STATIC ANALYSIS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      grep '?' $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -iE "$GREP_REDIRECT" | tee $LOOT_DIR/web/static-redirect-$TARGET.txt | head -n $GREP_MAX_LINES
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING RCE STATIC ANALYSIS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      grep '?' $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -iE "$GREP_RCE" | tee $LOOT_DIR/web/static-rce-$TARGET.txt | head -n $GREP_MAX_LINES
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING IDOR STATIC ANALYSIS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      grep '?' $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -iE "$GREP_IDOR" | tee $LOOT_DIR/web/static-idor-$TARGET.txt | head -n $GREP_MAX_LINES
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING SQL STATIC ANALYSIS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      grep '?' $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -iE "$GREP_SQL" | tee $LOOT_DIR/web/static-sql-$TARGET.txt | head -n $GREP_MAX_LINES
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING LFI STATIC ANALYSIS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      grep '?' $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -iE "$GREP_LFI" | tee $LOOT_DIR/web/static-lfi-$TARGET.txt | head -n $GREP_MAX_LINES
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING SSTI STATIC ANALYSIS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      grep '?' $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -iE "$GREP_SSTI" | tee $LOOT_DIR/web/static-ssti-$TARGET.txt | head -n $GREP_MAX_LINES
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING DEBUG STATIC ANALYSIS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      grep '?' $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -iE "$GREP_DEBUG" | tee $LOOT_DIR/web/static-debug-$TARGET.txt | head -n $GREP_MAX_LINES
fi