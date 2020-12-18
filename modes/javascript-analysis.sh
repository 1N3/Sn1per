      mkdir -p $LOOT_DIR/web/javascript/$TARGET 2> /dev/null
      cd $LOOT_DIR/web/javascript/$TARGET
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED DOWNLOADING ALL JAVASCRIPT FILES $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      egrep --binary-files=text "\.js" $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -v '.json|.jsp'
      for a in `egrep --binary-files=text "\.js" $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -v '.json|.jsp' | head -n $MAX_JAVASCRIPT_FILES | cut -d\? -f1 | sort -u`; do echo "Downloading - $a" && FILENAME=$(echo "$a" | awk -F/ '{print $(NF-0)}') && curl --connect-timeout 10 --max-time 10 -s -R -L --insecure $a | js-beautify - > $FILENAME 2> /dev/null; done;
      for a in `egrep --binary-files=text "\.js" $LOOT_DIR/web/weblinks-htt*-$TARGET.txt 2> /dev/null | egrep -v '.json|.jsp' | egrep -i 'http' | head -n $MAX_JAVASCRIPT_FILES | cut -d\? -f1 | sort -u`; do echo "Downloading - $a" && FILENAME=$(echo "$a" | awk -F/ '{print $(NF-0)}') && curl --connect-timeout 10 --max-time 10 -s -R -L --insecure $a | js-beautify - > $FILENAME 2> /dev/null; done;
      for a in `egrep --binary-files=text "\.js" $LOOT_DIR/web/weblinks-htt*-$TARGET.txt 2> /dev/null | egrep -v '.json|.jsp' | egrep -iv 'http' | head -n $MAX_JAVASCRIPT_FILES | cut -d\? -f1 | sort -u`; do echo "Downloading - https://$a" && FILENAME=$(echo "https://$a" | awk -F/ '{print $(NF-0)}') && curl --connect-timeout 10 --max-time 10 -s -R -L --insecure $a | js-beautify - > $FILENAME 2> /dev/null; done;
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED DISPLAYING ALL JAVASCRIPT COMMENTS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cat $LOOT_DIR/web/javascript/$TARGET/*.js 2> /dev/null | egrep "\/\/|\/\*" | sort -u | tee $LOOT_DIR/web/javascript-$TARGET-comments.txt 
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED DISPLAYING ALL JAVASCRIPT LINKS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cat $LOOT_DIR/web/javascript/$TARGET/*.js 2> /dev/null | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u | tee $LOOT_DIR/web/javascript-$TARGET-urls.txt
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING LINKFINDER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cd $PLUGINS_DIR/LinkFinder/
      for a in `ls $LOOT_DIR/web/javascript/$TARGET/*.js 2> /dev/null`; do echo "Analyzing - $a" && FILENAME=$(echo "$a" | awk -F/ '{print $(NF-0)}') && python3 linkfinder.py -d -i $a -o cli 2> /dev/null | egrep -v "application\/|SSL error" > $LOOT_DIR/web/javascript-linkfinder-$TARGET-$FILENAME.txt 2> /dev/null; done;
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED DISPLAYING PATH RELATIVE LINKS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cat $LOOT_DIR/web/javascript-linkfinder-$TARGET-*.txt 2> /dev/null | grep -v "Running " | awk '{print $1}' | sort -u | tee $LOOT_DIR/web/javascript-$TARGET-path-relative.txt
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED DISPLAYING JAVASCRIPT URLS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      grep -h http $LOOT_DIR/web/javascript-linkfinder-$TARGET-*.txt 2> /dev/null | grep -v "Running " | awk '{print $1}' | egrep "http\:\/\/|https\:\/\/" | sort -u | tee $LOOT_DIR/web/javascript-$TARGET-linkfinder-urls.txt
      sort -u $LOOT_DIR/web/javascript-$TARGET-urls.txt $LOOT_DIR/web/javascript-$TARGET-linkfinder-urls.txt 2> /dev/null > $LOOT_DIR/web/javascript-$TARGET-urls-sorted.txt
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED DISPLAYING JAVASCRIPT DOMAINS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      grep -h http $LOOT_DIR/web/javascript-linkfinder-$TARGET-*.txt 2> /dev/null | grep -v "Running " | awk '{print $1}' | egrep "http\:\/\/|https\:\/\/" | cut -d\/ -f3 | sort -u | tee $LOOT_DIR/web/javascript-$TARGET-domains.txt
      WEB_JAVASCRIPT_ANALYSIS="0"
