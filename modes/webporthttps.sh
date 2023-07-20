# WEBPORTHTTPS MODE #####################################################################################################
if [[ "$MODE" = "webporthttps" ]]; then
  if [[ "$REPORT" = "1" ]]; then
    if [[ ! -z "$WORKSPACE" ]]; then
      args="$args -w $WORKSPACE"
      LOOT_DIR=$INSTALL_DIR/loot/workspace/$WORKSPACE
      echo -e "$OKBLUE[*]$RESET Saving loot to $LOOT_DIR [$RESET${OKGREEN}OK${RESET}$OKBLUE]$RESET"
      mkdir -p $LOOT_DIR 2> /dev/null
      mkdir $LOOT_DIR/domains 2> /dev/null
      mkdir $LOOT_DIR/screenshots 2> /dev/null
      mkdir $LOOT_DIR/nmap 2> /dev/null
      mkdir $LOOT_DIR/notes 2> /dev/null
      mkdir $LOOT_DIR/reports 2> /dev/null
      mkdir $LOOT_DIR/scans 2> /dev/null
      mkdir $LOOT_DIR/output 2> /dev/null
    fi
    echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2> /dev/null
    echo "sniper -t $TARGET -m $MODE -p $PORT --noreport $args" >> $LOOT_DIR/scans/$TARGET-$MODE.txt
    echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt
    ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt

    echo "[sn1persecurity.com] •?((¯°·._.• Started Sn1per scan: https://$TARGET:$PORT [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
    if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Started Sn1per scan: https://$TARGET:$PORT [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
    fi
    sniper -t $TARGET -m $MODE -p $PORT --noreport $args | tee $LOOT_DIR/output/sniper-$TARGET-$MODE-$PORT-`date +"%Y%m%d%H%M"`.txt 2>&1
    exit
  fi
  echo -e "$OKRED                ____               $RESET"
  echo -e "$OKRED    _________  /  _/___  ___  _____$RESET"
  echo -e "$OKRED   / ___/ __ \ / // __ \/ _ \/ ___/$RESET"
  echo -e "$OKRED  (__  ) / / // // /_/ /  __/ /    $RESET"
  echo -e "$OKRED /____/_/ /_/___/ .___/\___/_/     $RESET"
  echo -e "$OKRED               /_/                 $RESET"
  echo -e "$RESET"
  echo -e "$OKORANGE + -- --=[https://sn1persecurity.com"
  echo -e "$OKORANGE + -- --=[Sn1per v$VER by @xer0dayz"
  echo -e ""
  echo -e ""
  echo -e "               ;               ,           "
  echo -e "             ,;                 '.         "
  echo -e "            ;:                   :;        "
  echo -e "           ::                     ::       "
  echo -e "           ::                     ::       "
  echo -e "           ':                     :        "
  echo -e "            :.                    :        "
  echo -e "         ;' ::                   ::  '     "
  echo -e "        .'  ';                   ;'  '.    "
  echo -e "       ::    :;                 ;:    ::   "
  echo -e "       ;      :;.             ,;:     ::   "
  echo -e "       :;      :;:           ,;\"      ::   "
  echo -e "       ::.      ':;  ..,.;  ;:'     ,.;:   "
  echo -e "        \"'\"...   '::,::::: ;:   .;.;\"\"'    "
  echo -e "            '\"\"\"....;:::::;,;.;\"\"\"         "
  echo -e "        .:::.....'\"':::::::'\",...;::::;.   "
  echo -e "       ;:' '\"\"'\"\";.,;:::::;.'\"\"\"\"\"\"  ':;   "
  echo -e "      ::'         ;::;:::;::..         :;  "
  echo -e "     ::         ,;:::::::::::;:..       :: "
  echo -e "     ;'     ,;;:;::::::::::::::;\";..    ':."
  echo -e "    ::     ;:\"  ::::::\"\"\"'::::::  \":     ::"
  echo -e "     :.    ::   ::::::;  :::::::   :     ; "
  echo -e "      ;    ::   :::::::  :::::::   :    ;  "
  echo -e "       '   ::   ::::::....:::::'  ,:   '   "
  echo -e "        '  ::    :::::::::::::\"   ::       "
  echo -e "           ::     ':::::::::\"'    ::       "
  echo -e "           ':       \"\"\"\"\"\"\"'      ::       "
  echo -e "            ::                   ;:        "
  echo -e "            ':;                 ;:\"        "
  echo -e "    -hrr-     ';              ,;'          "
  echo -e "                \"'           '\"            "
  echo -e "                  ''''$RESET"
  echo ""
  echo "$TARGET" >> $LOOT_DIR/domains/targets.txt
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED RUNNING TCP PORT SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  port_https=$PORT
  if [[ -z "$port_https" ]];
  then
    echo -e "$OKRED + -- --=[Port $PORT closed... skipping.$RESET"
  else
    echo -e "$OKORANGE + -- --=[Port $PORT opened... running tests...$RESET"
    echo "$TARGET" >> $LOOT_DIR/web/webhosts-unsorted.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED CHECKING HTTP HEADERS AND METHODS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    wget -qO- -T 1 --connect-timeout=5 --read-timeout=10 --tries=1 https://$TARGET:$PORT |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' >> $LOOT_DIR/web/title-https-$TARGET-$PORT.txt 2> /dev/null
    curl --connect-timeout 5 --max-time 10 -I -s -R --insecure https://$TARGET:$PORT | tee $LOOT_DIR/web/headers-https-$TARGET-$PORT.txt 2> /dev/null
    curl --connect-timeout 5 --max-time 10 -I -s -R -L --insecure https://$TARGET:$PORT | tee $LOOT_DIR/web/websource-https-$TARGET-$PORT.txt 2> /dev/null
    curl --connect-timeout 5 --max-time 10 -I -s -R --insecure -X OPTIONS https://$TARGET:$PORT | grep Allow\: | tee $LOOT_DIR/web/http_options-$TARGET-port$PORT.txt 2> /dev/null
    if [[ "$WEBTECH" = "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED GATHERING WEB FINGERPRINT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      webtech -u https://$TARGET:$PORT | grep \- | cut -d- -f2- | tee $LOOT_DIR/web/webtech-$TARGET-https-port$PORT.txt
    fi
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED DISPLAYING META GENERATOR TAGS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cat $LOOT_DIR/web/websource-https-$TARGET-$PORT.txt 2> /dev/null | grep generator | cut -d\" -f4 2> /dev/null | tee $LOOT_DIR/web/webgenerator-https-$TARGET-$PORT.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED DISPLAYING COMMENTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cat $LOOT_DIR/web/websource-https-$TARGET-$PORT.txt 2> /dev/null | grep "<\!\-\-" 2> /dev/null | tee $LOOT_DIR/web/webcomments-https-$TARGET-$PORT.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED DISPLAYING SITE LINKS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cat $LOOT_DIR/web/websource-https-$TARGET-$PORT.txt 2> /dev/null | egrep "\"" | cut -d\" -f2 | grep  \/ | sort -u 2> /dev/null | tee $LOOT_DIR/web/weblinks-https-$TARGET-$PORT.txt 2> /dev/null
    if [[ "$WAFWOOF" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED CHECKING FOR WAF $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      wafw00f https://$TARGET | tee $LOOT_DIR/web/waf-$TARGET-https-port443.txt 2> /dev/null
      echo ""
    fi
    if [[ "$WHATWEB" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED GATHERING HTTP INFO $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      whatweb -a 3 https://$TARGET:$PORT | tee $LOOT_DIR/web/whatweb-$TARGET-https-port$PORT.raw  2> /dev/null
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/whatweb-$TARGET-https-port$PORT.raw > $LOOT_DIR/web/whatweb-$TARGET-https-port$PORT.txt 2> /dev/null
      rm -f $LOOT_DIR/web/whatweb-$TARGET-https-port$PORT.raw 2> /dev/null
      echo ""
    fi
    if [[ "$WIG" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED GATHERING SERVER INFO $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      python3 $PLUGINS_DIR/wig/wig.py -d -q https://$TARGET:$PORT | tee $LOOT_DIR/web/wig-$TARGET-https-$PORT
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/wig-$TARGET-https-$PORT > $LOOT_DIR/web/wig-$TARGET-https-$PORT.txt 2> /dev/null
      rm -f $LOOT_DIR/web/wig-$TARGET-https-$PORT 2> /dev/null
    fi
    if [[ "$SSL" = "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED GATHERING SSL/TLS INFO $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      sslscan --no-failed $TARGET:$PORT | tee $LOOT_DIR/web/sslscan-$TARGET-$PORT.raw 2> /dev/null
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/sslscan-$TARGET-$PORT.raw > $LOOT_DIR/web/sslscan-$TARGET-$PORT.txt 2> /dev/null
      rm -f $LOOT_DIR/web/sslscan-$TARGET-$PORT.raw 2> /dev/null
      echo ""
    fi
    if [[ "$SSL_INSECURE" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED CHECKING FOR INSECURE SSL/TLS CONFIGURATIONS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      curl https://$TARGET:$PORT 2> $LOOT_DIR/web/curldebug-$TARGET-$PORT.txt > /dev/null
    fi
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED SAVING SCREENSHOTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    if [[ $CUTYCAPT = "1" ]]; then
      if [[ $DISTRO == "blackarch"  ]]; then
        /bin/CutyCapt --url=https://$TARGET:$PORT --out=$LOOT_DIR/screenshots/$TARGET-port$PORT.jpg --insecure --max-wait=5000 2> /dev/null
      else
        cutycapt --url=https://$TARGET:$PORT --out=$LOOT_DIR/screenshots/$TARGET-port$PORT.jpg --insecure --max-wait=5000 2> /dev/null
      fi
    fi
    if [[ $WEBSCREENSHOT = "1" ]]; then
      cd $LOOT_DIR
      python2 $INSTALL_DIR/bin/webscreenshot.py -r chromium https://$TARGET:$PORT
    fi
    if [[ "$BURP_SCAN" == "1" ]]; then
        echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
        echo -e "$OKRED RUNNING BURPSUITE SCAN $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
        if [[ "$VERBOSE" == "1" ]]; then
          echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN curl -X POST \"http://$BURP_HOST:$BURP_PORT/v0.1/scan\" -d \"{\"scope\":{\"include\":[{\"rule\":\"https://$TARGET:$PORT\"}],\"type\":\"SimpleScope\"},\"urls\":[\"https://$TARGET:$PORT\"]}\"$RESET"
        fi
        curl -s -X POST "http://$BURP_HOST:$BURP_PORT/v0.1/scan" -d "{\"scope\":{\"include\":[{\"rule\":\"https://$TARGET:$PORT\"}],\"type\":\"SimpleScope\"},\"urls\":[\"https://$TARGET:$PORT\"]}"
        echo ""
    fi
    if [[ "$NMAP_SCRIPTS" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      nmap -Pn -p $PORT -sV -v --script-timeout 90 --script=http-auth-finder,http-auth,http-brute,/usr/share/nmap/scripts/vulners,http-default-accounts $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port$PORT
      sed -r "s/</\&lh\;/g" $LOOT_DIR/output/nmap-$TARGET-port$PORT 2> /dev/null > $LOOT_DIR/output/nmap-$TARGET-port$PORT.txt 2> /dev/null
      rm -f $LOOT_DIR/output/nmap-$TARGET-port$PORT 2> /dev/null
    fi
    if [[ "$PASSIVE_SPIDER" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING PASSIVE WEB SPIDER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2022-33-index?url=*.$TARGET&output=json" -H 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Safari/537.36' 2> /dev/null | jq -r .url | egrep -v "null" | tee $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null | head -n 250
    fi
    if [[ "$WAYBACKMACHINE" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED FETCHING WAYBACK MACHINE URLS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      curl -sX GET "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" | tee $LOOT_DIR/web/waybackurls-$TARGET.txt 2> /dev/null | head -n 250
    fi
    if [[ "$HACKERTARGET" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED FETCHING HACKERTARGET URLS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      curl -s GET "https://api.hackertarget.com/pagelinks/?q=https://$TARGET" | egrep -v "API count|no links found|input url is invalid|API count|no links found|input url is invalid|error getting links" | tee $LOOT_DIR/web/hackertarget-https-$TARGET.txt 2> /dev/null | head -n 250
    fi
    if [[ "$GAU" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED FETCHING GUA URLS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      gau -subs $TARGET | tee $LOOT_DIR/web/gua-$TARGET.txt 2> /dev/null | head -n 250
    fi
    if [[ "$BLACKWIDOW" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING ACTIVE WEB SPIDER & APPLICATION SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      touch $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cp $LOOT_DIR/web/spider-$TARGET.txt $LOOT_DIR/web/spider-$TARGET.bak 2>/dev/null
      blackwidow -u https://$TARGET:$PORT -l 3 -v n 2> /dev/null
      cp -f /usr/share/blackwidow/"$TARGET"_"$PORT"/"$TARGET"_"$PORT"-*.txt $LOOT_DIR/web/ 2>/dev/null 
      cat /usr/share/blackwidow/"$TARGET"_*/"$TARGET"_*-urls-sorted.txt > $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cat $LOOT_DIR/web/hackertarget-*-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cat $LOOT_DIR/web/waybackurls-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cat $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cat $LOOT_DIR/web/gua-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      sed -ir "s/</\&lh\;/g" $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      mv -f $LOOT_DIR/web/spider-$TARGET.txtr $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      sort -u $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null > $LOOT_DIR/web/spider-$TARGET.sorted 2>/dev/null
      mv $LOOT_DIR/web/spider-$TARGET.sorted $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      diff $LOOT_DIR/web/spider-$TARGET.bak $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{print $2}' 2> /dev/null > $LOOT_DIR/web/spider-new-$TARGET.txt
      if [[ $(wc -c $LOOT_DIR/web/spider-new-$TARGET.txt | awk '{print $1}') > 3 ]]; then
        echo "[sn1persecurity.com] •?((¯°·._.• Spider URL change detected on $TARGET (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
        head -n 20 $LOOT_DIR/web/spider-new-$TARGET.txt 2> /dev/null >> $LOOT_DIR/scans/notifications_new.txt 2> /dev/null
      fi
      if [[ "$SLACK_NOTIFICATIONS_SPIDER_NEW" == "1" && "SLACK_NOTIFICATIONS" == "1" ]]; then
        /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/web/spider-new-$TARGET.txt"
      fi
    fi
    if [[ "$INJECTX" == "1" ]]; then
      rm -f $LOOT_DIR/web/injectx-$TARGET-https-${PORT}.raw 2> /dev/null
      #cat $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | grep '?' | grep 'https\:' | xargs -P $THREADS -r -n 1 -I '{}' injectx.py -u '{}' -vy | tee -a $LOOT_DIR/web/injectx-$TARGET-https.txt
      for a in `cat $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | grep '?' | grep "https\:" | cut -d '?' -f2 | cut -d '=' -f1 | sort -u`; do for b in `grep $a $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | grep "https\:" | head -n 1`; do injectx.py -u $b -vy | tee -a $LOOT_DIR/web/injectx-$TARGET-https-${PORT}.txt; done; done;
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/injectx-$TARGET-https-${PORT}.raw 2> /dev/null > $LOOT_DIR/web/injectx-$TARGET-https-${PORT}.txt
    fi
    source $INSTALL_DIR/modes/static-grep-search.sh
    if [[ "$WEB_JAVASCRIPT_ANALYSIS" == "1" ]]; then
      source $INSTALL_DIR/modes/javascript-analysis.sh
    fi
    touch $LOOT_DIR/web/dirsearch-$TARGET.bak 2> /dev/null
    cp $LOOT_DIR/web/dirsearch-$TARGET.txt $LOOT_DIR/web/dirsearch-$TARGET.bak 2> /dev/null
    if [[ "$WEB_BRUTE_COMMONSCAN" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING COMMON FILE/DIRECTORY BRUTE FORCE $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [[ "$DIRSEARCH" == "1" ]]; then
        python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u http://$TARGET:$PORT -w $WEB_BRUTE_COMMON -x $WEB_BRUTE_EXCLUDE_CODES -F -e "$WEB_BRUTE_EXTENSIONS" -t $THREADS --exclude-texts=Attack Detected,Please contact the system administrator,Page Not Found,URL No Longer Exists --random-agent --output=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
      fi
      if [[ "$GOBUSTER" == "1" ]]; then
          gobuster -u https://$TARGET:$PORT -w $WEB_BRUTE_COMMON -e -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36" -t $THREADS -o $LOOT_DIR/web/webbrute-$TARGET-https-port$PORT-common.txt -fw -r
      fi
    fi
    if [[ "$WEB_BRUTE_FULLSCAN" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING FULL FILE/DIRECTORY BRUTE FORCE $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [[ "$DIRSEARCH" == "1" ]]; then
        python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET:$PORT -w $WEB_BRUTE_FULL -x $WEB_BRUTE_EXCLUDE_CODES -F -e "/" -t $THREADS --exclude-texts=Attack Detected,Please contact the system administrator,Page Not Found,URL No Longer Exists --random-agent --output=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
      fi
      if [[ "$GOBUSTER" == "1" ]]; then
        gobuster -u https://$TARGET:$PORT -w $WEB_BRUTE_FULL -e -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36" -t $THREADS -o $LOOT_DIR/web/webbrute-$TARGET-https-port$PORT-full.txt -fw -r
      fi
    fi
    if [[ "$WEB_BRUTE_EXPLOITSCAN" == "1" ]]; then
        echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
        echo -e "$OKRED RUNNING FILE/DIRECTORY BRUTE FORCE FOR VULNERABILITIES $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
        if [[ "$DIRSEARCH" == "1" ]]; then
          python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET:$PORT -w $WEB_BRUTE_EXPLOITS -x $WEB_BRUTE_EXCLUDE_CODES -F -e "/" -t $THREADS --exclude-texts=Attack Detected,Please contact the system administrator,Page Not Found,URL No Longer Exists --random-agent --output=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
        fi
        if [[ "$GOBUSTER" == "1" ]]; then
          gobuster -u https://$TARGET:$PORT -w $WEB_BRUTE_EXPLOITS -e -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36" -t $THREADS -o $LOOT_DIR/web/webbrute-$TARGET-https-port$PORT-exploits.txt -fw -r
        fi
    fi
    if [[ "$DIRSEARCH" == "1" ]]; then
      cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* 2> /dev/null
      cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* > $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
      sort -u $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > $LOOT_DIR/web/dirsearch-$TARGET.sorted 2> /dev/null
      mv $LOOT_DIR/web/dirsearch-$TARGET.sorted $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null 
      diff $LOOT_DIR/web/dirsearch-$TARGET.bak $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{print $2 " " $3 " " $4}' 2> /dev/null > $LOOT_DIR/web/dirsearch-new-$TARGET.txt
      if [[ $(wc -c $LOOT_DIR/web/dirsearch-new-$TARGET.txt| awk '{print $1}') > 3 ]]; then
        echo "[sn1persecurity.com] •?((¯°·._.• Disovered URL change detected on $TARGET (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
        cat $LOOT_DIR/web/dirsearch-new-$TARGET.txt 2> /dev/null >> $LOOT_DIR/scans/notifications_new.txt 2> /dev/null
      fi
      if [[ "$SLACK_NOTIFICATIONS_DIRSEARCH_NEW" == "1" ]]; then
        /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/web/dirsearch-new-$TARGET.txt"
      fi
    fi
    if [[ "$GOBUSTER" == "1" ]]; then
        sort -u $LOOT_DIR/web/webbrute-$TARGET-*.txt 2> /dev/null > $LOOT_DIR/web/webbrute-$TARGET.txt 2> /dev/null
    fi
    wget --connect-timeout=5 --read-timeout=10 --tries=1 https://$TARGET:${PORT}/robots.txt -O $LOOT_DIR/web/robots-$TARGET:${PORT}-https.txt 2> /dev/null
    if [[ "$CLUSTERD" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED ENUMERATING WEB SOFTWARE $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      clusterd --sVl -i $TARGET -p ${PORT} 2> /dev/null | tee $LOOT_DIR/web/clusterd-$TARGET-port${PORT}.txt
    fi
    if [[ "$CMSMAP" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING CMSMAP $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cmsmap https://$TARGET:${PORT} | tee $LOOT_DIR/web/cmsmap-$TARGET-http-port${PORT}a.txt
      echo ""
      cmsmap https://$TARGET:${PORT}/wordpress/ | tee $LOOT_DIR/web/cmsmap-$TARGET-http-port${PORT}b.txt
      echo ""
    fi
    if [[ "$WPSCAN" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING WORDPRESS VULNERABILITY SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [[ "$WP_API_KEY" ]]; then
        wpscan --url https://$TARGET:${PORT} --no-update --disable-tls-checks --api-token $WP_API_KEY 2> /dev/null | tee $LOOT_DIR/web/wpscan-$TARGET-https-port${PORT}a.raw
        echo ""
        wpscan --url https://$TARGET:${PORT}/wordpress/ --no-update --disable-tls-checks --api-token $WP_API_KEY 2> /dev/null | tee $LOOT_DIR/web/wpscan-$TARGET-https-port${PORT}b.raw
        echo ""
      else
        wpscan --url https://$TARGET:${PORT} --no-update --disable-tls-checks 2> /dev/null | tee $LOOT_DIR/web/wpscan-$TARGET-https-port${PORT}a.raw
        echo ""
        wpscan --url https://$TARGET:${PORT}/wordpress/ --no-update --disable-tls-checks 2> /dev/null | tee $LOOT_DIR/web/wpscan-$TARGET-https-port${PORT}b.raw
      fi
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/wpscan-$TARGET-https-port${PORT}a.raw 2> /dev/null > $LOOT_DIR/web/wpscan-$TARGET-https-port${PORT}a.txt
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/wpscan-$TARGET-https-port${PORT}b.raw 2> /dev/null > $LOOT_DIR/web/wpscan-$TARGET-https-port${PORT}b.txt
      rm -f $LOOT_DIR/web/wpscan-$TARGET-http*.raw 2> /dev/null
    fi
    if [[ "$NIKTO" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING WEB VULNERABILITY SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      nikto -h https://$TARGET:${PORT} -output $LOOT_DIR/web/nikto-$TARGET-https-port${PORT}.txt
      sed -ir "s/</\&lh\;/g" $LOOT_DIR/web/nikto-$TARGET-https-port${PORT}.txt
    fi
    if [[ "$SHOCKER" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING SHELLSHOCK EXPLOIT SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      python3 $PLUGINS_DIR/shocker/shocker.py -H $TARGET --cgilist $PLUGINS_DIR/shocker/shocker-cgi_list --sVl --port ${PORT} | tee $LOOT_DIR/web/shocker-$TARGET-port${PORT}.txt
    fi
    if [[ "$JEXBOSS" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING JEXBOSS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cd /tmp/
      python3 /usr/share/sniper/plugins/jexboss/jexboss.py -u https://$TARGET:${PORT} | tee $LOOT_DIR/web/jexboss-$TARGET-port${PORT}.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/jexboss-$TARGET-port${PORT}.raw > $LOOT_DIR/web/jexboss-$TARGET-port${PORT}.txt 2> /dev/null
      rm -f $LOOT_DIR/web/jexboss-$TARGET-port${PORT}.raw 2> /dev/null
      cd $INSTALL_DIR
    fi
    if [[ "$SMUGGLER" = "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING HTTP REQUEST SMUGGLING DETECTION $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      python3 /usr/share/sniper/plugins/smuggler/smuggler.py --no-color -u https://$TARGET:${PORT} | tee $LOOT_DIR/web/smuggler-$TARGET-port${PORT}.txt
    fi
    if [[ "$NUCLEI" = "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING NUCLEI SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      nuclei -silent -t /root/nuclei-templates/ -c $THREADS -target https://$TARGET:${PORT} -o $LOOT_DIR/web/nuclei-https-${TARGET}-port${PORT}.txt
    fi
    cd $INSTALL_DIR
    SSL="true"
    source $INSTALL_DIR/modes/web_autopwn.sh 
    source $INSTALL_DIR/modes/osint_stage_2.sh
  fi
  if [[ "$BURP_SCAN" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING BURPSUITE SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    curl -s -X POST "http://$BURP_HOST:$BURP_PORT/v0.1/scan" -d "{\"scope\":{\"include\":[{\"rule\":\"https://$TARGET:$PORT\"}],\"type\":\"SimpleScope\"},\"urls\":[\"https://$TARGET:$PORT\"]}"
    echo "" 
    for a in {1..30}; 
    do 
      echo -n "[-] SCAN #$a: "
      curl -sI "http://$BURP_HOST:$BURP_PORT/v0.1/scan/$a" | grep HTTP | awk '{print $2}'
      BURP_STATUS=$(curl -s http://$BURP_HOST:$BURP_PORT/v0.1/scan/$a | grep -o -P "crawl_and_audit.{1,100}" | cut -d\" -f3 | grep "remaining")
      while [[ ${#BURP_STATUS} -gt "5" ]]; 
      do 
        BURP_STATUS=$(curl -s http://$BURP_HOST:$BURP_PORT/v0.1/scan/$a | grep -o -P "crawl_and_audit.{1,100}" | cut -d\" -f3 | grep "remaining")
        BURP_STATUS_FULL=$(curl -s http://$BURP_HOST:$BURP_PORT/v0.1/scan/$a | grep -o -P "crawl_and_audit.{1,100}" | cut -d\" -f3)
        echo "[i] STATUS: $BURP_STATUS_FULL"
        sleep 15
      done
    done 
    echo "[+] VULNERABILITIES: "
    echo "----------------------------------------------------------------"
    for a in {1..30}; 
    do
      curl -s "http://$BURP_HOST:$BURP_PORT/v0.1/scan/$a" | jq '.issue_events[].issue | "[" + .severity + "] " + .name + " - " + .origin + .path' | sort -u | sed 's/\"//g' | tee $LOOT_DIR/web/burpsuite-$TARGET-$a.txt
    done
    echo "[-] Done!"
    fi
    if [[ "$ZAP_SCAN" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING OWASP ZAP SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo "[i] Scanning: https://$TARGET:$PORT/"
      sudo python3 /usr/share/sniper/bin/zap-scan.py "https://$TARGET:$PORT/" 
      DATE=$(date +"%Y%m%d%H%M")
      sudo grep "'" /usr/share/sniper/bin/zap-report.txt | cut -d\' -f2 | cut -d\\ -f1 > $LOOT_DIR/web/zap-report-$TARGET-https-$DATE.html
      cp -f $LOOT_DIR/web/zap-report-$TARGET-https-$DATE.html $LOOT_DIR/web/zap-report-$TARGET-https.html 2> /dev/null
      echo "[i] Scan complete."
      echo "[+] Report saved to: $LOOT_DIR/web/zap-report-$TARGET-https-$DATE.html"
    fi
    if [[ "$ARACHNI_SCAN" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING ARACHNI SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      DATE=$(date +"%Y%m%d%H%M")
      mkdir -p $LOOT_DIR/web/arachni_${TARGET}_${PORT}_${DATE}/
      arachni --report-save-path=$LOOT_DIR/web/arachni_${TARGET}_${PORT}_${DATE}/ --output-only-positives http://$TARGET:$PORT | tee ${LOOT_DIR}/web/arachni_webscan_${TARGET}_${PORT}_${DATE}.txt

      cd $LOOT_DIR/web/arachni_${TARGET}_${PORT}_${DATE}/
      arachni_reporter $LOOT_DIR/web/arachni_${TARGET}_${PORT}_${DATE}/*.afr --report=html:outfile=$LOOT_DIR/web/arachni_${TARGET}_${PORT}_${DATE}/arachni.zip
      cd $LOOT_DIR/web/arachni_${TARGET}_${PORT}_${DATE}/
      unzip arachni.zip
      cd $INSTALL_DIR
    fi
    if [[ "$SC0PE_VULNERABLITY_SCANNER" == "1" ]]; then
        echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
        echo -e "$OKRED RUNNING SC0PE WEB VULNERABILITY SCAN $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
        SSL="true"
        source $INSTALL_DIR/modes/sc0pe-passive-webscan.sh
        source $INSTALL_DIR/modes/sc0pe-active-webscan.sh
        for file in `ls $INSTALL_DIR/templates/passive/web/recursive/*.sh 2> /dev/null`; do
          source $file
        done
        source $INSTALL_DIR/modes/sc0pe-network-scan.sh
        echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    fi
    source $INSTALL_DIR/modes/sc0pe.sh 
    cd $INSTALL_DIR
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED SCAN COMPLETE! $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo "$TARGET" >> $LOOT_DIR/scans/updated.txt
    rm -f $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt 2> /dev/null
    ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt
    rm -f $INSTALL_DIR/.fuse_* 2> /dev/null
    VULNERABLE_METASPLOIT=$(egrep -h -i -s "may be vulnerable|is vulnerable|IKE response with leak|File saved in" $LOOT_DIR/output/msf-$TARGET-*.txt 2> /dev/null)
    if [[ ${#VULNERABLE_METASPLOIT} -ge 5 ]]; then
      echo "$VULNERABLE_METASPLOIT" > $LOOT_DIR/output/vulnerable-metasploit-$TARGET.txt 2> /dev/null
    fi
    VULNERABLE_SHELLSHOCK=$(egrep -h -i -s "The following URLs appear to be exploitable:" $LOOT_DIR/web/shocker-$TARGET-*.txt 2> /dev/null)
    if [[ ${#VULNERABLE_SHELLSHOCK} -ge 5 ]]; then
      echo "$VULNERABLE_SHELLSHOCK" > $LOOT_DIR/output/vulnerable-shellshock-$TARGET.txt 2> /dev/null
    fi
    SHELLED=$(egrep -h -i -s "Meterpreter session|Command executed|File(s) found:|Command Stager progress|File uploaded|Command shell session" $LOOT_DIR/output/msf-$TARGET-*.txt 2> /dev/null)
    if [[ ${#SHELLED} -ge 5 ]]; then
      echo "$SHELLED" > $LOOT_DIR/output/shelled-$TARGET.txt 2> /dev/null
    fi

    echo "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per scan: https://$TARGET:$PORT [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
    if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per scan: https://$TARGET:$PORT [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
    fi
    if [[ "$LOOT" = "1" ]]; then
      loot
    fi
    exit
  fi 