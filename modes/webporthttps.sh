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
    echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/running-$TARGET-webporthttps.txt
    if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Started Sn1per scan: https://$TARGET:$PORT [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
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
  echo -e "$OKORANGE + -- --=[https://xerosecurity.com"
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
  nmap -sV -Pn --data-length=50 -p $PORT --open $TARGET -oX $LOOT_DIR/nmap/nmap-https-$TARGET.xml
  port_https=`grep 'portid="'$PORT'"' $LOOT_DIR/nmap/nmap-https-$TARGET.xml | grep open`
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
    curl --connect-timeout 5 -I -s -R https://$TARGET:$PORT | tee $LOOT_DIR/web/headers-https-$TARGET-$PORT.txt 2> /dev/null
    curl --connect-timeout 5 -I -s -R -L https://$TARGET:$PORT | tee $LOOT_DIR/web/websource-https-$TARGET-$PORT.txt 2> /dev/null
    curl --connect-timeout 5 --max-time 10 -I -s -R -X OPTIONS https://$TARGET:$PORT | grep Allow\: | tee $LOOT_DIR/web/http_options-$TARGET-port$PORT.txt 2> /dev/null
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
      wafw00f https://$TARGET:$PORT | tee $LOOT_DIR/web/waf-$TARGET-https-port$PORT.txt 2> /dev/null
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
      nmap -A -Pn -T5 -p $PORT -sV --script=/usr/share/nmap/scripts/iis-buffer-overflow.nse --script=http-vuln*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port$PORT
      sed -r "s/</\&lh\;/g" $LOOT_DIR/output/nmap-$TARGET-port$PORT 2> /dev/null > $LOOT_DIR/output/nmap-$TARGET-port$PORT.txt 2> /dev/null
      rm -f $LOOT_DIR/output/nmap-$TARGET-port$PORT 2> /dev/null
    fi
    if [[ "$PASSIVE_SPIDER" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING PASSIVE WEB SPIDER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2019-51-index?url=*.$TARGET&output=json" | jq -r .url | egrep -v "null" | tee $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null
    fi
    if [[ "$WAYBACKMACHINE" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED FETCHING WAYBACK MACHINE URLS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      curl -sX GET "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" | tee $LOOT_DIR/web/waybackurls-$TARGET.txt 2> /dev/null
    fi
    if [[ "$HACKERTARGET" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED FETCHING HACKERTARGET URLS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      curl -sX GET "http://api.hackertarget.com/pagelinks/?q=https://$TARGET" | egrep -v "API count|no links found|input url is invalid|API count|no links found|input url is invalid" | tee $LOOT_DIR/web/hackertarget-https-$TARGET.txt 2> /dev/null
    fi
    if [[ "$BLACKWIDOW" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING ACTIVE WEB SPIDER & APPLICATION SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      touch $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cp $LOOT_DIR/web/spider-$TARGET.txt $LOOT_DIR/web/spider-$TARGET.bak 2>/dev/null
      blackwidow -u https://$TARGET:$PORT -l 3 -s y -v n 2> /dev/null
      cp -f /usr/share/blackwidow/"$TARGET"_"$PORT"/"$TARGET"_"$PORT"-*.txt $LOOT_DIR/web/ 2>/dev/null 
      cat /usr/share/blackwidow/"$TARGET"_*/"$TARGET"_*-urls-sorted.txt > $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cat $LOOT_DIR/web/hackertarget-*-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cat $LOOT_DIR/web/waybackurls-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cat $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      sed -ir "s/</\&lh\;/g" $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      sort -u $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null > $LOOT_DIR/web/spider-$TARGET.sorted 2>/dev/null
      mv $LOOT_DIR/web/spider-$TARGET.sorted $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      diff $LOOT_DIR/web/spider-$TARGET.bak $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{print $2}' 2> /dev/null > $LOOT_DIR/web/spider-new-$TARGET.txt
      if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
        /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/web/spider-new-$TARGET.txt"
      fi
    fi
    touch $LOOT_DIR/web/dirsearch-$TARGET.bak 2> /dev/null
    cp $LOOT_DIR/web/dirsearch-$TARGET.txt $LOOT_DIR/web/dirsearch-$TARGET.bak 2> /dev/null
    if [[ "$WEB_BRUTE_COMMONSCAN" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING COMMON FILE/DIRECTORY BRUTE FORCE $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [[ "$DIRSEARCH" == "1" ]]; then
        python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u http://$TARGET:$PORT -w $WEB_BRUTE_STEALTH -x 400,403,404,405,406,429,502,503,504 -F -e $WEB_BRUTE_EXTENSIONS -f -r -t $THREADS --random-agents --plain-text-report=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > /dev/null && cat $LOOT_DIR/web/dirsearch-$TARGET.txt
        python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u http://$TARGET:$PORT -w $WEB_BRUTE_COMMON -x 400,403,404,405,406,429,502,503,504 -F -e * -t $THREADS --random-agents --plain-text-report=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > /dev/null && cat $LOOT_DIR/web/dirsearch-$TARGET.txt
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
        python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET:$PORT -w $WEB_BRUTE_FULL -x 400,403,404,405,406,429,502,503,504 -F -e * -t $THREADS --random-agents --plain-text-report=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > /dev/null && cat $LOOT_DIR/web/dirsearch-$TARGET.txt
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
          python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET:$PORT -w $WEB_BRUTE_EXPLOITS -x 400,403,404,405,406,429,502,503,504 -F -e * -t $THREADS --random-agents --plain-text-report=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > /dev/null && cat $LOOT_DIR/web/dirsearch-$TARGET.txt
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
      if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
        /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/web/dirsearch-new-$TARGET.txt"
      fi
    fi
    if [[ "$GOBUSTER" == "1" ]]; then
        sort -u $LOOT_DIR/web/webbrute-$TARGET-*.txt 2> /dev/null > $LOOT_DIR/web/webbrute-$TARGET.txt 2> /dev/null
    fi
    wget https://$TARGET:$PORT/robots.txt -O $LOOT_DIR/web/robots-$TARGET:$PORT-https.txt 2> /dev/null
    if [[ "$CLUSTERD" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED ENUMERATING WEB SOFTWARE $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      clusterd --ssl -i $TARGET -p $PORT 2> /dev/null | tee $LOOT_DIR/web/clusterd-$TARGET-port$PORT.txt
    fi
    if [[ "$CMSMAP" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING CMSMAP $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cmsmap https://$TARGET:$PORT | tee $LOOT_DIR/web/cmsmap-$TARGET-http-port$PORTa.txt
      echo ""
      cmsmap https://$TARGET:$PORT/wordpress/ | tee $LOOT_DIR/web/cmsmap-$TARGET-http-port$PORTb.txt
      echo ""
    fi
    if [[ "$WPSCAN" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING WORDPRESS VULNERABILITY SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      wpscan --url https://$TARGET:$PORT --no-update --disable-tls-checks 2> /dev/null | tee $LOOT_DIR/web/wpscan-$TARGET-http-port$PORTa.txt
      echo ""
      wpscan --url https://$TARGET:$PORT/wordpress/ --no-update --disable-tls-checks 2> /dev/null | tee $LOOT_DIR/web/wpscan-$TARGET-http-port$PORTb.txt
    fi
    if [[ "$NIKTO" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING WEB VULNERABILITY SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      nikto -h https://$TARGET:$PORT -output $LOOT_DIR/web/nikto-$TARGET-https-port$PORT.txt
      sed -ir "s/</\&lh\;/g" $LOOT_DIR/web/nikto-$TARGET-https-port$PORT.txt
    fi
    if [[ "$SHOCKER" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING SHELLSHOCK EXPLOIT SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      python $PLUGINS_DIR/shocker/shocker.py -H $TARGET --cgilist $PLUGINS_DIR/shocker/shocker-cgi_list --ssl --port $PORT | tee $LOOT_DIR/web/shocker-$TARGET-port$PORT.txt
    fi
    if [[ "$JEXBOSS" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING JEXBOSS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cd /tmp/
      python /usr/share/sniper/plugins/jexboss/jexboss.py -u https://$TARGET:$PORT | tee $LOOT_DIR/web/jexboss-$TARGET-port$PORT.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/jexboss-$TARGET-port$PORT.raw > $LOOT_DIR/web/jexboss-$TARGET-port$PORT.txt 2> /dev/null
      rm -f $LOOT_DIR/web/jexboss-$TARGET-port$PORT.raw 2> /dev/null
      cd $INSTALL_DIR
    fi
    cd $INSTALL_DIR
    if [[ "$METASPLOIT_EXPLOIT" == "1" ]]; then
      SSL="true"
      source modes/web_autopwn.sh 
    fi
    source modes/osint_stage_2.sh
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED SCAN COMPLETE! $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo "$TARGET" >> $LOOT_DIR/scans/updated.txt
  mv $LOOT_DIR/scans/running-$TARGET-webporthttps.txt $LOOT_DIR/scans/finished-$TARGET-webporthttps.txt 2> /dev/null
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
  if [[ "$LOOT" = "1" ]]; then
    loot
  fi
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Finished Sn1per scan: https://$TARGET:$PORT [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
  exit
fi 