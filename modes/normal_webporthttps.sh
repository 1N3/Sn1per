if [ "$MODE" = "web" ]; then
  if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Started Sn1per HTTPS web scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
  if [ "$PASSIVE_SPIDER" == "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING PASSIVE WEB SPIDER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.$TARGET&output=json" | jq -r .url | tee $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null
  fi
  if [ "$WAYBACKMACHINE" == "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED FETCHING WAYBACK MACHINE URLS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    curl -sX GET "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" | tee $LOOT_DIR/web/waybackurls-$TARGET.txt 2> /dev/null
  fi
  if [ "$HACKERTARGET" == "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED FETCHING HACKERTARGET URLS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    curl -sX GET "http://api.hackertarget.com/pagelinks/?q=https://$TARGET" | tee $LOOT_DIR/web/hackertarget-https-$TARGET.txt 2> /dev/null
  fi
  if [ "$BLACKWIDOW" == "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING ACTIVE WEB SPIDER & APPLICATION SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    touch $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    cp $LOOT_DIR/web/spider-$TARGET.txt $LOOT_DIR/web/spider-$TARGET.bak 2>/dev/null
    blackwidow -u https://$TARGET:443 -l 3 -s y -v n
    cp -f /usr/share/blackwidow/"$TARGET"_443/"$TARGET"_443-*.txt $LOOT_DIR/web/ 2>/dev/null 
    cat /usr/share/blackwidow/"$TARGET"_*/"$TARGET"_*-urls-sorted.txt > $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    cat $LOOT_DIR/web/waybackurls-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    cat $LOOT_DIR/web/hackertarget-*-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    cat $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    sed -ir "s/</\&lh\;/g" $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    sort -u $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null > $LOOT_DIR/web/spider-$TARGET.sorted 2>/dev/null
    mv $LOOT_DIR/web/spider-$TARGET.sorted $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    diff $LOOT_DIR/web/spider-$TARGET.bak $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{print $2}' 2> /dev/null > $LOOT_DIR/web/spider-new-$TARGET.txt
    if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/web/spider-new-$TARGET.txt"
    fi
  fi
  touch $LOOT_DIR/web/dirsearch-$TARGET.bak 2> /dev/null
  cp $LOOT_DIR/web/dirsearch-$TARGET.txt $LOOT_DIR/web/dirsearch-$TARGET.bak 2> /dev/null
  if [ "$WEB_BRUTE_COMMONSCAN" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING COMMON FILE/DIRECTORY BRUTE FORCE $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [ "$DIRSEARCH" == "1" ]; then
        python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET -w $WEB_BRUTE_STEALTH -x 400,403,404,405,406,429,502,503,504 -F -e $WEB_BRUTE_EXTENSIONS -f -r -t $THREADS --random-agents --plain-text-report=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > /dev/null && cat $LOOT_DIR/web/dirsearch-$TARGET.txt
        python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET -w $WEB_BRUTE_COMMON -x 400,403,404,405,406,429,502,503,504 -F -e * -t $THREADS --random-agents --plain-text-report=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > /dev/null && cat $LOOT_DIR/web/dirsearch-$TARGET.txt
      fi
      if [ "$GOBUSTER" == "1" ]; then
          gobuster -u https://$TARGET -w $WEB_BRUTE_COMMON -e | tee $LOOT_DIR/web/gobuster-$TARGET-https-common.txt
      fi
  fi
  if [ "$WEB_BRUTE_FULLSCAN" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING FULL FILE/DIRECTORY BRUTE FORCE $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [ "$DIRSEARCH" == "1" ]; then
          python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET -w $WEB_BRUTE_FULL -x 400,403,404,405,406,429,502,503,504 -F -e * -t $THREADS --random-agents --plain-text-report=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > /dev/null && cat $LOOT_DIR/web/dirsearch-$TARGET.txt
      fi
      if [ "$GOBUSTER" == "1" ]; then
          gobuster -u https://$TARGET -w $WEB_BRUTE_FULL -e | tee $LOOT_DIR/web/gobuster-$TARGET-https-full.txt
      fi
  fi
  if [ "$WEB_BRUTE_EXPLOITSCAN" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING FILE/DIRECTORY BRUTE FORCE FOR VULNERABILITIES $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [ "$DIRSEARCH" == "1" ]; then
          python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET -w $WEB_BRUTE_EXPLOITS -x 400,403,404,405,406,429,502,503,504 -F -e * -t $THREADS --random-agents --plain-text-report=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > /dev/null && cat $LOOT_DIR/web/dirsearch-$TARGET.txt
      fi
      if [ "$GOBUSTER" == "1" ]; then
          gobuster -u https://$TARGET -w $WEB_BRUTE_EXPLOITS -e | tee $LOOT_DIR/web/gobuster-$TARGET-https-exploits.txt
      fi
  fi
  if [ "$DIRSEARCH" == "1" ]; then
      cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* 2> /dev/null
      cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* > $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
      sort -u $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > $LOOT_DIR/web/dirsearch-$TARGET.sorted 2> /dev/null
      mv $LOOT_DIR/web/dirsearch-$TARGET.sorted $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null 
      diff $LOOT_DIR/web/dirsearch-$TARGET.bak $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{print $2 " " $3 " " $4}' 2> /dev/null > $LOOT_DIR/web/dirsearch-new-$TARGET.txt
      if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
        /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/web/dirsearch-new-$TARGET.txt"
      fi
  fi
  if [ "$GOBUSTER" == "1" ]; then
      sort -u $LOOT_DIR/web/webbrute-$TARGET-*.txt 2> /dev/null > $LOOT_DIR/web/webbrute-$TARGET.txt 2> /dev/null
  fi
  wget https://$TARGET/robots.txt -O $LOOT_DIR/web/robots-$TARGET-https.txt 2> /dev/null
  if [ "$CLUSTERD" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED ENUMERATING WEB SOFTWARE $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      clusterd --ssl -i $TARGET 2> /dev/null | tee $LOOT_DIR/web/clusterd-$TARGET-https.txt
  fi
  if [ "$CMSMAP" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING CMSMAP $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cmsmap https://$TARGET | tee $LOOT_DIR/web/cmsmap-$TARGET-httpsa.txt
      echo ""
      cmsmap https://$TARGET/wordpress/ | tee $LOOT_DIR/web/cmsmap-$TARGET-httpsb.txt
      echo ""
  fi
  if [ "$WPSCAN" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING WORDPRESS VULNERABILITY SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      wpscan --url https://$TARGET --no-update --disable-tls-checks 2> /dev/null | tee $LOOT_DIR/web/cmsmap-$TARGET-httpsa.txt
      echo ""
      wpscan --url https://$TARGET/wordpress/ --no-update --disable-tls-checks 2> /dev/null | tee $LOOT_DIR/web/cmsmap-$TARGET-httpsb.txt
  fi
  if [ "$NIKTO" == "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING WEB VULNERABILITY SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nikto -h https://$TARGET -output $LOOT_DIR/web/nikto-$TARGET-http-port443.txt
    sed -ir "s/</\&lh\;/g" $LOOT_DIR/web/nikto-$TARGET-http-port443.txt
  fi
  if [ "$SHOCKER" = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING SHELLSHOCK EXPLOIT SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      python $PLUGINS_DIR/shocker/shocker.py -H $TARGET --cgilist $PLUGINS_DIR/shocker/shocker-cgi_list --ssl --port 443 | tee $LOOT_DIR/web/shocker-$TARGET-port443.txt
  fi
  if [ "$JEXBOSS" = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING JEXBOSS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cd /tmp/
      python /usr/share/sniper/plugins/jexboss/jexboss.py -u https://$TARGET | tee $LOOT_DIR/web/jexboss-$TARGET-port443.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/jexboss-$TARGET-port443.raw > $LOOT_DIR/web/jexboss-$TARGET-port443.txt 2> /dev/null
      rm -f $LOOT_DIR/web/jexboss-$TARGET-port443.raw 2> /dev/null
      cd $INSTALL_DIR
  fi
  if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Finished Sn1per HTTPS web scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
  cd $INSTALL_DIR
  if [ "$METASPLOIT_EXPLOIT" == "1" ]; then
      PORT="443"
      SSL="true"
      source modes/web_autopwn.sh
  fi
fi